# -*- coding: utf-8 -*-
# Copyright 2020 The Matrix.org Foundation C.I.C.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import logging
import urllib.parse
from typing import TYPE_CHECKING, Dict, Optional, Tuple
from xml.etree import ElementTree as ET

from twisted.web.client import PartialDownloadError

from synapse.api.errors import Codes, LoginError
from synapse.handlers.sso import MappingException, UserAttributes
from synapse.http.site import SynapseRequest
from synapse.types import UserID, map_username_to_mxid_localpart

if TYPE_CHECKING:
    from synapse.app.homeserver import HomeServer

logger = logging.getLogger(__name__)


class CasHandler:
    """
    Utility class for to handle the response from a CAS SSO service.

    Args:
        hs
    """

    def __init__(self, hs: "HomeServer"):
        self.hs = hs
        self._hostname = hs.hostname
        self._store = hs.get_datastore()
        self._auth_handler = hs.get_auth_handler()
        self._registration_handler = hs.get_registration_handler()

        self._cas_server_url = hs.config.cas_server_url
        self._cas_service_url = hs.config.cas_service_url
        self._cas_displayname_attribute = hs.config.cas_displayname_attribute
        self._cas_required_attributes = hs.config.cas_required_attributes

        self._http_client = hs.get_proxied_http_client()

        # identifier for the external_ids table
        self._auth_provider_id = "cas"

        self._sso_handler = hs.get_sso_handler()

    def _build_service_param(self, args: Dict[str, str]) -> str:
        """
        Generates a value to use as the "service" parameter when redirecting or
        querying the CAS service.

        Args:
            args: Additional arguments to include in the final redirect URL.

        Returns:
            The URL to use as a "service" parameter.
        """
        return "%s%s?%s" % (
            self._cas_service_url,
            "/_matrix/client/r0/login/cas/ticket",
            urllib.parse.urlencode(args),
        )

    async def _validate_ticket(
        self, ticket: str, service_args: Dict[str, str]
    ) -> Tuple[str, Optional[str]]:
        """
        Validate a CAS ticket with the server, parse the response, and return the user and display name.

        Args:
            ticket: The CAS ticket from the client.
            service_args: Additional arguments to include in the service URL.
                Should be the same as those passed to `get_redirect_url`.
        """
        uri = self._cas_server_url + "/proxyValidate"
        args = {
            "ticket": ticket,
            "service": self._build_service_param(service_args),
        }
        try:
            body = await self._http_client.get_raw(uri, args)
        except PartialDownloadError as pde:
            # Twisted raises this error if the connection is closed,
            # even if that's being used old-http style to signal end-of-data
            body = pde.response

        user, attributes = self._parse_cas_response(body)
        displayname = attributes.pop(self._cas_displayname_attribute, None)

        for required_attribute, required_value in self._cas_required_attributes.items():
            # If required attribute was not in CAS Response - Forbidden
            if required_attribute not in attributes:
                raise LoginError(401, "Unauthorized", errcode=Codes.UNAUTHORIZED)

            # Also need to check value
            if required_value is not None:
                actual_value = attributes[required_attribute]
                # If required attribute value does not match expected - Forbidden
                if required_value != actual_value:
                    raise LoginError(401, "Unauthorized", errcode=Codes.UNAUTHORIZED)

        return user, displayname

    def _parse_cas_response(
        self, cas_response_body: bytes
    ) -> Tuple[str, Dict[str, Optional[str]]]:
        """
        Retrieve the user and other parameters from the CAS response.

        Args:
            cas_response_body: The response from the CAS query.

        Returns:
            A tuple of the user and a mapping of other attributes.
        """
        user = None
        attributes = {}
        try:
            root = ET.fromstring(cas_response_body)
            if not root.tag.endswith("serviceResponse"):
                raise Exception("root of CAS response is not serviceResponse")
            success = root[0].tag.endswith("authenticationSuccess")
            for child in root[0]:
                if child.tag.endswith("user"):
                    user = child.text
                if child.tag.endswith("attributes"):
                    for attribute in child:
                        # ElementTree library expands the namespace in
                        # attribute tags to the full URL of the namespace.
                        # We don't care about namespace here and it will always
                        # be encased in curly braces, so we remove them.
                        tag = attribute.tag
                        if "}" in tag:
                            tag = tag.split("}")[1]
                        attributes[tag] = attribute.text
            if user is None:
                raise Exception("CAS response does not contain user")
        except Exception:
            logger.exception("Error parsing CAS response")
            raise LoginError(401, "Invalid CAS response", errcode=Codes.UNAUTHORIZED)
        if not success:
            raise LoginError(
                401, "Unsuccessful CAS response", errcode=Codes.UNAUTHORIZED
            )
        return user, attributes

    def get_redirect_url(self, service_args: Dict[str, str]) -> str:
        """
        Generates a URL for the CAS server where the client should be redirected.

        Args:
            service_args: Additional arguments to include in the final redirect URL.

        Returns:
            The URL to redirect the client to.
        """
        args = urllib.parse.urlencode(
            {"service": self._build_service_param(service_args)}
        )

        return "%s/login?%s" % (self._cas_server_url, args)

    async def handle_ticket(
        self,
        request: SynapseRequest,
        ticket: str,
        client_redirect_url: Optional[str],
        session: Optional[str],
    ) -> None:
        """
        Called once the user has successfully authenticated with the SSO.
        Validates a CAS ticket sent by the client and completes the auth process.

        If the user interactive authentication session is provided, marks the
        UI Auth session as complete, then returns an HTML page notifying the
        user they are done.

        Otherwise, this registers the user if necessary, and then returns a
        redirect (with a login token) to the client.

        Args:
            request: the incoming request from the browser. We'll
                respond to it with a redirect or an HTML page.

            ticket: The CAS ticket provided by the client.

            client_redirect_url: the redirectUrl parameter from the `/cas/ticket` HTTP request, if given.
                This should be the same as the redirectUrl from the original `/login/sso/redirect` request.

            session: The session parameter from the `/cas/ticket` HTTP request, if given.
                This should be the UI Auth session id.
        """
        args = {}
        if client_redirect_url:
            args["redirectUrl"] = client_redirect_url
        if session:
            args["session"] = session
        username, user_display_name = await self._validate_ticket(ticket, args)

        # Pull out the user-agent and IP from the request.
        user_agent = request.get_user_agent("")
        ip_address = self.hs.get_ip_from_request(request)

        # Get the matrix ID from the CAS username.
        try:
            user_id = await self._map_cas_user_to_matrix_user(
                username, user_display_name, user_agent, ip_address
            )
        except MappingException as e:
            logger.exception("Could not map user")
            self._sso_handler.render_error(request, "mapping_error", str(e))
            return

        if session:
            await self._auth_handler.complete_sso_ui_auth(
                user_id, session, request,
            )
        else:
            # If this not a UI auth request than there must be a redirect URL.
            assert client_redirect_url

            await self._auth_handler.complete_sso_login(
                user_id, request, client_redirect_url
            )

    async def _map_cas_user_to_matrix_user(
        self,
        remote_user_id: str,
        display_name: Optional[str],
        user_agent: str,
        ip_address: str,
    ) -> str:
        """
        Given a CAS username, retrieve the user ID for it and possibly register the user.

        Args:
            remote_user_id: The username from the CAS response.
            display_name: The display name from the CAS response.
            user_agent: The user agent of the client making the request.
            ip_address: The IP address of the client making the request.

        Raises:
            MappingException: if there was an error while mapping some properties

        Returns:
             The user ID associated with this response.
        """

        async def cas_response_to_user_attributes(failures: int) -> UserAttributes:
            """
            Map from CAS attributes to user attributes.
            """
            localpart = map_username_to_mxid_localpart(remote_user_id)

            # Due to the grandfathering logic matching any previously registered
            # mxids it isn't expected for there to be any failures.
            if failures:
                raise RuntimeError("CAS is not expected to de-duplicate Matrix IDs")

            return UserAttributes(localpart=localpart, display_name=display_name)

        async def grandfather_existing_users() -> Optional[str]:
            # Since CAS did not used to support storing data into the user_external_ids
            # tables, we need to attempt to map to existing users.
            user_id = UserID(
                map_username_to_mxid_localpart(remote_user_id), self._hostname
            ).to_string()

            logger.debug(
                "Looking for existing account based on mapped %s", user_id,
            )

            users = await self._store.get_users_by_id_case_insensitive(user_id)
            if users:
                registered_user_id = list(users.keys())[0]
                logger.info("Grandfathering mapping to %s", registered_user_id)
                return registered_user_id

            return None

        return await self._sso_handler.get_mxid_from_sso(
            self._auth_provider_id,
            remote_user_id,
            user_agent,
            ip_address,
            cas_response_to_user_attributes,
            grandfather_existing_users,
        )
