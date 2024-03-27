#
# This file is licensed under the Affero General Public License (AGPL) version 3.
#
# Copyright 2020 The Matrix.org Foundation C.I.C.
# Copyright (C) 2023 New Vector, Ltd
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# See the GNU Affero General Public License for more details:
# <https://www.gnu.org/licenses/agpl-3.0.html>.
#
# Originally licensed under the Apache License, Version 2.0:
# <http://www.apache.org/licenses/LICENSE-2.0>.
#
# [This file includes modifications made by New Vector Limited]
#
#
import logging
import urllib.parse
from typing import TYPE_CHECKING, Dict, List, Optional
from xml.etree import ElementTree as ET

import attr

from twisted.web.client import PartialDownloadError

from synapse.api.errors import HttpResponseException
from synapse.handlers.sso import MappingException, UserAttributes
from synapse.http.site import SynapseRequest
from synapse.types import UserID, map_username_to_mxid_localpart

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)

class HttpSsoHandler:
    """
    Utility class for to handle the response from a CAS SSO service.

    Args:
        hs
    """

    def __init__(self, hs: "HomeServer"):
        self.hs = hs
        self._hostname = hs.hostname
        self._store = hs.get_datastores().main
        self._auth_handler = hs.get_auth_handler()
        self._registration_handler = hs.get_registration_handler()

        self._http_client = hs.get_proxied_http_client()

        # identifier for the external_ids table
        self.idp_id = "httpsso"

        # user-facing name of this auth provider
        self.idp_name = hs.config.httpsso.idp_name

        # MXC URI for icon for this auth provider
        self.idp_icon = hs.config.httpsso.idp_icon

        # optional brand identifier for this auth provider
        self.idp_brand = hs.config.httpsso.idp_brand

        self._httpsso_enable_registration = hs.config.httpsso.httpsso_enable_registration

        self._sso_handler = hs.get_sso_handler()

        self._sso_handler.register_identity_provider(self)

    async def handle_redirect_request(
        self,
        request: SynapseRequest,
        client_redirect_url: Optional[bytes],
        ui_auth_session_id: Optional[str] = None,
    ) -> str:
        """Generates a URL for the CAS server where the client should be redirected.

        Args:
            request: the incoming HTTP request
            client_redirect_url: the URL that we should redirect the
                client to after login (or None for UI Auth).
            ui_auth_session_id: The session ID of the ongoing UI Auth (or
                None if this is a login).

        Returns:
            URL to redirect to
        """

        if ui_auth_session_id:
            args = {"session": ui_auth_session_id}
        else:
            assert client_redirect_url
            args = {"redirectUrl": client_redirect_url.decode("utf8")}

        args = urllib.parse.urlencode(args)

        return self.hs.config.httpsso.httpsso_service_url + "?" + args

    async def handle_payload(
        self,
        request: SynapseRequest,
        payload: dict,
        client_redirect_url: Optional[str],
        session: Optional[str],
    ) -> None:
        if session:
            return await self._sso_handler.complete_sso_ui_auth_request(
                self.idp_id,
                payload['user'],
                session,
                request,
            )
        assert client_redirect_url is not None

        localpart = map_username_to_mxid_localpart(payload['user'])
        display_name = payload['user']
        email = payload['email']

        async def cas_response_to_user_attributes(failures: int) -> UserAttributes:
            """
            Map from SSO attributes to user attributes.
            """
            # Due to the grandfathering logic matching any previously registered
            # mxids it isn't expected for there to be any failures.
            if failures:
                raise RuntimeError("HTTP SSO is not expected to de-duplicate Matrix IDs")

            return UserAttributes(
                localpart = localpart,
                display_name = display_name,
                emails = [email]
                )

        async def grandfather_existing_users() -> Optional[str]:
            # Since SSO did not always use the user_external_ids table, always
            # to attempt to map to existing users.
            user_id = UserID(localpart, self._hostname).to_string()

            logger.debug(
                "Looking for existing account based on mapped %s",
                user_id,
            )

            users = await self._store.get_users_by_id_case_insensitive(user_id)
            if users:
                registered_user_id = list(users.keys())[0]
                logger.info("Grandfathering mapping to %s", registered_user_id)
                return registered_user_id

            return None

        await self._sso_handler.complete_sso_login_request(
            self.idp_id,
            payload['user'],
            request,
            client_redirect_url,
            cas_response_to_user_attributes,
            grandfather_existing_users,
            registration_enabled=self._httpsso_enable_registration,
        )

