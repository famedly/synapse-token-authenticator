# -*- coding: utf-8 -*-
# Copyright (C) 2024 Famedly
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
import re
from typing import Awaitable, Callable, Optional, Tuple
import logging
from jwcrypto import jwt, jwk
from jwcrypto.common import JWException, json_decode
import json
import base64
import requests
from requests.auth import HTTPBasicAuth
from urllib.parse import urljoin

import synapse
from synapse.module_api import ModuleApi
from synapse.types import UserID

from twisted.web import resource

from synapse_token_authenticator.config import TokenAuthenticatorConfig
from synapse_token_authenticator.utils import OpenIDProviderMetadata

logger = logging.getLogger(__name__)


class TokenAuthenticator(object):
    __version__ = "0.0.0"

    def __init__(self, config: dict, account_handler: ModuleApi):
        self.api = account_handler

        auth_checkers = {}

        self.config: TokenAuthenticatorConfig = config
        if (jwt := getattr(self.config, "jwt", None)) is not None:
            if jwt.secret:
                k = {
                    "k": base64.urlsafe_b64encode(jwt.secret.encode("utf-8")).decode(
                        "utf-8"
                    ),
                    "kty": "oct",
                }
                self.key = jwk.JWK(**k)
            else:
                with open(jwt.keyfile, "r") as f:
                    self.key = jwk.JWK.from_pem(f.read())
            auth_checkers[("com.famedly.login.token", ("token",))] = self.check_jwt_auth

        if (oidc := getattr(self.config, "oidc", None)) is not None:
            auth_checkers[
                ("com.famedly.login.token.oidc", ("token",))
            ] = self.check_oidc_auth

            self.api.register_web_resource(
                "/_famedly/login/com.famedly.login.token.oidc",
                self.LoginMetadataResource(oidc),
            )

        self.api.register_password_auth_provider_callbacks(auth_checkers=auth_checkers)

    class LoginMetadataResource(resource.Resource):
        def __init__(self, oidc_config: object):
            self.issuer = oidc_config.issuer
            self.metadata_url = urljoin(
                oidc_config.issuer, "/.well-known/openid-configuration"
            )
            self.organization_id = oidc_config.organization_id
            self.project_id = oidc_config.project_id

        def render_GET(self, request):
            request.setHeader(b"content-type", b"application/json")
            request.setHeader(b"access-control-allow-origin", b"*")
            return json.dumps(
                {
                    "issuer": self.issuer,
                    "issuer-metadata": self.metadata_url,
                    "organization-id": self.organization_id,
                    "project-id": self.project_id,
                }
            ).encode("utf-8")

    async def check_jwt_auth(
        self, username: str, login_type: str, login_dict: "synapse.module_api.JsonDict"
    ) -> Optional[
        Tuple[
            str,
            Optional[Callable[["synapse.module_api.LoginResponse"], Awaitable[None]]],
        ]
    ]:
        logger.info("Receiving auth request")
        if login_type != "com.famedly.login.token":
            logger.info("Wrong login type")
            return None
        if "token" not in login_dict:
            logger.info("Missing token")
            return None
        token = login_dict["token"]

        check_claims = {}
        if self.config.jwt.require_expiry:
            check_claims["exp"] = None
        try:
            # OK, let's verify the token
            token = jwt.JWT(
                jwt=token,
                key=self.key,
                check_claims=check_claims,
                algs=[self.config.jwt.algorithm],
            )
        except ValueError as e:
            logger.info("Unrecognized token", e)
            return None
        except JWException as e:
            logger.info("Invalid token", e)
            return None
        payload = json_decode(token.claims)
        if "sub" not in payload:
            logger.info("Missing user_id field")
            return None
        token_user_id_or_localpart = payload["sub"]
        if not isinstance(token_user_id_or_localpart, str):
            logger.info("user_id isn't a string")
            return None

        token_user_id_str = self.api.get_qualified_user_id(token_user_id_or_localpart)
        user_id_str = self.api.get_qualified_user_id(username)
        user_id = UserID.from_string(user_id_str)

        # checking whether required UUID contained in case of chatbox mode
        if (
            "type" in payload
            and payload["type"] == "chatbox"
            and not re.search(
                "[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}$",
                user_id.localpart,
            )
        ):
            logger.info("user_id does not end with a UUID even though in chatbox mode")
            return None

        if not user_id.domain == self.api.server_name:
            logger.info("user_id isn't for our homeserver")
            return

        if user_id_str != token_user_id_str:
            logger.info("Non-matching user")
            return None

        user_exists = await self.api.check_user_exists(user_id_str)
        if not user_exists and not self.config.jwt.allow_registration:
            logger.info("User doesn't exist and registration is disabled")
            return None

        if not user_exists:
            logger.info("User doesn't exist, registering them...")
            await self.api.register_user(
                user_id.localpart, admin=payload.get("admin", False)
            )

        if "admin" in payload:
            await self.api.set_user_admin(user_id_str, payload["admin"])

        if "displayname" in payload:
            await self.api._hs.get_profile_handler().set_displayname(
                requester=synapse.types.create_requester(user_id),
                target_user=user_id,
                by_admin=True,
                new_displayname=payload["displayname"],
            )

        logger.info("All done and valid, logging in!")
        return (user_id_str, None)

    async def check_oidc_auth(
        self, username: str, login_type: str, login_dict: "synapse.module_api.JsonDict"
    ) -> Optional[
        Tuple[
            str,
            Optional[Callable[["synapse.module_api.LoginResponse"], Awaitable[None]]],
        ]
    ]:
        logger.info("Receiving auth request")
        if login_type != "com.famedly.login.token.oidc":
            logger.info("Wrong login type")
            return None
        if "token" not in login_dict:
            logger.info("Missing token")
            return None
        token = login_dict["token"]

        oidc = self.config.oidc
        oidc_metadata = OpenIDProviderMetadata(oidc.issuer)

        # Further validation using token introspection
        data = {"token": token, "token_type_hint": "access_token", "scope": "openid"}
        auth = HTTPBasicAuth(oidc.client_id, oidc.client_secret)
        response = requests.post(
            oidc_metadata.introspection_endpoint, data=data, auth=auth
        )
        if response.status_code == 401:
            logger.info("User's access token is invalid")
            return None

        introspection_resp = response.json()

        if not introspection_resp["active"]:
            logger.info("User is not active")
            return None

        allowed_roles = ["User", "OrgAdmin"]

        if not any(
            [
                role in allowed_roles
                for role in introspection_resp[
                    f"urn:zitadel:iam:org:project:{oidc.project_id}:roles"
                ]
            ]
        ):
            logger.info("User does not have a role in this project")
            return None

        if introspection_resp["iss"] != oidc_metadata.issuer:
            logger.info(f"Token issuer does not match: {introspection_resp['iss']}")
            return None

        if (
            oidc.allowed_client_ids is not None
            and introspection_resp["client_id"] not in oidc.allowed_client_ids
        ):
            logger.info(
                f"Client {introspection_resp['client_id']} is not in the list of allowed clients"
            )
            return None

        # Checking if the user's localpart matches
        user_id_str = self.api.get_qualified_user_id(username)
        user_id = UserID.from_string(user_id_str)

        if introspection_resp["localpart"] != user_id.localpart:
            logger.info("The provided username is incorrect")
            return None

        user_exists = await self.api.check_user_exists(user_id_str)
        if not user_exists and not self.config.oidc.allow_registration:
            logger.info("User doesn't exist and registration is disabled")
            return None

        if not user_exists:
            logger.info("User doesn't exist, registering it...")
            await self.api.register_user(user_id.localpart)

        user_id_str = self.api.get_qualified_user_id(username)

        logger.info("All done and valid, logging in!")
        return (user_id_str, None)

    @staticmethod
    def parse_config(config: dict):
        return TokenAuthenticatorConfig(config)
