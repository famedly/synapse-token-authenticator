# -*- coding: utf-8 -*-
# Copyright (C) 2020 Famedly
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
import os
import base64

import synapse
from synapse.module_api import ModuleApi
from synapse.types import UserID, create_requester

logger = logging.getLogger(__name__)


class TokenAuthenticator(object):
    __version__ = "0.0.0"

    def __init__(self, config: dict, account_handler: ModuleApi):
        self.api = account_handler

        self.config = config
        if self.config.secret:
            k = {
                "k": base64.urlsafe_b64encode(
                    self.config.secret.encode("utf-8")
                ).decode("utf-8"),
                "kty": "oct",
            }
            self.key = jwk.JWK(**k)
        else:
            with open(self.config.keyfile, "r") as f:
                self.key = jwk.JWK.from_pem(f.read())

        self.api.register_password_auth_provider_callbacks(
            auth_checkers={
                ("com.famedly.login.token", ("token",)): self.check_auth,
            },
        )

    async def check_auth(
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
        if self.config.require_expiracy:
            check_claims["exp"] = None
        try:
            # OK, let's verify the token
            token = jwt.JWT(
                jwt=token,
                key=self.key,
                check_claims=check_claims,
                algs=[self.config.algorithm],
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
        if not user_exists and not self.config.allow_registration:
            logger.info("User doesn't exist and registration is disabled")
            return None

        if not user_exists:
            logger.info("User doesn't exist, registering it...")
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

    @staticmethod
    def parse_config(config):
        class _TokenAuthenticatorConfig(object):
            pass

        _config = _TokenAuthenticatorConfig()
        _config.secret = config.get("secret", False)
        _config.keyfile = config.get("keyfile", False)
        if not _config.secret and not _config.keyfile:
            raise Exception("Missing secret or keyfile")
        if _config.keyfile and not os.path.exists(_config.keyfile):
            raise Exception("Keyfile doesn't exist")

        _config.algorithm = config.get("algorithm", "HS512")
        if not _config.algorithm in [
            "HS256",
            "HS384",
            "HS512",
            "RS256",
            "RS384",
            "RS512",
            "ES256",
            "ES384",
            "ES512",
            "PS256",
            "PS384",
            "PS512",
            "EdDSA",
        ]:
            raise Exception("Unknown algorithm " + _config.algorithm)

        _config.allow_registration = config.get("allow_registration", False)
        _config.require_expiracy = config.get("require_expiracy", True)
        return _config
