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

from mock import Mock
from synapse_token_authenticator import TokenAuthenticator
from jwcrypto import jwt, jwk
import time
import base64

from synapse.server import HomeServer
from synapse.module_api import ModuleApi

admins = {}


def get_auth_provider(config=None, user_exists=True):
    async def set_user_admin(user_id: str, admin: bool):
        return admins.update({user_id: admin})

    async def is_user_admin(user_id: str):
        return admins.get(user_id, False)

    async def check_user_exists(user_id: str):
        return user_exists

    async def register_user(
        localpart: str,
        admin: bool = False,
    ):
        return "@alice:example.test"

    hs = Mock(HomeServer, hostname="example.test")

    account_handler = Mock(ModuleApi)
    account_handler._hs = hs
    account_handler.server_name = "example.test"
    account_handler.register_user.side_effect = register_user
    account_handler.check_user_exists.side_effect = check_user_exists
    account_handler.set_user_admin.side_effect = set_user_admin
    account_handler.is_user_admin.side_effect = is_user_admin

    def get_qualified_user_id(*args):
        return ModuleApi.get_qualified_user_id(account_handler, *args)

    account_handler.get_qualified_user_id.side_effect = get_qualified_user_id

    if config:
        config_parsed = TokenAuthenticator.parse_config(config)
    else:
        config_parsed = TokenAuthenticator.parse_config(
            {
                "jwt": {"secret": "foxies"},
                "oidc": {
                    "issuer": "https://idp.example.test",
                    "client_id": "1111@project",
                    "client_secret": "2222@project",
                    "project_id": "231872387283",
                    "organization_id": "2283783782778",
                },
            }
        )
    return TokenAuthenticator(config_parsed, account_handler)


def get_jwt_token(
    username, exp_in=None, secret="foxies", algorithm="HS512", admin=None, claims=None
):
    k = {
        "k": base64.urlsafe_b64encode(secret.encode("utf-8")).decode("utf-8"),
        "kty": "oct",
    }
    key = jwk.JWK(**k)
    if claims is None:
        claims = {}
    claims["sub"] = username
    if admin is not None:
        claims.update({"admin": admin})

    if exp_in != -1:
        if exp_in is None:
            claims["exp"] = int(time.time()) + 120
        else:
            claims["exp"] = int(time.time()) + exp_in
    token = jwt.JWT(header={"alg": algorithm}, claims=claims)
    token.make_signed_token(key)
    return token.serialize()


def get_oidc_login(username):
    return {
        "type": "com.famedly.login.token.oidc",
        "identifier": {"type": "m.id.user", "user": username},
        "token": "zitadel_access_token",
    }


def mock_idp_get(*args, **kwargs):
    class Response:
        def __init__(self, json_data, status_code):
            self.json_data = json_data
            self.status_code = status_code

        def json(self):
            return self.json_data

        def raise_for_status(self):
            ...

    hostname = "https://idp.example.test"

    if args[0] == f"{hostname}/.well-known/openid-configuration":
        return Response(
            {
                "issuer": hostname,
                "introspection_endpoint": f"{hostname}/oauth/v2/introspect",
                "id_token_signing_alg_values_supported": "RS256",
                "jwks_uri": f"{hostname}/oauth/v2/keys",
            },
            200,
        )
    else:
        return Response(None, 404)


def mock_idp_post(*args, **kwargs):
    class Response:
        def __init__(self, json_data, status_code):
            self.json_data = json_data
            self.status_code = status_code

        def json(self):
            return self.json_data

        def raise_for_status(self):
            ...

    hostname = "https://idp.example.test"

    if args[0] == f"{hostname}/oauth/v2/introspect":
        # Fail if no access token is provided
        if kwargs.get("data") is None:
            return Response(None, 401)
        # Fail if access token is incorrect
        if kwargs["data"]["token"] != "zitadel_access_token":
            return Response(None, 401)

        return Response(
            {
                "active": True,
                "iss": hostname,
                "localpart": "alice",
                "urn:zitadel:iam:org:project:231872387283:roles": {
                    "OrgAdmin": {"2283783782778": "meow"}
                },
            },
            200,
        )
    else:
        return Response(None, 404)
