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

import base64
import json
import time
from typing import Any
from unittest.mock import AsyncMock, Mock, patch

from jwcrypto import jwk, jwt
from synapse.server import HomeServer
from synapse.util import Clock
from twisted.internet.testing import MemoryReactor
from typing_extensions import override

import tests.unittest as synapsetest
from tests.test_utils import FakeResponse as Response

admins = {}


class ModuleApiTestCase(synapsetest.HomeserverTestCase):
    @classmethod
    def setUpClass(cls):
        async def set_user_admin(user_id: str, admin: bool):
            return admins.update({user_id: admin})

        async def is_user_admin(user_id: str):
            return admins.get(user_id, False)

        async def register_user(
            localpart: str,
            admin: bool = False,
        ):
            return "@alice:example.test"

        cls.patchers = [
            patch(
                "synapse.module_api.ModuleApi.set_user_admin",
                new=AsyncMock(side_effect=set_user_admin),
            ),
            patch(
                "synapse.module_api.ModuleApi.is_user_admin",
                new=AsyncMock(side_effect=is_user_admin),
            ),
            patch(
                "synapse.module_api.ModuleApi.check_user_exists",
                new=AsyncMock(return_value=True),
            ),
            patch(
                "synapse.module_api.ModuleApi.register_user",
                new=AsyncMock(side_effect=register_user),
            ),
            patch(
                "synapse.handlers.profile.ProfileHandler.set_displayname",
                new=AsyncMock(return_value=None),
            ),
        ]

        for patcher in cls.patchers:
            patcher.start()

    @classmethod
    def tearDownClass(cls):
        for patcher in cls.patchers:
            patcher.stop()

    # Ignore ARG001
    @override
    def prepare(
        self, reactor: MemoryReactor, clock: Clock, homeserver: HomeServer
    ) -> None:
        self.store = homeserver.get_datastores().main
        self.module_api = homeserver.get_module_api()
        self.event_creation_handler = homeserver.get_event_creation_handler()
        self.sync_handler = homeserver.get_sync_handler()
        self.auth_handler = homeserver.get_auth_handler()

    @override
    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        # Mock out the calls over federation.
        self.fed_transport_client = Mock(spec=["send_transaction"])
        self.fed_transport_client.send_transaction = AsyncMock(return_value={})

        return self.setup_test_homeserver(
            federation_transport_client=self.fed_transport_client,
        )

    def default_config(self) -> dict[str, Any]:
        conf = super().default_config()
        conf["server_name"] = "example.test"
        if "modules" not in conf:
            conf["modules"] = [
                {
                    "module": "synapse_token_authenticator.TokenAuthenticator",
                    "config": {
                        "jwt": {"secret": "foxies"},
                        "custom_flow": {
                            "algorithm": "HS512",
                            "secret": "foxies",
                            "notify_on_registration_uri": "http://example.test",
                        },
                        "oidc": {
                            "issuer": "https://idp.example.test",
                            "client_id": "1111@project",
                            "client_secret": "2222@project",
                            "project_id": "231872387283",
                            "organization_id": "2283783782778",
                        },
                    },
                }
            ]
        return conf


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


def mock_idp_req(method, uri, data=None, **extrargs):
    if method == "GET":
        return mock_idp_get(uri, **extrargs)
    else:
        return mock_idp_post(uri, data, **extrargs)


def mock_idp_get(uri, **kwargs):
    hostname = "https://idp.example.test"

    if uri == f"{hostname}/.well-known/openid-configuration":
        return Response.json(
            payload={
                "issuer": hostname,
                "introspection_endpoint": f"{hostname}/oauth/v2/introspect",
                "id_token_signing_alg_values_supported": "RS256",
                "jwks_uri": f"{hostname}/oauth/v2/keys",
            }
        )
    else:
        return Response(code=404)


def mock_idp_post(uri, data_raw, **kwargs):
    data = json.loads(data_raw)
    hostname = "https://idp.example.test"

    if uri == f"{hostname}/oauth/v2/introspect":
        # Fail if no access token is provided
        if data is None:
            return Response(code=401)
        # Fail if access token is incorrect
        if data["token"] != "zitadel_access_token":
            return Response(code=401)

        return Response.json(
            payload={
                "active": True,
                "iss": hostname,
                "localpart": "alice",
                "urn:zitadel:iam:org:project:231872387283:roles": {
                    "OrgAdmin": {"2283783782778": "meow"}
                },
            }
        )
    else:
        return Response(code=404)
