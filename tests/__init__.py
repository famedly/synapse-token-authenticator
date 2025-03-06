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
import logging
import time
import json
from typing import Any
from unittest.mock import AsyncMock, Mock, patch
from urllib.parse import parse_qs

from jwcrypto import jwk, jwt, jwe
from synapse.server import HomeServer
from synapse.util import Clock
from twisted.internet.testing import MemoryReactor
from typing_extensions import override

import tests.unittest as synapsetest
from tests.test_utils import FakeResponse as Response

admins = {}
logger = logging.getLogger(__name__)
ENC_JWK = jwk.JWK.generate(kty="RSA", size=2048)


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
                        "oidc": {
                            "issuer": "https://idp.example.test",
                            "client_id": "1111@project",
                            "client_secret": "2222@project",
                            "project_id": "231872387283",
                            "organization_id": "2283783782778",
                        },
                        "oauth": {
                            "jwt_validation": {
                                "validator": ["exist"],
                                "require_expiry": True,
                                "localpart_path": "urn:messaging:matrix:localpart",
                                "fq_uid_path": "urn:messaging:matrix:mxid",
                                "required_scopes": "foo bar",
                                "jwk_set": get_jwk(),
                            },
                            "username_type": "user_id",
                            "registration_enabled": True,
                        },
                        "epa": {
                            "localpart_path": "sub",
                            "displayname_path": "urn:telematik:claims:display_name",
                            "jwk_set": get_jwk(),
                            "enc_jwk": get_enc_jwk(),
                            "registration_enabled": True,
                            "iss": "http://test.example",
                            "resource_id": "https://famedly.de",
                            "validator": ["exist"],
                        },
                    },
                }
            ]
        return conf


def get_jwk(secret="foxies", id="123456") -> jwk.JWK:
    return jwk.JWK(
        k=base64.urlsafe_b64encode(secret.encode("utf-8")).decode("utf-8"),
        kty="oct",
        kid=id,
    )


def get_enc_jwk() -> jwk.JWK:
    return ENC_JWK


def get_jwt_token(
    username,
    exp_in=None,
    secret="foxies",
    algorithm="HS512",
    admin=None,
    claims=None,
    id="123456",
    extra_headers: dict = {},
) -> str:
    key = get_jwk(secret, id)
    if claims is None:
        claims = {}
    claims["sub"] = username
    claims["iss"] = "http://test.example"
    if admin is not None:
        claims.update({"admin": admin})

    if exp_in != -1:
        if exp_in is None:
            claims["exp"] = int(time.time()) + 120
        else:
            claims["exp"] = int(time.time()) + exp_in

    token = jwt.JWT(
        header={"alg": algorithm, "kid": id, **extra_headers}, claims=claims
    )
    token.make_signed_token(key)
    return token.serialize()


def get_jwe_token(
    username,
    exp_in=None,
    secret="foxies",
    algorithm="HS512",
    admin=None,
    claims=None,
    id="123456",
    extra_headers: dict = {"typ": "at+jwt"},
):
    token = get_jwt_token(
        username, exp_in, secret, algorithm, admin, claims, id, extra_headers
    )
    enc_key = get_enc_jwk()
    protected_header = {
        "alg": "RSA-OAEP-256",
        "enc": "A256CBC-HS512",
        "typ": "JWE",
        "kid": enc_key.key_id,
    }
    jwetoken = jwe.JWE(token, recipient=enc_key.public(), protected=protected_header)

    return jwetoken.serialize(True)


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
    query = data_raw.decode()
    data = parse_qs(query)
    hostname = "https://idp.example.test"
    if uri == f"{hostname}/oauth/v2/introspect":
        # Fail if no access token is provided
        if data is None:
            return Response(code=401)
        # Fail if access token is incorrect
        if data.get("token")[0] != "zitadel_access_token":
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


def mock_for_oauth(method, uri, data=None, **extrargs):
    match (method, uri):
        case ("POST", "http://idp.test/introspect"):
            data = parse_qs(data.decode())
            match data:
                case {"token": _}:
                    pass
                case _:
                    logger.error(f"Bad introspect request: {data}")
                    return Response(code=400)
            return Response.json(
                payload={
                    "active": True,
                    "localpart": "alice",
                    "scope": "bar foo",
                    "name": "Alice",
                    "roles": {
                        "OrgAdmin": ["123456"],
                        "Admin": ["123456"],
                    },
                    "email": "alice@test.example",
                    "sub": "aliceid",
                    "iss": "http://test.example",
                }
            )
        case ("POST", "http://iop.test/notify"):
            data = json.loads(data)
            match data:
                case {
                    "localpart": _,
                    "fully_qualified_uid": _,
                    "displayname": _,
                }:
                    assert data == {
                        "localpart": "alice",
                        "fully_qualified_uid": "@alice:example.test",
                        "displayname": "Alice",
                    }
                case _:
                    logger.error(f"Bad notify request: {data}")
                    return Response(code=400)
            return Response.json(payload=None)
        case (m, u):
            logger.error(f"Unknown request {m} {u}")
            return Response(code=404)
