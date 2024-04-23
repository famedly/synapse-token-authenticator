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

from unittest import mock

import tests.unittest as synapsetest

from . import ModuleApiTestCase, get_jwt_token

default_claims = {
    "urn:messaging:matrix:localpart": "alice",
    "urn:messaging:matrix:mxid": "@alice:example.test",
    "name": "Alice",
}


class CustomFlowTests(ModuleApiTestCase):
    async def test_wrong_login_type(self):
        token = get_jwt_token("aliceid", claims=default_claims)
        result = await self.hs.mockmod.check_custom_flow(
            "alice", "com.famedly.login.token", {"token": token}
        )
        self.assertEqual(result, None)

    async def test_missing_token(self):
        result = await self.hs.mockmod.check_custom_flow(
            "alice", "com.famedly.login.token.custom", {}
        )
        self.assertEqual(result, None)

    async def test_invalid_token(self):
        result = await self.hs.mockmod.check_custom_flow(
            "alice", "com.famedly.login.token.custom", {"token": "invalid"}
        )
        self.assertEqual(result, None)

    async def test_token_wrong_secret(self):
        token = get_jwt_token("aliceid", secret="wrong secret", claims=default_claims)
        result = await self.hs.mockmod.check_custom_flow(
            "alice", "com.famedly.login.token.custom", {"token": token}
        )
        self.assertEqual(result, None)

    async def test_token_wrong_alg(self):
        token = get_jwt_token("aliceid", algorithm="HS256", claims=default_claims)
        result = await self.hs.mockmod.check_custom_flow(
            "alice", "com.famedly.login.token.custom", {"token": token}
        )
        self.assertEqual(result, None)

    async def test_token_expired(self):
        token = get_jwt_token("aliceid", exp_in=-60, claims=default_claims)
        result = await self.hs.mockmod.check_custom_flow(
            "alice", "com.famedly.login.token.custom", {"token": token}
        )
        self.assertEqual(result, None)

    async def test_token_no_expiry(self):
        token = get_jwt_token("aliceid", exp_in=-1, claims=default_claims)
        result = await self.hs.mockmod.check_custom_flow(
            "alice", "com.famedly.login.token.custom", {"token": token}
        )
        self.assertEqual(result, None)

    async def test_token_bad_localpart(self):
        claims = default_claims.copy()
        claims["urn:messaging:matrix:localpart"] = "bobby"
        token = get_jwt_token("aliceid", claims=claims)
        result = await self.hs.mockmod.check_custom_flow(
            "alice", "com.famedly.login.token.custom", {"token": token}
        )
        self.assertEqual(result, None)

    async def test_token_bad_mxid(self):
        claims = default_claims.copy()
        claims["urn:messaging:matrix:mxid"] = "@bobby:example.test"
        token = get_jwt_token("aliceid", claims=claims)
        result = await self.hs.mockmod.check_custom_flow(
            "alice", "com.famedly.login.token.custom", {"token": token}
        )
        self.assertEqual(result, None)

    async def test_token_claims_username_mismatch(self):
        token = get_jwt_token("aliceid", claims=default_claims)
        result = await self.hs.mockmod.check_custom_flow(
            "bobby", "com.famedly.login.token.custom", {"token": token}
        )
        self.assertEqual(result, None)

    @synapsetest.override_config(
        {
            "modules": [
                {
                    "module": "synapse_token_authenticator.TokenAuthenticator",
                    "config": {
                        "custom_flow": {
                            "secret": "foxies",
                            "require_expiry": False,
                            "algorithm": "HS512",
                            "notify_on_registration_uri": "http://example.test",
                        }
                    },
                }
            ]
        }
    )
    async def test_token_no_expiry_with_config(self, *args):
        token = get_jwt_token("aliceid", exp_in=-1, claims=default_claims)
        result = await self.hs.mockmod.check_custom_flow(
            "alice", "com.famedly.login.token.custom", {"token": token}
        )
        self.assertEqual(result[0], "@alice:example.test")

    async def test_valid_login(self):
        token = get_jwt_token("aliceid", claims=default_claims)
        result = await self.hs.mockmod.check_custom_flow(
            "alice", "com.famedly.login.token.custom", {"token": token}
        )
        self.assertEqual(result[0], "@alice:example.test")

    @mock.patch("synapse.module_api.ModuleApi.check_user_exists", return_value=False)
    @mock.patch(
        "synapse.http.client.SimpleHttpClient.post_json_get_json", return_value={}
    )
    async def test_valid_login_register(self, *args):
        token = get_jwt_token("aliceid", claims=default_claims)
        result = await self.hs.mockmod.check_custom_flow(
            "alice", "com.famedly.login.token.custom", {"token": token}
        )
        self.assertEqual(result[0], "@alice:example.test")
