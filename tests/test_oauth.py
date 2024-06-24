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

from . import ModuleApiTestCase, get_jwt_token, get_jwk, mock_for_oauth
from copy import deepcopy

default_claims = {
    "urn:messaging:matrix:localpart": "alice",
    "urn:messaging:matrix:mxid": "@alice:example.test",
    "name": "Alice",
    "scope": "bar foo",
}


class CustomFlowTests(ModuleApiTestCase):
    async def test_wrong_login_type(self):
        token = get_jwt_token("aliceid", claims=default_claims)
        result = await self.hs.mockmod.check_oauth(
            "alice", "com.famedly.login.token", {"token": token}
        )
        self.assertEqual(result, None)

    async def test_missing_token(self):
        result = await self.hs.mockmod.check_oauth(
            "alice", "com.famedly.login.token.oauth", {}
        )
        self.assertEqual(result, None)

    async def test_invalid_token(self):
        result = await self.hs.mockmod.check_oauth(
            "alice", "com.famedly.login.token.oauth", {"token": "invalid"}
        )
        self.assertEqual(result, None)

    async def test_token_wrong_secret(self):
        token = get_jwt_token("aliceid", secret="wrong secret", claims=default_claims)
        result = await self.hs.mockmod.check_oauth(
            "alice", "com.famedly.login.token.oauth", {"token": token}
        )
        self.assertEqual(result, None)

    async def test_token_expired(self):
        token = get_jwt_token("aliceid", exp_in=-60, claims=default_claims)
        result = await self.hs.mockmod.check_oauth(
            "alice", "com.famedly.login.token.oauth", {"token": token}
        )
        self.assertEqual(result, None)

    async def test_token_no_expiry(self):
        token = get_jwt_token("aliceid", exp_in=-1, claims=default_claims)
        result = await self.hs.mockmod.check_oauth(
            "alice", "com.famedly.login.token.oauth", {"token": token}
        )
        self.assertEqual(result, None)

    async def test_token_bad_localpart(self):
        claims = default_claims.copy()
        claims["urn:messaging:matrix:localpart"] = "bobby"
        token = get_jwt_token("aliceid", claims=claims)
        result = await self.hs.mockmod.check_oauth(
            "alice", "com.famedly.login.token.oauth", {"token": token}
        )
        self.assertEqual(result, None)

    async def test_token_bad_mxid(self):
        claims = default_claims.copy()
        claims["urn:messaging:matrix:mxid"] = "@bobby:example.test"
        token = get_jwt_token("aliceid", claims=claims)
        result = await self.hs.mockmod.check_oauth(
            "alice", "com.famedly.login.token.oauth", {"token": token}
        )
        self.assertEqual(result, None)

    async def test_token_claims_username_mismatch(self):
        token = get_jwt_token("aliceid", claims=default_claims)
        result = await self.hs.mockmod.check_oauth(
            "bobby", "com.famedly.login.token.oauth", {"token": token}
        )
        self.assertEqual(result, None)

    @synapsetest.override_config(
        {
            "modules": [
                {
                    "module": "synapse_token_authenticator.TokenAuthenticator",
                    "config": {
                        "oauth": {
                            "jwt_validation": {
                                "validator": ["exist"],
                                "require_expiry": False,
                                "jwk_set": get_jwk(),
                            },
                            "username_type": "user_id",
                        },
                    },
                }
            ]
        }
    )
    async def test_token_no_expiry_with_config(self, *args):
        token = get_jwt_token("aliceid", exp_in=-1, claims=default_claims)
        result = await self.hs.mockmod.check_oauth(
            "alice", "com.famedly.login.token.oauth", {"token": token}
        )
        self.assertEqual(result[0], "@alice:example.test")

    async def test_valid_login(self):
        token = get_jwt_token("aliceid", claims=default_claims)
        result = await self.hs.mockmod.check_oauth(
            "alice", "com.famedly.login.token.oauth", {"token": token}
        )
        self.assertEqual(result[0], "@alice:example.test")

    @mock.patch("synapse.module_api.ModuleApi.check_user_exists", return_value=False)
    @mock.patch(
        "synapse.http.client.SimpleHttpClient.post_json_get_json", return_value={}
    )
    async def test_valid_login_register(self, *args):
        token = get_jwt_token("aliceid", claims=default_claims)
        result = await self.hs.mockmod.check_oauth(
            "alice", "com.famedly.login.token.oauth", {"token": token}
        )
        self.assertEqual(result[0], "@alice:example.test")

    async def test_invalid_scope(self):
        claims = default_claims.copy()
        claims["scope"] = "foo"
        token = get_jwt_token("aliceid", claims=claims)
        result = await self.hs.mockmod.check_oauth(
            "alice", "com.famedly.login.token.oauth", {"token": token}
        )
        self.assertEqual(result, None)

    config_for_introspection = {
        "modules": [
            {
                "module": "synapse_token_authenticator.TokenAuthenticator",
                "config": {
                    "oauth": {
                        "introspection_validation": {
                            "endpoint": "http://idp.test/introspect",
                            "validator": ["in", "active", ["equal", True]],
                            "localpart_path": "localpart",
                            "displayname_path": "name",
                            "required_scopes": "foo bar",
                        },
                        "username_type": "user_id",
                        "notify_on_registration": {"url": "http://iop.test/notify"},
                        "registration_enabled": True,
                    },
                },
            }
        ]
    }

    @synapsetest.override_config(config_for_introspection)
    @mock.patch(
        "synapse.http.client.SimpleHttpClient.request", side_effect=mock_for_oauth
    )
    @mock.patch("synapse.module_api.ModuleApi.check_user_exists", return_value=False)
    async def test_valid_login_introspection(self, *args):
        token = get_jwt_token("aliceid", claims=default_claims)
        result = await self.hs.mockmod.check_oauth(
            "alice", "com.famedly.login.token.oauth", {"token": token}
        )
        self.assertEqual(result[0], "@alice:example.test")

    config_for_introspection_bad_notify_url = deepcopy(config_for_introspection)
    config_for_introspection_bad_notify_url["modules"][0]["config"]["oauth"][
        "notify_on_registration"
    ]["url"] = "http://bad-iop.test/notify"

    @synapsetest.override_config(config_for_introspection_bad_notify_url)
    @mock.patch(
        "synapse.http.client.SimpleHttpClient.request", side_effect=mock_for_oauth
    )
    @mock.patch("synapse.module_api.ModuleApi.check_user_exists", return_value=False)
    async def test_login_introspection_notify_fails(self, *args):
        token = get_jwt_token("aliceid", claims=default_claims)
        result = await self.hs.mockmod.check_oauth(
            "alice", "com.famedly.login.token.oauth", {"token": token}
        )
        self.assertEqual(result, None)

    config_for_introspection_bad_notify_url_but_ok = deepcopy(
        config_for_introspection_bad_notify_url
    )
    config_for_introspection_bad_notify_url_but_ok["modules"][0]["config"]["oauth"][
        "notify_on_registration"
    ]["interrupt_on_error"] = False

    @synapsetest.override_config(config_for_introspection_bad_notify_url_but_ok)
    @mock.patch(
        "synapse.http.client.SimpleHttpClient.request", side_effect=mock_for_oauth
    )
    @mock.patch("synapse.module_api.ModuleApi.check_user_exists", return_value=False)
    async def test_login_introspection_notify_fails_but_ok(self, *args):
        token = get_jwt_token("aliceid", claims=default_claims)
        result = await self.hs.mockmod.check_oauth(
            "alice", "com.famedly.login.token.oauth", {"token": token}
        )
        self.assertEqual(result[0], "@alice:example.test")

    config_for_introspection_more_required_scopes = deepcopy(config_for_introspection)
    config_for_introspection_more_required_scopes["modules"][0]["config"]["oauth"][
        "introspection_validation"
    ]["required_scopes"] = ["foo", "bar", "baz"]

    @synapsetest.override_config(config_for_introspection_more_required_scopes)
    @mock.patch(
        "synapse.http.client.SimpleHttpClient.request", side_effect=mock_for_oauth
    )
    async def test_login_introspection_invalid_scope(self, *args):
        claims = default_claims.copy()
        claims["scope"] = "foo"
        token = get_jwt_token("aliceid", claims=claims)
        result = await self.hs.mockmod.check_oauth(
            "alice", "com.famedly.login.token.oauth", {"token": token}
        )
        self.assertEqual(result, None)
