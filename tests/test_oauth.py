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
from jwcrypto.jwk import JWKSet

default_claims = {
    "urn:messaging:matrix:localpart": "alice",
    "urn:messaging:matrix:mxid": "@alice:example.test",
    "name": "Alice",
    "scope": "bar foo",
    "roles": {
        "OrgAdmin": ["123456"],
        "Admin": ["123456"],
    },
    "email": "alice@test.example",
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

    config_for_jwt = {
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

    config_for_jwt_reg_disabled = deepcopy(config_for_jwt)
    config_for_jwt_reg_disabled["modules"][0]["config"]["oauth"][
        "registration_enabled"
    ] = False

    @synapsetest.override_config(config_for_jwt_reg_disabled)
    @mock.patch("synapse.module_api.ModuleApi.check_user_exists", return_value=False)
    async def test_valid_login_registration_disabled(self, *args):
        token = get_jwt_token("alice", claims=default_claims)
        result = await self.hs.mockmod.check_oauth(
            "alice", "com.famedly.login.token.epa", {"token": token}
        )
        self.assertEqual(result, None)

    @synapsetest.override_config(config_for_jwt)
    @mock.patch(
        "synapse_token_authenticator.TokenAuthenticator._get_external_id",
        new_callable=mock.AsyncMock,
        return_value=[],
    )
    async def test_token_no_expiry_with_config(self, *args):
        token = get_jwt_token("aliceid", exp_in=-1, claims=default_claims)
        result = await self.hs.mockmod.check_oauth(
            "alice", "com.famedly.login.token.oauth", {"token": token}
        )
        self.assertEqual(result[0], "@alice:example.test")

    @mock.patch(
        "synapse_token_authenticator.TokenAuthenticator._get_external_id",
        new_callable=mock.AsyncMock,
        return_value=[],
    )
    async def test_valid_login(self, *args):
        token = get_jwt_token("aliceid", claims=default_claims)
        result = await self.hs.mockmod.check_oauth(
            "alice", "com.famedly.login.token.oauth", {"token": token}
        )
        self.assertEqual(result[0], "@alice:example.test")

    @mock.patch("synapse.module_api.ModuleApi.check_user_exists", return_value=False)
    @mock.patch(
        "synapse.http.client.SimpleHttpClient.post_json_get_json", return_value={}
    )
    @mock.patch(
        "synapse.module_api.ModuleApi.record_user_external_id",
        new_callable=mock.AsyncMock,
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

    config_for_jwt_jwks_url = deepcopy(config_for_jwt)
    config_for_jwt_jwks_url["modules"][0]["config"]["oauth"]["jwt_validation"].pop(
        "jwk_set"
    )
    config_for_jwt_jwks_url["modules"][0]["config"]["oauth"]["jwt_validation"][
        "jwks_endpoint"
    ] = "https://my_idp.com/oauth/v2/keys"
    jwks = JWKSet()
    jwks.add(get_jwk())

    @synapsetest.override_config(config_for_jwt_jwks_url)
    @mock.patch(
        "synapse.http.client.SimpleHttpClient.get_raw", return_value=jwks.export()
    )
    @mock.patch(
        "synapse_token_authenticator.TokenAuthenticator._get_external_id",
        new_callable=mock.AsyncMock,
        return_value=[],
    )
    async def test_fetch_jwks(self, *args):
        token = get_jwt_token("aliceid", claims=default_claims)
        result = await self.hs.mockmod.check_oauth(
            "alice", "com.famedly.login.token.oauth", {"token": token}
        )
        self.assertEqual(result[0], "@alice:example.test")

    config_for_jwt_admin_path = deepcopy(config_for_jwt)
    config_for_jwt_admin_path["modules"][0]["config"]["oauth"]["jwt_validation"][
        "admin_path"
    ] = ["roles", "Admin"]
    config_for_jwt_admin_path["modules"][0]["config"]["oauth"][
        "registration_enabled"
    ] = True

    @synapsetest.override_config(config_for_jwt_admin_path)
    @mock.patch("synapse.module_api.ModuleApi.check_user_exists", return_value=False)
    @mock.patch(
        "synapse.http.client.SimpleHttpClient.get_raw", return_value=jwks.export()
    )
    @mock.patch(
        "synapse.module_api.ModuleApi.record_user_external_id",
        new_callable=mock.AsyncMock,
    )
    @mock.patch("synapse.module_api.ModuleApi.register_user")
    async def test_login_register_admin(self, register_user_mock, *args):
        token = get_jwt_token("aliceid", claims=default_claims)
        result = await self.hs.mockmod.check_oauth(
            "alice", "com.famedly.login.token.oauth", {"token": token}
        )

        register_user_mock.assert_called_with("alice", admin=True)
        self.assertEqual(result[0], "@alice:example.test")

    config_for_jwt_admin_path_wrong = deepcopy(config_for_jwt_admin_path)
    config_for_jwt_admin_path_wrong["modules"][0]["config"]["oauth"]["jwt_validation"][
        "admin_path"
    ] = ["roles", "SomethingAdmin"]

    @synapsetest.override_config(config_for_jwt_admin_path_wrong)
    @mock.patch("synapse.module_api.ModuleApi.check_user_exists", return_value=False)
    @mock.patch(
        "synapse.http.client.SimpleHttpClient.get_raw", return_value=jwks.export()
    )
    @mock.patch(
        "synapse.module_api.ModuleApi.record_user_external_id",
        new_callable=mock.AsyncMock,
    )
    @mock.patch("synapse.module_api.ModuleApi.register_user")
    async def test_login_register_admin_negative(self, register_user_mock, *args):
        token = get_jwt_token("aliceid", claims=default_claims)
        result = await self.hs.mockmod.check_oauth(
            "alice", "com.famedly.login.token.oauth", {"token": token}
        )

        register_user_mock.assert_called_with("alice", admin=False)
        self.assertEqual(result[0], "@alice:example.test")

    @mock.patch("synapse.module_api.ModuleApi.check_user_exists", return_value=False)
    @mock.patch(
        "synapse.http.client.SimpleHttpClient.get_raw", return_value=jwks.export()
    )
    @mock.patch(
        "synapse.module_api.ModuleApi.record_user_external_id",
        new_callable=mock.AsyncMock,
    )
    async def test_login_register_external_user_id(self, external_id_mock, *args):
        token = get_jwt_token("aliceid", claims=default_claims)
        result = await self.hs.mockmod.check_oauth(
            "alice", "com.famedly.login.token.oauth", {"token": token}
        )

        external_id_mock.assert_called_with(
            auth_provider_id="http://test.example",
            remote_user_id="aliceid",
            registered_user_id="@alice:example.test",
        )
        self.assertEqual(result[0], "@alice:example.test")

    config_for_jwt_email_path = deepcopy(config_for_jwt_admin_path)
    config_for_jwt_email_path["modules"][0]["config"]["oauth"]["jwt_validation"][
        "email_path"
    ] = "email"

    @synapsetest.override_config(config_for_jwt_email_path)
    @mock.patch("synapse.module_api.ModuleApi.check_user_exists", return_value=False)
    @mock.patch(
        "synapse.http.client.SimpleHttpClient.get_raw", return_value=jwks.export()
    )
    @mock.patch(
        "synapse.module_api.ModuleApi.record_user_external_id",
        new_callable=mock.AsyncMock,
    )
    @mock.patch(
        "synapse_token_authenticator.TokenAuthenticator._add_user_email",
        new_callable=mock.AsyncMock,
    )
    async def test_login_register_threepid(self, add_threepid_mock, *args):
        token = get_jwt_token("aliceid", claims=default_claims)
        result = await self.hs.mockmod.check_oauth(
            "alice", "com.famedly.login.token.oauth", {"token": token}
        )

        add_threepid_mock.assert_called_with(
            "@alice:example.test",
            "alice@test.example",
        )
        self.assertEqual(result[0], "@alice:example.test")

    @synapsetest.override_config(config_for_jwt)
    @mock.patch(
        "synapse_token_authenticator.TokenAuthenticator._get_external_id",
        new_callable=mock.AsyncMock,
        return_value=[
            ("some_auth_provider", "some_external_id"),
            ("http://test.example", "aliceid"),
        ],
    )
    async def test_login_check_external_id(self, *args):
        token = get_jwt_token("aliceid", claims=default_claims)
        result = await self.hs.mockmod.check_oauth(
            "alice", "com.famedly.login.token.oauth", {"token": token}
        )
        self.assertEqual(result[0], "@alice:example.test")

    @synapsetest.override_config(config_for_jwt)
    @mock.patch(
        "synapse_token_authenticator.TokenAuthenticator._get_external_id",
        new_callable=mock.AsyncMock,
        return_value=[("some_auth_provider", "some_external_id")],
    )
    async def test_login_check_external_id_negative(self, *args):
        token = get_jwt_token("aliceid", claims=default_claims)
        result = await self.hs.mockmod.check_oauth(
            "alice", "com.famedly.login.token.oauth", {"token": token}
        )
        self.assertEqual(result, None)

    config_for_external_id = deepcopy(config_for_jwt)
    config_for_external_id["modules"][0]["config"]["oauth"]["check_external_id"] = False

    @synapsetest.override_config(config_for_external_id)
    @mock.patch(
        "synapse_token_authenticator.TokenAuthenticator._get_external_id",
        new_callable=mock.AsyncMock,
        return_value=[("some_auth_provider", "some_external_id")],
    )
    async def test_login_check_external_id_disabled(self, *args):
        token = get_jwt_token("aliceid", claims=default_claims)
        result = await self.hs.mockmod.check_oauth(
            "alice", "com.famedly.login.token.oauth", {"token": token}
        )
        self.assertEqual(result[0], "@alice:example.test")

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
    @mock.patch(
        "synapse.module_api.ModuleApi.record_user_external_id",
        new_callable=mock.AsyncMock,
    )
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
    @mock.patch(
        "synapse.module_api.ModuleApi.record_user_external_id",
        new_callable=mock.AsyncMock,
    )
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

    config_for_introspection_admin_path = deepcopy(config_for_introspection)
    config_for_introspection_admin_path["modules"][0]["config"]["oauth"][
        "introspection_validation"
    ]["admin_path"] = ["roles", "Admin"]

    @synapsetest.override_config(config_for_introspection_admin_path)
    @mock.patch(
        "synapse.http.client.SimpleHttpClient.request", side_effect=mock_for_oauth
    )
    @mock.patch("synapse.module_api.ModuleApi.check_user_exists", return_value=False)
    @mock.patch(
        "synapse.module_api.ModuleApi.record_user_external_id",
        new_callable=mock.AsyncMock,
    )
    @mock.patch("synapse.module_api.ModuleApi.register_user")
    async def test_login_introspection_register_admin(self, register_user_mock, *args):
        token = get_jwt_token("aliceid", claims=default_claims)
        result = await self.hs.mockmod.check_oauth(
            "alice", "com.famedly.login.token.oauth", {"token": token}
        )
        register_user_mock.assert_called_with("alice", admin=True)
        self.assertEqual(result[0], "@alice:example.test")

    @mock.patch(
        "synapse.http.client.SimpleHttpClient.request", side_effect=mock_for_oauth
    )
    @mock.patch("synapse.module_api.ModuleApi.check_user_exists", return_value=False)
    @mock.patch(
        "synapse.module_api.ModuleApi.record_user_external_id",
        new_callable=mock.AsyncMock,
    )
    async def test_login_introspection_external_user_id(self, external_id_mock, *args):
        token = get_jwt_token("aliceid", claims=default_claims)
        result = await self.hs.mockmod.check_oauth(
            "alice", "com.famedly.login.token.oauth", {"token": token}
        )
        external_id_mock.assert_called_with(
            auth_provider_id="http://test.example",
            remote_user_id="aliceid",
            registered_user_id="@alice:example.test",
        )
        self.assertEqual(result[0], "@alice:example.test")

    config_for_introspection_email_path = deepcopy(config_for_introspection)
    config_for_introspection_email_path["modules"][0]["config"]["oauth"][
        "introspection_validation"
    ]["email_path"] = "email"

    @synapsetest.override_config(config_for_introspection_email_path)
    @mock.patch(
        "synapse.http.client.SimpleHttpClient.request", side_effect=mock_for_oauth
    )
    @mock.patch("synapse.module_api.ModuleApi.check_user_exists", return_value=False)
    @mock.patch(
        "synapse.module_api.ModuleApi.record_user_external_id",
        new_callable=mock.AsyncMock,
    )
    @mock.patch(
        "synapse_token_authenticator.TokenAuthenticator._add_user_email",
        new_callable=mock.AsyncMock,
    )
    async def test_login_introspection_threepid(self, add_threepid_mock, *args):
        token = get_jwt_token("aliceid", claims=default_claims)
        result = await self.hs.mockmod.check_oauth(
            "alice", "com.famedly.login.token.oauth", {"token": token}
        )
        add_threepid_mock.assert_called_with(
            "@alice:example.test",
            "alice@test.example",
        )
        self.assertEqual(result[0], "@alice:example.test")
