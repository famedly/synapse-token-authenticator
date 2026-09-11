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

import json
from copy import deepcopy
from unittest import mock

from jwcrypto.jwk import JWKSet
from synapse.types import JsonDict

import tests.unittest as synapsetest
from synapse_token_authenticator.resources.metadata import MetadataResource
from tests import ModuleApiTestCase, get_jwk, get_jwt_token, mock_for_oauth

default_claims: JsonDict = {
    "urn:messaging:matrix:localpart": "alice",
    "urn:messaging:matrix:mxid": "@alice:example.test",
    "name": "Alice",
    "scope": "bar foo",
    "roles": {
        "OrgAdmin": ["123456"],
        "Admin": ["123456"],
        "MatrixAdmin": ["123456"],
    },
    "email": "alice@test.example",
}

alternative_fq_uids_claims = deepcopy(default_claims)
# The key of "alternative_fq_uids" is what is used in the configs for the tests that use this
alternative_fq_uids_claims["alternative_fq_uids"] = [
    "@alice:example.test",
    "@alice2:example.test",
]


class CustomFlowTests(ModuleApiTestCase):
    async def test_wrong_login_type(self):
        token = get_jwt_token("aliceid", claims=default_claims)
        result = await self.hs.mockmod.check_oauth(
            "alice", "com.famedly.login.token", {"token": token}
        )
        assert result is None

    async def test_missing_token(self):
        result = await self.hs.mockmod.check_oauth(
            "alice", "com.famedly.login.token.oauth", {}
        )
        assert result is None

    async def test_invalid_token(self):
        result = await self.hs.mockmod.check_oauth(
            "alice", "com.famedly.login.token.oauth", {"token": "invalid"}
        )
        assert result is None

    async def test_token_wrong_secret(self):
        # The secret needs to be 64 bytes, so pad it and bulk copy it. 16 * 4 = 64
        secret = "wrong secret1234" * 4
        token = get_jwt_token("aliceid", secret=secret, claims=default_claims)
        result = await self.hs.mockmod.check_oauth(
            "alice", "com.famedly.login.token.oauth", {"token": token}
        )
        assert result is None

    async def test_token_expired(self):
        token = get_jwt_token("aliceid", exp_in=-60, claims=default_claims)
        result = await self.hs.mockmod.check_oauth(
            "alice", "com.famedly.login.token.oauth", {"token": token}
        )
        assert result is None

    async def test_token_no_expiry(self):
        token = get_jwt_token("aliceid", exp_in=-1, claims=default_claims)
        result = await self.hs.mockmod.check_oauth(
            "alice", "com.famedly.login.token.oauth", {"token": token}
        )
        assert result is None

    async def test_token_bad_localpart(self):
        claims = default_claims.copy()
        claims["urn:messaging:matrix:localpart"] = "bobby"
        token = get_jwt_token("aliceid", claims=claims)
        result = await self.hs.mockmod.check_oauth(
            "alice", "com.famedly.login.token.oauth", {"token": token}
        )
        assert result is None

    async def test_token_bad_mxid(self):
        claims = default_claims.copy()
        claims["urn:messaging:matrix:mxid"] = "@bobby:example.test"
        token = get_jwt_token("aliceid", claims=claims)
        result = await self.hs.mockmod.check_oauth(
            "alice", "com.famedly.login.token.oauth", {"token": token}
        )
        assert result is None

    async def test_token_claims_username_mismatch(self):
        token = get_jwt_token("aliceid", claims=default_claims)
        result = await self.hs.mockmod.check_oauth(
            "bobby", "com.famedly.login.token.oauth", {"token": token}
        )
        assert result is None

    config_for_jwt: JsonDict = {
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
        assert result is None

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
        assert result[0] == "@alice:example.test"

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
        assert result[0] == "@alice:example.test"

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
        assert result[0] == "@alice:example.test"

    async def test_invalid_scope(self):
        claims = default_claims.copy()
        claims["scope"] = "foo"
        token = get_jwt_token("aliceid", claims=claims)
        result = await self.hs.mockmod.check_oauth(
            "alice", "com.famedly.login.token.oauth", {"token": token}
        )
        assert result is None

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
        assert result[0] == "@alice:example.test"

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
        assert result[0] == "@alice:example.test"

    config_for_jwt_admin_paths = deepcopy(config_for_jwt)
    config_for_jwt_admin_paths["modules"][0]["config"]["oauth"]["jwt_validation"][
        "admin_path"
    ] = [["roles", "NotAdmin"], ["roles", "MatrixAdmin"]]
    config_for_jwt_admin_paths["modules"][0]["config"]["oauth"][
        "registration_enabled"
    ] = True

    @synapsetest.override_config(config_for_jwt_admin_paths)
    @mock.patch("synapse.module_api.ModuleApi.check_user_exists", return_value=False)
    @mock.patch(
        "synapse.http.client.SimpleHttpClient.get_raw", return_value=jwks.export()
    )
    @mock.patch(
        "synapse.module_api.ModuleApi.record_user_external_id",
        new_callable=mock.AsyncMock,
    )
    @mock.patch("synapse.module_api.ModuleApi.register_user")
    async def test_login_register_multiple_admin_paths(self, register_user_mock, *args):
        token = get_jwt_token("aliceid", claims=default_claims)
        result = await self.hs.mockmod.check_oauth(
            "alice", "com.famedly.login.token.oauth", {"token": token}
        )

        register_user_mock.assert_called_with("alice", admin=True)
        assert result[0] == "@alice:example.test"

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
        assert result[0] == "@alice:example.test"

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
        assert result[0] == "@alice:example.test"

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
        assert result[0] == "@alice:example.test"

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
        assert result[0] == "@alice:example.test"

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
        assert result is None

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
        assert result[0] == "@alice:example.test"

    config_for_introspection: JsonDict = {
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
        assert result[0] == "@alice:example.test"

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
        assert result is None

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
        assert result[0] == "@alice:example.test"

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
        assert result is None

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
        assert result[0] == "@alice:example.test"

    config_for_introspection_admin_paths = deepcopy(config_for_introspection)
    config_for_introspection_admin_paths["modules"][0]["config"]["oauth"][
        "introspection_validation"
    ]["admin_path"] = [["roles", "AnotherAdmin"], ["roles", "MatrixAdmin"]]

    @synapsetest.override_config(config_for_introspection_admin_paths)
    @mock.patch(
        "synapse.http.client.SimpleHttpClient.request", side_effect=mock_for_oauth
    )
    @mock.patch("synapse.module_api.ModuleApi.check_user_exists", return_value=False)
    @mock.patch(
        "synapse.module_api.ModuleApi.record_user_external_id",
        new_callable=mock.AsyncMock,
    )
    @mock.patch("synapse.module_api.ModuleApi.register_user")
    async def test_login_introspection_register_multiple_admin_paths(
        self, register_user_mock, *args
    ):
        token = get_jwt_token("aliceid", claims=default_claims)
        result = await self.hs.mockmod.check_oauth(
            "alice", "com.famedly.login.token.oauth", {"token": token}
        )
        register_user_mock.assert_called_with("alice", admin=True)
        assert result[0] == "@alice:example.test"

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
        assert result[0] == "@alice:example.test"

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
        assert result[0] == "@alice:example.test"

    config_for_oauth_metadata = deepcopy(config_for_jwt)
    config_for_oauth_metadata["modules"][0]["config"]["oauth"][
        "expose_metadata_resource"
    ] = {
        "name": "com.famedly.login.token.oauth",
        "something": "else",
    }

    @synapsetest.override_config(config_for_oauth_metadata)
    def test_oauth_metadata_resource_is_registered(self):
        path = "/_famedly/login/com.famedly.login.token.oauth"
        resource = self.hs._module_web_resources.get(path)
        assert isinstance(resource, MetadataResource)

        request = mock.Mock()
        body = resource.render_GET(request)
        assert json.loads(body) == {
            "name": "com.famedly.login.token.oauth",
            "something": "else",
        }
        request.setHeader.assert_any_call(b"content-type", b"application/json")
        request.setHeader.assert_any_call(b"access-control-allow-origin", b"*")

    ###
    # A collection of config fragments to run the same battery of tests over. They should all come out with the same
    # result. Start with the base and add or subtract to it what is needed. There are 5 not including the base.
    ###

    config_for_alternative_fq_uids_path_test_base: JsonDict = {
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
                        "introspection_validation": {
                            "endpoint": "http://idp.test/introspect",
                            "validator": ["in", "active", ["equal", True]],
                            "required_scopes": "foo bar",
                        },
                        "username_type": "user_id",
                        # turn this off, for no reason other than mocks are messy and this isn't needed for testing
                        "check_external_id": False,
                    },
                },
            }
        ]
    }

    # A config that uses only the jwt validation alternative_fq_uids_path and does not include any introspection
    # validation data.
    config_for_jwt_alternate_fq_uids = deepcopy(
        config_for_alternative_fq_uids_path_test_base
    )
    config_for_jwt_alternate_fq_uids["modules"][0]["config"]["oauth"]["jwt_validation"][
        "alternative_fq_uids_path"
    ] = "alternative_fq_uids"
    # remove the "introspection_validation" data completely. This helps check that our checks for non-existence work
    config_for_jwt_alternate_fq_uids["modules"][0]["config"]["oauth"].pop(
        "introspection_validation"
    )

    # A config that uses only the jwt validation alternative_fq_uids_path and includes irrelevant data that is not used
    # in the introspection validation data.
    config_for_jwt_alternate_fq_uids_with_nonempty_intro_config = deepcopy(
        config_for_alternative_fq_uids_path_test_base
    )
    config_for_jwt_alternate_fq_uids_with_nonempty_intro_config["modules"][0]["config"][
        "oauth"
    ]["jwt_validation"]["alternative_fq_uids_path"] = "alternative_fq_uids"

    # A config that uses only the introspection validation alternative_fq_uids_path and does not include any jwt
    # validation data.
    config_for_intro_alternate_fq_uids = deepcopy(
        config_for_alternative_fq_uids_path_test_base
    )
    config_for_intro_alternate_fq_uids["modules"][0]["config"]["oauth"][
        "introspection_validation"
    ]["alternative_fq_uids_path"] = "alternative_fq_uids"
    # remove the "jwt_validation" data completely. This helps check that our checks for non-existence work
    config_for_intro_alternate_fq_uids["modules"][0]["config"]["oauth"].pop(
        "jwt_validation"
    )

    # A config that uses only the introspection validation alternative_fq_uids_path and includes irrelevant data that is
    # not used in jwt validation data.
    config_for_intro_alternate_fq_uids_with_nonempty_jwt_config = deepcopy(
        config_for_alternative_fq_uids_path_test_base
    )
    config_for_intro_alternate_fq_uids_with_nonempty_jwt_config["modules"][0]["config"][
        "oauth"
    ]["introspection_validation"]["alternative_fq_uids_path"] = "alternative_fq_uids"

    # A config that uses both jwt and introspection validation
    config_for_both_alternate_fq_uids = deepcopy(
        config_for_alternative_fq_uids_path_test_base
    )
    config_for_both_alternate_fq_uids["modules"][0]["config"]["oauth"][
        "jwt_validation"
    ]["alternative_fq_uids_path"] = "alternative_fq_uids"
    config_for_both_alternate_fq_uids["modules"][0]["config"]["oauth"][
        "introspection_validation"
    ]["alternative_fq_uids_path"] = "alternative_fq_uids"

    async def _test_valid_logins_alternate_fq_uids(self, token: str):
        # Full mxids work if in the list above
        result1 = await self.hs.mockmod.check_oauth(
            "@alice:example.test", "com.famedly.login.token.oauth", {"token": token}
        )
        assert result1[0] == "@alice:example.test"

        result2 = await self.hs.mockmod.check_oauth(
            "@alice2:example.test", "com.famedly.login.token.oauth", {"token": token}
        )
        assert result2[0] == "@alice2:example.test"

        # localparts of an mxid work too
        result3 = await self.hs.mockmod.check_oauth(
            "alice", "com.famedly.login.token.oauth", {"token": token}
        )
        assert result3[0] == "@alice:example.test"

        result4 = await self.hs.mockmod.check_oauth(
            "alice2", "com.famedly.login.token.oauth", {"token": token}
        )
        assert result4[0] == "@alice2:example.test"

    async def _test_invalid_logins_alternate_fq_uids(self, token: str) -> None:
        # Full mxids won't work if they are not in the claims list
        result1 = await self.hs.mockmod.check_oauth(
            "@alice3:example.test", "com.famedly.login.token.oauth", {"token": token}
        )
        assert result1 is None

        # Localparts don't either
        result2 = await self.hs.mockmod.check_oauth(
            "alice3", "com.famedly.login.token.oauth", {"token": token}
        )
        assert result2 is None

    @synapsetest.override_config(config_for_jwt_alternate_fq_uids)
    async def test_jwt_validation_no_intro_with_alt_fq_uid_path(self) -> None:
        token = get_jwt_token("aliceid", claims=alternative_fq_uids_claims)

        await self._test_valid_logins_alternate_fq_uids(token)
        await self._test_invalid_logins_alternate_fq_uids(token)

    @synapsetest.override_config(
        config_for_jwt_alternate_fq_uids_with_nonempty_intro_config
    )
    @mock.patch(
        "synapse.http.client.SimpleHttpClient.request", side_effect=mock_for_oauth
    )
    async def test_jwt_validation_some_intro_with_alt_fq_uid_path(self, *args) -> None:
        token = get_jwt_token("aliceid", claims=alternative_fq_uids_claims)

        await self._test_valid_logins_alternate_fq_uids(token)
        await self._test_invalid_logins_alternate_fq_uids(token)

    @synapsetest.override_config(config_for_intro_alternate_fq_uids)
    @mock.patch(
        "synapse.http.client.SimpleHttpClient.request", side_effect=mock_for_oauth
    )
    async def test_intro_validation_no_jwt_with_alt_fq_uid_path(self, *args) -> None:
        token = get_jwt_token("aliceid", claims=alternative_fq_uids_claims)

        await self._test_valid_logins_alternate_fq_uids(token)
        await self._test_invalid_logins_alternate_fq_uids(token)

    @synapsetest.override_config(
        config_for_intro_alternate_fq_uids_with_nonempty_jwt_config
    )
    @mock.patch(
        "synapse.http.client.SimpleHttpClient.request", side_effect=mock_for_oauth
    )
    async def test_intro_validation_some_jwt_with_alt_fq_uid_path(self, *args) -> None:
        token = get_jwt_token("aliceid", claims=alternative_fq_uids_claims)

        await self._test_valid_logins_alternate_fq_uids(token)
        await self._test_invalid_logins_alternate_fq_uids(token)

    @synapsetest.override_config(config_for_both_alternate_fq_uids)
    @mock.patch(
        "synapse.http.client.SimpleHttpClient.request", side_effect=mock_for_oauth
    )
    async def test_both_validation_with_alt_fq_uid_path(self, *args) -> None:
        token = get_jwt_token("aliceid", claims=alternative_fq_uids_claims)

        await self._test_valid_logins_alternate_fq_uids(token)
        await self._test_invalid_logins_alternate_fq_uids(token)

    # This particular test is more about the claims being wrong than the config, so any custom config would work
    @synapsetest.override_config(config_for_jwt_alternate_fq_uids)
    async def test_alternate_fq_uids_path_not_a_list_is_invalid_and_cannot_be_used(
        self, *args
    ) -> None:
        # Need slightly custom claim for this one
        alternative_fq_uids_claims = deepcopy(default_claims)
        # key is the same reference as what `alternative_fq_uids_path` is set to above in the config, but this time
        # make sure it is not a list format
        alternative_fq_uids_claims["alternative_fq_uids"] = "@alice:example.test"

        token = get_jwt_token("aliceid", claims=alternative_fq_uids_claims)

        # Full mxids won't work if they are not in the claims list
        result1 = await self.hs.mockmod.check_oauth(
            "@alice:example.test", "com.famedly.login.token.oauth", {"token": token}
        )
        assert result1 is None

        result2 = await self.hs.mockmod.check_oauth(
            "@alice3:example.test", "com.famedly.login.token.oauth", {"token": token}
        )
        assert result2 is None

        # Localparts don't either
        result3 = await self.hs.mockmod.check_oauth(
            "alice", "com.famedly.login.token.oauth", {"token": token}
        )
        assert result3 is None

        result4 = await self.hs.mockmod.check_oauth(
            "alice3", "com.famedly.login.token.oauth", {"token": token}
        )
        assert result4 is None
