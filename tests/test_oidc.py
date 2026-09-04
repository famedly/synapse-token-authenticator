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
from tests import ModuleApiTestCase, get_oidc_login, mock_idp_req


class OIDCTests(ModuleApiTestCase):
    async def test_wrong_login_type(self):
        result = await self.hs.mockmod.check_oidc_auth(
            "alice", "m.password", get_oidc_login("alice")
        )
        assert result is None

    async def test_missing_token(self):
        result = await self.hs.mockmod.check_oidc_auth(
            "alice", "com.famedly.login.token,oidc", {}
        )
        assert result is None

    @mock.patch(
        "synapse.http.client.SimpleHttpClient.request", side_effect=mock_idp_req
    )
    async def test_invalid_token(self, *args):
        result = await self.hs.mockmod.check_oidc_auth(
            "alice", "com.famedly.login.token.oidc", {"token": "invalid"}
        )
        assert result is None

    @mock.patch(
        "synapse.http.client.SimpleHttpClient.request", side_effect=mock_idp_req
    )
    async def test_valid_login(self, *args):
        result = await self.hs.mockmod.check_oidc_auth(
            "alice", "com.famedly.login.token.oidc", get_oidc_login("alice")
        )
        assert result[0] == "@alice:example.test"

    @mock.patch(
        "synapse.http.client.SimpleHttpClient.request", side_effect=mock_idp_req
    )
    @synapsetest.override_config(
        {
            "modules": [
                {
                    "module": "synapse_token_authenticator.TokenAuthenticator",
                    "config": {
                        "oidc": {
                            "issuer": "https://idp.example.test",
                            "client_id": "1111@projectüш",
                            "client_secret": "2222@projectüш",
                            "project_id": "231872387283",
                            "organization_id": "2283783782778",
                            "allow_registration": True,
                        }
                    },
                }
            ]
        }
    )
    async def test_valid_login_unicode_client_id(self, *args):
        result = await self.hs.mockmod.check_oidc_auth(
            "alice", "com.famedly.login.token.oidc", get_oidc_login("alice")
        )
        assert result[0] == "@alice:example.test"

    @mock.patch(
        "synapse.http.client.SimpleHttpClient.request", side_effect=mock_idp_req
    )
    @mock.patch("synapse.module_api.ModuleApi.check_user_exists", return_value=False)
    async def test_valid_login_no_register(self, *args):
        result = await self.hs.mockmod.check_oidc_auth(
            "alice", "com.famedly.login.token.oidc", get_oidc_login("alice")
        )
        assert result is None

    @mock.patch(
        "synapse.http.client.SimpleHttpClient.request", side_effect=mock_idp_req
    )
    @mock.patch("synapse.module_api.ModuleApi.check_user_exists", return_value=False)
    @synapsetest.override_config(
        {
            "modules": [
                {
                    "module": "synapse_token_authenticator.TokenAuthenticator",
                    "config": {
                        "oidc": {
                            "issuer": "https://idp.example.test",
                            "client_id": "1111@project",
                            "client_secret": "2222@project",
                            "project_id": "231872387283",
                            "organization_id": "2283783782778",
                            "allow_registration": True,
                        }
                    },
                }
            ]
        }
    )
    async def test_valid_login_with_register(self, *args):
        result = await self.hs.mockmod.check_oidc_auth(
            "alice", "com.famedly.login.token.oidc", get_oidc_login("alice")
        )
        assert result[0] == "@alice:example.test"

    @mock.patch(
        "synapse.http.client.SimpleHttpClient.request", side_effect=mock_idp_req
    )
    @synapsetest.override_config(
        {
            "modules": [
                {
                    "module": "synapse_token_authenticator.TokenAuthenticator",
                    "config": {
                        "oidc": {
                            "issuer": "https://idp.example.test",
                            "client_id": "1111@project",
                            "client_secret": "2222@project",
                            "project_id": "231872387283",
                            "organization_id": "2283783782778",
                            "allowed_client_ids": ["1111@project", "other@project"],
                        }
                    },
                }
            ]
        }
    )
    async def test_allowed_client_ids_list_allows(self, *args):
        result = await self.hs.mockmod.check_oidc_auth(
            "alice", "com.famedly.login.token.oidc", get_oidc_login("alice")
        )
        assert result[0] == "@alice:example.test"

    @mock.patch(
        "synapse.http.client.SimpleHttpClient.request", side_effect=mock_idp_req
    )
    @synapsetest.override_config(
        {
            "modules": [
                {
                    "module": "synapse_token_authenticator.TokenAuthenticator",
                    "config": {
                        "oidc": {
                            "issuer": "https://idp.example.test",
                            "client_id": "1111@project",
                            "client_secret": "2222@project",
                            "project_id": "231872387283",
                            "organization_id": "2283783782778",
                            "allowed_client_ids": ["other@project"],
                        }
                    },
                }
            ]
        }
    )
    async def test_allowed_client_ids_list_rejects(self, *args):
        result = await self.hs.mockmod.check_oidc_auth(
            "alice", "com.famedly.login.token.oidc", get_oidc_login("alice")
        )
        assert result is None

    @mock.patch(
        "synapse.http.client.SimpleHttpClient.request", side_effect=mock_idp_req
    )
    @synapsetest.override_config(
        {
            "modules": [
                {
                    "module": "synapse_token_authenticator.TokenAuthenticator",
                    "config": {
                        "oidc": {
                            "issuer": "https://idp.example.test",
                            "client_id": "1111@project",
                            "client_secret": "2222@project",
                            "project_id": "231872387283",
                            "organization_id": "2283783782778",
                            "allowed_client_ids": "1111@project other@project",
                        }
                    },
                }
            ]
        }
    )
    async def test_allowed_client_ids_space_separated_allows(self, *args):
        result = await self.hs.mockmod.check_oidc_auth(
            "alice", "com.famedly.login.token.oidc", get_oidc_login("alice")
        )
        assert result[0] == "@alice:example.test"

    @mock.patch(
        "synapse.http.client.SimpleHttpClient.request", side_effect=mock_idp_req
    )
    @synapsetest.override_config(
        {
            "modules": [
                {
                    "module": "synapse_token_authenticator.TokenAuthenticator",
                    "config": {
                        "oidc": {
                            "issuer": "https://idp.example.test",
                            "client_id": "1111@project",
                            "client_secret": "2222@project",
                            "project_id": "231872387283",
                            "organization_id": "2283783782778",
                            "allowed_client_ids": "other@project another@project",
                        }
                    },
                }
            ]
        }
    )
    async def test_allowed_client_ids_space_separated_rejects(self, *args):
        result = await self.hs.mockmod.check_oidc_auth(
            "alice", "com.famedly.login.token.oidc", get_oidc_login("alice")
        )
        assert result is None
