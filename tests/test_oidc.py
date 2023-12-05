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

from twisted.trial import unittest
from . import get_auth_provider, get_oidc_login, mock_idp_get, mock_idp_post
from unittest import mock


class OIDCTests(unittest.TestCase):
    async def test_wrong_login_type(self):
        auth_provider = get_auth_provider()
        result = await auth_provider.check_oidc_auth(
            "alice", "m.password", get_oidc_login("alice")
        )
        self.assertEqual(result, None)

    async def test_missing_token(self):
        auth_provider = get_auth_provider()
        result = await auth_provider.check_oidc_auth(
            "alice", "com.famedly.login.token,oidc", {}
        )
        self.assertEqual(result, None)

    @mock.patch("requests.get", side_effect=mock_idp_get)
    @mock.patch("requests.post", side_effect=mock_idp_post)
    async def test_invalid_token(self, *args):
        auth_provider = get_auth_provider()
        result = await auth_provider.check_oidc_auth(
            "alice", "com.famedly.login.token.oidc", {"token": "invalid"}
        )
        self.assertEqual(result, None)

    @mock.patch("requests.get", side_effect=mock_idp_get)
    @mock.patch("requests.post", side_effect=mock_idp_post)
    async def test_valid_login(self, *args):
        auth_provider = get_auth_provider()
        result = await auth_provider.check_oidc_auth(
            "alice", "com.famedly.login.token.oidc", get_oidc_login("alice")
        )
        self.assertEqual(result[0], "@alice:example.test")

    @mock.patch("requests.get", side_effect=mock_idp_get)
    @mock.patch("requests.post", side_effect=mock_idp_post)
    async def test_valid_login_no_register(self, *args):
        auth_provider = get_auth_provider(user_exists=False)
        result = await auth_provider.check_oidc_auth(
            "alice", "com.famedly.login.token.oidc", get_oidc_login("alice")
        )
        self.assertEqual(result, None)

    @mock.patch("requests.get", side_effect=mock_idp_get)
    @mock.patch("requests.post", side_effect=mock_idp_post)
    async def test_valid_login_with_register(self, *args):
        config = {
            "oidc": {
                "issuer": "https://idp.example.test",
                "client_id": "1111@project",
                "client_secret": "2222@project",
                "project_id": "231872387283",
                "organization_id": "2283783782778",
                "allow_registration": True,
            },
        }
        auth_provider = get_auth_provider(config=config, user_exists=False)
        result = await auth_provider.check_oidc_auth(
            "alice", "com.famedly.login.token.oidc", get_oidc_login("alice")
        )
        self.assertEqual(result[0], "@alice:example.test")
