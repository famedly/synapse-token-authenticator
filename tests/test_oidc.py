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

from twisted.trial import unittest
from . import get_auth_provider


class OIDCTests(unittest.TestCase):
    async def test_wrong_login_type(self):
        auth_provider = get_auth_provider()
        # TODO: add a function that returns example login dict
        # token = get_token("alice")
        result = await auth_provider.check_oidc_auth("alice", "m.password", {})
        self.assertEqual(result, None)

    async def test_missing_token(self):
        auth_provider = get_auth_provider()
        result = await auth_provider.check_oidc_auth(
            "alice", "com.famedly.login.token,oidc", {}
        )
        self.assertEqual(result, None)

    async def test_invalid_token(self):
        auth_provider = get_auth_provider()
        result = await auth_provider.check_oidc_auth(
            "alice", "com.famedly.login.token.oidc", {"token": "invalid"}
        )
        self.assertEqual(result, None)

    async def test_token_wrong_alg(self):
        auth_provider = get_auth_provider()
        # TODO: add a function that returns example login dict
        # token = get_token("alice", algorithm="HS256")
        result = await auth_provider.check_oidc_auth(
            "alice", "com.famedly.login.token.oidc", {}
        )
        self.assertEqual(result, None)

    async def test_valid_login(self):
        auth_provider = get_auth_provider()
        # TODO: add a function that returns example login dict
        # token = get_token("alice")
        result = await auth_provider.check_oidc_auth(
            "alice", "com.famedly.login.token.oidc", {}
        )
        self.assertEqual(result[0], "@alice:example.org")

    async def test_valid_login_no_register(self):
        auth_provider = get_auth_provider(user_exists=False)
        # TODO: add a function that returns example login dict
        # token = get_token("alice")
        result = await auth_provider.check_oidc_auth(
            "alice", "com.famedly.login.token.oidc", {}
        )
        self.assertEqual(result, None)

    async def test_valid_login_with_register(self):
        # TODO: example config
        config = {
            "oidc": {
                "issuer": "https://idp.example.org",
                "client_id": "",
                "client_secret": "",
                "project_id": "",
                "organization_id": "",
                "allow_registration": True,
            },
        }
        auth_provider = get_auth_provider(config=config, user_exists=False)
        # TODO: add a function that returns example login dict
        # token = get_token("alice")
        result = await auth_provider.check_oidc_auth(
            "alice", "com.famedly.login.token.oidc", {}
        )
        self.assertEqual(result[0], "@alice:example.org")
