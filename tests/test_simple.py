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
from twisted.internet import defer
from . import get_auth_provider, get_token


class SimpleTestCase(unittest.TestCase):
    async def test_wrong_login_type(self):
        auth_provider = get_auth_provider()
        token = get_token("alice")
        result = await auth_provider.check_auth("alice", "m.password", {"token": token})
        self.assertEqual(result, None)

    async def test_missing_token(self):
        auth_provider = get_auth_provider()
        result = await auth_provider.check_auth("alice", "com.famedly.login.token", {})
        self.assertEqual(result, None)

    async def test_invalid_token(self):
        auth_provider = get_auth_provider()
        result = await auth_provider.check_auth(
            "alice", "com.famedly.login.token", {"token": "invalid"}
        )
        self.assertEqual(result, None)

    async def test_token_wrong_secret(self):
        auth_provider = get_auth_provider()
        token = get_token("alice", secret="wrong secret")
        result = await auth_provider.check_auth(
            "alice", "com.famedly.login.token", {"token": token}
        )
        self.assertEqual(result, None)

    async def test_token_wrong_alg(self):
        auth_provider = get_auth_provider()
        token = get_token("alice", algorithm="HS256")
        result = await auth_provider.check_auth(
            "alice", "com.famedly.login.token", {"token": token}
        )
        self.assertEqual(result, None)

    async def test_token_expired(self):
        auth_provider = get_auth_provider()
        token = get_token("alice", exp_in=-60)
        result = await auth_provider.check_auth(
            "alice", "com.famedly.login.token", {"token": token}
        )
        self.assertEqual(result, None)

    async def test_token_no_expiracy(self):
        auth_provider = get_auth_provider()
        token = get_token("alice", exp_in=-1)
        result = await auth_provider.check_auth(
            "alice", "com.famedly.login.token", {"token": token}
        )
        self.assertEqual(result, None)

    async def test_token_no_expiracy_with_config(self):
        auth_provider = get_auth_provider(
            config={
                "secret": "foxies",
                "require_expiracy": False,
            }
        )
        token = get_token("alice", exp_in=-1)
        result = await auth_provider.check_auth(
            "alice", "com.famedly.login.token", {"token": token}
        )
        self.assertEqual(result[0], "@alice:example.org")

    async def test_valid_login(self):
        auth_provider = get_auth_provider()
        token = get_token("alice")
        result = await auth_provider.check_auth(
            "alice", "com.famedly.login.token", {"token": token}
        )
        self.assertEqual(result[0], "@alice:example.org")

    async def test_valid_login_no_register(self):
        auth_provider = get_auth_provider(user_exists=False)
        token = get_token("alice")
        result = await auth_provider.check_auth(
            "alice", "com.famedly.login.token", {"token": token}
        )
        self.assertEqual(result, None)

    async def test_chatbox_login(self):
        auth_provider = get_auth_provider()
        token = get_token(
            "alice_5833eb34-7dbf-44a7-90cf-868c50922c06", claims={"type": "chatbox"}
        )
        result = await auth_provider.check_auth(
            "alice_5833eb34-7dbf-44a7-90cf-868c50922c06",
            "com.famedly.login.token",
            {"token": token},
        )
        self.assertEqual(
            result[0], "@alice_5833eb34-7dbf-44a7-90cf-868c50922c06:example.org"
        )

    async def test_chatbox_login_invalid_format(self):
        auth_provider = get_auth_provider(user_exists=False)
        token = get_token("alice", claims={"type": "chatbox"})
        result = await auth_provider.check_auth(
            "alice", "com.famedly.login.token", {"token": token}
        )
        self.assertEqual(result, None)

    async def test_valid_login_with_register(self):
        config = {
            "secret": "foxies",
            "allow_registration": True,
        }
        auth_provider = get_auth_provider(config=config, user_exists=False)
        token = get_token("alice")
        result = await auth_provider.check_auth(
            "alice", "com.famedly.login.token", {"token": token}
        )
        self.assertEqual(result[0], "@alice:example.org")

    async def test_valid_login_with_admin(self):
        auth_provider = get_auth_provider()
        token = get_token("alice", admin=True)
        result = await auth_provider.check_auth(
            "alice", "com.famedly.login.token", {"token": token}
        )
        self.assertEqual(result[0], "@alice:example.org")
        self.assertIdentical(
            await auth_provider.api.is_user_admin("@alice:example.org"), True
        )
