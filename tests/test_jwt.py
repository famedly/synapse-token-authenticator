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


class JWTTests(ModuleApiTestCase):
    async def test_wrong_login_type(self):
        token = get_jwt_token("alice")
        result = await self.hs.mockmod.check_jwt_auth(
            "alice", "m.password", {"token": token}
        )
        self.assertEqual(result, None)

    async def test_missing_token(self):
        result = await self.hs.mockmod.check_jwt_auth(
            "alice", "com.famedly.login.token", {}
        )
        self.assertEqual(result, None)

    async def test_invalid_token(self):
        result = await self.hs.mockmod.check_jwt_auth(
            "alice", "com.famedly.login.token", {"token": "invalid"}
        )
        self.assertEqual(result, None)

    async def test_token_wrong_secret(self):
        token = get_jwt_token("alice", secret="wrong secret")
        result = await self.hs.mockmod.check_jwt_auth(
            "alice", "com.famedly.login.token", {"token": token}
        )
        self.assertEqual(result, None)

    async def test_token_wrong_alg(self):
        token = get_jwt_token("alice", algorithm="HS256")
        result = await self.hs.mockmod.check_jwt_auth(
            "alice", "com.famedly.login.token", {"token": token}
        )
        self.assertEqual(result, None)

    async def test_token_expired(self):
        token = get_jwt_token("alice", exp_in=-60)
        result = await self.hs.mockmod.check_jwt_auth(
            "alice", "com.famedly.login.token", {"token": token}
        )
        self.assertEqual(result, None)

    async def test_token_no_expiry(self):
        token = get_jwt_token("alice", exp_in=-1)
        result = await self.hs.mockmod.check_jwt_auth(
            "alice", "com.famedly.login.token", {"token": token}
        )
        self.assertEqual(result, None)

    @synapsetest.override_config(
        {
            "modules": [
                {
                    "module": "synapse_token_authenticator.TokenAuthenticator",
                    "config": {
                        "jwt": {
                            "secret": "foxies",
                            "require_expiry": False,
                        }
                    },
                }
            ]
        }
    )
    async def test_token_no_expiry_with_config(self, *args):
        token = get_jwt_token("alice", exp_in=-1)
        result = await self.hs.mockmod.check_jwt_auth(
            "alice", "com.famedly.login.token", {"token": token}
        )
        self.assertEqual(result[0], "@alice:example.test")

    async def test_valid_login(self):
        token = get_jwt_token("alice")
        result = await self.hs.mockmod.check_jwt_auth(
            "alice", "com.famedly.login.token", {"token": token}
        )
        self.assertEqual(result[0], "@alice:example.test")

    @mock.patch("synapse.module_api.ModuleApi.check_user_exists", return_value=False)
    async def test_valid_login_no_register(self, *args):
        token = get_jwt_token("alice")
        result = await self.hs.mockmod.check_jwt_auth(
            "alice", "com.famedly.login.token", {"token": token}
        )
        self.assertEqual(result, None)

    async def test_chatbox_login(self):
        token = get_jwt_token(
            "alice_5833eb34-7dbf-44a7-90cf-868c50922c06", claims={"type": "chatbox"}
        )
        result = await self.hs.mockmod.check_jwt_auth(
            "alice_5833eb34-7dbf-44a7-90cf-868c50922c06",
            "com.famedly.login.token",
            {"token": token},
        )
        self.assertEqual(
            result[0], "@alice_5833eb34-7dbf-44a7-90cf-868c50922c06:example.test"
        )

    @mock.patch("synapse.module_api.ModuleApi.check_user_exists", return_value=False)
    async def test_chatbox_login_invalid_format(self, *args):
        token = get_jwt_token("alice", claims={"type": "chatbox"})
        result = await self.hs.mockmod.check_jwt_auth(
            "alice", "com.famedly.login.token", {"token": token}
        )
        self.assertEqual(result, None)

    @mock.patch("synapse.module_api.ModuleApi.check_user_exists", return_value=False)
    @synapsetest.override_config(
        {
            "modules": [
                {
                    "module": "synapse_token_authenticator.TokenAuthenticator",
                    "config": {
                        "jwt": {
                            "secret": "foxies",
                            "allow_registration": True,
                        },
                    },
                }
            ]
        }
    )
    async def test_valid_login_with_register(self, *args):
        token = get_jwt_token("alice")
        result = await self.hs.mockmod.check_jwt_auth(
            "alice", "com.famedly.login.token", {"token": token}
        )
        self.assertEqual(result[0], "@alice:example.test")

    async def test_valid_login_with_admin(self):
        token = get_jwt_token("alice", admin=True)
        result = await self.hs.mockmod.check_jwt_auth(
            "alice", "com.famedly.login.token", {"token": token}
        )
        self.assertEqual(result[0], "@alice:example.test")
        self.assertIdentical(
            await self.module_api.is_user_admin("@alice:example.test"), True
        )
