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

from pathlib import Path
from unittest import mock

import pytest
from jwcrypto.jwk import JWK

import tests.unittest as synapsetest
from tests import _DEFAULT_TOKEN_SECRET, ModuleApiTestCase, get_jwt_token


class JWTTests(ModuleApiTestCase):
    async def test_wrong_login_type(self):
        token = get_jwt_token("alice")
        result = await self.hs.mockmod.check_jwt_auth(
            "alice", "m.password", {"token": token}
        )
        assert result is None

    async def test_missing_token(self):
        result = await self.hs.mockmod.check_jwt_auth(
            "alice", "com.famedly.login.token", {}
        )
        assert result is None

    async def test_invalid_token(self):
        result = await self.hs.mockmod.check_jwt_auth(
            "alice", "com.famedly.login.token", {"token": "invalid"}
        )
        assert result is None

    async def test_token_wrong_secret(self):
        # The secret needs to be 64 bytes, so pad it and bulk copy it. 16 * 4 = 64
        secret = "wrong secret1234" * 4
        token = get_jwt_token("alice", secret=secret)
        result = await self.hs.mockmod.check_jwt_auth(
            "alice", "com.famedly.login.token", {"token": token}
        )
        assert result is None

    async def test_token_wrong_alg(self):
        token = get_jwt_token("alice", algorithm="HS256")
        result = await self.hs.mockmod.check_jwt_auth(
            "alice", "com.famedly.login.token", {"token": token}
        )
        assert result is None

    async def test_token_expired(self):
        token = get_jwt_token("alice", exp_in=-60)
        result = await self.hs.mockmod.check_jwt_auth(
            "alice", "com.famedly.login.token", {"token": token}
        )
        assert result is None

    async def test_token_no_expiry(self):
        token = get_jwt_token("alice", exp_in=-1)
        result = await self.hs.mockmod.check_jwt_auth(
            "alice", "com.famedly.login.token", {"token": token}
        )
        assert result is None

    @synapsetest.override_config(
        {
            "modules": [
                {
                    "module": "synapse_token_authenticator.TokenAuthenticator",
                    "config": {
                        "jwt": {
                            "secret": _DEFAULT_TOKEN_SECRET,
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
        assert result[0] == "@alice:example.test"

    async def test_valid_login(self):
        token = get_jwt_token("alice")
        result = await self.hs.mockmod.check_jwt_auth(
            "alice", "com.famedly.login.token", {"token": token}
        )
        assert result[0] == "@alice:example.test"

    @mock.patch("synapse.module_api.ModuleApi.check_user_exists", return_value=False)
    async def test_valid_login_no_register(self, *args):
        token = get_jwt_token("alice")
        result = await self.hs.mockmod.check_jwt_auth(
            "alice", "com.famedly.login.token", {"token": token}
        )
        assert result is None

    async def test_chatbox_login(self):
        token = get_jwt_token(
            "alice_5833eb34-7dbf-44a7-90cf-868c50922c06", claims={"type": "chatbox"}
        )
        result = await self.hs.mockmod.check_jwt_auth(
            "alice_5833eb34-7dbf-44a7-90cf-868c50922c06",
            "com.famedly.login.token",
            {"token": token},
        )
        assert result[0] == "@alice_5833eb34-7dbf-44a7-90cf-868c50922c06:example.test"

    @mock.patch("synapse.module_api.ModuleApi.check_user_exists", return_value=False)
    async def test_chatbox_login_invalid_format(self, *args):
        token = get_jwt_token("alice", claims={"type": "chatbox"})
        result = await self.hs.mockmod.check_jwt_auth(
            "alice", "com.famedly.login.token", {"token": token}
        )
        assert result is None

    @mock.patch("synapse.module_api.ModuleApi.check_user_exists", return_value=False)
    @synapsetest.override_config(
        {
            "modules": [
                {
                    "module": "synapse_token_authenticator.TokenAuthenticator",
                    "config": {
                        "jwt": {
                            "secret": _DEFAULT_TOKEN_SECRET,
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
        assert result[0] == "@alice:example.test"

    async def test_valid_login_with_admin(self):
        token = get_jwt_token("alice", admin=True)
        result = await self.hs.mockmod.check_jwt_auth(
            "alice", "com.famedly.login.token", {"token": token}
        )
        assert result[0] == "@alice:example.test"
        self.assertIdentical(
            await self.module_api.is_user_admin("@alice:example.test"), True
        )


class JWTKeyfileTests(ModuleApiTestCase):
    @pytest.fixture(autouse=True)
    def _create_jwt_keyfile(self, tmp_path: Path) -> None:
        self._jwt_key = JWK.generate(kty="RSA", size=2048)
        keyfile = tmp_path / "jwk.pem"
        keyfile.write_bytes(
            self._jwt_key.export_to_pem(private_key=True, password=None)
        )
        self._jwt_keyfile = str(keyfile)

    def default_config(self) -> dict:
        conf = super().default_config()
        conf["modules"][0]["config"]["jwt"] = {
            "keyfile": self._jwt_keyfile,
            "algorithm": "RS256",
        }
        return conf

    async def test_valid_login_with_keyfile(self):
        token = get_jwt_token("alice", algorithm="RS256", key=self._jwt_key)
        result = await self.hs.mockmod.check_jwt_auth(
            "alice", "com.famedly.login.token", {"token": token}
        )
        assert result[0] == "@alice:example.test"
