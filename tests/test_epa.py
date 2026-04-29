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

from copy import deepcopy
from unittest import mock

from jwcrypto import jwk
from synapse.types import JsonDict

import tests.unittest as synapsetest

from . import ModuleApiTestCase, get_enc_jwk, get_jwe_token, get_jwk, get_jwt_token


def get_default_claims() -> JsonDict:
    return {
        "aud": "https://famedly.de",
        "jti": "666f3725783e5356544fce5d869",
        "urn:telematik:claims:display_name": "Peter Müller",
    }


class CustomFlowTests(ModuleApiTestCase):
    async def test_wrong_login_type(self) -> None:
        token = get_jwe_token("alice", claims=get_default_claims())
        result = await self.hs.mockmod.check_epa(
            "alice", "com.famedly.login.token", {"token": token}
        )
        self.assertEqual(result, None)

    async def test_missing_token(self) -> None:
        result = await self.hs.mockmod.check_epa(
            "alice", "com.famedly.login.token.epa", {}
        )
        self.assertEqual(result, None)

    async def test_invalid_token(self) -> None:
        result = await self.hs.mockmod.check_epa(
            "alice", "com.famedly.login.token.epa", {"token": "invalid"}
        )
        self.assertEqual(result, None)

    async def test_token_wrong_secret(self) -> None:
        # The secret needs to be 64 bytes, so pad it and bulk copy it. 16 * 4 = 64
        secret = "wrong secret1234" * 4
        token = get_jwe_token("alice", secret=secret, claims=get_default_claims())
        result = await self.hs.mockmod.check_epa(
            "alice", "com.famedly.login.token.epa", {"token": token}
        )
        self.assertEqual(result, None)

    async def test_token_expired(self) -> None:
        token = get_jwe_token("alice", exp_in=-60, claims=get_default_claims())
        result = await self.hs.mockmod.check_epa(
            "alice", "com.famedly.login.token.epa", {"token": token}
        )
        self.assertEqual(result, None)

    async def test_token_no_expiry(self) -> None:
        token = get_jwe_token("alice", exp_in=-1, claims=get_default_claims())
        result = await self.hs.mockmod.check_epa(
            "alice", "com.famedly.login.token.epa", {"token": token}
        )
        self.assertEqual(result, None)

    async def test_username_ignored(self) -> None:
        token = get_jwe_token("alice", claims=get_default_claims())
        result = await self.hs.mockmod.check_epa(
            "dont_match", "com.famedly.login.token.epa", {"token": token}
        )
        self.assertEqual(result[0], "@alice:example.test")

    async def test_token_missing_typ(self) -> None:
        token = get_jwe_token("alice", claims=get_default_claims(), extra_headers={})
        result = await self.hs.mockmod.check_epa(
            "alice", "com.famedly.login.token.epa", {"token": token}
        )
        self.assertEqual(result, None)

    async def test_token_wrong_typ(self) -> None:
        token = get_jwe_token(
            "alice", claims=get_default_claims(), extra_headers={"typ": "wrong"}
        )
        result = await self.hs.mockmod.check_epa(
            "alice", "com.famedly.login.token.epa", {"token": token}
        )
        self.assertEqual(result, None)

    async def test_token_missing_aud(self) -> None:
        claims = get_default_claims()
        claims.pop("aud")
        token = get_jwe_token("alice", claims=claims)
        result = await self.hs.mockmod.check_epa(
            "alice", "com.famedly.login.token.epa", {"token": token}
        )
        self.assertEqual(result, None)

    async def test_login(self) -> None:
        token = get_jwe_token("alice", claims=get_default_claims())
        result = await self.hs.mockmod.check_epa(
            "alice", "com.famedly.login.token.epa", {"token": token}
        )
        self.assertEqual(result[0], "@alice:example.test")

    async def test_login_alternative_typ(self) -> None:
        token = get_jwe_token(
            "alice",
            claims=get_default_claims(),
            extra_headers={"typ": "application/at+jwt"},
        )
        result = await self.hs.mockmod.check_epa(
            "alice", "com.famedly.login.token.epa", {"token": token}
        )
        self.assertEqual(result[0], "@alice:example.test")

    async def test_token_missing_jti(self) -> None:
        claims = get_default_claims()
        claims.pop("jti")
        token = get_jwe_token("alice", claims=claims)
        result = await self.hs.mockmod.check_epa(
            "alice", "com.famedly.login.token.epa", {"token": token}
        )
        self.assertEqual(result, None)

    async def test_token_token_not_enc(self) -> None:
        token = get_jwt_token("alice", claims=get_default_claims())
        result = await self.hs.mockmod.check_epa(
            "alice", "com.famedly.login.token.epa", {"token": token}
        )
        self.assertEqual(result, None)

    config_for_epa: JsonDict = {
        "modules": [
            {
                "module": "synapse_token_authenticator.TokenAuthenticator",
                "config": {
                    "epa": {
                        "localpart_path": "sub",
                        "displayname_path": "urn:telematik:claims:display_name",
                        "jwk_set": get_jwk(),
                        "enc_jwk": get_enc_jwk(),
                        "registration_enabled": True,
                        "iss": "http://test.example",
                        "resource_id": "https://famedly.de",
                    },
                },
            }
        ]
    }

    config_for_epa_wrong_iss = deepcopy(config_for_epa)
    config_for_epa_wrong_iss["modules"][0]["config"]["epa"]["iss"] = "wrong_iss"

    @synapsetest.override_config(config_for_epa_wrong_iss)
    async def test_token_wrong_iss(self) -> None:
        token = get_jwe_token("alice", claims=get_default_claims())
        result = await self.hs.mockmod.check_epa(
            "alice", "com.famedly.login.token.epa", {"token": token}
        )
        self.assertEqual(result, None)

    config_for_epa_wrong_aud = deepcopy(config_for_epa)
    config_for_epa_wrong_aud["modules"][0]["config"]["epa"]["resource_id"] = "wrong_aud"

    @synapsetest.override_config(config_for_epa_wrong_aud)
    async def test_token_wrong_aud(self) -> None:
        token = get_jwe_token("alice", claims=get_default_claims())
        result = await self.hs.mockmod.check_epa(
            "alice", "com.famedly.login.token.epa", {"token": token}
        )
        self.assertEqual(result, None)

    @mock.patch("synapse.module_api.ModuleApi.check_user_exists", return_value=False)
    async def test_valid_login_register(self, *args) -> None:
        token = get_jwe_token("alice", claims=get_default_claims())
        result = await self.hs.mockmod.check_epa(
            "alice", "com.famedly.login.token.epa", {"token": token}
        )
        self.assertEqual(result[0], "@alice:example.test")

    config_for_epa_jwks_url = deepcopy(config_for_epa)
    config_for_epa_jwks_url["modules"][0]["config"]["epa"].pop("jwk_set")
    config_for_epa_jwks_url["modules"][0]["config"]["epa"][
        "jwks_endpoint"
    ] = "https://my_idp.com/oauth/v2/keys"
    jwks = jwk.JWKSet()
    jwks.add(get_jwk())

    @synapsetest.override_config(config_for_epa_jwks_url)
    @mock.patch(
        "synapse.http.client.SimpleHttpClient.get_raw", return_value=jwks.export()
    )
    async def test_fetch_jwks(self, *args) -> None:
        token = get_jwe_token("alice", claims=get_default_claims())
        result = await self.hs.mockmod.check_epa(
            "alice", "com.famedly.login.token.epa", {"token": token}
        )
        self.assertEqual(result[0], "@alice:example.test")

    config_for_epa_reg_disabled = deepcopy(config_for_epa)
    config_for_epa_reg_disabled["modules"][0]["config"]["epa"][
        "registration_enabled"
    ] = False

    @synapsetest.override_config(config_for_epa_reg_disabled)
    @mock.patch("synapse.module_api.ModuleApi.check_user_exists", return_value=False)
    async def test_valid_login_registration_disabled(self, *args) -> None:
        token = get_jwe_token("alice", claims=get_default_claims())
        result = await self.hs.mockmod.check_epa(
            "alice", "com.famedly.login.token.epa", {"token": token}
        )
        self.assertEqual(result, None)

    config_for_epa_lowercase = deepcopy(config_for_epa)
    config_for_epa_lowercase["modules"][0]["config"]["epa"][
        "lowercase_localpart"
    ] = True

    @synapsetest.override_config(config_for_epa_lowercase)
    async def test_localpart_lowercase(self) -> None:
        token = get_jwe_token("AlIcE", claims=get_default_claims())
        result = await self.hs.mockmod.check_epa(
            "alice", "com.famedly.login.token.epa", {"token": token}
        )
        self.assertEqual(result[0], "@alice:example.test")

    async def test_localpart_not_lowercase(self) -> None:
        token = get_jwe_token("AlIcE", claims=get_default_claims())
        result = await self.hs.mockmod.check_epa(
            "alice", "com.famedly.login.token.epa", {"token": token}
        )
        self.assertEqual(result[0], "@AlIcE:example.test")
