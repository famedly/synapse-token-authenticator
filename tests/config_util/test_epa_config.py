import json

import pytest
from jwcrypto.jwk import JWK, JWKSet
from pydantic import ValidationError

from synapse_token_authenticator.config_util.base import Exist
from synapse_token_authenticator.config_util.epa_config import EPaConfig
from tests import get_enc_jwk, get_jwk_set


class TestEPaConfig:
    def test_epa_config(self):
        enc_jwk = json.loads(get_enc_jwk().export(private_key=True))
        jwk_set = get_jwk_set().export(private_keys=True)
        config = EPaConfig(
            iss="https://example.com",
            resource_id="https://example.com",
            enc_jwk=enc_jwk,
            jwk_set=jwk_set,
        )
        assert config.iss == "https://example.com"
        assert config.resource_id == "https://example.com"
        assert config.validator == Exist()
        assert config.expose_metadata_resource is None
        assert config.registration_enabled is False
        assert config.enc_jwk is not None and isinstance(config.enc_jwk, JWK)
        assert config.enc_jwk_file is None
        assert config.enc_jwks_endpoint == "/.well-known/jwks.json"
        assert config.jwk_set is not None and isinstance(config.jwk_set, JWKSet)
        assert config.jwk_file is None
        assert config.jwks_endpoint is None
        assert config.localpart_path is None
        assert config.displayname_path is None
        assert config.lowercase_localpart is False

    def test_epa_config_without_enc_jwk(self):
        jwk_set = get_jwk_set().export(private_keys=True)
        with pytest.raises(ValidationError):
            EPaConfig(
                iss="https://example.com",
                resource_id="https://example.com",
                jwk_set=jwk_set,
            )

    def test_epa_config_with_enc_jwk_file(self, tmp_path):
        jwk_set = get_jwk_set().export(private_keys=True)
        enc_jwk_path = tmp_path / "enc_jwk.pem"
        enc_jwk_path.write_bytes(
            JWK.generate(kty="RSA", size=2048).export_to_pem(
                private_key=True, password=None
            )
        )
        config = EPaConfig(
            iss="https://example.com",
            resource_id="https://example.com",
            enc_jwk_file=str(enc_jwk_path),
            jwk_set=jwk_set,
        )
        assert config.enc_jwk is not None and isinstance(config.enc_jwk, JWK)
        assert config.enc_jwk_file == str(enc_jwk_path)

    def test_epa_config_without_jwk_set(self):
        enc_jwk = json.loads(get_enc_jwk().export(private_key=True))
        with pytest.raises(ValidationError):
            EPaConfig(
                iss="https://example.com",
                resource_id="https://example.com",
                enc_jwk=enc_jwk,
            )

    def test_epa_config_without_iss(self):
        enc_jwk = json.loads(get_enc_jwk().export(private_key=True))
        jwk_set = get_jwk_set().export(private_keys=True)
        with pytest.raises(ValidationError):
            EPaConfig(
                resource_id="https://example.com",
                enc_jwk=enc_jwk,
                jwk_set=jwk_set,
            )
