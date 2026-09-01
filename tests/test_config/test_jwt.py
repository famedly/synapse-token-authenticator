import pytest
from jwcrypto.jwk import JWK
from pydantic import ValidationError

from synapse_token_authenticator.config.jwt import JwtConfig


class TestJwtConfig:
    def test_jwt_config(self):
        config = JwtConfig(
            secret="secret",
        )
        assert config.secret == "secret"
        assert config.keyfile is None
        assert config.algorithm == "HS512"
        assert config.allow_registration is False
        assert config.require_expiry is True

    def test_jwt_config_wrong_algorithm(self):
        with pytest.raises(ValidationError):
            JwtConfig(algorithm="invalid")

    def test_jwt_config_missing_secret_or_keyfile(self):
        with pytest.raises(ValidationError):
            JwtConfig()

    def test_jwt_config_keyfile_does_not_exist(self):
        with pytest.raises(ValidationError):
            JwtConfig(keyfile="keyfile.pem")

    def test_jwt_config_with_keyfile(self, tmp_path):
        jwk_path = tmp_path / "jwk.pem"
        jwk_path.write_bytes(
            JWK.generate(kty="RSA", size=2048).export_to_pem(
                private_key=True, password=None
            )
        )
        config = JwtConfig(keyfile=str(jwk_path))
        assert config.keyfile == str(jwk_path)
