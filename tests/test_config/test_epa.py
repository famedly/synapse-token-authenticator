import pytest
from jwcrypto.jwk import JWK, JWKSet
from pydantic import ValidationError

from synapse_token_authenticator.claims_validator import Exist, In
from synapse_token_authenticator.config.epa import EPaConfig
from tests import get_enc_jwk, get_jwk, get_jwk_set


class TestEPaConfig:
    def test_epa_config_defaults(self):
        enc_jwk = get_enc_jwk()
        jwk_set = get_jwk()
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
        assert isinstance(config.enc_jwk, JWK)
        assert config.enc_jwk_file is None
        assert config.enc_jwks_endpoint == "/.well-known/jwks.json"
        assert isinstance(config.jwk_set, JWK)
        assert config.jwk_file is None
        assert config.jwks_endpoint is None
        assert config.localpart_path is None
        assert config.displayname_path is None
        assert config.lowercase_localpart is False

    def test_epa_config_without_enc_jwk(self):
        jwk_set = get_jwk_set()
        with pytest.raises(ValidationError):
            EPaConfig(
                iss="https://example.com",
                resource_id="https://example.com",
                jwk_set=jwk_set,
            )

    def test_epa_config_with_enc_jwk_file(self, tmp_path):
        jwk_set = get_jwk_set()
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
        assert isinstance(config.enc_jwk, JWK)
        assert config.enc_jwk_file == str(enc_jwk_path)

    def test_epa_config_without_jwk_set(self):
        enc_jwk = get_enc_jwk()
        with pytest.raises(ValidationError):
            EPaConfig(
                iss="https://example.com",
                resource_id="https://example.com",
                enc_jwk=enc_jwk,
            )

    def test_epa_config_without_iss(self):
        enc_jwk = get_enc_jwk()
        jwk_set = get_jwk_set()
        with pytest.raises(ValidationError):
            EPaConfig(
                resource_id="https://example.com",
                enc_jwk=enc_jwk,
                jwk_set=jwk_set,
            )

    def test_epa_config_does_not_accept_list_expose_metadata_resource(self):
        enc_jwk = get_enc_jwk()
        jwk_set = get_jwk_set()
        with pytest.raises(ValidationError, match="Input should be a valid dictionary"):
            EPaConfig(
                iss="https://example.com",
                resource_id="https://example.com",
                validator=["in", "active", ["equal", True]],
                expose_metadata_resource=["something"],
                registration_enabled=True,
                enc_jwk=enc_jwk,
                jwk_set=jwk_set,
                localpart_path="urn:messaging:matrix:localpart",
                displayname_path="some_displayname_path",
                lowercase_localpart=True,
            )

    def test_epa_config_full(self):
        enc_jwk = get_enc_jwk()
        jwk_set = get_jwk_set()
        config = EPaConfig(
            iss="https://example.com",
            resource_id="https://example.com",
            validator=["in", "active", ["equal", True]],
            expose_metadata_resource={"name": "expose_metadata_resource"},
            registration_enabled=True,
            enc_jwk=enc_jwk,
            jwk_set=jwk_set,
            localpart_path="urn:messaging:matrix:localpart",
            displayname_path="some_displayname_path",
            lowercase_localpart=True,
        )
        assert config.iss == "https://example.com"
        assert config.resource_id == "https://example.com"
        assert isinstance(config.validator, In)
        assert config.expose_metadata_resource == {"name": "expose_metadata_resource"}
        assert config.registration_enabled is True
        assert isinstance(config.enc_jwk, JWK)
        assert isinstance(config.jwk_set, JWKSet)
        assert config.localpart_path == "urn:messaging:matrix:localpart"
        assert config.displayname_path == "some_displayname_path"
        assert config.lowercase_localpart is True
