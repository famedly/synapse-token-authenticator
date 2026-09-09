import pytest
from jwcrypto.jwk import JWK, JWKSet
from pydantic import ValidationError

from synapse_token_authenticator.claims_validator import Equal, Exist, In
from synapse_token_authenticator.config.epa import EPaConfig
from tests import get_enc_jwk, get_jwk, get_jwk_set


class TestEPaConfig:
    def test_epa_config_defaults(self):
        config = EPaConfig(
            iss="https://example.com",
            resource_id="https://example.com",
            enc_jwk=get_enc_jwk(),
            jwk_set=get_jwk(),
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

    def test_epa_config_validator(self):
        config = EPaConfig(
            iss="https://example.com",
            resource_id="https://example.com",
            enc_jwk=get_enc_jwk(),
            jwk_set=get_jwk(),
            validator=Exist(),
        )
        assert config.validator == Exist()

        config = EPaConfig(
            iss="https://example.com",
            resource_id="https://example.com",
            enc_jwk=get_enc_jwk(),
            jwk_set=get_jwk(),
            validator=["equal", "foo"],
        )
        assert config.validator == Equal("foo")

    def test_epa_config_jwk_set_as_json_string(self):
        jwk_str = get_jwk().export()
        config = EPaConfig(
            iss="https://example.com",
            resource_id="https://example.com",
            enc_jwk=get_enc_jwk(),
            jwk_set=jwk_str,
        )
        assert isinstance(config.jwk_set, JWK)

        jwk_set_str = get_jwk_set().export()
        config = EPaConfig(
            iss="https://example.com",
            resource_id="https://example.com",
            enc_jwk=get_enc_jwk(),
            jwk_set=jwk_set_str,
        )
        assert isinstance(config.jwk_set, JWKSet)

    def test_epa_config_jwk_set_as_dict(self):
        jwk_dict = get_jwk().export(as_dict=True)
        config = EPaConfig(
            iss="https://example.com",
            resource_id="https://example.com",
            enc_jwk=get_enc_jwk(),
            jwk_set=jwk_dict,
        )
        assert isinstance(config.jwk_set, JWK)

        jwk_set_dict = get_jwk_set().export(as_dict=True)
        config = EPaConfig(
            iss="https://example.com",
            resource_id="https://example.com",
            enc_jwk=get_enc_jwk(),
            jwk_set=jwk_set_dict,
        )
        assert isinstance(config.jwk_set, JWKSet)

    def test_epa_config_enc_jwk_as_json_string(self):
        enc_jwk_str = get_enc_jwk().export()
        config = EPaConfig(
            iss="https://example.com",
            resource_id="https://example.com",
            enc_jwk=enc_jwk_str,
            jwk_set=get_jwk(),
        )
        assert isinstance(config.enc_jwk, JWK)

    def test_epa_config_enc_jwk_set_as_dict(self):
        enc_jwk_dict = get_enc_jwk().export(as_dict=True)
        config = EPaConfig(
            iss="https://example.com",
            resource_id="https://example.com",
            enc_jwk=enc_jwk_dict,
            jwk_set=get_jwk(),
        )
        assert isinstance(config.enc_jwk, JWK)

    def test_epa_config_without_enc_jwk(self):
        with pytest.raises(ValidationError):
            EPaConfig(
                iss="https://example.com",
                resource_id="https://example.com",
                jwk_set=get_jwk_set(),
            )

    def test_epa_config_enc_jwk_file_does_not_exist(self):
        with pytest.raises(ValidationError):
            EPaConfig(
                iss="https://example.com",
                resource_id="https://example.com",
                enc_jwk_file="no_such_file.pem",
                jwk_set=get_jwk(),
            )

    def test_epa_config_with_enc_jwk_file_opens_and_loads(self, tmp_path):
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
            jwk_set=get_jwk_set(),
        )
        assert isinstance(config.enc_jwk, JWK)

    def test_epa_config_jwk_file_does_not_exist(self):
        with pytest.raises(ValidationError):
            EPaConfig(
                iss="https://example.com",
                resource_id="https://example.com",
                enc_jwk=get_enc_jwk(),
                jwk_file="no_such_file.pem",
            )

    def test_epa_config_with_jwk_file_opens_and_loads(self, tmp_path):
        jwk_path = tmp_path / "jwk.pem"
        jwk_path.write_bytes(
            JWK.generate(kty="RSA", size=2048).export_to_pem(
                private_key=True, password=None
            )
        )
        config = EPaConfig(
            iss="https://example.com",
            resource_id="https://example.com",
            enc_jwk=get_enc_jwk(),
            jwk_file=str(jwk_path),
        )
        assert isinstance(config.jwk_set, JWK)

    def test_epa_config_more_than_one_enc_jwk_source_should_raise_error(self, tmp_path):
        enc_jwk_path = tmp_path / "enc_jwk.pem"
        enc_jwk_path.write_bytes(
            JWK.generate(kty="RSA", size=2048).export_to_pem(
                private_key=True, password=None
            )
        )
        with pytest.raises(ValidationError):
            EPaConfig(
                iss="https://example.com",
                resource_id="https://example.com",
                enc_jwk=get_enc_jwk(),
                enc_jwk_file=str(enc_jwk_path),
                jwk_set=get_jwk_set(),
            )

    def test_epa_config_without_jwk_set(self):
        with pytest.raises(ValidationError):
            EPaConfig(
                iss="https://example.com",
                resource_id="https://example.com",
                enc_jwk=get_enc_jwk(),
            )

    def test_epa_config_with_more_than_one_jwk_source_should_raise_error(
        self, tmp_path
    ):
        enc_jwk_path = tmp_path / "enc_jwk.pem"
        with pytest.raises(ValidationError):
            EPaConfig(
                iss="https://example.com",
                resource_id="https://example.com",
                enc_jwk=get_enc_jwk(),
                jwk_set=get_jwk_set(),
                jwk_file=str(enc_jwk_path),
            )

        with pytest.raises(ValidationError):
            EPaConfig(
                iss="https://example.com",
                resource_id="https://example.com",
                enc_jwk=get_enc_jwk(),
                jwk_set=get_jwk_set(),
                jwks_endpoint="https://example.com/.well-known/jwks.json",
            )

        with pytest.raises(ValidationError):
            EPaConfig(
                iss="https://example.com",
                resource_id="https://example.com",
                enc_jwk=get_enc_jwk(),
                jwk_file=str(enc_jwk_path),
                jwks_endpoint="https://example.com/.well-known/jwks.json",
            )

    def test_epa_config_without_iss(self):
        with pytest.raises(ValidationError):
            EPaConfig(
                resource_id="https://example.com",
                enc_jwk=get_enc_jwk(),
                jwk_set=get_jwk_set(),
            )

    def test_epa_config_with_expose_metadata_resource_none(self):
        config = EPaConfig(
            iss="https://example.com",
            resource_id="https://example.com",
            expose_metadata_resource=None,
            enc_jwk=get_enc_jwk(),
            jwk_set=get_jwk_set(),
        )
        assert config.expose_metadata_resource is None

    def test_epa_config_fails_with_expose_metadata_resource_name_with_empty_string(
        self,
    ):
        with pytest.raises(
            ValidationError, match="expose_metadata_resource must have a name field"
        ):
            EPaConfig(
                iss="https://example.com",
                resource_id="https://example.com",
                expose_metadata_resource={"name": ""},
                enc_jwk=get_enc_jwk(),
                jwk_set=get_jwk_set(),
            )

    def test_epa_config_fails_with_expose_metadata_resource_as_list(self):
        with pytest.raises(ValidationError, match="Input should be a valid dictionary"):
            EPaConfig(
                iss="https://example.com",
                resource_id="https://example.com",
                validator=["in", "active", ["equal", True]],
                expose_metadata_resource=["something"],
                registration_enabled=True,
                enc_jwk=get_enc_jwk(),
                jwk_set=get_jwk_set(),
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
