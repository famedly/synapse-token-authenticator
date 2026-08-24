import json

import pytest
from jwcrypto.jwk import JWK, JWKSet
from pydantic import ValidationError

from synapse_token_authenticator.claims_validator import AnyOf, Equal, Exist, In, Not
from synapse_token_authenticator.config.base import (
    JwkSource,
    ValidatorMapping,
)
from tests import get_jwk, get_jwk_set


class TestValidatorMapping:
    def test_validator_fails_if_not_dict_or_list(self):
        with pytest.raises(ValueError):
            ValidatorMapping(validator="validator has to be a dict or list")

    def test_validator_fails_if_none(self):
        with pytest.raises(ValidationError):
            ValidatorMapping(validator=None)

    def test_validator_succeeds_if_default(self):
        config = ValidatorMapping()
        assert config.validator == Exist()

    def test_validator_fails_if_empty_dict(self):
        with pytest.raises(ValidationError):
            ValidatorMapping(validator={})

    def test_validator_fails_if_dict_unknown_type(self):
        with pytest.raises(ValidationError):
            ValidatorMapping(validator={"type": "unknown", "value": "something"})

    def test_validator_fails_if_dict_missing_fields(self):
        with pytest.raises(ValidationError):
            ValidatorMapping(validator={"type": "equal"})

    def test_validator_succeeds_if_dict_equal(self):
        config = ValidatorMapping(validator={"type": "equal", "value": "something"})
        assert config.validator == Equal(value="something")

    def test_validator_fails_if_empty_list(self):
        with pytest.raises(ValidationError):
            ValidatorMapping(validator=[])

    def test_validator_fails_if_list_unknown_type(self):
        with pytest.raises(ValidationError):
            ValidatorMapping(validator=["unknown", "something"])

    def test_validator_fails_if_list_missing_fields(self):
        with pytest.raises(ValidationError):
            ValidatorMapping(validator=["equal"])

    def test_validator_list_equal(self):
        config = ValidatorMapping(validator=["equal", "something"])
        assert config.validator == Equal(value="something")

    def test_validator_list_not(self):
        config = ValidatorMapping(validator=["not", ["in", "foo"]])
        assert isinstance(config.validator, Not)
        assert isinstance(config.validator.validator, In)
        assert config.validator.validator.path == "foo"

    def test_validator_list_any_of(self):
        config = ValidatorMapping(
            validator=[
                "any_of",
                [
                    ["in", "foo"],
                    ["in", "bar"],
                ],
            ]
        )
        assert isinstance(config.validator, AnyOf)
        assert len(config.validator.validators) == 2
        assert isinstance(config.validator.validators[0], In)
        assert isinstance(config.validator.validators[1], In)
        assert config.validator.validators[0].path == "foo"
        assert config.validator.validators[1].path == "bar"


class TestJwkSource:
    def test_jwk_source_succeeds_if_jwk_set_is_jwk_set(self):
        jwk_set_input = get_jwk_set().export(private_keys=True)
        config = JwkSource(jwk_set=jwk_set_input)
        assert isinstance(config.jwk_set, JWKSet)
        assert config.jwk_file is None
        assert config.jwks_endpoint is None

    def test_jwk_source_succeeds_if_jwk_set_is_jwk(self):
        jwk_input = json.loads(get_jwk().export(private_key=True))
        config = JwkSource(jwk_set=jwk_input)
        assert isinstance(config.jwk_set, JWK)
        assert config.jwk_file is None
        assert config.jwks_endpoint is None

    def test_jwk_source_succeeds_if_jwk_file(self, tmp_path):
        jwk = JWK.generate(kty="RSA", size=2048)
        jwk_path = tmp_path / "jwk.pem"
        jwk_path.write_bytes(jwk.export_to_pem(private_key=True, password=None))
        config = JwkSource(jwk_file=str(jwk_path))
        assert config.jwk_file == str(jwk_path)
        assert isinstance(config.jwk_set, JWK)
        assert config.jwks_endpoint is None

    def test_jwk_source_succeeds_if_jwks_endpoint(self):
        config = JwkSource(jwks_endpoint="https://example.com/jwks")
        assert config.jwk_set is None
        assert config.jwk_file is None
        assert config.jwks_endpoint == "https://example.com/jwks"

    def test_jwk_source_fails_if_no_jwk(self):
        with pytest.raises(ValidationError):
            JwkSource()
