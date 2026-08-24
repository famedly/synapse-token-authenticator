import pytest
from jwcrypto.jwk import JWK
from pydantic import ValidationError

from synapse_token_authenticator.claims_validator import Exist
from synapse_token_authenticator.config_util.http_auth import NoAuth
from synapse_token_authenticator.config_util.oauth_config import (
    IntrospectionValidationConfig,
    JwtValidationConfig,
    NotifyOnRegistration,
    OAuthConfig,
)
from tests import get_jwk


class TestJwtValidationConfig:
    def test_jwt_validation_config(self):
        jwk = get_jwk().export(private_key=True)
        config = JwtValidationConfig(jwk_set=jwk)
        assert config.validator == Exist()
        assert config.require_expiry is False
        assert config.localpart_path is None
        assert config.user_id_path is None
        assert config.fq_uid_path is None
        assert config.displayname_path is None
        assert config.admin_path is None
        assert config.email_path is None
        assert config.required_scopes is None
        assert config.jwk_set is not None and isinstance(config.jwk_set, JWK)
        assert config.jwk_file is None
        assert config.jwks_endpoint is None

    def test_jwt_validation_config_missing_jwk_source(self):
        with pytest.raises(ValidationError):
            JwtValidationConfig()


class TestIntrospectionValidationConfig:
    def test_introspection_validation_config(self):
        config = IntrospectionValidationConfig(endpoint="https://example.com")

        assert config.endpoint == "https://example.com"
        assert config.validator == Exist()
        assert config.auth == NoAuth()
        assert config.localpart_path is None
        assert config.user_id_path is None
        assert config.fq_uid_path is None
        assert config.displayname_path is None
        assert config.admin_path is None
        assert config.email_path is None
        assert config.required_scopes is None

    def test_introspection_validation_config_missing_endpoint(self):
        with pytest.raises(ValidationError):
            IntrospectionValidationConfig()


class TestNotifyOnRegistration:
    def test_notify_on_registration(self):
        config = NotifyOnRegistration(url="https://example.com")
        assert config.url == "https://example.com"
        assert config.auth == NoAuth()
        assert config.interrupt_on_error is True

    def test_notify_on_registration_missing_url(self):
        with pytest.raises(ValidationError):
            NotifyOnRegistration()


class TestOAuthConfig:
    def test_oauth_config(self):
        jwk = get_jwk().export(private_key=True)
        config = OAuthConfig(
            jwt_validation=JwtValidationConfig(jwk_set=jwk),
            introspection_validation=IntrospectionValidationConfig(
                endpoint="https://example.com"
            ),
            username_type="user_id",
            notify_on_registration=NotifyOnRegistration(url="https://example.com"),
        )

        assert config.jwt_validation is not None
        assert config.introspection_validation is not None
        assert config.username_type == "user_id"
        assert config.notify_on_registration is not None
        assert config.expose_metadata_resource is None
        assert config.registration_enabled is False
        assert config.check_external_id is True

    def test_oauth_config_wrong_username_type(self):
        jwk = get_jwk().export(private_key=True)
        with pytest.raises(ValidationError):
            OAuthConfig(
                jwt_validation=JwtValidationConfig(jwk_set=jwk),
                introspection_validation=IntrospectionValidationConfig(
                    endpoint="https://example.com"
                ),
                username_type="invalid username type like email",
            )

    def test_oauth_config_missing_jwt_validation_or_introspection_validation(self):
        with pytest.raises(ValidationError):
            OAuthConfig(
                username_type="user_id",
                notify_on_registration=NotifyOnRegistration(url="https://example.com"),
            )
