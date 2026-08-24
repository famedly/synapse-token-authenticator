import pytest
from pydantic import ValidationError

from synapse_token_authenticator.config.oidc import OIDCConfig
from synapse_token_authenticator.config.oauth import OAuthConfig, JwtValidationConfig
from synapse_token_authenticator.claims_validator import Exist

class TestOAuthConfig:
    """
    Test the subclasses first
    - JwtValidationConfig
        - validator
        - jwk set or keyfile or jwks endpoint
    - IntrospectionValidationConfig
        - validator
        - auth
    - NotifyOnRegistration
        - auth

    test username type
    test if jwt_validation or introspection_validation is specified
    """
    def test_oauth_config(self):
        config = OAuthConfig(
            jwt_validation=JwtValidationConfig(
                validator=Exist(),
            ),
        )
        assert config.jwt_validation.validator == Exist()
        assert config.jwt_validation.require_expiry is False




class TestOIDCConfig:
    def test_oidc_config(self):
        config = OIDCConfig(
            issuer="https://example.com",
            client_id="client_id",
            client_secret="client_secret",
            project_id="project_id",
            organization_id="organization_id",
        )
        assert config.issuer == "https://example.com"
        assert config.client_id == "client_id"
        assert config.client_secret == "client_secret"
        assert config.project_id == "project_id"
        assert config.organization_id == "organization_id"
        assert config.allowed_client_ids is None
        assert config.allow_registration is False

    def test_oidc_config_is_not_missing_required_fields(self):
        with pytest.raises(ValidationError) as e:
            OIDCConfig(
                client_id="client_id",
                client_secret="client_secret",
                project_id="project_id",
                organization_id="organization_id",
            )
        assert "Field required" in str(e)
