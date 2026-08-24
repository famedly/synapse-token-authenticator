import pytest
from pydantic import ValidationError

from synapse_token_authenticator.config.oidc_config import OIDCConfig


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
