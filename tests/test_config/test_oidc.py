import pytest
from pydantic import ValidationError

from synapse_token_authenticator.config.oidc import OIDCConfig


class TestOIDCConfig:
    def test_oidc_config_defaults(self):
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

    def test_oidc_config_full(self):
        config = OIDCConfig(
            issuer="https://idp.example.test",
            client_id="1111@project",
            client_secret="2222@project",
            project_id="231872387283",
            organization_id="2283783782778",
            allowed_client_ids=["client-a", "client-b"],
            allow_registration=True,
        )
        assert config.issuer == "https://idp.example.test"
        assert config.client_id == "1111@project"
        assert config.client_secret == "2222@project"
        assert config.project_id == "231872387283"
        assert config.organization_id == "2283783782778"
        assert config.allowed_client_ids == ["client-a", "client-b"]
        assert config.allow_registration is True

    def test_oidc_config_allowed_client_ids_accepts_str(self):
        config = OIDCConfig(
            issuer="https://example.com",
            client_id="client_id",
            client_secret="client_secret",
            project_id="project_id",
            organization_id="organization_id",
            allowed_client_ids="client-a client-b",
        )
        assert config.allowed_client_ids == ["client-a", "client-b"]

    def test_oidc_config_is_not_missing_required_fields(self):
        with pytest.raises(ValidationError) as e:
            OIDCConfig(
                client_id="client_id",
                client_secret="client_secret",
                project_id="project_id",
                organization_id="organization_id",
            )
        assert "Field required" in str(e)
