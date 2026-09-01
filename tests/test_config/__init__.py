from synapse_token_authenticator.config import TokenAuthenticatorConfig


class TestTokenAuthenticatorConfig:
    def test_null_sections_are_skipped(self):
        config = TokenAuthenticatorConfig(
            {
                "jwt": None,
                "oidc": None,
                "oauth": None,
                "epa": None,
            }
        )
        assert config.jwt is None
        assert config.oidc is None
        assert config.oauth is None
        assert config.epa is None

    def test_missing_sections_remain_none(self):
        config = TokenAuthenticatorConfig({})
        assert config.jwt is None
        assert config.oidc is None
        assert config.oauth is None
        assert config.epa is None
