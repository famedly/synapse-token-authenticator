from synapse_token_authenticator.config.epa_config import EPaConfig
from synapse_token_authenticator.config.jwt_config import JwtConfig
from synapse_token_authenticator.config.oauth_config import OAuthConfig
from synapse_token_authenticator.config.oidc_config import OIDCConfig


class TokenAuthenticatorConfig:
    """
    Parses and validates the provided config dictionary.
    """

    def __init__(self, other: dict):
        if jwt := other.get("jwt"):
            self.jwt = JwtConfig(**jwt)
        if oidc := other.get("oidc"):
            self.oidc = OIDCConfig(**oidc)
        if config := other.get("oauth"):
            self.oauth = OAuthConfig(**config)
        if epa := other.get("epa"):
            self.epa = EPaConfig(**epa)
