from synapse_token_authenticator.config.epa import EPaConfig
from synapse_token_authenticator.config.jwt import JwtConfig
from synapse_token_authenticator.config.oauth import OAuthConfig
from synapse_token_authenticator.config.oidc import OIDCConfig


class TokenAuthenticatorConfig:
    """
    Parses and validates the provided config dictionary.
    """

    jwt: JwtConfig | None = None
    oidc: OIDCConfig | None = None
    oauth: OAuthConfig | None = None
    epa: EPaConfig | None = None

    def __init__(self, other: dict):
        # Skip missing *and* explicit null (e.g. YAML `jwt:` / Helm `jwt: null`).
        if other.get("jwt"):
            self.jwt = JwtConfig(**other["jwt"])
        if other.get("oidc"):
            self.oidc = OIDCConfig(**other["oidc"])
        if other.get("oauth"):
            self.oauth = OAuthConfig(**other["oauth"])
        if other.get("epa"):
            self.epa = EPaConfig(**other["epa"])
