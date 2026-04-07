import os
from typing import Any

from synapse_token_authenticator.config_classes import (
    EPaConfig,
    JwtConfig,
    OAuthConfig,
    OIDCConfig,
)


class TokenAuthenticatorConfig:
    """
    Parses and validates the provided config dictionary.
    """

    jwt: JwtConfig | None = None
    oidc: OIDCConfig | None = None
    oauth: OAuthConfig | None = None
    epa: EPaConfig | None = None

    def __init__(self, other: dict[str, Any]):
        if jwt := other.get("jwt", {}):
            jwt_config = JwtConfig(jwt)
            verify_jwt_based_cfg(jwt_config)
            self.jwt = jwt_config

        if oidc := other.get("oidc", {}):
            self.oidc = OIDCConfig(oidc)

        if config := other.get("oauth", {}):
            self.oauth = OAuthConfig(**config)

        if epa := other.get("epa", {}):
            self.epa = EPaConfig(**epa)


def verify_jwt_based_cfg(cfg: JwtConfig):
    if cfg.secret is None and cfg.keyfile is None:
        raise Exception("Missing secret or keyfile")
    if cfg.keyfile is not None and not os.path.exists(cfg.keyfile):
        raise Exception("Keyfile doesn't exist")

    if cfg.algorithm not in [
        "HS256",
        "HS384",
        "HS512",
        "RS256",
        "RS384",
        "RS512",
        "ES256",
        "ES384",
        "ES512",
        "PS256",
        "PS384",
        "PS512",
        "EdDSA",
    ]:
        raise Exception(f"Unknown algorithm: '{cfg.algorithm}'")
