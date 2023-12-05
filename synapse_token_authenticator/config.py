import os


class TokenAuthenticatorConfig:
    """
    Parses and validates the provided config dictionary.
    """

    def __init__(self, other: dict):
        if jwt := other.get("jwt"):

            class JwtConfig:
                def __init__(self, other: dict):
                    self.secret: str | None = other.get("secret")
                    self.keyfile: str | None = other.get("keyfile")

                    self.algorithm: str = other.get("algorithm", "HS512")
                    self.allow_registration: bool = other.get(
                        "allow_registration", False
                    )
                    self.require_expiry: bool = other.get("require_expiry", True)

            self.jwt = JwtConfig(jwt)
            self.verify_jwt()

        if oidc := other.get("oidc"):

            class OIDCConfig:
                def __init__(self, other: dict):
                    try:
                        self.issuer: str = other["issuer"]
                        self.client_id: str = other["client_id"]
                        self.client_secret: str = other["client_secret"]
                        self.project_id: str = other["project_id"]
                        self.organization_id: str = other["organization_id"]
                    except KeyError as error:
                        raise Exception(f"Config option must be set: {error.args[0]}")

                    self.allowed_client_ids: str | None = other.get(
                        "allowed_client_ids"
                    )

                    self.allow_registration: bool = other.get(
                        "allow_registration", False
                    )

            self.oidc = OIDCConfig(oidc)

    def verify_jwt(self):
        if self.jwt.secret is None and self.jwt.keyfile is None:
            raise Exception("Missing secret or keyfile")
        if self.jwt.keyfile is not None and not os.path.exists(self.jwt.keyfile):
            raise Exception("Keyfile doesn't exist")

        if self.jwt.algorithm not in [
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
            raise Exception(f"Unknown algorithm: '{self.jwt.algorithm}'")
