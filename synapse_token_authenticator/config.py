import os
from dataclasses import dataclass, field
from typing import Any, Literal, TypeAlias

from jwcrypto.jwk import JWK, JWKSet

from synapse_token_authenticator.claims_validator import (
    Exist,
    Validator,
    parse_validator,
)
from synapse_token_authenticator.http_auth import (
    HttpAuth,
    NoAuth,
    coerce_http_auth,
)


class OIDCConfig:
    def __init__(self, other: dict):
        try:
            self.issuer: str = other["issuer"]
            self.client_id: str = other["client_id"]
            self.client_secret: str = other["client_secret"]
            self.project_id: str = other["project_id"]
            self.organization_id: str = other["organization_id"]
        except KeyError as error:
            error_msg = f"Config option must be set: {error.args[0]}"
            raise Exception(error_msg) from error

        self.allowed_client_ids: str | None = other.get("allowed_client_ids")

        self.allow_registration: bool = other.get("allow_registration", False)


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
            verify_jwt_based_cfg(self.jwt)

        if oidc := other.get("oidc"):
            self.oidc = OIDCConfig(oidc)

        if config := other.get("oauth"):
            Path: TypeAlias = str | list[str]
            PathList: TypeAlias = Path | list[list[str]]

            @dataclass
            class JwtValidationConfig:
                validator: Validator = field(default_factory=Exist)
                require_expiry: bool = False
                localpart_path: Path | None = None
                user_id_path: Path | None = None
                fq_uid_path: Path | None = None
                displayname_path: Path | None = None
                admin_path: PathList | None = None
                email_path: Path | None = None
                required_scopes: str | list[str] | None = None
                jwk_set: JWKSet | JWK | None = None
                jwk_file: str | None = None
                jwks_endpoint: str | None = None

                def __post_init__(self):
                    if not isinstance(self.validator, Exist):
                        self.validator = parse_validator(self.validator)

                    if self.jwk_set and ("keys" in self.jwk_set):
                        self.jwk_set = JWKSet(**self.jwk_set)
                    elif self.jwk_set:
                        self.jwk_set = JWK(**self.jwk_set)
                    elif self.jwk_file:
                        with open(self.jwk_file) as f:
                            self.jwk_set = JWK.from_pem(f.read())
                    elif not self.jwks_endpoint:
                        error_msg = "No JWK"
                        raise Exception(error_msg)

            @dataclass
            class IntrospectionValidationConfig:
                endpoint: str
                validator: Validator = field(default_factory=Exist)
                auth: HttpAuth = field(default_factory=NoAuth)
                localpart_path: Path | None = None
                user_id_path: Path | None = None
                fq_uid_path: Path | None = None
                displayname_path: Path | None = None
                admin_path: PathList | None = None
                email_path: Path | None = None
                required_scopes: str | list[str] | None = None

                def __post_init__(self):
                    if not isinstance(self.validator, Exist):
                        self.validator = parse_validator(self.validator)
                    # dataclasses does not run Pydantic's BeforeValidator
                    self.auth = coerce_http_auth(self.auth)

            @dataclass
            class NotifyOnRegistration:
                url: str
                auth: HttpAuth = field(default_factory=NoAuth)
                interrupt_on_error: bool = True

                def __post_init__(self):
                    # dataclasses does not run Pydantic's BeforeValidator
                    self.auth = coerce_http_auth(self.auth)

            @dataclass
            class OAuthConfig:
                jwt_validation: JwtValidationConfig | None = None
                introspection_validation: IntrospectionValidationConfig | None = None
                username_type: Literal["fq_uid", "localpart", "user_id"] | None = None
                notify_on_registration: NotifyOnRegistration | None = None
                expose_metadata_resource: Any = None
                registration_enabled: bool = False
                check_external_id: bool = True

                def __post_init__(self):
                    if self.notify_on_registration:
                        self.notify_on_registration = NotifyOnRegistration(
                            **self.notify_on_registration
                        )
                    if self.jwt_validation:
                        self.jwt_validation = JwtValidationConfig(
                            **(self.jwt_validation)
                        )
                    if self.introspection_validation:
                        self.introspection_validation = IntrospectionValidationConfig(
                            **self.introspection_validation
                        )
                    if not (self.jwt_validation or self.introspection_validation):
                        error_msg = "Neither jwt_validation nor introspection_validation was specified"
                        raise Exception(error_msg)
                    if self.username_type not in [
                        "fq_uid",
                        "localpart",
                        "user_id",
                        None,
                    ]:
                        error_msg = f"Unknown username_type {self.username_type}"
                        raise Exception(error_msg)

            self.oauth = OAuthConfig(**config)

        if epa := other.get("epa"):

            @dataclass
            class EPaConfig:
                iss: str
                resource_id: str
                validator: Validator = field(default_factory=Exist)
                expose_metadata_resource: Any = None
                registration_enabled: bool = False
                enc_jwk: JWK | None = None
                enc_jwk_file: str | None = None
                enc_jwks_endpoint: str = "/.well-known/jwks.json"
                jwk_set: JWKSet | JWK | None = None
                jwk_file: str | None = None
                jwks_endpoint: str | None = None
                localpart_path: str | None = None
                displayname_path: str | None = None
                lowercase_localpart: bool = False

                def __post_init__(self):
                    if not isinstance(self.validator, Exist):
                        self.validator = parse_validator(self.validator)

                    if self.enc_jwk:
                        self.enc_jwk = JWK(**self.enc_jwk)
                    elif self.enc_jwk_file:
                        with open(self.enc_jwk_file) as f:
                            self.enc_jwk = JWK.from_pem(f.read())
                    else:
                        error_msg = "No encryption JWK"
                        raise Exception(error_msg)

                    if self.jwk_set and ("keys" in self.jwk_set):
                        self.jwk_set = JWKSet(**self.jwk_set)
                    elif self.jwk_set:
                        self.jwk_set = JWK(**self.jwk_set)
                    elif self.jwk_file:
                        with open(self.jwk_file) as f:
                            self.jwk_set = JWK.from_pem(f.read())
                    elif not self.jwks_endpoint:
                        error_msg = "No JWK"
                        raise Exception(error_msg)

            self.epa = EPaConfig(**epa)


def verify_jwt_based_cfg(cfg):
    if cfg.secret is None and cfg.keyfile is None:
        error_msg = "Missing secret or keyfile"
        raise Exception(error_msg)
    if cfg.keyfile is not None and not os.path.exists(cfg.keyfile):
        error_msg = "Keyfile doesn't exist"
        raise Exception(error_msg)

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
        error_msg = f"Unknown algorithm: '{cfg.algorithm}'"
        raise Exception(error_msg)
