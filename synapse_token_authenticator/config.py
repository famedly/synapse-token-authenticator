import os
from typing import Annotated, Any, Literal, Self, TypeAlias

from jwcrypto.jwk import JWK, JWKSet
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, model_validator

from synapse_token_authenticator.claims_validator import (
    Exist,
    Validator,
    parse_validator,
)
from synapse_token_authenticator.http_auth import HttpAuth, NoAuth

# Path and PathList type for jwt validation config
Path: TypeAlias = str | list[str]
PathList: TypeAlias = Path | list[list[str]]

# UsernameType for oauth config
UsernameType: TypeAlias = Literal["fq_uid", "localpart", "user_id"]

# JwtAlgorithm for jwt config
JwtAlgorithm: TypeAlias = Literal[
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
]


def _coerce_claims_validator(value: Any) -> Validator:
    if isinstance(value, (dict, list)):
        # parse_validator mutates; copy first
        if isinstance(value, dict):
            value = dict(value)
        else:
            value = list(value)
        return parse_validator(value)
    return value


# Use Any instead of Validator so Pydantic does not try to resolve its's forward refs.
ClaimsValidator: TypeAlias = Annotated[
    Any,
    BeforeValidator(_coerce_claims_validator),
]


def _coerce_jwk_set(value: Any) -> JWKSet | JWK | None:
    if value is None or isinstance(value, (JWK, JWKSet)):
        return value
    if isinstance(value, dict):
        if "keys" in value:
            return JWKSet(**value)
        return JWK(**value)
    raise ValueError("Invalid jwk_set")


def _coerce_jwk(value: Any) -> JWK | None:
    if value is None or isinstance(value, JWK):
        return value
    if isinstance(value, dict):
        return JWK(**value)
    raise ValueError("Invalid jwk")


JwkSetField: TypeAlias = Annotated[
    JWKSet | JWK | None,
    BeforeValidator(_coerce_jwk_set),
]
JwkField: TypeAlias = Annotated[JWK | None, BeforeValidator(_coerce_jwk)]


class _ConfigModel(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True, extra="forbid")


class OIDCConfig(_ConfigModel):
    issuer: str
    client_id: str
    client_secret: str
    project_id: str
    organization_id: str
    allowed_client_ids: str | None = None
    allow_registration: bool = False


class JwtConfig(_ConfigModel):
    secret: str | None = None
    keyfile: str | None = None
    algorithm: JwtAlgorithm = "HS512"
    allow_registration: bool = False
    require_expiry: bool = True

    @model_validator(mode="after")
    def validate_secret_or_keyfile(self) -> Self:
        if self.secret is None and self.keyfile is None:
            raise ValueError("Missing secret or keyfile")
        if self.keyfile is not None and not os.path.exists(self.keyfile):
            raise ValueError("Keyfile doesn't exist")
        return self


class JwtValidationConfig(_ConfigModel):
    validator: ClaimsValidator = Field(default_factory=Exist)
    require_expiry: bool = False
    localpart_path: Path | None = None
    user_id_path: Path | None = None
    fq_uid_path: Path | None = None
    displayname_path: Path | None = None
    admin_path: PathList | None = None
    email_path: Path | None = None
    required_scopes: str | list[str] | None = None
    jwk_set: JwkSetField = None
    jwk_file: str | None = None
    jwks_endpoint: str | None = None

    @model_validator(mode="after")
    def load_jwk_set(self) -> Self:
        if self.jwk_set is not None:
            return self
        if self.jwk_file:
            with open(self.jwk_file, "rb") as f:
                self.jwk_set = JWK.from_pem(f.read())
            return self
        if self.jwks_endpoint:
            return self
        raise ValueError("No JWK")


class IntrospectionValidationConfig(_ConfigModel):
    endpoint: str
    validator: ClaimsValidator = Field(default_factory=Exist)
    auth: HttpAuth = Field(default_factory=NoAuth)
    localpart_path: Path | None = None
    user_id_path: Path | None = None
    fq_uid_path: Path | None = None
    displayname_path: Path | None = None
    admin_path: PathList | None = None
    email_path: Path | None = None
    required_scopes: str | list[str] | None = None


class NotifyOnRegistration(_ConfigModel):
    url: str
    auth: HttpAuth = Field(default_factory=NoAuth)
    interrupt_on_error: bool = True


class OAuthConfig(_ConfigModel):
    jwt_validation: JwtValidationConfig | None = None
    introspection_validation: IntrospectionValidationConfig | None = None
    username_type: UsernameType | None = None
    notify_on_registration: NotifyOnRegistration | None = None
    expose_metadata_resource: Any = None
    registration_enabled: bool = False
    check_external_id: bool = True

    @model_validator(mode="after")
    def require_validation_backend(self) -> Self:
        if not (self.jwt_validation or self.introspection_validation):
            raise ValueError(
                "Neither jwt_validation nor introspection_validation was specified"
            )
        return self


class EPaConfig(_ConfigModel):
    iss: str
    resource_id: str
    validator: ClaimsValidator = Field(default_factory=Exist)
    expose_metadata_resource: Any = None
    registration_enabled: bool = False
    enc_jwk: JwkField = None
    enc_jwk_file: str | None = None
    enc_jwks_endpoint: str = "/.well-known/jwks.json"
    jwk_set: JwkSetField = None
    jwk_file: str | None = None
    jwks_endpoint: str | None = None
    localpart_path: str | None = None
    displayname_path: str | None = None
    lowercase_localpart: bool = False

    @model_validator(mode="after")
    def load_keys(self) -> Self:
        if self.enc_jwk is None:
            if self.enc_jwk_file:
                with open(self.enc_jwk_file, "rb") as f:
                    self.enc_jwk = JWK.from_pem(f.read())
            else:
                raise ValueError("No encryption JWK")

        if self.jwk_set is None:
            if self.jwk_file:
                with open(self.jwk_file, "rb") as f:
                    self.jwk_set = JWK.from_pem(f.read())
            elif not self.jwks_endpoint:
                raise ValueError("No JWK")
        return self


class TokenAuthenticatorConfig(_ConfigModel):
    """Parses and validates the provided config dictionary."""

    model_config = ConfigDict(arbitrary_types_allowed=True, extra="ignore")

    jwt: JwtConfig | None = None
    oidc: OIDCConfig | None = None
    oauth: OAuthConfig | None = None
    epa: EPaConfig | None = None

    def __init__(self, config: dict[str, Any] | None = None, **data: Any):
        if config is not None:
            super().__init__(**config)
        else:
            super().__init__(**data)
