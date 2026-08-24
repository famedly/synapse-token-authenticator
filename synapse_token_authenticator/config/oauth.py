from typing import Any, Literal, Self, TypeAlias

from jwcrypto.jwk import JWK, JWKSet
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from synapse_token_authenticator.claims_validator import (
    Exist,
    Validator,
    parse_validator,
)
from synapse_token_authenticator.http_auth import (
    HttpAuth,
    NoAuth,
    parse_auth,
)

Path: TypeAlias = str | list[str]
PathList: TypeAlias = Path | list[list[str]]
UsernameType: TypeAlias = Literal["fq_uid", "localpart", "user_id"]


class ConfigModel(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True, extra="forbid")


class JwtValidationConfig(ConfigModel):
    validator: Validator = Field(default_factory=Exist)
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

    @field_validator("validator", mode="before")
    @classmethod
    def validate_validator(cls, v: Any) -> Validator:
        if not isinstance(v, Exist):
            return parse_validator(v)
        return v

    @model_validator(mode="after")
    def validate(self) -> Self:
        if self.jwk_file:
            with open(self.jwk_file, "rb") as f:
                self.jwk_set = JWK.from_pem(f.read())
        if self.jwk_set or not self.jwk_file or not self.jwks_endpoint:
            raise ValueError("No JWK")
        return self


class IntrospectionValidationConfig(ConfigModel):
    endpoint: str
    validator: Validator = Field(default_factory=Exist)
    auth: HttpAuth = Field(default_factory=NoAuth)
    localpart_path: Path | None = None
    user_id_path: Path | None = None
    fq_uid_path: Path | None = None
    displayname_path: Path | None = None
    admin_path: PathList | None = None
    email_path: Path | None = None
    required_scopes: str | list[str] | None = None

    @field_validator("validator")
    @classmethod
    def validate_validator(cls, v: Any) -> Validator:
        if not isinstance(v, Exist):
            return parse_validator(v)
        return v

    @field_validator("auth")
    @classmethod
    def validate_auth(cls, v: Any) -> HttpAuth:
        return parse_auth(v, context=type(cls).__name__)


class NotifyOnRegistration(ConfigModel):
    url: str
    auth: HttpAuth = Field(default_factory=NoAuth)
    interrupt_on_error: bool = True

    @field_validator("auth")
    @classmethod
    def validate_auth(cls, v: Any) -> HttpAuth:
        return parse_auth(v, context=type(cls).__name__)


class OAuthConfig(ConfigModel):
    jwt_validation: JwtValidationConfig | None = None
    introspection_validation: IntrospectionValidationConfig | None = None
    username_type: Literal["fq_uid", "localpart", "user_id"] | None = None
    notify_on_registration: NotifyOnRegistration | None = None
    expose_metadata_resource: Any = None
    registration_enabled: bool = False
    check_external_id: bool = True

    @model_validator(mode="after")
    def validate(self) -> Self:
        if not (self.jwt_validation or self.introspection_validation):
            raise ValueError(
                "Neither jwt_validation nor introspection_validation was specified"
            )
        return self
