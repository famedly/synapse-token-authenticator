import json
from typing import Any, Literal, Self, TypeAlias

from jwcrypto.jwk import JWK, JWKSet
from pydantic import (
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)
from pydantic.dataclasses import dataclass

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


# To prevent breaking changes, we allow extra fields.
@dataclass(config=ConfigDict(arbitrary_types_allowed=True, extra="ignore"))
class JwtValidationConfig:
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
    jwk_file: str | None = Field(default=None, min_length=1)
    jwks_endpoint: str | None = Field(default=None, min_length=1)

    @field_validator("validator", mode="before")
    @classmethod
    def coerce_validator(cls, value: Any) -> Validator:
        if not isinstance(value, Exist):
            return parse_validator(value)
        return value

    @field_validator("jwk_set", mode="before")
    @classmethod
    def parse_jwk_set(cls, value: Any) -> JWKSet | JWK | None:
        if value is None:
            return None
        if isinstance(value, (JWKSet, JWK)):
            return value
        if isinstance(value, str):
            return JWKSet.from_json(value)
        if isinstance(value, dict) and "keys" in value:
            return JWKSet.from_json(json.dumps(value))
        if isinstance(value, dict):
            return JWK(**value)
        return None

    @model_validator(mode="after")
    def decide_jwk_set(self) -> Self:
        if self.jwk_set:
            return self
        elif self.jwk_file:
            with open(self.jwk_file, "rb") as f:
                self.jwk_set = JWK.from_pem(f.read())
                return self
        elif not self.jwks_endpoint:
            raise ValueError("No JWK set")
        return self


@dataclass(config=ConfigDict(arbitrary_types_allowed=True, extra="ignore"))
class IntrospectionValidationConfig:
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

    @field_validator("validator", mode="before")
    @classmethod
    def coerce_validator(cls, value: Any) -> Validator:
        if not isinstance(value, Exist):
            return parse_validator(value)
        return value

    @field_validator("auth", mode="before")
    @classmethod
    def coerce_auth(cls, value: Any) -> HttpAuth:
        return parse_auth(value, context=cls.__name__)


@dataclass(config=ConfigDict(arbitrary_types_allowed=True, extra="ignore"))
class NotifyOnRegistration:
    url: str
    auth: HttpAuth = Field(default_factory=NoAuth)
    interrupt_on_error: bool = True

    @field_validator("auth", mode="before")
    @classmethod
    def coerce_auth(cls, value: Any) -> HttpAuth:
        return parse_auth(value, context=cls.__name__)


@dataclass(config=ConfigDict(arbitrary_types_allowed=True, extra="ignore"))
class OAuthConfig:
    jwt_validation: JwtValidationConfig | None = None
    introspection_validation: IntrospectionValidationConfig | None = None
    username_type: Literal["fq_uid", "localpart", "user_id"] | None = None
    notify_on_registration: NotifyOnRegistration | None = None
    expose_metadata_resource: dict | None = None
    registration_enabled: bool = False
    check_external_id: bool = True

    @field_validator("expose_metadata_resource", mode="after")
    @classmethod
    def validate_expose_metadata_resource(cls, value: Any) -> dict | None:
        if not value:
            return None
        # We assume value is a dict at this point because Pydantic handles validation
        # before this runs. (If a non-dict slips through, that's a Pydantic issue)
        if not value.get("name"):
            raise ValueError("expose_metadata_resource must have a name field")
        return value

    @model_validator(mode="after")
    def validate_notify_on_registration(self) -> Self:
        if not (self.jwt_validation or self.introspection_validation):
            raise ValueError(
                "Neither jwt_validation nor introspection_validation was specified"
            )
        return self
