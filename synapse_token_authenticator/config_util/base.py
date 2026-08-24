from typing import Annotated, Any, Literal, Self, TypeAlias

from jwcrypto.jwk import JWK, JWKSet
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, model_validator

from synapse_token_authenticator.claims_validator import Exist, parse_validator

Path: TypeAlias = str | list[str]
PathList: TypeAlias = Path | list[list[str]]
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
UsernameType: TypeAlias = Literal["fq_uid", "localpart", "user_id"]


class BaseConfigModel(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True, extra="forbid")


# Use Any so Pydantic does not try to resolve claims_validator forward refs (Exist, Not, ...).
ValidatorField = Annotated[Any, BeforeValidator(parse_validator)]


class ValidatorMapping(BaseConfigModel):
    validator: ValidatorField = Field(default_factory=Exist)


def _coerce_jwk_set(value: Any) -> JWKSet | JWK | None:
    if not value:
        return None
    if isinstance(value, dict) and value.get("keys"):
        return JWKSet(**value)
    elif isinstance(value, dict):
        return JWK(**value)
    elif "keys" in value:
        return JWKSet.from_json(value)
    else:
        return JWK.from_json(value)


def _coerce_jwk(value: Any) -> JWK | None:
    if value is None or isinstance(value, JWK):
        return value
    if value and isinstance(value, dict):
        return JWK(**value)
    raise ValueError("Invalid jwk")


JwkSetField = Annotated[JWKSet | JWK | None, BeforeValidator(_coerce_jwk_set)]
JwkField = Annotated[JWK | None, BeforeValidator(_coerce_jwk)]


class JwkSource(BaseConfigModel):
    jwk_set: JwkSetField = None
    jwk_file: str | None = None
    jwks_endpoint: str | None = None

    @model_validator(mode="after")
    def resolve_jwk(self) -> Self:
        if self.jwk_set:
            return self
        elif self.jwk_file:
            with open(self.jwk_file, "rb") as f:
                self.jwk_set = JWK.from_pem(f.read())
            return self
        elif not self.jwks_endpoint:
            raise ValueError("No JWK")
        return self


class ClaimsMapping(ValidatorMapping):
    localpart_path: Path | None = None
    user_id_path: Path | None = None
    fq_uid_path: Path | None = None
    displayname_path: Path | None = None
    admin_path: PathList | None = None
    email_path: Path | None = None
    required_scopes: str | list[str] | None = None
