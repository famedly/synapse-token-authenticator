import json
from typing import Any, Self, TypeAlias

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

Path: TypeAlias = str | list[str]


# To prevent breaking changes, we allow extra fields.
@dataclass(config=ConfigDict(arbitrary_types_allowed=True, extra="ignore"))
class EPaConfig:
    iss: str = Field(min_length=1)
    resource_id: str = Field(min_length=1)
    validator: Validator = Field(default_factory=Exist)
    expose_metadata_resource: dict | None = None
    registration_enabled: bool = False
    enc_jwk: JWK | None = None
    enc_jwk_file: str | None = Field(default=None, min_length=1)
    enc_jwks_endpoint: str = "/.well-known/jwks.json"
    jwk_set: JWKSet | JWK | None = None
    jwk_file: str | None = Field(default=None, min_length=1)
    jwks_endpoint: str | None = Field(default=None, min_length=1)
    localpart_path: Path | None = None
    displayname_path: Path | None = None
    lowercase_localpart: bool = False

    @field_validator("validator", mode="before")
    @classmethod
    def coerce_validator(cls, value: Any) -> Validator:
        if not isinstance(value, Exist):
            return parse_validator(value)
        return value

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

    @field_validator("enc_jwk", mode="before")
    @classmethod
    def parse_enc_jwk(cls, value: Any) -> JWK | None:
        if value is None:
            return None
        if isinstance(value, JWK):
            return value
        if isinstance(value, dict):
            return JWK(**value)
        return None

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
    def decide_enc_jwk(self) -> Self:
        if self.enc_jwk:
            return self
        elif self.enc_jwk_file:
            with open(self.enc_jwk_file, "rb") as f:
                self.enc_jwk = JWK.from_pem(f.read())
                return self
        else:
            raise ValueError("No encryption JWK")

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
