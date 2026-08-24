from typing import Any, Self, TypeAlias

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

Path: TypeAlias = str | list[str]


class EPaConfig(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True, extra="forbid")

    iss: str
    resource_id: str
    validator: Validator = Field(
        default_factory=Exist,
    )
    expose_metadata_resource: Any = None
    registration_enabled: bool = False
    enc_jwk: JWK | None = None
    enc_jwk_file: str | None = None
    enc_jwks_endpoint: str = "/.well-known/jwks.json"
    jwk_set: JWKSet | JWK | None = None
    jwk_file: str | None = None
    jwks_endpoint: str | None = None
    localpart_path: Path | None = None
    displayname_path: Path | None = None
    lowercase_localpart: bool = False

    @field_validator("validator", mode="before")
    @classmethod
    def validate_validator(cls, v: Any) -> Validator:
        if not isinstance(v, Exist):
            return parse_validator(v)
        return v

    @model_validator(mode="after")
    def load_keys(self) -> Self:
        if self.enc_jwk_file:
            with open(self.enc_jwk_file, "rb") as f:
                self.enc_jwk = JWK.from_pem(f.read())
        if not self.enc_jwk or not self.enc_jwk_file:
            raise ValueError("No encryption JWK")

        if self.jwk_file:
            with open(self.jwk_file, "rb") as f:
                self.jwk_set = JWK.from_pem(f.read())
        if not self.jwk_set or not self.jwk_file or not self.jwks_endpoint:
            raise ValueError("No JWK")
        return self
