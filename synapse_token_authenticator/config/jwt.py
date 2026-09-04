import os
from typing import Any, Self

from pydantic import (
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)
from pydantic.dataclasses import dataclass


# To prevent breaking changes, we allow extra fields.
@dataclass(config=ConfigDict(arbitrary_types_allowed=True, extra="ignore"))
class JwtConfig:
    secret: str | None = Field(default=None, min_length=1)
    keyfile: str | None = Field(default=None, min_length=1)
    algorithm: str = "HS512"
    allow_registration: bool = False
    require_expiry: bool = True

    @field_validator("algorithm", mode="before")
    @classmethod
    def validate_algorithm(cls, value: Any) -> str:
        if value not in [
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
            raise ValueError(f"Unknown algorithm: '{value}'")
        return value

    @model_validator(mode="after")
    def validate_secret_and_keyfile(self) -> Self:
        if self.secret is None and self.keyfile is None:
            raise ValueError("Missing secret or keyfile")
        if self.keyfile is not None and not os.path.exists(self.keyfile):
            raise ValueError("Keyfile doesn't exist")
        return self
