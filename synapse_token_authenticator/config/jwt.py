import os
from typing import Literal, Self, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, model_validator

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


class JwtConfig(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True, extra="forbid")

    secret: str | None = None
    keyfile: str | None = None
    algorithm: JwtAlgorithm = Field(default="HS512")
    allow_registration: bool = False
    require_expiry: bool = True

    @model_validator(mode="after")
    def validate_secret_or_keyfile(self) -> Self:
        if not (self.secret or self.keyfile):
            raise ValueError("Missing secret or keyfile")
        if self.keyfile and not os.path.exists(self.keyfile):
            raise ValueError("Keyfile doesn't exist")
        return self
