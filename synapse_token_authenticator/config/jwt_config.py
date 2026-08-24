import os
from typing import Self

from pydantic import Field, model_validator

from synapse_token_authenticator.config.base import BaseConfigModel, JwtAlgorithm


class JwtConfig(BaseConfigModel):

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
