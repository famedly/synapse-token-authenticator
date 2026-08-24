from typing import Any, Self

from jwcrypto.jwk import JWK
from pydantic import model_validator

from synapse_token_authenticator.config_util.base import (
    JwkField,
    JwkSetField,
    JwkSource,
    Path,
    ValidatorMapping,
)


class EPaConfig(ValidatorMapping, JwkSource):
    iss: str
    resource_id: str
    expose_metadata_resource: Any = None
    registration_enabled: bool = False
    enc_jwk: JwkField = None
    enc_jwk_file: str | None = None
    enc_jwks_endpoint: str = "/.well-known/jwks.json"
    jwk_set: JwkSetField = None
    jwk_file: str | None = None
    jwks_endpoint: str | None = None
    localpart_path: Path | None = None
    displayname_path: Path | None = None
    lowercase_localpart: bool = False

    @model_validator(mode="after")
    def load_keys(self) -> Self:
        if not self.enc_jwk and self.enc_jwk_file:
            with open(self.enc_jwk_file, "rb") as f:
                self.enc_jwk = JWK.from_pem(f.read())
        if not self.enc_jwk:
            raise ValueError("No encryption JWK")
        return self
