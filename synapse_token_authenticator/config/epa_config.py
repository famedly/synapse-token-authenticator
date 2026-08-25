from typing import Annotated, Any, Self

from jwcrypto.jwk import JWK
from pydantic import BeforeValidator, model_validator

from synapse_token_authenticator.config.base import (
    JwkSetField,
    JwkSource,
    Path,
    ValidatorMapping,
)


def _coerce_jwk(value: JWK | dict | None) -> JWK | None:
    if not value:
        return None
    if isinstance(value, JWK):
        return value
    if value and isinstance(value, dict):
        return JWK(**value)
    raise ValueError("Invalid jwk")


JwkField = Annotated[JWK | None, BeforeValidator(_coerce_jwk)]


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
    def resolve_enc_jwk_source(self) -> Self:
        if not self.enc_jwk and self.enc_jwk_file:
            with open(self.enc_jwk_file, "rb") as f:
                self.enc_jwk = JWK.from_pem(f.read())
        if not self.enc_jwk:
            raise ValueError("No encryption JWK")
        return self
