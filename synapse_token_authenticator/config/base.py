import json
from typing import Annotated, Any, Literal, Self, TypeAlias, cast

from jwcrypto.jwk import JWK, JWKSet
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, model_validator

from synapse_token_authenticator.claims_validator import (
    AllOf,
    AnyOf,
    Equal,
    Exist,
    In,
    ListAllOf,
    ListAnyOf,
    MatchesRegex,
    Not,
    Validator,
)

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
    model_config = ConfigDict(arbitrary_types_allowed=True, extra="ignore")


VALIDATOR_CLASS_MAP = {
    "exist": Exist,
    "not": Not,
    "equal": Equal,
    "regex": MatchesRegex,
    "any_of": AnyOf,
    "all_of": AllOf,
    "in": In,
    "list_any_of": ListAnyOf,
    "list_all_of": ListAllOf,
}


def _coerce_validator(d: Validator | dict | list) -> Validator:
    # This does not use parse_validator from claims_validator.py because it consumes the
    # validator object.
    if isinstance(
        d, (Exist, Not, Equal, MatchesRegex, AnyOf, AllOf, In, ListAnyOf, ListAllOf)
    ):
        return d

    if isinstance(d, dict):
        val_type = d.get("type")
        if not val_type:
            raise ValueError("Missing field 'type' for validator")
        validator_class = VALIDATOR_CLASS_MAP.get(val_type)
        if not validator_class:
            raise ValueError(f"Unknown validator type {val_type}")
        kwargs = {k: v for k, v in d.items() if k != "type"}
        try:
            return validator_class(**kwargs)
        except TypeError as e:
            raise ValueError("Invalid validator definition") from e
    elif isinstance(d, list):
        if not d:
            raise ValueError("Missing field 'type' for validator")
        val_type, *args = d
        validator_class = VALIDATOR_CLASS_MAP.get(val_type)
        if not validator_class:
            raise ValueError(f"Unknown validator type {val_type}")
        try:
            return validator_class(*args)
        except TypeError as e:
            raise ValueError("Invalid validator definition") from e
    else:
        raise ValueError(  # noqa: TRY004
            "Validator parsing failed, expected list or dict"
        )


ValidatorField = Annotated[Validator, BeforeValidator(_coerce_validator)]


class ValidatorMapping(BaseConfigModel):
    validator: ValidatorField = Field(default_factory=Exist)


def _coerce_jwk_set(value: str | dict | JWK | JWKSet | None) -> JWKSet | JWK | None:
    if not value:
        return None
    if isinstance(value, str):
        # Pre-parse the JSON to find out if a "keys" object is properly inside. Using a
        # substring match on "keys" may yield incorrect results if the actual word
        # "keys" was part of something else. Unfortunately, can not then dump that
        # pre-parsed JSON right into the JWKSet itself, as further subprocessing of the
        # JSON loads the correct JWK objects for us.
        if "keys" in json.loads(value):
            return JWKSet.from_json(value)
        return JWK.from_json(value)
    if isinstance(value, (JWK, JWKSet)):
        return value
    if isinstance(value, dict):
        # mypy keeps JWK|JWKSet in the union because they subclass dict.
        data = cast(dict[str, Any], value)
        if "keys" in data:
            return JWKSet(**data)
        return JWK(**data)


JwkSetField = Annotated[JWKSet | JWK | None, BeforeValidator(_coerce_jwk_set)]


class JwkSource(BaseConfigModel):
    # JwkSetField already includes `| None` (see Annotated above), so this is optional
    # without writing `JwkSetField | None`. Default None is intentional: config may only
    # provide jwks_endpoint, in which case resolve_jwk leaves jwk_set unset and the
    # oauth/epa auth checkers fetch+decode the JWKS on each login and assign jwk_set
    # then. That requires a mutable model (not frozen).
    jwk_set: JwkSetField = None
    jwk_file: str | None = None
    jwks_endpoint: str | None = None

    @model_validator(mode="after")
    def resolve_jwk_source(self) -> Self:
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
