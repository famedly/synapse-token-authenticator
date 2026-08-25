import json
from typing import Annotated, Any, Literal, Self, TypeAlias

from jwcrypto.jwk import JWK, InvalidJWKType, InvalidJWKValue, JWKSet
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


def _coerce_jwk_set(value: Any) -> JWKSet | JWK | None:
    if value is None:
        return None
    # JWK and JWKSet is also dict. Handle before the plain-dict branch.
    if isinstance(value, (JWK, JWKSet)):
        return value
    try:
        if isinstance(value, str):
            # Pre-parse the JSON to find out if a "keys" object exists(Not a substring
            # match on "keys"). `from_json()` re-parses the JSON and builds JWK objects.
            data = json.loads(value)
            if "keys" in data:
                return JWKSet.from_json(value)
            return JWK.from_json(value)
        if isinstance(value, dict):
            # JWK(**{}) succeeds but is not a usable key. Reject empty config.
            if not value:
                raise ValueError("Invalid jwk_set")
            if "keys" in value:
                # from_json accepts RFC list-of-dicts (and {"keys": []}); JWKSet(**)
                # does not.
                return JWKSet.from_json(json.dumps(value))
            return JWK(**value)
    except ValueError:
        raise
    except (InvalidJWKValue, InvalidJWKType, json.JSONDecodeError, TypeError) as e:
        raise ValueError("Invalid jwk_set") from e
    raise ValueError("Invalid jwk_set")


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
        # Use identity, not truthiness: empty JWKSet is a valid explicit jwk_set.
        if self.jwk_set is not None:
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


class ExposeMetadataResource(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str
