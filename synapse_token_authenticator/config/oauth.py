import json
from typing import Any, Literal, Self, TypeAlias

from jwcrypto.jwk import JWK, JWKSet
from pydantic import (
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)
from pydantic.dataclasses import dataclass
from synapse.types import JsonDict

from synapse_token_authenticator.claims_validator import (
    Exist,
    Validator,
    parse_validator,
)
from synapse_token_authenticator.http_auth import (
    HttpAuth,
    NoAuth,
    parse_auth,
)
from synapse_token_authenticator.utils import ClaimsMismatchError, get_path_in_dict

Path: TypeAlias = str | list[str]
PathList: TypeAlias = Path | list[list[str]]


# To prevent breaking changes, we allow extra fields.
@dataclass(config=ConfigDict(arbitrary_types_allowed=True, extra="ignore"))
class JwtValidationConfig:
    validator: Validator = Field(default_factory=Exist)
    # We recommend using the default value of True for require_expiry like in JWT
    # Config, but we keep it to False for backwards compatibility with existing config.
    require_expiry: bool = False
    localpart_path: Path | None = None
    fq_uid_path: Path | None = None
    alternative_fq_uids_path: Path | None = None
    displayname_path: Path | None = None
    admin_path: PathList | None = None
    email_path: Path | None = None
    required_scopes: str | list[str] | None = None
    jwk_set: JWKSet | JWK | None = None
    jwk_file: str | None = Field(default=None, min_length=1)
    jwks_endpoint: str | None = Field(default=None, min_length=1)

    @field_validator("validator", mode="before")
    @classmethod
    def coerce_validator(cls, value: Any) -> Validator:
        if not isinstance(value, Exist):
            return parse_validator(value)
        return value

    @field_validator("jwk_set", mode="before")
    @classmethod
    def parse_jwk_set(cls, value: Any) -> JWKSet | JWK | None:
        if value is None:
            return None
        if isinstance(value, (JWKSet, JWK)):
            return value
        if isinstance(value, str):
            if json.loads(value).get("keys"):
                return JWKSet.from_json(value)
            else:
                return JWK.from_json(value)
        if isinstance(value, dict):
            if "keys" in value:
                return JWKSet.from_json(json.dumps(value))
            else:
                return JWK(**value)
        return None

    @model_validator(mode="after")
    def decide_jwk_set(self) -> Self:
        sources = [
            self.jwk_set is not None,
            self.jwk_file is not None,
            self.jwks_endpoint is not None,
        ]
        if sum(sources) == 1:
            if self.jwk_set:
                return self
            elif self.jwk_file:
                try:
                    with open(self.jwk_file, "rb") as f:
                        self.jwk_set = JWK.from_pem(f.read())
                        return self
                except FileNotFoundError:
                    raise ValueError(f"jwk_file '{self.jwk_file}' not found")
            elif self.jwks_endpoint:
                return self
        raise ValueError(
            "Exactly one of jwk_set, jwk_file, or jwks_endpoint must be set"
        )

    @model_validator(mode="after")
    def validate_alternative_fq_uids_path_option_is_viable(self) -> Self:
        # Static methods can not return Self, since no class is passed in. This will either raise or move on and return
        # self appropriately here.
        validate_alternative_fq_uids_path_option_is_viable(
            self.alternative_fq_uids_path, self.localpart_path, self.fq_uid_path
        )
        return self


@dataclass(config=ConfigDict(arbitrary_types_allowed=True, extra="ignore"))
class IntrospectionValidationConfig:
    endpoint: str
    validator: Validator = Field(default_factory=Exist)
    auth: HttpAuth = Field(default_factory=NoAuth)
    localpart_path: Path | None = None
    fq_uid_path: Path | None = None
    alternative_fq_uids_path: Path | None = None
    displayname_path: Path | None = None
    admin_path: PathList | None = None
    email_path: Path | None = None
    required_scopes: str | list[str] | None = None

    @field_validator("validator", mode="before")
    @classmethod
    def coerce_validator(cls, value: Any) -> Validator:
        if not isinstance(value, Exist):
            return parse_validator(value)
        return value

    @field_validator("auth", mode="before")
    @classmethod
    def coerce_auth(cls, value: Any) -> HttpAuth:
        return parse_auth(value, context=cls.__name__)

    @model_validator(mode="after")
    def validate_alternative_fq_uids_path_option_is_viable(self) -> Self:
        # Static methods can not return Self, since no class is passed in. This will either raise or move on and return
        # self appropriately here.
        validate_alternative_fq_uids_path_option_is_viable(
            self.alternative_fq_uids_path, self.localpart_path, self.fq_uid_path
        )
        return self


@dataclass(config=ConfigDict(arbitrary_types_allowed=True, extra="ignore"))
class NotifyOnRegistration:
    url: str
    auth: HttpAuth = Field(default_factory=NoAuth)
    interrupt_on_error: bool = True

    @field_validator("auth", mode="before")
    @classmethod
    def coerce_auth(cls, value: Any) -> HttpAuth:
        return parse_auth(value, context=cls.__name__)


@dataclass(config=ConfigDict(arbitrary_types_allowed=True, extra="ignore"))
class OAuthConfig:
    jwt_validation: JwtValidationConfig | None = None
    introspection_validation: IntrospectionValidationConfig | None = None
    username_type: Literal["fq_uid", "localpart", "user_id"] | None = None
    notify_on_registration: NotifyOnRegistration | None = None
    expose_metadata_resource: dict | None = None
    registration_enabled: bool = False
    check_external_id: bool = True

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

    @model_validator(mode="after")
    def validate_notify_on_registration(self) -> Self:
        if not (self.jwt_validation or self.introspection_validation):
            raise ValueError(
                "Neither jwt_validation nor introspection_validation was specified"
            )
        return self

    @model_validator(mode="after")
    def ensure_alternate_fq_uids_paths_do_not_counter_other_paths(self) -> Self:
        # Since both the JWT and Introspection validation sections can contain alternative_fq_uids_path and the other
        # user id related paths, make sure they do not co-exist between the classes. This currently constitutes
        # undefined behavior as the resolution order has not been fully worked out.
        #
        # Clashing values on same validation sections are checked on each respective class.
        if not (self.jwt_validation and self.introspection_validation):
            # If both of these validation subtypes are not defined, then nothing else to do here
            return self

        if (
            # both should not be cross defined
            (
                self.jwt_validation.alternative_fq_uids_path
                and (
                    self.introspection_validation.localpart_path
                    or self.introspection_validation.fq_uid_path
                )
            )
            or (
                self.introspection_validation.alternative_fq_uids_path
                and (
                    self.jwt_validation.localpart_path
                    or self.jwt_validation.fq_uid_path
                )
            )
        ):
            raise ValueError(
                "Cannot have `alternative_fq_uids_path` defined on one form of validation with the other using a different `*_path`-like option."
            )
        return self

    def should_use_alternative_fq_uids(self) -> bool:
        """Simple bool for deciding to check for alternative fq user ids"""
        return bool(
            (self.jwt_validation and self.jwt_validation.alternative_fq_uids_path)
            or (
                self.introspection_validation
                and self.introspection_validation.alternative_fq_uids_path
            )
        )

    def search_claims_for_alternative_fq_uid(
        self, value: str, jwt_claims_dict: JsonDict, intro_claims_dict: JsonDict
    ) -> str | None:
        """
        Check both jwt and introspection claims for the list at the end of the alternative_fq_uids_path. If the claim
        has no data, return None. If the value is not in found in either claim list found at validation path, raise
        ClaimMismatchError. If it exists in either/or both claim list(s) return the value.
        So:
        exist in both lists: return value
        neither list exists: return None
        exists in one list but other list does not exist: return value
        either list exists, but the value is not present: raise ClaimMismatchError
        """
        # These results will either be the same as value, or will be None. No other options(as they would have raised
        # the ClaimMismatchError exception)
        jwt_result = resolve_value_in_claim_list(
            value, jwt_claims_dict, "Jwt", self.jwt_validation
        )
        intro_result = resolve_value_in_claim_list(
            value, intro_claims_dict, "Introspection", self.introspection_validation
        )
        # Both are the same as value, or one or both of them is None. Add them to a set then discard None and the
        # remainder is the value. If there was no found value, it means that neither claims existed and there was
        # nothing to find, so the returned value is None
        consolidated = {jwt_result, intro_result}
        consolidated.discard(None)
        return value if len(consolidated) == 1 else None


def resolve_value_in_claim_list(
    value: str,
    claims_dict: dict,
    context_str: str,
    validation_class: IntrospectionValidationConfig | JwtValidationConfig | None,
) -> str | None:
    """
    From a given claims_dict, follow the path to where the claim list is supposed to be. If it exists, and the value
    is present in that list, return the value. If the claim list does not exist, return None.

    These returns and raises feel strange, but maintain the existing contract of how the rest of the validation
    is done.
    """
    if validation_class is None or (
        validation_class and not validation_class.alternative_fq_uids_path
    ):
        return None

    # mypy seems to think that the path can be None here, even with the `not` in the condition above
    assert validation_class.alternative_fq_uids_path is not None

    claim = get_path_in_dict(validation_class.alternative_fq_uids_path, claims_dict)
    if claim is None:
        return None

    # if this is not a list, then the claim was messed up as it is supposed to be a list. Guard this so the other side
    # can find out they messed up.
    if not isinstance(claim, list):
        raise TypeError(
            f"{context_str} Claim referenced from `alternative_fq_uids_path` must be in the form of a list"
        )

    if value in claim:
        return value
    raise ClaimsMismatchError(
        f"{context_str} Claim List did not contain expected value: {value}"
    )


def validate_alternative_fq_uids_path_option_is_viable(
    alternative_fq_uids_path: Path | None = None,
    localpart_path: Path | None = None,
    fq_uid_path: Path | None = None,
) -> bool:
    # Guard for an empty list if the value is present. Borrow that a falsey value can work both for an empty list
    # and an empty string, but exclude None because it is a valid option.
    if not alternative_fq_uids_path and alternative_fq_uids_path is not None:
        raise ValueError(
            "alternative_fq_uids_path must not be empty or must be omitted"
        )
    if alternative_fq_uids_path and (localpart_path or fq_uid_path):
        raise ValueError(
            "localpart_path and/or user_id_path cannot be used with alternative_fq_uids_path"
        )
    return True
