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
from synapse_token_authenticator.utils import get_path_in_dict

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
        # Guard for an empty list if the value is present. Borrow that a falsey value can work both for an empty list
        # and an empty string, but exclude None because it is a valid option.
        if (
            not self.alternative_fq_uids_path
            and self.alternative_fq_uids_path is not None
        ):
            raise ValueError(
                "alternative_fq_uids_path must not be empty or must be omitted"
            )
        if self.alternative_fq_uids_path and (self.localpart_path or self.fq_uid_path):
            raise ValueError(
                "localpart_path and/or user_id_path cannot be used with alternative_fq_uids_path"
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
        # Guard for an empty list if the value is present. Borrow that a falsey value can work both for an empty list
        # and an empty string, but exclude None because it is a valid option.
        if (
            not self.alternative_fq_uids_path
            and self.alternative_fq_uids_path is not None
        ):
            raise ValueError(
                "alternative_fq_uids_path must not be empty or must be omitted"
            )
        if self.alternative_fq_uids_path and (self.localpart_path or self.fq_uid_path):
            raise ValueError(
                "localpart_path and/or user_id_path cannot be used with alternative_fq_uids_path"
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
    def ensure_alternate_fq_uid_paths_do_not_counter_other_paths(self) -> Self:
        # Since both the JWT and Introspection validation sections can contain alternative_fq_uids_path and the other
        # user id related paths, make sure they do not co-exist between the classes. This currently constitutes
        # undefined behavior as the resolution order has not been fully worked out.
        #
        # Clashing values on same validation sections are checked on each respective class.

        if (
            # both have to exist
            self.jwt_validation
            and self.introspection_validation
            # but, both should not be cross defined
            and (
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
            )
        ):
            raise ValueError(
                "Cannot have `alternative_fq_uid_path` defined on one form of validation with the other using a different `*_path`-like option."
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

    def get_value_in_jwt_claim_for_alternative_fq_uid_path_or_none(
        self, value: str, claims_dict: dict
    ) -> str | None:
        """If the value is in the claims object at the alternative_fq_uid_path, return the value or None if it is not"""
        if not self.jwt_validation or (
            self.jwt_validation and not self.jwt_validation.alternative_fq_uids_path
        ):
            return None

        # mypy seems to think that alternative_fq_uids_path can be None here
        assert self.jwt_validation.alternative_fq_uids_path is not None
        claim = get_path_in_dict(
            self.jwt_validation.alternative_fq_uids_path, claims_dict
        )
        if claim is None:
            return None

        # if this is not a list, then the claim was messed up as it is supposed to be a list
        assert isinstance(
            claim, list
        ), "Jwt claim for `alternative_fq_uid_path` must be a list"

        return value if value in claim else None

    def get_value_in_introspection_claim_for_alternative_fq_uid_path_or_none(
        self, value: str, claims_dict: dict
    ) -> str | None:
        """If the value is in the claims object at the alternative_fq_uid_path, return the value or None if it is not"""
        if not self.introspection_validation or (
            self.introspection_validation
            and not self.introspection_validation.alternative_fq_uids_path
        ):
            return None

        # mypy seems to think that alternative_fq_uids_path can be None here
        assert self.introspection_validation.alternative_fq_uids_path is not None
        claim = get_path_in_dict(
            self.introspection_validation.alternative_fq_uids_path, claims_dict
        )
        if claim is None:
            return None

        # if this is not a list, then the claim was messed up as it is supposed to be a list
        assert isinstance(
            claim, list
        ), "Introspection claim for `alternative_fq_uid_path` must be a list"

        return value if value in claim else None
