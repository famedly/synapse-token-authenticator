from dataclasses import dataclass, field
from typing import Any, List, Literal, TypeAlias, Union

from jwcrypto.jwk import JWK, JWKSet
from synapse.config import ConfigError

from synapse_token_authenticator.claims_validator import (
    Exist,
    Validator,
    parse_validator,
)
from synapse_token_authenticator.types import (
    Path,
    PathList,
)
from synapse_token_authenticator.utils import basic_auth, bearer_auth


@dataclass
class NoAuth:
    def header_map(self):
        return {}


@dataclass
class BasicAuth:
    username: str
    password: str

    def header_map(self):
        return basic_auth(self.username, self.password)


@dataclass
class BearerAuth:
    token: str

    def header_map(self):
        return bearer_auth(self.token)


HttpAuth: TypeAlias = Union[BasicAuth, BearerAuth, NoAuth]


class JwtConfig:
    def __init__(self, other: dict):
        self.secret: str | None = other.get("secret")
        self.keyfile: str | None = other.get("keyfile")
        if not self.secret and not self.keyfile:
            raise ConfigError("Must have either secret or keyfile in JWT configuration")
        self.algorithm: str = other.get("algorithm", "HS512")
        self.allow_registration: bool = other.get("allow_registration", False)
        self.require_expiry: bool = other.get("require_expiry", True)


class OIDCConfig:
    def __init__(self, other: dict):
        try:
            self.issuer: str = other["issuer"]
            self.client_id: str = other["client_id"]
            self.client_secret: str = other["client_secret"]
            self.project_id: str = other["project_id"]
            self.organization_id: str = other["organization_id"]
        except KeyError as error:
            raise Exception(f"Config option must be set: {error.args[0]}")

        self.allowed_client_ids: str | None = other.get("allowed_client_ids")

        self.allow_registration: bool = other.get("allow_registration", False)


@dataclass
class JwtValidationConfig:
    validator: Validator = field(default_factory=Exist)
    require_expiry: bool = False
    localpart_path: Path | None = None
    user_id_path: Path | None = None
    fq_uid_path: Path | None = None
    displayname_path: Path | None = None
    admin_path: PathList | None = None
    email_path: Path | None = None
    required_scopes: str | List[str] | None = None
    jwk_set: JWKSet | JWK | None = None
    jwk_file: str | None = None
    jwks_endpoint: str | None = None

    def __post_init__(self):
        if not isinstance(self.validator, Exist):
            self.validator = parse_validator(self.validator)

        if self.jwk_set and ("keys" in self.jwk_set):
            self.jwk_set = JWKSet(**self.jwk_set)
        elif self.jwk_set:
            self.jwk_set = JWK(**self.jwk_set)
        elif self.jwk_file:
            with open(self.jwk_file) as f:
                self.jwk_set = JWK.from_pem(f.read())
        elif not self.jwks_endpoint:
            raise Exception("No JWK")


@dataclass
class IntrospectionValidationConfig:
    endpoint: str
    validator: Validator = field(default_factory=Exist)
    auth: HttpAuth = field(default_factory=NoAuth)
    localpart_path: Path | None = None
    user_id_path: Path | None = None
    fq_uid_path: Path | None = None
    displayname_path: Path | None = None
    admin_path: PathList | None = None
    email_path: Path | None = None
    required_scopes: str | List[str] | None = None

    def __post_init__(self):
        if not isinstance(self.validator, Exist):
            self.validator = parse_validator(self.validator)

        if not isinstance(self.auth, NoAuth):
            self.auth = parse_auth(self.auth)


@dataclass
class NotifyOnRegistration:
    url: str
    auth: HttpAuth = field(default_factory=NoAuth)
    interrupt_on_error: bool = True

    def __post_init__(self):
        if not isinstance(self.auth, NoAuth):
            self.auth = parse_auth(self.auth)


@dataclass
class OAuthConfig:
    jwt_validation: JwtValidationConfig | None = None
    introspection_validation: IntrospectionValidationConfig | None = None
    username_type: Literal["fq_uid", "localpart", "user_id"] | None = None
    notify_on_registration: NotifyOnRegistration | None = None
    expose_metadata_resource: Any = None
    registration_enabled: bool = False
    check_external_id: bool = True

    def __post_init__(self):
        if self.notify_on_registration:
            self.notify_on_registration = NotifyOnRegistration(
                **self.notify_on_registration
            )
        if self.jwt_validation:
            self.jwt_validation = JwtValidationConfig(**(self.jwt_validation))
        if self.introspection_validation:
            self.introspection_validation = IntrospectionValidationConfig(
                **self.introspection_validation
            )
        if not (self.jwt_validation or self.introspection_validation):
            raise Exception(
                "Neither jwt_validation nor introspection_validation was specified"
            )
        if self.username_type not in [
            "fq_uid",
            "localpart",
            "user_id",
            None,
        ]:
            raise Exception(f"Unknown username_type {self.username_type}")


@dataclass
class EPaConfig:
    iss: str
    resource_id: str
    validator: Validator = field(default_factory=Exist)
    expose_metadata_resource: Any = None
    registration_enabled: bool = False
    enc_jwk: JWK | None = None
    enc_jwk_file: str | None = None
    enc_jwks_endpoint: str = "/.well-known/jwks.json"
    jwk_set: JWKSet | JWK | None = None
    jwk_file: str | None = None
    jwks_endpoint: str | None = None
    localpart_path: str | None = None
    displayname_path: str | None = None
    lowercase_localpart: bool = False

    def __post_init__(self):
        if not isinstance(self.validator, Exist):
            self.validator = parse_validator(self.validator)

        if self.enc_jwk:
            self.enc_jwk = JWK(**self.enc_jwk)
        elif self.enc_jwk_file:
            with open(self.enc_jwk_file) as f:
                self.enc_jwk = JWK.from_pem(f.read())
        else:
            raise Exception("No encryption JWK")

        if self.jwk_set and ("keys" in self.jwk_set):
            self.jwk_set = JWKSet(**self.jwk_set)
        elif self.jwk_set:
            self.jwk_set = JWK(**self.jwk_set)
        elif self.jwk_file:
            with open(self.jwk_file) as f:
                self.jwk_set = JWK.from_pem(f.read())
        elif not self.jwks_endpoint:
            raise Exception("No JWK")


def parse_auth(d: dict) -> HttpAuth:
    if isinstance(d, dict):
        type = d.pop("type")
        if type is None:
            return NoAuth()
        elif type == "basic":
            return BasicAuth(**d)
        elif type == "bearer":
            return BearerAuth(**d)
        else:
            raise Exception(f"Unknown HttpAuth type {type}")
    elif isinstance(d, list):
        type = d.pop(0)
        if type is None:
            return NoAuth()
        elif type == "basic":
            return BasicAuth(*d)
        elif type == "bearer":
            return BearerAuth(*d)
        else:
            raise Exception(f"Unknown HttpAuth type {type}")
    else:
        raise Exception("HttpAuth parsing failed, expected list or dict")
