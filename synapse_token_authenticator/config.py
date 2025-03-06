import os
from dataclasses import dataclass, field
from typing import List, Literal, Union, TypeAlias, Any
from jwcrypto.jwk import JWK, JWKSet
from synapse_token_authenticator.claims_validator import (
    parse_validator,
    Validator,
    Exist,
)
from synapse_token_authenticator.utils import bearer_auth, basic_auth


class TokenAuthenticatorConfig:
    """
    Parses and validates the provided config dictionary.
    """

    def __init__(self, other: dict):
        if jwt := other.get("jwt"):

            class JwtConfig:
                def __init__(self, other: dict):
                    self.secret: str | None = other.get("secret")
                    self.keyfile: str | None = other.get("keyfile")

                    self.algorithm: str = other.get("algorithm", "HS512")
                    self.allow_registration: bool = other.get(
                        "allow_registration", False
                    )
                    self.require_expiry: bool = other.get("require_expiry", True)

            self.jwt = JwtConfig(jwt)
            verify_jwt_based_cfg(self.jwt)

        if oidc := other.get("oidc"):

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

                    self.allowed_client_ids: str | None = other.get(
                        "allowed_client_ids"
                    )

                    self.allow_registration: bool = other.get(
                        "allow_registration", False
                    )

            self.oidc = OIDCConfig(oidc)

        if config := other.get("oauth"):

            Path: TypeAlias = Union[str, List[str]]

            @dataclass
            class JwtValidationConfig:
                validator: Validator = field(default_factory=Exist)
                require_expiry: bool = False
                localpart_path: Path | None = None
                user_id_path: Path | None = None
                fq_uid_path: Path | None = None
                displayname_path: Path | None = None
                admin_path: Path | None = None
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
                admin_path: Path | None = None
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
                        self.jwt_validation = JwtValidationConfig(
                            **(self.jwt_validation)
                        )
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

            self.oauth = OAuthConfig(**config)

        if epa := other.get("epa"):

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

            self.epa = EPaConfig(**epa)


def verify_jwt_based_cfg(cfg):
    if cfg.secret is None and cfg.keyfile is None:
        raise Exception("Missing secret or keyfile")
    if cfg.keyfile is not None and not os.path.exists(cfg.keyfile):
        raise Exception("Keyfile doesn't exist")

    if cfg.algorithm not in [
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
        raise Exception(f"Unknown algorithm: '{cfg.algorithm}'")


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


def parse_auth(d: dict) -> HttpAuth:
    if isinstance(d, dict):
        type = d.pop("type")
        match type:
            case None:
                return NoAuth()
            case "basic":
                return BasicAuth(**d)
            case "bearer":
                return BearerAuth(**d)
            case t:
                raise Exception(f"Unknown HttpAuth type {t}")
    elif isinstance(d, list):
        type = d.pop(0)
        match type:
            case None:
                return NoAuth()
            case "basic":
                return BasicAuth(*d)
            case "bearer":
                return BearerAuth(*d)
            case t:
                raise Exception(f"Unknown HttpAuth type {t}")
    else:
        raise Exception("HttpAuth parsing failed, expected list or dict")
