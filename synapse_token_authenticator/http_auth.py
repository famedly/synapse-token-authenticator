from base64 import b64encode
from typing import Annotated, Any, TypeAlias

from pydantic import BaseModel, BeforeValidator, ConfigDict


class AuthValidationError(ValueError):
    def __init__(self, message: str):
        self.message = message
        super().__init__(message)


class NoAuth(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    def header_map(self) -> dict[bytes, list[bytes]]:
        return {}


class BasicAuth(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    username: str
    password: str

    def header_map(self) -> dict[bytes, list[bytes]]:
        token = b64encode(
            b":".join((self.username.encode("utf-8"), self.password.encode("utf-8")))
        )
        return {b"Authorization": [b"Basic " + token]}


class BearerAuth(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    token: str

    def header_map(self) -> dict[bytes, list[bytes]]:
        return {b"Authorization": [b"Bearer " + self.token.encode("utf-8")]}


def parse_dict_auth(value: dict) -> NoAuth | BasicAuth | BearerAuth:
    try:
        auth_type = value.pop("type")
    except KeyError as error:
        raise AuthValidationError("HttpAuth missing type") from error
    if auth_type is None:
        return NoAuth()
    if auth_type == "basic":
        return BasicAuth(username=value["username"], password=value["password"])
    if auth_type == "bearer":
        return BearerAuth(token=value["token"])
    raise AuthValidationError(f"Unknown HttpAuth type {auth_type}")


def parse_list_auth(value: list) -> NoAuth | BasicAuth | BearerAuth:
    if not value:
        raise AuthValidationError("HttpAuth parsing failed, empty list")
    auth_type, *args = value
    if auth_type is None:
        return NoAuth()
    if auth_type == "basic":
        if len(args) != 2:
            raise AuthValidationError("BasicAuth expects username and password")
        return BasicAuth(username=args[0], password=args[1])
    if auth_type == "bearer":
        if len(args) != 1:
            raise AuthValidationError("BearerAuth expects a single token")
        return BearerAuth(token=args[0])
    raise AuthValidationError(f"Unknown HttpAuth type {auth_type}")


def _coerce_http_auth(value: Any) -> NoAuth | BasicAuth | BearerAuth:
    if isinstance(value, (NoAuth, BasicAuth, BearerAuth)):
        return value
    if isinstance(value, dict):
        return parse_dict_auth(value)
    if isinstance(value, list):
        return parse_list_auth(value)
    raise AuthValidationError("HttpAuth parsing failed, expected list or dict")


HttpAuth: TypeAlias = Annotated[
    NoAuth | BasicAuth | BearerAuth,
    BeforeValidator(_coerce_http_auth),
]
