from base64 import b64encode
from typing import Annotated, Any, TypeAlias

from pydantic import BaseModel, BeforeValidator, ConfigDict


class NoAuth(BaseModel):
    model_config = ConfigDict(frozen=True)

    def header_map(self) -> dict[bytes, list[bytes]]:
        return {}


class BasicAuth(BaseModel):
    model_config = ConfigDict(frozen=True)

    username: str
    password: str

    def header_map(self) -> dict[bytes, list[bytes]]:
        token = b64encode(
            b":".join((self.username.encode("utf-8"), self.password.encode("utf-8")))
        )
        return {b"Authorization": [b"Basic " + token]}


class BearerAuth(BaseModel):
    model_config = ConfigDict(frozen=True)

    token: str

    def header_map(self) -> dict[bytes, list[bytes]]:
        return {b"Authorization": [b"Bearer " + self.token.encode("utf-8")]}


def parse_auth(value: dict | list) -> NoAuth | BasicAuth | BearerAuth:
    """Parse an HttpAuth config value without mutating the input."""
    if isinstance(value, dict):
        data = dict(value)
        try:
            auth_type = data.pop("type")
        except KeyError as error:
            raise ValueError("HttpAuth missing type") from error
        if auth_type is None:
            return NoAuth()
        if auth_type == "basic":
            return BasicAuth(**data)
        if auth_type == "bearer":
            return BearerAuth(**data)
        raise ValueError(f"Unknown HttpAuth type {auth_type}")

    if isinstance(value, list):
        items = list(value)
        if not items:
            raise ValueError("HttpAuth parsing failed, empty list")
        auth_type, *args = items
        if auth_type is None:
            return NoAuth()
        if auth_type == "basic":
            username, password, *rest = args
            if rest:
                raise ValueError("BasicAuth expects username and password")
            return BasicAuth(username=username, password=password)
        if auth_type == "bearer":
            token, *rest = args
            if rest:
                raise ValueError("BearerAuth expects a single token")
            return BearerAuth(token=token)
        raise ValueError(f"Unknown HttpAuth type {auth_type}")

    raise ValueError("HttpAuth parsing failed, expected list or dict")


def _coerce_http_auth(value: Any) -> NoAuth | BasicAuth | BearerAuth:
    if isinstance(value, (NoAuth, BasicAuth, BearerAuth)):
        return value
    if isinstance(value, (dict, list)):
        return parse_auth(value)
    raise ValueError("HttpAuth parsing failed, expected list or dict")


HttpAuth: TypeAlias = Annotated[
    NoAuth | BasicAuth | BearerAuth,
    BeforeValidator(_coerce_http_auth),
]
