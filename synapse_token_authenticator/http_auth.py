import logging
from base64 import b64encode
from typing import TypeAlias

from pydantic import BaseModel, ConfigDict

logger = logging.getLogger(__name__)


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


HttpAuth: TypeAlias = NoAuth | BasicAuth | BearerAuth


def parse_dict_auth(value: dict) -> HttpAuth:
    auth_type = value.pop("type")
    # This is not KeyError safe, but it is caught in the caller
    if auth_type is None:
        return NoAuth()
    if auth_type == "basic":
        return BasicAuth(**value)
    if auth_type == "bearer":
        return BearerAuth(**value)
    raise Exception(f"Unknown HttpAuth type '{auth_type}'")


def parse_list_auth(value: list) -> HttpAuth:
    auth_type = value.pop(0)
    # This is not IndexError safe, but it is caught in the caller
    if auth_type is None:
        return NoAuth()
    if auth_type == "basic":
        if len(value) != 2:
            raise Exception("BasicAuth expects username and password")
        return BasicAuth(username=value[0], password=value[1])
    if auth_type == "bearer":
        if len(value) != 1:
            raise Exception("BearerAuth expects a single token")
        return BearerAuth(token=value[0])
    raise Exception(f"Unknown HttpAuth type '{auth_type}'")


def parse_auth(
    value: dict | list | HttpAuth, *, context: str | None = None
) -> HttpAuth:
    if isinstance(value, (NoAuth, BasicAuth, BearerAuth)):
        return value
    try:
        if isinstance(value, dict):
            return parse_dict_auth(value)
        if isinstance(value, list):
            return parse_list_auth(value)
        raise Exception("HttpAuth parsing failed, expected list or dict")
    except Exception as e:
        if context:
            logger.error("%s: HttpAuth configuration error: %s", context, e)
        else:
            logger.error("HttpAuth configuration error: %s", e)
        raise e from e
