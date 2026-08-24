import logging
from base64 import b64encode
from typing import Annotated, TypeAlias

from pydantic import BeforeValidator

from synapse_token_authenticator.config_util.base import BaseConfigModel

logger = logging.getLogger(__name__)


class NoAuth(BaseConfigModel):

    def header_map(self) -> dict[bytes, list[bytes]]:
        return {}


class BasicAuth(BaseConfigModel):
    username: str
    password: str

    def header_map(self) -> dict[bytes, list[bytes]]:
        token = b64encode(
            b":".join((self.username.encode("utf-8"), self.password.encode("utf-8")))
        )
        return {b"Authorization": [b"Basic " + token]}


class BearerAuth(BaseConfigModel):
    token: str

    def header_map(self) -> dict[bytes, list[bytes]]:
        return {b"Authorization": [b"Bearer " + self.token.encode("utf-8")]}


HttpAuth: TypeAlias = NoAuth | BasicAuth | BearerAuth


def parse_dict_auth(value: dict) -> HttpAuth:
    auth_type = value.pop("type")
    # Declaring the auth block without a 'type' parameter is an error and should raise
    # the KeyError. If a user don't want to use authentication system, they should not
    # include the auth block at all.
    if auth_type is None:
        return NoAuth()
    if auth_type == "basic":
        return BasicAuth(**value)
    if auth_type == "bearer":
        return BearerAuth(**value)
    raise Exception(f"Unknown HttpAuth type '{auth_type}'")


def parse_list_auth(value: list) -> HttpAuth:
    auth_type = value.pop(0)
    # Declaring the auth block without a 'type' information is an error and should
    # raise the IndexError. If a user don't want to use authentication system, they
    # should not include the auth block at all.
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


def parse_auth(value: dict | list | HttpAuth) -> HttpAuth:
    if isinstance(value, (NoAuth, BasicAuth, BearerAuth)):
        return value
    try:
        if isinstance(value, dict):
            return parse_dict_auth(value)
        if isinstance(value, list):
            return parse_list_auth(value)
        raise Exception("HttpAuth parsing failed, expected list or dict")
    except Exception as e:
        logger.error("HttpAuth configuration error: %s", e)
        raise e from e


HttpAuthField = Annotated[HttpAuth, BeforeValidator(parse_auth)]
