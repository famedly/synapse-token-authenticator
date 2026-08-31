import logging
from base64 import b64encode
from typing import TypeAlias

from pydantic import ConfigDict, Field, ValidationError
from pydantic.dataclasses import dataclass

logger = logging.getLogger(__name__)

HTTP_AUTH_CONFIGURATION_ERROR = "Auth configuration error:"


@dataclass(config=ConfigDict(frozen=True, extra="forbid", strict=True))
class NoAuth:
    def header_map(self) -> dict[bytes, list[bytes]]:
        return {}


@dataclass(config=ConfigDict(frozen=True, extra="forbid", strict=True))
class BasicAuth:
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)

    def header_map(self) -> dict[bytes, list[bytes]]:
        token = b64encode(
            b":".join((self.username.encode("utf-8"), self.password.encode("utf-8")))
        )
        return {b"Authorization": [b"Basic " + token]}


@dataclass(config=ConfigDict(frozen=True, extra="forbid", strict=True))
class BearerAuth:
    token: str = Field(min_length=1)

    def header_map(self) -> dict[bytes, list[bytes]]:
        return {b"Authorization": [b"Bearer " + self.token.encode("utf-8")]}


HttpAuth: TypeAlias = NoAuth | BasicAuth | BearerAuth


AUTH_TYPES = {
    "basic": BasicAuth,
    "bearer": BearerAuth,
}


def _format_auth_error(context: str | None, error: BaseException) -> str:
    if context:
        return f"{context}: {HTTP_AUTH_CONFIGURATION_ERROR} {error}"
    return f"{HTTP_AUTH_CONFIGURATION_ERROR} {error}"


def parse_auth(value: dict | list | HttpAuth, context: str | None = None) -> HttpAuth:
    if isinstance(value, (NoAuth, BasicAuth, BearerAuth)):
        return value
    try:
        kwargs: dict | None = None
        args: list | None = None
        if isinstance(value, dict):
            # Declaring the auth block without a 'type' parameter is an error and should
            # raise KeyError. If a user don't want to use authentication, they should not
            # include the auth block at all.
            auth_type = value.pop("type")
            kwargs = value
        elif isinstance(value, list):
            # Declaring the auth block without a type is an error and should raise
            # IndexError on an empty list.
            auth_type = value.pop(0)
            args = value
        else:
            raise TypeError("Auth parsing failed, expected list or dict")

        # Only explicit None means NoAuth. Falsy values like "" must not silently
        # disable authentication.
        if auth_type is None:
            return NoAuth()

        auth = AUTH_TYPES.get(auth_type)
        if auth is None:
            raise ValueError(f"Unknown Auth type '{auth_type}'")
        if kwargs is not None:
            return auth(**kwargs)
        if args is not None:
            return auth(*args)
        raise ValueError("Auth parsing failed: missing fields")
    except (KeyError, IndexError, TypeError, ValueError, ValidationError) as e:
        message = _format_auth_error(context, e)
        logger.error(message)
        raise ValueError(message) from e
