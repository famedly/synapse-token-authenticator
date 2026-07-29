from __future__ import annotations

from base64 import b64encode
from dataclasses import dataclass
from typing import Protocol


class HttpAuth(Protocol):
    def header_map(self) -> dict[bytes, list[bytes]]:
        """Retrieve the mapping for the authorization for Header generation"""
        ...


@dataclass
class NoAuth:
    def header_map(self) -> dict[bytes, list[bytes]]:
        return {}


@dataclass
class BasicAuth:
    username: str
    password: str

    def header_map(self) -> dict[bytes, list[bytes]]:
        return basic_auth(self.username, self.password)


@dataclass
class BearerAuth:
    token: str

    def header_map(self) -> dict[bytes, list[bytes]]:
        return bearer_auth(self.token)


def parse_auth(d: dict | list) -> HttpAuth:
    if isinstance(d, dict):
        _type = d.pop("type")
        if _type is None:
            return NoAuth()
        elif _type == "basic":
            return BasicAuth(**d)
        elif _type == "bearer":
            return BearerAuth(**d)
        else:
            raise Exception(f"Unknown HttpAuth type {_type}")
    elif isinstance(d, list):
        _type = d.pop(0)
        if _type is None:
            return NoAuth()
        elif _type == "basic":
            return BasicAuth(*d)
        elif _type == "bearer":
            return BearerAuth(*d)
        else:
            raise Exception(f"Unknown HttpAuth type {_type}")
    else:
        raise Exception("HttpAuth parsing failed, expected list or dict")


def basic_auth(username: str, password: str) -> dict[bytes, list[bytes]]:
    authorization = b64encode(
        b":".join((username.encode("utf8"), password.encode("utf8")))
    )
    return {b"Authorization": [b"Basic " + authorization]}


def bearer_auth(token: str) -> dict[bytes, list[bytes]]:
    return {b"Authorization": [b"Bearer " + token.encode("utf8")]}
