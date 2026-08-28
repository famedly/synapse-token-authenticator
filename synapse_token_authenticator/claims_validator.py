"""
This module contains custom DSL specifically designed to check jwt claims. It could be argued
that an existing solution can be used instead, here is a few key points:

Existing solution:
1. No need to maintain our own
2. More out of the box features
3. Validation errors reporting, useful for debuging

Current solution:
1. Flexibility: having dict-style syntax for explicitness + shorter list-style syntax
   for information density and visual simplicity (one simple check -- one line)
2. Being domain specific, it really focuses on validating JWT claims. This means we don't have
   anything extra, like comparing numbers, the main terminal checkers are `equal` and `regex`
3. Is fairly simple, so there's not much maintanence cost. If we ever need something significantly
   more complicated, we better switch to another engine/DSL
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Protocol

from synapse_token_authenticator.utils import get_path_in_dict


class InvalidClaimsValidatorError(ValueError):
    """Invalid claims validator definition."""


class Validator(Protocol):
    def validate(self, x: Any) -> bool: ...


@dataclass
class Exist:
    def validate(self, x: Any) -> bool:
        return True


@dataclass
class Not:
    validator: Validator

    def __post_init__(self):
        self.validator = parse_validator(self.validator)

    def validate(self, x: Any) -> bool:
        return not self.validator.validate(x)


@dataclass
class Equal:
    value: Any

    def validate(self, x: Any) -> bool:
        return x == self.value


@dataclass
class MatchesRegex:
    regex: str
    full_match: bool | None = True

    def __post_init__(self):
        self.regex_prog = re.compile(self.regex)

    def validate(self, s: Any) -> bool:
        if not isinstance(s, str):
            return False
        if self.full_match:
            return bool(self.regex_prog.fullmatch(s))
        return bool(self.regex_prog.search(s))


@dataclass
class AnyOf:
    validators: list[Validator]

    def __post_init__(self):
        self.validators = [parse_validator(v) for v in self.validators]

    def validate(self, x: Any) -> bool:
        return any(v.validate(x) for v in self.validators)


@dataclass
class AllOf:
    validators: list[Validator]

    def __post_init__(self):
        self.validators = [parse_validator(v) for v in self.validators]

    def validate(self, x: Any) -> bool:
        return all(v.validate(x) for v in self.validators)


@dataclass
class In:
    path: str | list[str]
    validator: Validator | None = None

    def __post_init__(self):
        if not self.path:
            raise InvalidClaimsValidatorError("Path list is empty")
        if self.validator:
            self.validator = parse_validator(self.validator)

    def validate(self, x: Any) -> bool:
        if not isinstance(x, dict):
            return False
        val = get_path_in_dict(self.path, x)
        return (
            (self.validator.validate(val) if self.validator else True) if val else False
        )


@dataclass
class ListAllOf:
    validator: Validator

    def __post_init__(self):
        if self.validator:
            self.validator = parse_validator(self.validator)

    def validate(self, list_: Any) -> bool:
        if not isinstance(list_, list):
            return False
        return all(self.validator.validate(x) for x in list_)


@dataclass
class ListAnyOf:
    validator: Validator

    def __post_init__(self):
        if self.validator:
            self.validator = parse_validator(self.validator)

    def validate(self, list_: Any) -> bool:
        if not isinstance(list_, list):
            return False
        return any(self.validator.validate(x) for x in list_)


VALIDATORS = {
    "exist": Exist,
    "not": Not,
    "equal": Equal,
    "regex": MatchesRegex,
    "any_of": AnyOf,
    "all_of": AllOf,
    "in": In,
    "list_any_of": ListAnyOf,
    "list_all_of": ListAllOf,
}


def parse_validator(d: dict | list) -> Validator:
    if isinstance(d, dict):
        val_type = d.pop("type")
        validator = VALIDATORS.get(val_type)
        if validator:
            return validator(**d)
        raise InvalidClaimsValidatorError(f"Unknown validator type {val_type}")
    if isinstance(d, list):
        val_type = d.pop(0)
        validator = VALIDATORS.get(val_type)
        if validator:
            return validator(*d)
        raise InvalidClaimsValidatorError(f"Unknown validator type {val_type}")
    raise InvalidClaimsValidatorError("Validator parsing failed, expected list or dict")
