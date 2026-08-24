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
from typing import Any, TypeAlias, Union

from synapse_token_authenticator.utils import get_path_in_dict

Validator: TypeAlias = Union[
    "Exist",
    "Not",
    "Equal",
    "MatchesRegex",
    "AnyOf",
    "AllOf",
    "In",
    "ListAnyOf",
    "ListAllOf",
]


def parse_validator(d: dict | list) -> Validator:
    if isinstance(d, dict):
        try:
            val_type = d.pop("type")
            if val_type == "exist":
                return Exist(**d)
            if val_type == "not":
                return Not(**d)
            if val_type == "equal":
                return Equal(**d)
            if val_type == "regex":
                return MatchesRegex(**d)
            if val_type == "any_of":
                return AnyOf(**d)
            if val_type == "all_of":
                return AllOf(**d)
            if val_type == "in":
                return In(**d)
            if val_type == "list_any_of":
                return ListAnyOf(**d)
            if val_type == "list_all_of":
                return ListAllOf(**d)
            raise ValueError(f"Unknown validator type {val_type}")
        except KeyError as e:
            raise ValueError("Missing field 'type' for validator") from e
        except TypeError as e:
            raise ValueError("Invalid validator definition") from e
    if isinstance(d, list):
        try:
            val_type = d.pop(0)
            if val_type == "exist":
                return Exist(*d)
            if val_type == "not":
                return Not(*d)
            if val_type == "equal":
                return Equal(*d)
            if val_type == "regex":
                return MatchesRegex(*d)
            if val_type == "any_of":
                return AnyOf(*d)
            if val_type == "all_of":
                return AllOf(*d)
            if val_type == "in":
                return In(*d)
            if val_type == "list_any_of":
                return ListAnyOf(*d)
            if val_type == "list_all_of":
                return ListAllOf(*d)
            raise ValueError(f"Unknown validator type {val_type}")
        except IndexError as e:
            raise ValueError("Missing field 'type' for validator") from e
        except TypeError as e:
            raise ValueError("Invalid validator definition") from e
    raise ValueError("Validator parsing failed, expected list or dict")


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
            error = "Path list is empty"
            raise Exception(error)
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
