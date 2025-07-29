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

from dataclasses import dataclass
from typing import List, Optional, Any, TypeAlias, Union
from synapse_token_authenticator.utils import get_path_in_dict
import re

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


def parse_validator(d: dict) -> Validator:
    if isinstance(d, dict):
        type = d.pop("type")
        if type == "exist":
            return Exist(**d)
        elif type == "not":
            return Not(**d)
        elif type == "equal":
            return Equal(**d)
        elif type == "regex":
            return MatchesRegex(**d)
        elif type == "any_of":
            return AnyOf(**d)
        elif type == "all_of":
            return AllOf(**d)
        elif type == "in":
            return In(**d)
        elif type == "list_any_of":
            return ListAnyOf(**d)
        elif type == "list_all_of":
            return ListAllOf(**d)
        else:
            raise Exception(f"Unknown validator type {type}")
    elif isinstance(d, list):
        type = d.pop(0)
        if type == "exist":
            return Exist(*d)
        elif type == "not":
            return Not(*d)
        elif type == "equal":
            return Equal(*d)
        elif type == "regex":
            return MatchesRegex(*d)
        elif type == "any_of":
            return AnyOf(*d)
        elif type == "all_of":
            return AllOf(*d)
        elif type == "in":
            return In(*d)
        elif type == "list_any_of":
            return ListAnyOf(*d)
        elif type == "list_all_of":
            return ListAllOf(*d)
        else:
            raise Exception(f"Unknown validator type {type}")
    else:
        raise Exception("Validator parsing failed, expected list or dict")


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
        else:
            return bool(self.regex_prog.search(s))


@dataclass
class AnyOf:
    validators: List[Validator]

    def __post_init__(self):
        self.validators = list(map(lambda v: parse_validator(v), self.validators))

    def validate(self, x: Any) -> bool:
        return any(v.validate(x) for v in self.validators)


@dataclass
class AllOf:
    validators: List[Validator]

    def __post_init__(self):
        self.validators = list(map(lambda v: parse_validator(v), self.validators))

    def validate(self, x: Any) -> bool:
        return all(v.validate(x) for v in self.validators)


@dataclass
class In:
    path: str | List[str]
    validator: Optional[Validator] = None

    def __post_init__(self):
        if not self.path:
            raise Exception("Path list is empty")
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
