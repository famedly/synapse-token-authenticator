from synapse_token_authenticator.claims_validator import parse_validator
from pytest import fixture


def test_validator_exists():
    assert parse_validator(["exist"]).validate(None)


def test_validator_in():
    assert parse_validator(["in", "foo"]).validate({"foo": 3})
    assert not parse_validator(["in", "foo"]).validate({"loo": 3})
    assert parse_validator(["in", "foo", ["equal", 3]]).validate({"foo": 3})
    assert not parse_validator(["in", "foo", ["equal", 3]]).validate({"foo": 4})


def test_validator_not():
    assert not parse_validator(["not", ["in", "foo"]]).validate({"foo": 3})
    assert parse_validator(["not", ["in", "foo"]]).validate({"loo": 3})
    assert not parse_validator(["not", ["exist"]]).validate(None)


def test_validator_equal():
    assert parse_validator(["equal", 3]).validate(3)
    assert not parse_validator(["equal", 3]).validate(4)
    assert parse_validator(["equal", {"hi": 3}]).validate({"hi": 3})
    assert not parse_validator(["equal", {"hi": 3}]).validate({"hi": 4})


def test_validator_regex():
    txt = "The rain in Spain"
    regexp = "The.*Spain"
    assert parse_validator(["regex", regexp]).validate(txt)
    assert parse_validator(["regex", regexp, False]).validate("smth" + txt + "smth")
    assert not parse_validator(["regex", regexp]).validate("bad string")


def test_validator_all_of():
    assert parse_validator(["all_of", [["in", "foo"], ["in", "loo"]]]).validate(
        {"foo": 3, "loo": 4}
    )
    assert not parse_validator(["all_of", [["in", "foo"], ["in", "loo"]]]).validate(
        {"foo": 3, "boo": 4}
    )
    assert parse_validator(["all_of", []]).validate([])


def test_validator_any_of():
    assert parse_validator(["any_of", [["in", "foo"], ["in", "loo"]]]).validate(
        {"foo": 3, "loo": 4}
    )
    assert parse_validator(["any_of", [["in", "foo"], ["in", "loo"]]]).validate(
        {"foo": 3}
    )
    assert not parse_validator(["any_of", [["in", "foo"], ["in", "loo"]]]).validate(
        {"boo": 3}
    )
    assert not parse_validator(["any_of", []]).validate({})


def test_validator_list_all_of():
    assert parse_validator(["list_all_of", ["in", "foo"]]).validate(
        [{"foo": 3}, {"foo": 4}]
    )
    assert parse_validator(["list_all_of", ["in", "foo"]]).validate([])
    assert not parse_validator(["list_all_of", ["in", "foo"]]).validate(
        [{"foo": 3}, {"loo": 4}]
    )


def test_validator_list_any_of():
    assert parse_validator(["list_any_of", ["in", "foo"]]).validate(
        [{"foo": 3}, {"foo": 4}]
    )
    assert not parse_validator(["list_any_of", ["in", "foo"]]).validate([])
    assert parse_validator(["list_any_of", ["in", "foo"]]).validate(
        [{"foo": 3}, {"loo": 4}]
    )


@fixture
def jwt_claims():
    return {
        "foo": "hello",
        "bar": "hi",
        "baz": {
            "laz": {
                "loo": 3,
                "goo": 4,
            }
        },
    }


def test_validator_full(jwt_claims):
    required_claims = {
        "type": "all_of",
        "validators": [
            {
                "type": "in",
                "path": "foo",
                "validator": {
                    "type": "regex",
                    "regex": "hell",
                    "full_match": False,
                },
            },
            {
                "type": "in",
                "path": "bar",
                "validator": {
                    "type": "equal",
                    "value": "hi",
                },
            },
            {
                "type": "in",
                "path": ["baz", "laz", "loo"],
                "validator": {"type": "equal", "value": 3},
            },
        ],
    }

    assert parse_validator(required_claims).validate(jwt_claims)


def test_validator_short(jwt_claims):
    required_claims_short = [
        "all_of",
        [
            ["in", "foo", ["regex", "hell", False]],
            ["in", "bar", ["equal", "hi"]],
            ["in", ["baz", "laz", "loo"], ["equal", 3]],
        ],
    ]

    assert parse_validator(required_claims_short).validate(jwt_claims)
