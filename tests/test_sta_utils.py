from dataclasses import dataclass

import pytest

from synapse_token_authenticator.utils import (
    all_list_elems_are_equal_return_the_elem,
    get_claim_from_validation,
    get_path_in_dict,
    get_reconcile_claim_paths,
    get_reconciled_claim,
    if_not_none,
    validate_scopes,
)


@dataclass
class SimpleValidationConfig:
    localpart_path: str | list[str] | None = None
    displayname_path: str | list[str] | None = None


def test_get_path_in_dict():
    assert get_path_in_dict("foo", {"foo": 3}) == 3
    assert get_path_in_dict("foo", {"loo": 3}) is None
    assert get_path_in_dict("foo", [3, 4]) is None
    assert get_path_in_dict("foo", {"foo": None}) is None
    assert get_path_in_dict(["foo"], {"foo": 3}) == 3
    assert get_path_in_dict(["foo", "loo"], {"foo": {"loo": 3}}) == 3
    assert get_path_in_dict(["foo", "loo", "boo"], {"foo": {"loo": {"boo": 3}}}) == 3
    assert get_path_in_dict(["foo", "loo"], {"foo": {"loo": {"boo": 3}}}) == {"boo": 3}
    assert get_path_in_dict([], {"foo": 3}) == {"foo": 3}
    assert get_path_in_dict(["foo", "loo"], {"foo": {"boo": 3}}) is None
    assert get_path_in_dict([["foo", "loo"], ["foo", "boo"]], {"foo": {"boo": 3}}) == 3
    assert (
        get_path_in_dict(
            [["foo", "loo"], ["foo", "boo"]], {"foo": {"boo": 3, "loo": 4}}
        )
        == 4
    )
    assert (
        get_path_in_dict(
            [["foo", "loo"], ["foo", "boo"]], {"foo": {"bar": 3, "lar": 4}}
        )
        is None
    )
    assert get_path_in_dict([["foo", "loo"]], {"foo": {"loo": 4}}) == 4
    assert get_path_in_dict([[], ["foo", "boo"]], {"foo": {"boo": 3}}) == {
        "foo": {"boo": 3}
    }
    assert get_path_in_dict([[], []], {"foo": {"loo": 3}}) == {"foo": {"loo": 3}}
    assert get_path_in_dict([["foo", "loo"], []], {"foo": {"loo": 3}}) == 3


def test_get_path_in_dict_pathlist_fallback_on_missing_key():
    """When the first path's key is entirely absent, later paths must still be tried."""
    assert (
        get_path_in_dict([["missing", "sub"], ["foo", "bar"]], {"foo": {"bar": 3}}) == 3
    )
    assert (
        get_path_in_dict([["a", "b"], ["c", "d"], ["e", "f"]], {"e": {"f": 42}}) == 42
    )
    assert (
        get_path_in_dict(
            [["missing", "sub"], ["also_missing", "sub"]], {"foo": {"bar": 3}}
        )
        is None
    )


def test_get_path_in_dict_pathlist_non_dict_intermediate():
    """When an intermediate value is a non-dict (e.g. int), later paths must still be tried."""
    assert (
        get_path_in_dict(
            [["foo", "bar"], ["baz", "qux"]], {"foo": 42, "baz": {"qux": 7}}
        )
        == 7
    )
    assert (
        get_path_in_dict(
            [["a", "b", "c"], ["x", "y"]],
            {"a": {"b": "not_a_dict"}, "x": {"y": 99}},
        )
        == 99
    )


def test_get_path_in_dict_zitadel_admin_path():
    """Real-world scenario: Zitadel project-scoped role claims with PathList fallback."""
    token = {
        "urn:zitadel:iam:org:project:12345:roles": {
            "MatrixAdmin": {"org_id": "famedly.localhost"}
        },
    }
    assert get_path_in_dict(
        [
            ["roles", "Admin"],
            ["urn:zitadel:iam:org:project:12345:roles", "MatrixAdmin"],
        ],
        token,
    ) == {"org_id": "famedly.localhost"}
    assert get_path_in_dict(
        [
            ["urn:zitadel:iam:org:project:12345:roles", "MatrixAdmin"],
            ["roles", "Admin"],
        ],
        token,
    ) == {"org_id": "famedly.localhost"}


def test_validate_scopes():
    assert validate_scopes("foo boo", "boo foo")
    assert validate_scopes(["foo", "boo"], "boo foo")
    assert not validate_scopes("foo boo", "foo")
    assert not validate_scopes(["foo", "boo"], "foo")
    assert validate_scopes("foo boo", "boo foo loo")


def test_if_not_none():
    assert if_not_none(lambda x: x + 1)(3) == 4
    assert if_not_none(lambda x: x + 1)(None) is None


def test_all_list_elems_are_equal_return_the_elem():
    assert all_list_elems_are_equal_return_the_elem([None, None]) is None
    assert all_list_elems_are_equal_return_the_elem([]) is None
    assert all_list_elems_are_equal_return_the_elem([3, None]) == 3
    assert all_list_elems_are_equal_return_the_elem([None, 3]) == 3
    assert all_list_elems_are_equal_return_the_elem([3, 3]) == 3
    assert all_list_elems_are_equal_return_the_elem([3]) == 3
    with pytest.raises(Exception):
        all_list_elems_are_equal_return_the_elem([3, 4])


def test_get_claim_from_validation_returns_none_without_config():
    claims = {"preferred_username": "user"}
    assert get_claim_from_validation(claims, None, "localpart_path") is None


def test_get_claim_from_validation_returns_none_without_path():
    claims = {"preferred_username": "user"}
    config = SimpleValidationConfig(localpart_path=None)
    assert get_claim_from_validation(claims, config, "localpart_path") is None


def test_get_claim_from_validation_reads_configured_path():
    claims = {"preferred_username": "user"}
    config = SimpleValidationConfig(localpart_path="preferred_username")
    assert get_claim_from_validation(claims, config, "localpart_path") == "user"


def test_get_claim_from_validation_returns_none_when_claim_missing():
    claims = {"other": "value"}
    config = SimpleValidationConfig(localpart_path="preferred_username")
    assert get_claim_from_validation(claims, config, "localpart_path") is None


def test_get_claim_from_validation_supports_nested_path():
    claims = {"user": {"name": "user"}}
    config = SimpleValidationConfig(localpart_path=["user", "name"])
    assert get_claim_from_validation(claims, config, "localpart_path") == "user"


def test_get_reconciled_claim_returns_none_when_both_absent():
    jwt_claims = {"preferred_username": "user"}
    introspection_claims = {"preferred_username": "user"}
    assert (
        get_reconciled_claim(
            jwt_claims,
            introspection_claims,
            None,
            None,
            "localpart_path",
        )
        is None
    )


def test_get_reconciled_claim_uses_single_source():
    jwt_claims = {"preferred_username": "user"}
    introspection_claims: dict = {}
    jwt_config = SimpleValidationConfig(localpart_path="preferred_username")
    assert (
        get_reconciled_claim(
            jwt_claims,
            introspection_claims,
            jwt_config,
            None,
            "localpart_path",
        )
        == "user"
    )


def test_get_reconciled_claim_requires_agreement():
    jwt_claims = {"preferred_username": "user"}
    introspection_claims = {"preferred_username": "user"}
    jwt_config = SimpleValidationConfig(localpart_path="preferred_username")
    introspection_config = SimpleValidationConfig(localpart_path="preferred_username")
    assert (
        get_reconciled_claim(
            jwt_claims,
            introspection_claims,
            jwt_config,
            introspection_config,
            "localpart_path",
        )
        == "user"
    )


def test_get_reconciled_claim_raises_on_mismatch():
    jwt_claims = {"preferred_username": "user"}
    introspection_claims = {"preferred_username": "someone_else"}
    jwt_config = SimpleValidationConfig(localpart_path="preferred_username")
    introspection_config = SimpleValidationConfig(localpart_path="preferred_username")
    with pytest.raises(Exception, match="are not equal"):
        get_reconciled_claim(
            jwt_claims,
            introspection_claims,
            jwt_config,
            introspection_config,
            "localpart_path",
        )


def test_get_reconcile_claim_paths_returns_none_when_both_missing():
    assert get_reconcile_claim_paths({}, {}, "sub") is None


def test_get_reconcile_claim_paths_uses_single_source():
    assert get_reconcile_claim_paths({"sub": "user-123"}, {}, "sub") == "user-123"


def test_get_reconcile_claim_paths_requires_agreement():
    jwt_claims = {"iss": "https://issuer.example"}
    introspection_claims = {"iss": "https://issuer.example"}
    assert (
        get_reconcile_claim_paths(jwt_claims, introspection_claims, "iss")
        == "https://issuer.example"
    )


def test_get_reconcile_claim_paths_raises_on_mismatch():
    jwt_claims = {"iss": "https://issuer.example"}
    introspection_claims = {"iss": "something else"}
    with pytest.raises(Exception, match="are not equal"):
        get_reconcile_claim_paths(jwt_claims, introspection_claims, "iss")
