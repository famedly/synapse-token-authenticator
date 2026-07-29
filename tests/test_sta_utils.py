from synapse_token_authenticator.utils import (
    all_list_elems_are_equal_return_the_elem,
    get_path_in_dict,
    if_not_none,
    validate_scopes,
)


def test_get_path_in_dict() -> None:
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


def test_get_path_in_dict_pathlist_fallback_on_missing_key() -> None:
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


def test_get_path_in_dict_pathlist_non_dict_intermediate() -> None:
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


def test_get_path_in_dict_zitadel_admin_path() -> None:
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


def test_validate_scopes() -> None:
    assert validate_scopes("foo boo", "boo foo")
    assert validate_scopes(["foo", "boo"], "boo foo")
    assert not validate_scopes("foo boo", "foo")
    assert not validate_scopes(["foo", "boo"], "foo")
    assert validate_scopes("foo boo", "boo foo loo")


def test_if_not_none() -> None:
    assert if_not_none(lambda x: x + 1)(3) == 4
    assert if_not_none(lambda x: x + 1)(None) is None


def test_all_list_elems_are_equal_return_the_elem() -> None:
    assert all_list_elems_are_equal_return_the_elem([None, None]) is None
    assert all_list_elems_are_equal_return_the_elem([]) is None
    assert all_list_elems_are_equal_return_the_elem([3, None]) == 3
    assert all_list_elems_are_equal_return_the_elem([None, 3]) == 3
    assert all_list_elems_are_equal_return_the_elem([3, 3]) == 3
    assert all_list_elems_are_equal_return_the_elem([3]) == 3
    try:
        all_list_elems_are_equal_return_the_elem([3, 4])
        assert False
    except Exception:
        assert True
