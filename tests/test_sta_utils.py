from synapse_token_authenticator.utils import (
    get_path_in_dict,
    validate_scopes,
    if_not_none,
    all_list_elems_are_equal_return_the_elem,
)


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
    try:
        all_list_elems_are_equal_return_the_elem([3, 4])
        assert False
    except Exception:
        assert True
