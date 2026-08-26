import logging

import pytest
from pydantic import ValidationError

from synapse_token_authenticator.config import TokenAuthenticatorConfig
from synapse_token_authenticator.http_auth import (
    BasicAuth,
    BearerAuth,
    NoAuth,
    parse_auth,
    parse_dict_auth,
    parse_list_auth,
)


class TestHttpAuth:
    def test_parse_auth_invalid_format(self):
        with pytest.raises(Exception) as e:
            parse_auth("something invalid")
        assert e.value.args[0] == "HttpAuth parsing failed, expected list or dict"

    def test_no_auth(self):
        no_auth = NoAuth()
        assert no_auth.header_map() == {}

    def test_basic_auth(self):
        basic_auth = BasicAuth(username="user", password="pass")
        assert basic_auth.header_map() == {b"Authorization": [b"Basic dXNlcjpwYXNz"]}

    def test_bearer_auth(self):
        bearer_auth = BearerAuth(token="token")
        assert bearer_auth.header_map() == {b"Authorization": [b"Bearer token"]}

    def test_parse_dict_auth(self):
        assert parse_dict_auth({"type": None}) == NoAuth()
        assert parse_dict_auth(
            {"type": "basic", "username": "user", "password": "pass"}
        ) == BasicAuth(username="user", password="pass")
        assert parse_dict_auth({"type": "bearer", "token": "token"}) == BearerAuth(
            token="token"
        )

    def test_parse_dict_auth_missing_type(self):
        with pytest.raises(Exception) as e:
            parse_dict_auth({"username": "user", "password": "pass"})
        assert e.value.args[0] == "type"

    def test_parse_dict_auth_basic_extra_fields(self):
        with pytest.raises(ValidationError) as e:
            parse_dict_auth(
                {
                    "type": "basic",
                    "username": "user",
                    "password": "pass",
                    "extra": "field",
                }
            )
        assert "Extra inputs are not permitted" in str(e)

    def test_parse_dict_auth_basic_missing_username(self):
        with pytest.raises(ValidationError) as e:
            parse_dict_auth({"type": "basic", "password": "pass"})
        assert "Field required" in str(e)

    def test_parse_dict_auth_unknown_http_auth_type(self):
        with pytest.raises(Exception) as e:
            parse_dict_auth({"type": "unknown", "token": "token"})
        assert e.value.args[0] == "Unknown HttpAuth type 'unknown'"

    def test_parse_list_auth_basic_empty_list(self):
        with pytest.raises(Exception) as e:
            parse_list_auth([])
        assert e.value.args[0] == "pop from empty list"

    def test_parse_auth_list(self):
        assert parse_list_auth([None]) == NoAuth()
        assert parse_list_auth(["basic", "user", "pass"]) == BasicAuth(
            username="user", password="pass"
        )
        assert parse_list_auth(["bearer", "token"]) == BearerAuth(token="token")

    def test_parse_list_auth_basic_missing_username(self):
        with pytest.raises(Exception) as e:
            parse_list_auth(["basic", "pass"])
        assert e.value.args[0] == "BasicAuth expects username and password"

    def test_parse_list_auth_basic_extra_fields(self):
        with pytest.raises(Exception) as e:
            parse_list_auth(["basic", "user", "pass", "extra", "field"])
        assert e.value.args[0] == "BasicAuth expects username and password"

    def test_parse_list_auth_bearer_extra_fields(self):
        with pytest.raises(Exception) as e:
            parse_list_auth(["bearer", "token", "extra", "field"])
        assert e.value.args[0] == "BearerAuth expects a single token"

    def test_parse_list_auth_unknown_http_auth_type(self):
        with pytest.raises(Exception) as e:
            parse_list_auth(["unknown"])
        assert e.value.args[0] == "Unknown HttpAuth type 'unknown'"


class TestHttpAuthConfigCoercion:
    def test_introspection_auth(self):
        dict_cfg = TokenAuthenticatorConfig(
            {
                "oauth": {
                    "introspection_validation": {
                        "endpoint": "http://idp.test/introspect",
                        "auth": {
                            "type": "basic",
                            "username": "user",
                            "password": "pass",
                        },
                    },
                    "notify_on_registration": {
                        "url": "http://iop.test/notify",
                        "auth": {"type": "bearer", "token": "token"},
                    },
                }
            }
        )
        introspection_auth = dict_cfg.oauth.introspection_validation.auth
        assert introspection_auth == BasicAuth(username="user", password="pass")
        assert introspection_auth.header_map() == {
            b"Authorization": [b"Basic dXNlcjpwYXNz"]
        }

        notify_on_registration_auth = dict_cfg.oauth.notify_on_registration.auth
        assert notify_on_registration_auth == BearerAuth(token="token")
        assert notify_on_registration_auth.header_map() == {
            b"Authorization": [b"Bearer token"]
        }

        list_cfg = TokenAuthenticatorConfig(
            {
                "oauth": {
                    "introspection_validation": {
                        "endpoint": "http://idp.test/introspect",
                        "auth": ["bearer", "token"],
                    },
                    "notify_on_registration": {
                        "url": "http://iop.test/notify",
                        "auth": ["basic", "user", "pass"],
                    },
                }
            }
        )
        introspection_auth = list_cfg.oauth.introspection_validation.auth
        assert introspection_auth == BearerAuth(token="token")
        assert introspection_auth.header_map() == {b"Authorization": [b"Bearer token"]}

        notify_on_registration_auth = list_cfg.oauth.notify_on_registration.auth
        assert notify_on_registration_auth == BasicAuth(
            username="user", password="pass"
        )
        assert notify_on_registration_auth.header_map() == {
            b"Authorization": [b"Basic dXNlcjpwYXNz"]
        }

    def test_auth_defaults_to_no_auth(self):
        cfg = TokenAuthenticatorConfig(
            {
                "oauth": {
                    "introspection_validation": {
                        "endpoint": "http://idp.test/introspect",
                    },
                    "notify_on_registration": {
                        "url": "http://iop.test/notify",
                    },
                }
            }
        )
        assert cfg.oauth.introspection_validation.auth == NoAuth()
        assert cfg.oauth.notify_on_registration.auth == NoAuth()
        assert cfg.oauth.introspection_validation.auth.header_map() == {}
        assert cfg.oauth.notify_on_registration.auth.header_map() == {}

    def test_introspection_auth_error_logs_config_class(self, caplog):
        with (
            caplog.at_level(logging.ERROR),
            pytest.raises(ValueError),
        ):
            TokenAuthenticatorConfig(
                {
                    "oauth": {
                        "introspection_validation": {
                            "endpoint": "http://idp.test/introspect",
                            "auth": {"type": "unknown"},
                        },
                    }
                }
            )
        assert (
            "IntrospectionValidationConfig: HttpAuth configuration error: Unknown HttpAuth type 'unknown'"
            in caplog.text
        )

    def test_notify_on_registration_auth_error_logs_config_class(self, caplog):
        with (
            caplog.at_level(logging.ERROR),
            pytest.raises(ValueError),
        ):
            TokenAuthenticatorConfig(
                {
                    "oauth": {
                        "introspection_validation": {
                            "endpoint": "http://idp.test/introspect",
                        },
                        "notify_on_registration": {
                            "url": "http://iop.test/notify",
                            "auth": ["unknown"],
                        },
                    }
                }
            )
        assert (
            "NotifyOnRegistration: HttpAuth configuration error: Unknown HttpAuth type 'unknown'"
            in caplog.text
        )
