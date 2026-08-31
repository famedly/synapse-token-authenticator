import logging

import pytest

from synapse_token_authenticator.config import TokenAuthenticatorConfig
from synapse_token_authenticator.http_auth import (
    BasicAuth,
    BearerAuth,
    NoAuth,
    parse_auth,
)


class TestHttpAuth:
    def test_parse_auth_invalid_format(self):
        with pytest.raises(
            ValueError, match="Auth parsing failed, expected list or dict"
        ):
            parse_auth("something invalid")

    def test_parse_auth_invalid_format_has_single_error_prefix(self):
        with pytest.raises(ValueError) as e:
            parse_auth("something invalid", context="NotifyOnRegistration")
        message = str(e.value)
        assert message.startswith(
            "NotifyOnRegistration: Auth configuration error: Auth parsing failed"
        )
        assert message.count("Auth configuration error:") == 1

    def test_no_auth(self):
        no_auth = NoAuth()
        assert no_auth.header_map() == {}

    def test_basic_auth(self):
        basic_auth = BasicAuth(username="user", password="pass")
        assert basic_auth.header_map() == {b"Authorization": [b"Basic dXNlcjpwYXNz"]}

    def test_basic_auth_fail_with_empty_credentials(self):
        with pytest.raises(ValueError, match="String should have at least 1 character"):
            BasicAuth(username="", password="")

    def test_bearer_auth(self):
        bearer_auth = BearerAuth(token="token")
        assert bearer_auth.header_map() == {b"Authorization": [b"Bearer token"]}

    def test_bearer_auth_fail_with_empty_token(self):
        with pytest.raises(ValueError, match="String should have at least 1 character"):
            BearerAuth(token="")

    def test_parse_dict_auth_none_type_is_no_auth(self):
        assert parse_auth({"type": None}) == NoAuth()

    def test_parse_dict_auth_fail_with_empty_string_type(self):
        with pytest.raises(ValueError, match="Unknown Auth type ''"):
            parse_auth({"type": ""})

    def test_parse_dict_auth(self):
        assert parse_auth(
            {"type": "basic", "username": "user", "password": "pass"}
        ) == BasicAuth(username="user", password="pass")
        assert parse_auth({"type": "bearer", "token": "token"}) == BearerAuth(
            token="token"
        )

    def test_parse_dict_auth_allows_empty_credentials(self):
        with pytest.raises(ValueError, match="String should have at least 1 character"):
            parse_auth({"type": "basic", "username": "", "password": ""})
        with pytest.raises(ValueError, match="String should have at least 1 character"):
            parse_auth({"type": "bearer", "token": ""})

    def test_parse_dict_auth_missing_type(self):
        with pytest.raises(ValueError, match="Auth configuration error: 'type'"):
            parse_auth({"username": "user", "password": "pass"})

    def test_parse_dict_auth_basic_extra_fields_are_not_allowed(self):
        with pytest.raises(ValueError, match="Unexpected keyword argument"):
            parse_auth(
                {
                    "type": "basic",
                    "username": "user",
                    "password": "pass",
                    "extra": "field",
                }
            )

    def test_parse_dict_auth_basic_missing_username(self):
        with pytest.raises(ValueError, match="Field required"):
            parse_auth({"type": "basic", "password": "pass"})

    def test_parse_dict_auth_basic_missing_credentials(self):
        with pytest.raises(ValueError, match="Field required"):
            parse_auth({"type": "basic"})

    def test_parse_dict_auth_bearer_missing_credentials(self):
        with pytest.raises(ValueError, match="Field required"):
            parse_auth({"type": "bearer"})

    def test_parse_dict_auth_unknown_auth_type(self):
        with pytest.raises(ValueError, match="Unknown Auth type 'unknown'"):
            parse_auth({"type": "unknown", "token": "token"})

    def test_parse_list_auth_basic_empty_list(self):
        with pytest.raises(
            ValueError, match="Auth configuration error: pop from empty list"
        ):
            parse_auth([])

    def test_parse_auth_list(self):
        assert parse_auth([None]) == NoAuth()
        assert parse_auth(["basic", "user", "pass"]) == BasicAuth(
            username="user", password="pass"
        )
        assert parse_auth(["bearer", "token"]) == BearerAuth(token="token")

    def test_parse_list_auth_fail_with_empty_credentials(self):
        with pytest.raises(ValueError, match="String should have at least 1 character"):
            parse_auth(["basic", "", ""])
        with pytest.raises(ValueError, match="String should have at least 1 character"):
            parse_auth(["bearer", ""])

    def test_parse_list_auth_fail_with_empty_string_type(self):
        with pytest.raises(ValueError, match="Unknown Auth type ''"):
            parse_auth([""])

    def test_parse_list_auth_basic_missing_username(self):
        with pytest.raises(ValueError, match="Field required"):
            parse_auth(["basic", "pass"])

    def test_parse_list_auth_basic_missing_credentials(self):
        with pytest.raises(ValueError, match="Field required"):
            parse_auth(["basic"])

    def test_parse_list_auth_bearer_missing_credentials(self):
        with pytest.raises(ValueError, match="Field required"):
            parse_auth(["bearer"])

    def test_parse_list_auth_basic_extra_fields_not_allowed(self):
        with pytest.raises(ValueError, match="Unexpected positional argument"):
            parse_auth(["basic", "user", "pass", "extra", "field"])

    def test_parse_list_auth_bearer_extra_fields_not_allowed(self):
        with pytest.raises(ValueError, match="Unexpected positional argument"):
            parse_auth(["bearer", "token", "extra", "field"])

    def test_parse_list_auth_unknown_auth_type(self):
        with pytest.raises(ValueError, match="Unknown Auth type 'unknown'"):
            parse_auth(["unknown"])

    def test_parse_auth_logs_context_for_unknown_type(self, caplog):
        with (
            caplog.at_level(logging.ERROR),
            pytest.raises(ValueError, match="Unknown Auth type 'unknown'"),
        ):
            parse_auth({"type": "unknown"}, context="IntrospectionValidationConfig")
        assert (
            "IntrospectionValidationConfig: Auth configuration error: Unknown Auth type 'unknown'"
            in caplog.text
        )

    def test_parse_auth_logs_context_for_missing_credentials(self, caplog):
        with (
            caplog.at_level(logging.ERROR),
            pytest.raises(ValueError, match="Field required"),
        ):
            parse_auth({"type": "basic"}, context="NotifyOnRegistration")
        assert "NotifyOnRegistration: Auth configuration error:" in caplog.text


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
            pytest.raises(ValueError, match="Unknown Auth type 'unknown'"),
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
            "IntrospectionValidationConfig: Auth configuration error: Unknown Auth type 'unknown'"
            in caplog.text
        )

    def test_notify_on_registration_auth_error_logs_config_class(self, caplog):
        with (
            caplog.at_level(logging.ERROR),
            pytest.raises(ValueError, match="Unknown Auth type 'unknown'"),
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
            "NotifyOnRegistration: Auth configuration error: Unknown Auth type 'unknown'"
            in caplog.text
        )

    def test_introspection_missing_credentials_logs_config_class(self, caplog):
        with (
            caplog.at_level(logging.ERROR),
            pytest.raises(ValueError, match="Field required"),
        ):
            TokenAuthenticatorConfig(
                {
                    "oauth": {
                        "introspection_validation": {
                            "endpoint": "http://idp.test/introspect",
                            "auth": {"type": "basic"},
                        },
                    }
                }
            )
        assert "IntrospectionValidationConfig: Auth configuration error:" in caplog.text
