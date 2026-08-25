import pytest
from jwcrypto.jwk import JWK
from pydantic import ValidationError

from synapse_token_authenticator.claims_validator import (
    AllOf,
    Exist,
    ListAnyOf,
    MatchesRegex,
)
from synapse_token_authenticator.config.http_auth import BasicAuth, BearerAuth, NoAuth
from synapse_token_authenticator.config.oauth_config import (
    IntrospectionValidationConfig,
    JwtValidationConfig,
    NotifyOnRegistration,
    OAuthConfig,
)
from tests import get_jwk


class TestJwtValidationConfig:
    def test_jwt_validation_config_defaults(self):
        jwk = get_jwk().export(private_key=True)
        config = JwtValidationConfig(jwk_set=jwk)
        assert config.validator == Exist()
        assert config.require_expiry is False
        assert config.localpart_path is None
        assert config.user_id_path is None
        assert config.fq_uid_path is None
        assert config.displayname_path is None
        assert config.admin_path is None
        assert config.email_path is None
        assert config.required_scopes is None
        assert isinstance(config.jwk_set, JWK)
        assert config.jwk_file is None
        assert config.jwks_endpoint is None

    def test_jwt_validation_config_full(self):
        jwk = get_jwk().export(private_key=True)
        config = JwtValidationConfig(
            validator=["list_any_of", ["in", "foo"]],
            require_expiry=True,
            localpart_path="urn:messaging:matrix:localpart",
            user_id_path=["urn", "user"],
            fq_uid_path="urn:messaging:matrix:mxid",
            displayname_path="name",
            admin_path=[["roles", "Admin"], ["roles", "OrgAdmin"]],
            email_path="email",
            required_scopes=["foo", "bar"],
            jwk_set=jwk,
            jwk_file=None,
            jwks_endpoint=None,
        )
        assert isinstance(config.validator, ListAnyOf)
        assert config.require_expiry is True
        assert config.localpart_path == "urn:messaging:matrix:localpart"
        assert config.user_id_path == ["urn", "user"]
        assert config.fq_uid_path == "urn:messaging:matrix:mxid"
        assert config.displayname_path == "name"
        assert config.admin_path == [["roles", "Admin"], ["roles", "OrgAdmin"]]
        assert config.email_path == "email"
        assert config.required_scopes == ["foo", "bar"]
        assert isinstance(config.jwk_set, JWK)

    def test_jwt_validation_config_required_scopes_accepts_str(self):
        jwk = get_jwk().export(private_key=True)
        config = JwtValidationConfig(jwk_set=jwk, required_scopes="foo bar")
        assert config.required_scopes == "foo bar"

    def test_jwt_validation_config_missing_jwk_source(self):
        with pytest.raises(ValidationError):
            JwtValidationConfig()

    def test_jwt_validation_config_jwks_endpoint_only(self):
        config = JwtValidationConfig(jwks_endpoint="https://idp.example/jwks")
        assert config.jwk_set is None
        assert config.jwks_endpoint == "https://idp.example/jwks"


class TestIntrospectionValidationConfig:
    def test_introspection_validation_config_defaults(self):
        config = IntrospectionValidationConfig(endpoint="https://example.com")

        assert config.endpoint == "https://example.com"
        assert config.validator == Exist()
        assert config.auth == NoAuth()
        assert config.localpart_path is None
        assert config.user_id_path is None
        assert config.fq_uid_path is None
        assert config.displayname_path is None
        assert config.admin_path is None
        assert config.email_path is None
        assert config.required_scopes is None

    def test_introspection_validation_config_full(self):
        config = IntrospectionValidationConfig(
            endpoint="https://idp.example/introspect",
            auth={"type": "bearer", "token": "secret-token"},
            validator={"type": "regex", "regex": "hello."},
            localpart_path="localpart",
            user_id_path=["profile", "id"],
            fq_uid_path="@user:example.test",
            displayname_path="name",
            admin_path=["admin"],
            email_path="email",
            required_scopes="openid profile",
        )
        assert config.endpoint == "https://idp.example/introspect"
        assert config.auth == BearerAuth(token="secret-token")
        assert isinstance(config.validator, MatchesRegex)
        assert config.localpart_path == "localpart"
        assert config.user_id_path == ["profile", "id"]
        assert config.fq_uid_path == "@user:example.test"
        assert config.displayname_path == "name"
        assert config.admin_path == ["admin"]
        assert config.email_path == "email"
        assert config.required_scopes == "openid profile"

    def test_introspection_validation_config_missing_endpoint(self):
        with pytest.raises(ValidationError):
            IntrospectionValidationConfig()


class TestNotifyOnRegistration:
    def test_notify_on_registration_defaults(self):
        config = NotifyOnRegistration(url="https://example.com")
        assert config.url == "https://example.com"
        assert config.auth == NoAuth()
        assert config.interrupt_on_error is True

    def test_notify_on_registration_full(self):
        config = NotifyOnRegistration(
            url="https://hook.example/notify",
            auth={"type": "bearer", "token": "hook-token"},
            interrupt_on_error=False,
        )
        assert config.url == "https://hook.example/notify"
        assert config.auth == BearerAuth(token="hook-token")
        assert config.interrupt_on_error is False

    def test_notify_on_registration_missing_url(self):
        with pytest.raises(ValidationError):
            NotifyOnRegistration()


class TestOAuthConfig:
    def test_oauth_config_defaults(self):
        jwk = get_jwk().export(private_key=True)
        config = OAuthConfig(
            jwt_validation=JwtValidationConfig(jwk_set=jwk),
            introspection_validation=IntrospectionValidationConfig(
                endpoint="https://example.com"
            ),
            username_type="user_id",
            notify_on_registration=NotifyOnRegistration(url="https://example.com"),
        )

        assert config.jwt_validation is not None
        assert config.introspection_validation is not None
        assert config.username_type == "user_id"
        assert config.notify_on_registration is not None
        assert config.expose_metadata_resource is None
        assert config.registration_enabled is False
        assert config.check_external_id is True

    def test_oauth_config_full(self):
        jwk = get_jwk().export(private_key=True)
        config = OAuthConfig(
            jwt_validation=JwtValidationConfig(
                jwk_set=jwk,
                require_expiry=True,
                localpart_path="localpart",
                required_scopes=["foo"],
            ),
            introspection_validation=IntrospectionValidationConfig(
                validator=["all_of", [["exist"], ["in", "foo", ["equal", 3]]]],
                endpoint="https://idp.example/introspect",
                auth=["bearer", "tok"],
                displayname_path="name",
            ),
            username_type="localpart",
            notify_on_registration={
                "url": "https://hook.example/notify",
                "auth": {"type": "basic", "username": "u", "password": "p"},
                "interrupt_on_error": False,
            },
            expose_metadata_resource={"name": "com.famedly.login.token.oauth"},
            registration_enabled=True,
            check_external_id=False,
        )

        assert config.jwt_validation is not None
        assert config.jwt_validation.require_expiry is True
        assert config.jwt_validation.localpart_path == "localpart"
        assert config.jwt_validation.required_scopes == ["foo"]
        assert isinstance(config.jwt_validation.jwk_set, JWK)

        assert config.introspection_validation is not None
        assert isinstance(config.introspection_validation.validator, AllOf)
        assert config.introspection_validation.auth == BearerAuth(token="tok")
        assert config.introspection_validation.displayname_path == "name"
        assert config.username_type == "localpart"

        assert config.notify_on_registration is not None
        assert config.notify_on_registration.url == "https://hook.example/notify"
        assert config.notify_on_registration.auth == BasicAuth(
            username="u", password="p"
        )
        assert config.notify_on_registration.interrupt_on_error is False
        assert config.expose_metadata_resource.model_dump() == {
            "name": "com.famedly.login.token.oauth"
        }
        assert config.registration_enabled is True
        assert config.check_external_id is False

    def test_oauth_config_valid_username_types(self):
        jwk = get_jwk().export(private_key=True)
        for username_type in ("fq_uid", "localpart", "user_id"):
            config = OAuthConfig(
                jwt_validation=JwtValidationConfig(jwk_set=jwk),
                username_type=username_type,
            )
            assert config.username_type == username_type

    def test_oauth_config_invalid_username_type(self):
        jwk = get_jwk().export(private_key=True)
        with pytest.raises(ValidationError):
            OAuthConfig(
                jwt_validation=JwtValidationConfig(jwk_set=jwk),
                introspection_validation=IntrospectionValidationConfig(
                    endpoint="https://example.com"
                ),
                username_type="invalid username type like email",
            )

    def test_oauth_config_missing_jwt_validation_or_introspection_validation(self):
        with pytest.raises(ValidationError):
            OAuthConfig(
                username_type="user_id",
                notify_on_registration=NotifyOnRegistration(url="https://example.com"),
            )

    def test_oauth_config_jwt_validation_only(self):
        jwk = get_jwk().export(private_key=True)
        config = OAuthConfig(jwt_validation=JwtValidationConfig(jwk_set=jwk))
        assert config.jwt_validation is not None
        assert config.introspection_validation is None

    def test_oauth_config_introspection_validation_only(self):
        config = OAuthConfig(
            introspection_validation=IntrospectionValidationConfig(
                endpoint="https://example.com"
            )
        )
        assert config.jwt_validation is None
        assert config.introspection_validation is not None
