# Copyright (C) 2024 Famedly
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
import base64
import logging
import re
from collections.abc import Awaitable, Callable
from http import HTTPStatus
from typing import Any, TypeAlias

import synapse
from jwcrypto import jwk, jwt
from jwcrypto.common import JWException, json_decode
from jwcrypto.jwk import JWK, JWKSet
from synapse.api.errors import HttpResponseException
from synapse.module_api import ModuleApi
from synapse.types import UserID
from twisted.internet import defer

from synapse_token_authenticator.config import (
    IntrospectionValidationConfig,
    JwtValidationConfig,
    OAuthConfig,
    TokenAuthenticatorConfig,
)
from synapse_token_authenticator.http_auth import BasicAuth
from synapse_token_authenticator.login_metadata import LoginMetadataResource
from synapse_token_authenticator.metadata import MetadataResource
from synapse_token_authenticator.public_key import PublicKeysResource
from synapse_token_authenticator.utils import (
    all_list_elems_are_equal_return_the_elem,
    get_oidp_metadata,
    get_path_in_dict,
    validate_scopes,
)

logger = logging.getLogger(__name__)

LoginCallback: TypeAlias = Callable[
    ["synapse.module_api.LoginResponse"], Awaitable[None]
]
AuthResult: TypeAlias = tuple[str, LoginCallback | None] | None

UUID_SUFFIX_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}$"
)


def _claim_from_validation_configs(
    attr: str,
    jwt_claims: dict,
    introspection_claims: dict,
    jwt_validation: JwtValidationConfig | None,
    introspection_validation: IntrospectionValidationConfig | None,
) -> Any:
    """Read the same path attribute from JWT and introspection claim sets."""

    def read(
        claims: dict, cfg: JwtValidationConfig | IntrospectionValidationConfig | None
    ) -> Any:
        path = getattr(cfg, attr, None) if cfg is not None else None
        return get_path_in_dict(path, claims) if path is not None else None

    return all_list_elems_are_equal_return_the_elem(
        [
            read(jwt_claims, jwt_validation),
            read(introspection_claims, introspection_validation),
        ]
    )


class TokenAuthenticator:
    __version__ = "0.13.1"

    def __init__(self, config: TokenAuthenticatorConfig, module_api: ModuleApi):
        auth_checkers: dict[tuple[str, tuple[str, ...]], Any] = {}
        self.api = module_api
        self.config = config

        if self.config.jwt:
            self.key = self._load_jwt_key()
            auth_checkers[("com.famedly.login.token", ("token",))] = self.check_jwt_auth

        if self.config.oidc:
            auth_checkers[("com.famedly.login.token.oidc", ("token",))] = (
                self.check_oidc_auth
            )
            self.api.register_web_resource(
                "/_famedly/login/com.famedly.login.token.oidc",
                LoginMetadataResource(self.config.oidc),
            )

        if self.config.oauth:
            self._maybe_register_metadata_resource(
                self.config.oauth.expose_metadata_resource
            )
            auth_checkers[("com.famedly.login.token.oauth", ("token",))] = (
                self.check_oauth
            )

        if self.config.epa:
            self._maybe_register_metadata_resource(
                self.config.epa.expose_metadata_resource
            )

            keys = JWKSet()
            if self.config.epa.enc_jwk:
                keys.add(self.config.epa.enc_jwk)
            self.api.register_web_resource(
                self.config.epa.enc_jwks_endpoint, PublicKeysResource(keys)
            )
            auth_checkers[("com.famedly.login.token.epa", ("token",))] = self.check_epa

        self.api.register_password_auth_provider_callbacks(auth_checkers=auth_checkers)

    def _load_jwt_key(self) -> JWK:
        jwt_config = self.config.jwt
        if jwt_config and jwt_config.secret:
            k = {
                "k": base64.urlsafe_b64encode(jwt_config.secret.encode("utf-8")).decode(
                    "utf-8"
                ),
                "kty": "oct",
            }
            return jwk.JWK(**k)
        assert jwt_config and jwt_config.keyfile
        with open(jwt_config.keyfile, "rb") as f:
            return jwk.JWK.from_pem(f.read())

    def _maybe_register_metadata_resource(self, expose_metadata_resource: Any) -> None:
        if not expose_metadata_resource:
            return
        resource_name = expose_metadata_resource["name"]
        self.api.register_web_resource(
            f"/_famedly/login/{resource_name}",
            MetadataResource(expose_metadata_resource),
        )

    async def check_jwt_auth(
        self, username: str, login_type: str, login_dict: "synapse.module_api.JsonDict"
    ) -> AuthResult:
        jwt_config = self.config.jwt
        assert jwt_config

        logger.info("Receiving auth request")
        if login_type != "com.famedly.login.token":
            logger.info("Wrong login type")
            return None
        if "token" not in login_dict:
            logger.info("Missing token")
            return None
        token = login_dict["token"]

        check_claims: dict = {}
        if jwt_config and jwt_config.require_expiry:
            check_claims["exp"] = None
        try:
            # OK, let's verify the token
            token = jwt.JWT(
                jwt=token,
                key=self.key,
                check_claims=check_claims,
                algs=[jwt_config.algorithm],
            )
        except ValueError as e:
            logger.info("Unrecognized token %s", e)
            return None
        except JWException as e:
            logger.info("Invalid token %s", e)
            return None
        payload = json_decode(token.claims)
        if "sub" not in payload:
            logger.info("Missing user_id field")
            return None
        token_user_id_or_localpart = payload["sub"]
        if not isinstance(token_user_id_or_localpart, str):
            logger.info("user_id isn't a string")
            return None

        token_user_id_str = self.api.get_qualified_user_id(token_user_id_or_localpart)
        user_id_str = self.api.get_qualified_user_id(username)
        user_id = UserID.from_string(user_id_str)

        # checking whether required UUID contained in case of chatbox mode
        if payload.get("type") == "chatbox" and not UUID_SUFFIX_RE.search(
            user_id.localpart
        ):
            logger.info("user_id does not end with a UUID even though in chatbox mode")
            return None

        if user_id.domain != self.api.server_name:
            logger.info("user_id isn't for our homeserver")
            return None

        if user_id_str != token_user_id_str:
            logger.info("Non-matching user")
            return None

        user_exists = await self.api.check_user_exists(user_id_str)
        if not user_exists and not jwt_config.allow_registration:
            logger.info("User doesn't exist and registration is disabled")
            return None

        if not user_exists:
            logger.info("User doesn't exist, registering them...")
            await self.api.register_user(
                user_id.localpart, admin=payload.get("admin", False)
            )

        if "admin" in payload:
            await self.api.set_user_admin(user_id_str, payload["admin"])

        if "displayname" in payload:
            await self.api.set_displayname(
                user_id=user_id,
                new_displayname=payload["displayname"],
            )

        logger.info("All done and valid, logging in!")
        return (user_id_str, None)

    async def check_oidc_auth(
        self, username: str, login_type: str, login_dict: "synapse.module_api.JsonDict"
    ) -> AuthResult:
        oidc_config = self.config.oidc
        assert oidc_config

        logger.info("Receiving auth request")
        if login_type != "com.famedly.login.token.oidc":
            logger.info("Wrong login type")
            return None
        if "token" not in login_dict:
            logger.info("Missing token")
            return None
        token = login_dict["token"]

        client = self.api._hs.get_proxied_http_client()
        oidc_metadata = await get_oidp_metadata(oidc_config.issuer, client)

        # Further validation using token introspection
        data = {"token": token, "token_type_hint": "access_token", "scope": "openid"}

        try:
            introspection_resp = await client.post_urlencoded_get_json(
                oidc_metadata.introspection_endpoint,
                data,
                headers=BasicAuth(
                    username=oidc_config.client_id, password=oidc_config.client_secret
                ).header_map(),
            )
        except HttpResponseException as e:
            if e.code == HTTPStatus.UNAUTHORIZED:
                logger.info("User's access token is invalid")
                return None
            raise

        if not introspection_resp["active"]:
            logger.info("User is not active")
            return None

        allowed_roles = ["User", "OrgAdmin"]
        project_roles = introspection_resp[
            f"urn:zitadel:iam:org:project:{oidc_config.project_id}:roles"
        ]

        if not any(role in allowed_roles for role in project_roles):
            logger.info("User does not have a role in this project")
            return None

        if introspection_resp["iss"] != oidc_metadata.issuer:
            logger.info("Token issuer does not match: %s", introspection_resp["iss"])
            return None

        if (
            oidc_config.allowed_client_ids is not None
            and introspection_resp["client_id"] not in oidc_config.allowed_client_ids
        ):
            logger.info(
                "Client %s is not in the list of allowed clients",
                introspection_resp["client_id"],
            )
            return None

        # Checking if the user's localpart matches
        user_id_str = self.api.get_qualified_user_id(username)
        user_id = UserID.from_string(user_id_str)

        if introspection_resp["localpart"] != user_id.localpart:
            logger.info("The provided username is incorrect")
            return None

        user_exists = await self.api.check_user_exists(user_id_str)
        if not user_exists and not oidc_config.allow_registration:
            logger.info("User doesn't exist and registration is disabled")
            return None

        if not user_exists:
            logger.info("User doesn't exist, registering it...")
            await self.api.register_user(user_id.localpart)

        user_id_str = self.api.get_qualified_user_id(username)

        logger.info("All done and valid, logging in!")
        return (user_id_str, None)

    async def check_oauth(
        self, username: str, login_type: str, login_dict: "synapse.module_api.JsonDict"
    ) -> AuthResult:
        oauth_config = self.config.oauth
        assert oauth_config

        logger.info("Receiving auth request")
        if login_type != "com.famedly.login.token.oauth":
            logger.info("Wrong login type")
            return None
        if "token" not in login_dict:
            logger.info("Missing token")
            return None
        token = login_dict["token"]

        client = self.api._hs.get_proxied_http_client()

        jwt_claims: dict = {}
        if oauth_config.jwt_validation:
            jwt_claims_or_none = await self._validate_oauth_jwt(
                token, oauth_config.jwt_validation, client
            )
            if jwt_claims_or_none is None:
                return None
            jwt_claims = jwt_claims_or_none

        introspection_claims: dict = {}
        if oauth_config.introspection_validation:
            introspection_claims_or_none = await self._validate_oauth_introspection(
                token, oauth_config.introspection_validation, client
            )
            if introspection_claims_or_none is None:
                return None
            introspection_claims = introspection_claims_or_none

        return await self._finish_oauth_login(
            username, oauth_config, jwt_claims, introspection_claims, client
        )

    async def _validate_oauth_jwt(
        self,
        token: str,
        jwt_validation: JwtValidationConfig,
        client,
    ) -> dict | None:
        check_claims: dict = {}
        if jwt_validation.require_expiry:
            check_claims["exp"] = None

        jwk_set: JWKSet | JWK | None = jwt_validation.jwk_set
        if jwt_validation.jwks_endpoint:
            jwks_json = await client.get_raw(jwt_validation.jwks_endpoint)
            jwk_set = JWKSet.from_json(jwks_json)

        try:
            verified = jwt.JWT(
                jwt=token,
                key=jwk_set,
                check_claims=check_claims,
            )
        except ValueError as e:
            logger.info("Unrecognized token %s", e)
            return None
        except JWException as e:
            logger.info("Invalid token %s", e)
            return None

        jwt_claims = json_decode(verified.claims)

        if jwt_validation.required_scopes:
            provided_scope = jwt_claims.get("scope")
            if not isinstance(provided_scope, str):
                logger.info("Token missing scope claim")
                return None
            if not validate_scopes(jwt_validation.required_scopes, provided_scope):
                logger.info("Token scope validation failed")
                return None

        if not jwt_validation.validator.validate(jwt_claims):
            logger.info("Token claims validation failed")
            return None

        return jwt_claims

    async def _validate_oauth_introspection(
        self,
        token: str,
        introspection_validation: IntrospectionValidationConfig,
        client,
    ) -> dict | None:
        try:
            introspection_claims = await client.post_urlencoded_get_json(
                introspection_validation.endpoint,
                {"token": token},
                headers=introspection_validation.auth.header_map(),
            )
        except HttpResponseException as e:
            if e.code == HTTPStatus.UNAUTHORIZED:
                logger.info("Introspection auth failed")
                return None
            raise

        if introspection_validation.required_scopes:
            provided_scope = introspection_claims.get("scope")
            if not isinstance(provided_scope, str):
                logger.info("Token missing scope claim")
                return None
            if not validate_scopes(
                introspection_validation.required_scopes, provided_scope
            ):
                logger.info("Token scope validation failed")
                return None

        if not introspection_validation.validator.validate(introspection_claims):
            logger.info("Introspection response validation failed for a token")
            return None

        return introspection_claims

    async def _finish_oauth_login(
        self,
        username: str,
        config: OAuthConfig,
        jwt_claims: dict,
        introspection_claims: dict,
        client,
    ) -> AuthResult:
        username_type = config.username_type
        jwt_validation = config.jwt_validation
        introspection_validation = config.introspection_validation

        def read_path(claims: dict, path: Any) -> Any:
            return get_path_in_dict(path, claims) if path is not None else None

        try:
            localpart = all_list_elems_are_equal_return_the_elem(
                [
                    read_path(
                        jwt_claims,
                        jwt_validation.localpart_path if jwt_validation else None,
                    ),
                    read_path(
                        introspection_claims,
                        (
                            introspection_validation.localpart_path
                            if introspection_validation
                            else None
                        ),
                    ),
                    username if username_type == "localpart" else None,
                    (
                        UserID.from_string(username).localpart
                        if username_type == "fq_uid"
                        else None
                    ),
                    (
                        UserID.from_string(
                            self.api.get_qualified_user_id(username)
                        ).localpart
                        if username_type == "user_id"
                        else None
                    ),
                ]
            )

            fully_qualified_uid = all_list_elems_are_equal_return_the_elem(
                [
                    read_path(
                        jwt_claims,
                        jwt_validation.fq_uid_path if jwt_validation else None,
                    ),
                    read_path(
                        introspection_claims,
                        (
                            introspection_validation.fq_uid_path
                            if introspection_validation
                            else None
                        ),
                    ),
                    username if username_type == "fq_uid" else None,
                    (
                        self.api.get_qualified_user_id(username)
                        if username_type in ("user_id", "localpart")
                        else None
                    ),
                ]
            )
        except Exception as e:  # noqa: BLE001
            logger.info("%s", e)
            return None

        if localpart is None and fully_qualified_uid is None:
            logger.info("No user id was provided")
            return None

        if localpart is None:
            localpart = UserID.from_string(fully_qualified_uid).localpart

        if fully_qualified_uid is None:
            fully_qualified_uid = self.api.get_qualified_user_id(localpart)

        try:
            displayname = _claim_from_validation_configs(
                "displayname_path",
                jwt_claims,
                introspection_claims,
                jwt_validation,
                introspection_validation,
            )
            admin = _claim_from_validation_configs(
                "admin_path",
                jwt_claims,
                introspection_claims,
                jwt_validation,
                introspection_validation,
            )
            email = _claim_from_validation_configs(
                "email_path",
                jwt_claims,
                introspection_claims,
                jwt_validation,
                introspection_validation,
            )
            external_id = all_list_elems_are_equal_return_the_elem(
                [
                    get_path_in_dict("sub", jwt_claims),
                    get_path_in_dict("sub", introspection_claims),
                ]
            )
            auth_provider = all_list_elems_are_equal_return_the_elem(
                [
                    get_path_in_dict("iss", jwt_claims),
                    get_path_in_dict("iss", introspection_claims),
                ]
            )
        except Exception as e:  # noqa: BLE001
            logger.info("%s", e)
            return None

        if not external_id:
            logger.info("Token is missing 'sub' claim")
            return None
        if not auth_provider:
            logger.info("Token is missing 'iss' claim")
            return None

        user_exists = await self.api.check_user_exists(fully_qualified_uid)

        if not user_exists and not config.registration_enabled:
            logger.info("User doesn't exist and registration is disabled")
            return None

        if not user_exists:
            logger.info("User doesn't exist, registering them...")
            if config.notify_on_registration:
                try:
                    await client.post_json_get_json(
                        config.notify_on_registration.url,
                        {
                            "localpart": localpart,
                            "fully_qualified_uid": fully_qualified_uid,
                            "displayname": displayname,
                        },
                        headers=config.notify_on_registration.auth.header_map(),
                    )
                except ValueError:
                    pass
                except HttpResponseException as e:
                    logger.info(e)
                    if config.notify_on_registration.interrupt_on_error:
                        return None

            user_id = await self.api.register_user(localpart, admin=bool(admin))
            logger.debug(
                "User '%s' created as '{%s}'",
                localpart,
                "Admin" if bool(admin) else "User",
            )

            if email:
                await self._add_user_email(user_id, email)
                logger.debug("Added the email for the user '%s'", localpart)

            await self.api.record_user_external_id(
                auth_provider_id=auth_provider,
                remote_user_id=external_id,
                registered_user_id=user_id,
            )

            logger.info("Registered user %s (%s)", localpart, displayname)

        if config.check_external_id and user_exists:
            external_ids = await self._get_external_id(fully_qualified_uid)
            if (
                len(external_ids) > 0
                and (auth_provider, external_id) not in external_ids
            ):
                logger.info("User didn't pass on the external id check")
                logger.debug(
                    "The external_id '%s' and auth_provider '%s' don't match any of the user's stored external ids",
                    external_id,
                    auth_provider,
                )
                return None

        if displayname:
            target_user = UserID.from_string(fully_qualified_uid)
            await self.api.set_displayname(
                user_id=target_user,
                new_displayname=displayname,
            )

        logger.info("All done and valid, logging in!")
        return (fully_qualified_uid, None)

    async def check_epa(
        self, _username: str, login_type: str, login_dict: "synapse.module_api.JsonDict"
    ) -> AuthResult:
        epa_config = self.config.epa
        assert epa_config is not None

        logger.info("Receiving auth request")
        if login_type != "com.famedly.login.token.epa":
            logger.info("Wrong login type")
            return None
        if "token" not in login_dict:
            logger.info("Missing token")
            return None
        token = login_dict["token"]

        jwk_set: JWKSet | JWK | None = epa_config.jwk_set
        if epa_config.jwks_endpoint:
            client = self.api._hs.get_proxied_http_client()
            jwks_json = await client.get_raw(epa_config.jwks_endpoint)
            jwk_set = JWKSet.from_json(jwks_json)

        check_claims: dict = {
            "iss": epa_config.iss,
            "exp": None,
        }
        try:
            enc_token = jwt.JWT(key=epa_config.enc_jwk, jwt=token, expected_type="JWE")
            verified = jwt.JWT(
                jwt=enc_token.claims,
                key=jwk_set,
                check_claims=check_claims,
            )
        except ValueError as e:
            logger.info("Unrecognized token %s", e)
            return None
        except JWException as e:
            logger.info("Invalid token %s", e)
            return None
        except TypeError as e:
            logger.info("Invalid token type %s", e)
            return None

        jwt_header = json_decode(verified.header)
        if "typ" not in jwt_header:
            logger.info("Token missing 'typ' in the header")
            return None
        if jwt_header["typ"] not in ["at+jwt", "application/at+jwt"]:
            logger.info(
                "Token has the wrong 'typ' in the header. Only 'at+jwt' or 'application/at+jwt' are accepted"
            )
            return None
        if "alg" not in jwt_header or jwt_header["alg"] == "none":
            logger.info("Token can't be signed with algorithm 'none'")
            return None

        jwt_claims = json_decode(verified.claims)
        if "jti" not in jwt_claims:
            logger.info("Missing 'jti' in claims")
            return None
        if "aud" not in jwt_claims:
            logger.info("Token missing 'aud' claim")
            return None
        if epa_config.resource_id != jwt_claims["aud"]:
            logger.info(
                "Token has the wrong 'aud'. The expected value is '%s'",
                epa_config.resource_id,
            )
            return None

        localpart = (
            get_path_in_dict(epa_config.localpart_path, jwt_claims)
            if epa_config.localpart_path
            else None
        )
        displayname = (
            get_path_in_dict(epa_config.displayname_path, jwt_claims)
            if epa_config.displayname_path
            else None
        )

        if not localpart:
            logger.info("Missing localpart")
            return None

        if epa_config.lowercase_localpart:
            localpart = localpart.lower()

        if not epa_config.validator.validate(jwt_claims):
            logger.info("Token claims validation failed")
            return None

        fully_qualified_uid = self.api.get_qualified_user_id(localpart)

        user_exists = await self.api.check_user_exists(fully_qualified_uid)

        if not user_exists and not epa_config.registration_enabled:
            logger.info("User doesn't exist and registration is disabled")
            return None

        if not user_exists:
            logger.info("User doesn't exist, registering them...")
            await self.api.register_user(localpart)
            logger.info("User '%s' registered", localpart)

        if displayname:
            target_user = UserID.from_string(fully_qualified_uid)
            await self.api.set_displayname(
                user_id=target_user,
                new_displayname=displayname,
            )

        logger.info("All done and valid, logging in!")
        return (fully_qualified_uid, None)

    @staticmethod
    def parse_config(config: dict) -> TokenAuthenticatorConfig:
        return TokenAuthenticatorConfig.model_validate(config)

    def _add_user_email(self, user_id, email) -> defer.Deferred:
        return defer.ensureDeferred(
            self.api._auth_handler.add_threepid(
                user_id, "email", email, self.api._hs.get_clock().time_msec()
            )
        )

    def _get_external_id(
        self, fully_qualified_uid: str
    ) -> "defer.Deferred[list[tuple[str, str]]]":
        return defer.ensureDeferred(
            self.api._store.get_external_ids_by_user(fully_qualified_uid)
        )
