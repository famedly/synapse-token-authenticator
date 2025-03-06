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
import json
import logging
import re
from collections.abc import Awaitable
from typing import Callable, List, Optional, Tuple
from urllib.parse import urljoin

import synapse
from jwcrypto import jwk, jwt
from jwcrypto.jwk import JWKSet
from jwcrypto.common import JWException, json_decode
from synapse.api.errors import HttpResponseException
from synapse.module_api import ModuleApi
from synapse.types import UserID
from twisted.web import resource
from twisted.internet import defer

from synapse_token_authenticator.config import TokenAuthenticatorConfig
from synapse_token_authenticator.utils import (
    get_oidp_metadata,
    basic_auth,
    validate_scopes,
    all_list_elems_are_equal_return_the_elem,
    get_path_in_dict,
    if_not_none,
    MetadataResource,
)

logger = logging.getLogger(__name__)


class TokenAuthenticator:
    __version__ = "0.0.0"

    def __init__(self, config: dict, account_handler: ModuleApi):
        self.api = account_handler

        auth_checkers = {}

        self.config: TokenAuthenticatorConfig = config
        if (jwt := getattr(self.config, "jwt", None)) is not None:
            if jwt.secret:
                k = {
                    "k": base64.urlsafe_b64encode(jwt.secret.encode("utf-8")).decode(
                        "utf-8"
                    ),
                    "kty": "oct",
                }
                self.key = jwk.JWK(**k)
            else:
                with open(jwt.keyfile) as f:
                    self.key = jwk.JWK.from_pem(f.read())
            auth_checkers[("com.famedly.login.token", ("token",))] = self.check_jwt_auth

        if (oidc := getattr(self.config, "oidc", None)) is not None:
            auth_checkers[("com.famedly.login.token.oidc", ("token",))] = (
                self.check_oidc_auth
            )

            self.api.register_web_resource(
                "/_famedly/login/com.famedly.login.token.oidc",
                self.LoginMetadataResource(oidc),
            )

        if (cfg := getattr(self.config, "oauth", None)) is not None:
            if cfg.expose_metadata_resource:
                resource_name = cfg.expose_metadata_resource["name"]
                self.api.register_web_resource(
                    f"/_famedly/login/{resource_name}",
                    MetadataResource(cfg.expose_metadata_resource),
                )

            auth_checkers[("com.famedly.login.token.oauth", ("token",))] = (
                self.check_oauth
            )

        if (cfg := getattr(self.config, "epa", None)) is not None:
            if cfg.expose_metadata_resource:
                resource_name = cfg.expose_metadata_resource["name"]
                self.api.register_web_resource(
                    f"/_famedly/login/{resource_name}",
                    MetadataResource(cfg.expose_metadata_resource),
                )

            # Registers the encryption public keys
            keys = JWKSet()
            keys.add(self.config.epa.enc_jwk)
            self.api.register_web_resource(
                self.config.epa.enc_jwks_endpoint, self.PublicKeysResource(keys)
            )

            auth_checkers[("com.famedly.login.token.epa", ("token",))] = self.check_epa

        self.api.register_password_auth_provider_callbacks(auth_checkers=auth_checkers)

    class LoginMetadataResource(resource.Resource):
        def __init__(self, oidc_config: object):
            self.issuer = oidc_config.issuer
            self.metadata_url = urljoin(
                oidc_config.issuer, "/.well-known/openid-configuration"
            )
            self.organization_id = oidc_config.organization_id
            self.project_id = oidc_config.project_id

        def render_GET(self, request):
            request.setHeader(b"content-type", b"application/json")
            request.setHeader(b"access-control-allow-origin", b"*")
            return json.dumps(
                {
                    "issuer": self.issuer,
                    "issuer-metadata": self.metadata_url,
                    "organization-id": self.organization_id,
                    "project-id": self.project_id,
                }
            ).encode("utf-8")

    class PublicKeysResource(resource.Resource):
        def __init__(self, keys: JWKSet):
            self.keys = keys.export(private_keys=False).encode("utf-8")

        def render_GET(self, request):
            request.setHeader(b"content-type", b"application/json")
            request.setHeader(b"access-control-allow-origin", b"*")
            return self.keys

    async def check_jwt_auth(
        self, username: str, login_type: str, login_dict: "synapse.module_api.JsonDict"
    ) -> Optional[
        tuple[
            str,
            Optional[Callable[["synapse.module_api.LoginResponse"], Awaitable[None]]],
        ]
    ]:
        logger.info("Receiving auth request")
        if login_type != "com.famedly.login.token":
            logger.info("Wrong login type")
            return None
        if "token" not in login_dict:
            logger.info("Missing token")
            return None
        token = login_dict["token"]

        check_claims: dict = {}
        if self.config.jwt.require_expiry:
            check_claims["exp"] = None
        try:
            # OK, let's verify the token
            token = jwt.JWT(
                jwt=token,
                key=self.key,
                check_claims=check_claims,
                algs=[self.config.jwt.algorithm],
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
        if (
            "type" in payload
            and payload["type"] == "chatbox"
            and not re.search(
                "[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}$",
                user_id.localpart,
            )
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
        if not user_exists and not self.config.jwt.allow_registration:
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
            await self.api._hs.get_profile_handler().set_displayname(
                requester=synapse.types.create_requester(user_id),
                target_user=user_id,
                by_admin=True,
                new_displayname=payload["displayname"],
            )

        logger.info("All done and valid, logging in!")
        return (user_id_str, None)

    async def check_oidc_auth(
        self, username: str, login_type: str, login_dict: "synapse.module_api.JsonDict"
    ) -> Optional[
        tuple[
            str,
            Optional[Callable[["synapse.module_api.LoginResponse"], Awaitable[None]]],
        ]
    ]:
        logger.info("Receiving auth request")
        if login_type != "com.famedly.login.token.oidc":
            logger.info("Wrong login type")
            return None
        if "token" not in login_dict:
            logger.info("Missing token")
            return None
        token = login_dict["token"]

        client = self.api._hs.get_proxied_http_client()
        oidc = self.config.oidc
        oidc_metadata = await get_oidp_metadata(oidc.issuer, client)

        # Further validation using token introspection
        data = {"token": token, "token_type_hint": "access_token", "scope": "openid"}

        try:
            introspection_resp = await client.post_urlencoded_get_json(
                oidc_metadata.introspection_endpoint,
                data,
                headers=basic_auth(oidc.client_id, oidc.client_secret),
            )
        except HttpResponseException as e:
            if e.code == 401:
                logger.info("User's access token is invalid")
                return None
            else:
                raise e

        if not introspection_resp["active"]:
            logger.info("User is not active")
            return None

        allowed_roles = ["User", "OrgAdmin"]

        if not any(
            [
                role in allowed_roles
                for role in introspection_resp[
                    f"urn:zitadel:iam:org:project:{oidc.project_id}:roles"
                ]
            ]
        ):
            logger.info("User does not have a role in this project")
            return None

        if introspection_resp["iss"] != oidc_metadata.issuer:
            logger.info(f"Token issuer does not match: {introspection_resp['iss']}")
            return None

        if (
            oidc.allowed_client_ids is not None
            and introspection_resp["client_id"] not in oidc.allowed_client_ids
        ):
            logger.info(
                f"Client {introspection_resp['client_id']} is not in the list of allowed clients"
            )
            return None

        # Checking if the user's localpart matches
        user_id_str = self.api.get_qualified_user_id(username)
        user_id = UserID.from_string(user_id_str)

        if introspection_resp["localpart"] != user_id.localpart:
            logger.info("The provided username is incorrect")
            return None

        user_exists = await self.api.check_user_exists(user_id_str)
        if not user_exists and not self.config.oidc.allow_registration:
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
    ) -> Optional[
        tuple[
            str,
            Optional[Callable[["synapse.module_api.LoginResponse"], Awaitable[None]]],
        ]
    ]:
        config = self.config.oauth
        logger.info("Receiving auth request")
        if login_type != "com.famedly.login.token.oauth":
            logger.info("Wrong login type")
            return None
        if "token" not in login_dict:
            logger.info("Missing token")
            return None
        token = login_dict["token"]

        client = self.api._hs.get_proxied_http_client()

        jwt_claims = {}

        if config.jwt_validation is not None:
            check_claims: dict = {}
            if config.jwt_validation.require_expiry:
                check_claims["exp"] = None
            if config.jwt_validation.jwks_endpoint:
                jwks_json = await client.get_raw(
                    config.jwt_validation.jwks_endpoint,
                )
                config.jwt_validation.jwk_set = JWKSet.from_json(jwks_json)
            try:
                token = jwt.JWT(
                    jwt=token,
                    key=config.jwt_validation.jwk_set,
                    check_claims=check_claims,
                )
            except ValueError as e:
                logger.info("Unrecognized token %s", e)
                return None
            except JWException as e:
                logger.info("Invalid token %s", e)
                return None

            jwt_claims = json_decode(token.claims)

            if config.jwt_validation.required_scopes:
                provided_scope = jwt_claims.get("scope")
                if not isinstance(provided_scope, str):
                    logger.info("Token missing scope claim")
                    return None

                if not validate_scopes(
                    config.jwt_validation.required_scopes, provided_scope
                ):
                    logger.info("Token scope validation failed")
                    return None

            if not config.jwt_validation.validator.validate(jwt_claims):
                logger.info("Token claims validation failed")
                return None

        introspection_claims = {}

        if config.introspection_validation is not None:
            try:
                introspection_claims = await client.post_urlencoded_get_json(
                    config.introspection_validation.endpoint,
                    {"token": token},
                    headers=config.introspection_validation.auth.header_map(),
                )
            except HttpResponseException as e:
                if e.code == 401:
                    logger.info("Introspection auth failed")
                    return None
                else:
                    raise e

            if config.introspection_validation.required_scopes:
                provided_scope = introspection_claims.get("scope")
                if not isinstance(provided_scope, str):
                    logger.info("Token missing scope claim")
                    return None

                if not validate_scopes(
                    config.introspection_validation.required_scopes, provided_scope
                ):
                    logger.info("Token scope validation failed")
                    return None

            if not config.introspection_validation.validator.validate(
                introspection_claims
            ):
                logger.info("Introspection response validation failed for a token")
                return None

        # getting localpart and fully qualified user_id, validate all sources for equality

        def get_from_set(set_):
            return if_not_none(lambda path: get_path_in_dict(path, set_))

        username_type = config.username_type

        try:
            get_localpart_mb = if_not_none(lambda x: x.localpart_path)

            localpart = all_list_elems_are_equal_return_the_elem(
                [
                    get_from_set(jwt_claims)(get_localpart_mb(config.jwt_validation)),
                    get_from_set(introspection_claims)(
                        get_localpart_mb(config.introspection_validation)
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

            get_fq_uid_mb = if_not_none(lambda x: x.fq_uid_path)

            fully_qualified_uid = all_list_elems_are_equal_return_the_elem(
                [
                    get_from_set(jwt_claims)(get_fq_uid_mb(config.jwt_validation)),
                    get_from_set(introspection_claims)(
                        get_fq_uid_mb(config.introspection_validation)
                    ),
                    username if username_type == "fq_uid" else None,
                    (
                        self.api.get_qualified_user_id(username)
                        if username_type == "user_id"
                        else None
                    ),
                    (
                        self.api.get_qualified_user_id(username)
                        if username_type == "localpart"
                        else None
                    ),
                ]
            )
        except Exception as e:
            logger.info(e)
            return None

        if localpart is None and fully_qualified_uid is None:
            logger.info("No user id was provided")
            return None

        if localpart is None:
            localpart = UserID.from_string(fully_qualified_uid).localpart

        if fully_qualified_uid is None:
            fully_qualified_uid = self.api.get_qualified_user_id(localpart)

        try:
            get_displayname_mb = if_not_none(lambda x: x.displayname_path)
            displayname = all_list_elems_are_equal_return_the_elem(
                [
                    get_from_set(jwt_claims)(get_displayname_mb(config.jwt_validation)),
                    get_from_set(introspection_claims)(
                        get_displayname_mb(config.introspection_validation)
                    ),
                ]
            )
        except Exception as e:
            logger.info(e)
            return None

        try:
            get_admin_mb = if_not_none(lambda x: x.admin_path)
            admin = all_list_elems_are_equal_return_the_elem(
                [
                    get_from_set(jwt_claims)(get_admin_mb(config.jwt_validation)),
                    get_from_set(introspection_claims)(
                        get_admin_mb(config.introspection_validation)
                    ),
                ]
            )
        except Exception as e:
            logger.info(e)
            return None

        try:
            get_email_mb = if_not_none(lambda x: x.email_path)
            email = all_list_elems_are_equal_return_the_elem(
                [
                    get_from_set(jwt_claims)(get_email_mb(config.jwt_validation)),
                    get_from_set(introspection_claims)(
                        get_email_mb(config.introspection_validation)
                    ),
                ]
            )
        except Exception as e:
            logger.info(e)
            return None

        try:
            external_id = all_list_elems_are_equal_return_the_elem(
                [
                    get_path_in_dict("sub", jwt_claims),
                    get_path_in_dict("sub", introspection_claims),
                ]
            )
        except Exception as e:
            logger.info(e)
            return None
        if not external_id:
            logger.info("Token is missing 'sub' claim")
            return None

        try:
            auth_provider = all_list_elems_are_equal_return_the_elem(
                [
                    get_path_in_dict("iss", jwt_claims),
                    get_path_in_dict("iss", introspection_claims),
                ]
            )
        except Exception as e:
            logger.info(e)
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
                f"User '{localpart}' created as '{  'Admin' if bool(admin) else 'User'}'"
            )

            if email:
                await self._add_user_email(user_id, email)
                logger.debug(f"Added the email for the user '{localpart}'")

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
                logger.debug(
                    f"The external_id '{external_id}' and auth_provider '{auth_provider}' don't match any of the user's stored external ids"
                )
                return None

        if displayname:
            user_id = UserID.from_string(fully_qualified_uid)
            await self.api._hs.get_profile_handler().set_displayname(
                requester=synapse.types.create_requester(user_id),
                target_user=user_id,
                by_admin=True,
                new_displayname=displayname,
            )

        logger.info("All done and valid, logging in!")
        return (fully_qualified_uid, None)

    async def check_epa(
        self, username: str, login_type: str, login_dict: "synapse.module_api.JsonDict"
    ) -> Optional[
        tuple[
            str,
            Optional[Callable[["synapse.module_api.LoginResponse"], Awaitable[None]]],
        ]
    ]:
        config = self.config.epa
        logger.info("Receiving auth request")
        if login_type != "com.famedly.login.token.epa":
            logger.info("Wrong login type")
            return None
        if "token" not in login_dict:
            logger.info("Missing token")
            return None
        token = login_dict["token"]

        if config.jwks_endpoint:
            client = self.api._hs.get_proxied_http_client()
            jwks_json = await client.get_raw(
                config.jwks_endpoint,
            )
            config.jwk_set = JWKSet.from_json(jwks_json)

        check_claims: dict = {
            "iss": config.iss,
            "exp": None,
        }
        try:
            enc_token = jwt.JWT(key=config.enc_jwk, jwt=token, expected_type="JWE")
            token = jwt.JWT(
                jwt=enc_token.claims,
                key=config.jwk_set,
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

        jwt_header = json_decode(token.header)
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

        jwt_claims = json_decode(token.claims)
        if "jti" not in jwt_claims:
            logger.info("Missing 'jti' in claims")
            return None
        if "aud" not in jwt_claims:
            logger.info("Token missing 'aud' claim")
            return None
        if config.resource_id != jwt_claims["aud"]:
            logger.info(
                f"Token has the wrong 'aud'. The expected value is '{config.resource_id}'"
            )
            return None

        localpart = get_path_in_dict(config.localpart_path, jwt_claims)
        displayname = get_path_in_dict(config.displayname_path, jwt_claims)

        if not localpart:
            logger.info("Missing localpart")
            return None
        if username != localpart:
            logger.info("The username doesn't match the localpart")
            return None

        if not config.validator.validate(jwt_claims):
            logger.info("Token claims validation failed")
            return None

        fully_qualified_uid = self.api.get_qualified_user_id(localpart)

        user_exists = await self.api.check_user_exists(fully_qualified_uid)

        if not user_exists and not config.registration_enabled:
            logger.info("User doesn't exist and registration is disabled")
            return None

        if not user_exists:
            logger.info("User doesn't exist, registering them...")
            await self.api.register_user(localpart)
            logger.info(f"User '{localpart}' registered")

        if displayname:
            user_id = UserID.from_string(fully_qualified_uid)
            await self.api._hs.get_profile_handler().set_displayname(
                requester=synapse.types.create_requester(user_id),
                target_user=user_id,
                by_admin=True,
                new_displayname=displayname,
            )

        logger.info("All done and valid, logging in!")
        return (fully_qualified_uid, None)

    @staticmethod
    def parse_config(config: dict):
        return TokenAuthenticatorConfig(config)

    def _add_user_email(self, user_id, email) -> defer.Deferred:
        return defer.ensureDeferred(
            self.api._auth_handler.add_threepid(
                user_id, "email", email, self.api._hs.get_clock().time_msec()
            )
        )

    def _get_external_id(
        self, fully_qualified_uid: str
    ) -> "defer.Deferred[List[Tuple[str, str]]]":
        return defer.ensureDeferred(
            self.api._store.get_external_ids_by_user(fully_qualified_uid)
        )
