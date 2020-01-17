# -*- coding: utf-8 -*-
# Copyright (C) 2019 Famedly
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

from twisted.internet import defer
import logging
from jwcrypto import jwt, jwk
from jwcrypto.common import JWException, json_decode
import os
import base64
import re

logger = logging.getLogger(__name__)

class TokenAuthenticator(object):
	__version__ = "0.0.0"

	def __init__(self, config, account_handler):
		self.account_handler = account_handler
		self.config = config
		if self.config.secret:
			k = {
				"k": base64.urlsafe_b64encode(self.config.secret.encode("utf-8")).decode("utf-8"),
				"kty": "oct",
			}
			self.key = jwk.JWK(**k)
		else:
			with open(self.config.keyfile, "r") as f:
				self.key = jwk.JWK.from_pem(f.read())

	def get_supported_login_types(self):
		return {"com.famedly.login.token": ("token",)}

	@defer.inlineCallbacks
	def check_auth(self, username_provided, login_type, login_dict):
		logger.info("Receiving auth request")
		if login_type != "com.famedly.login.token":
			logger.info("Wrong login type")
			defer.returnValue(None)
			return
		token = login_dict["token"]
		if not token:
			logger.info("Missing token")
			defer.returnValue(None)
			return

		check_claims = {}
		if self.config.require_expiracy:
			check_claims["exp"] = None
		try:
			# OK, let's verify the token
			t = jwt.JWT(jwt=token, key=self.key, check_claims=check_claims)
		except JWException as e:
			logger.info("Invalid token", e)
			defer.returnValue(None)
			return
		payload = json_decode(t.claims)
		if "sub" not in payload:
			logger.info("Missing user_id field")
			defer.returnValue(None)
			return
		user_id_or_localpart = payload["sub"]
		if not isinstance(user_id_or_localpart, str):
			logger.info("user_id isn't a string")
			defer.returnValue(None)
			return

		if user_id_or_localpart[0] == "@":
			if not user_id_or_localpart.endswith(":" + self.account_handler.hs.hostname):
				logger.info("user_id isn't for our homeserver")
				defer.returnValue(None)
				return
			localpart = user_id_or_localpart[1:-len(self.account_handler.hs.hostname)-1]
		else:
			localpart = user_id_or_localpart

		valid_localpart = not bool(re.compile(r"[^a-zA-Z0-9-.=_/]").search(localpart))
		if not valid_localpart:
			logger.info("Invalid localpart")
			defer.returnValue(None)
			return

		user_id = "@" + localpart + ":" + self.account_handler.hs.hostname
		if user_id != username_provided and localpart != username_provided:
			logger.info("Non-matching user")
			defer.returnValue(None)
			return

		user_exists = yield self.account_handler.check_user_exists(user_id)
		if not user_exists and not self.config.allow_registration:
			logger.info("User doesn't exist and registration is disabled")
			defer.returnValue(None)
			return

		if not user_exists:
			logger.info("User doesn't exist, registering it...")
			user_id = yield self.account_handler.register_user(localpart)
		logger.info("All done and valid, logging in!")
		defer.returnValue(user_id)

	@staticmethod
	def parse_config(config):
		class _TokenAuthenticatorConfig(object):
			pass
		_config = _TokenAuthenticatorConfig()
		_config.secret = config.get("secret", False)
		_config.keyfile = config.get("keyfile", False)
		if not _config.secret and not _config.keyfile:
			raise Exception("Missing secret or keyfile")
		if _config.keyfile and not os.path.exists(_config.keyfile):
			raise Exception("Keyfile doesn't exist")

		_config.algorithm = config.get("algorithm", "HS512")
		if not _config.algorithm in ["HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EdDSA"]:
			raise Exception("Unknown algorithm " + _config.algorithm)

		_config.allow_registration = config.get("allow_registration", False)
		_config.require_expiracy = config.get("require_expiracy", True)
		return _config
