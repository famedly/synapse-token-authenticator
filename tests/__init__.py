# -*- coding: utf-8 -*-
# Copyright (C) 2020 Famedly
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

from mock import Mock
from synapse_token_authenticator import TokenAuthenticator
from jwcrypto import jwt, jwk
import time
import base64

admins = {}

def get_auth_provider(config = None, user_exists = True):
	def set_user_admin(user_id: str, admin: bool):
		return admins.update({user_id: admin})
	def is_user_admin(user_id: str):
		return admins.get(user_id, False)
	account_handler = Mock(spec_set=["check_user_exists", "hs", "register_user", "set_user_admin",
		"is_user_admin"])
	account_handler.check_user_exists.return_value = user_exists
	account_handler.register_user.return_value = "@alice:example.org"
	account_handler.hs.hostname = "example.org"
	account_handler.set_user_admin.side_effect = set_user_admin
	account_handler.is_user_admin.side_effect = is_user_admin
	if config:
		config_parsed = TokenAuthenticator.parse_config(config)
	else:
		config_parsed = TokenAuthenticator.parse_config({ "secret": "foxies" })
	return TokenAuthenticator(config_parsed, account_handler)

def get_token(username, exp_in = None, secret = "foxies", algorithm = "HS512", admin = None):
	k = {
		"k": base64.urlsafe_b64encode(secret.encode("utf-8")).decode("utf-8"),
		"kty": "oct",
	}
	key = jwk.JWK(**k)
	claims = {
		"sub": username,
	}
	if admin is not None:
		claims.update({"admin": admin})

	if exp_in != -1:
		if exp_in == None:
			claims["exp"] = int(time.time()) + 120
		else:
			claims["exp"] = int(time.time()) + exp_in
	token = jwt.JWT(header={"alg": algorithm}, claims=claims)
	token.make_signed_token(key)
	return token.serialize()
