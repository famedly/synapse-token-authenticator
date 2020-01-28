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
from token_authenticator import TokenAuthenticator
from jwcrypto import jwt, jwk
import time
import base64

def get_auth_provider(config = None, user_exists = True):
	account_handler = Mock(spec_set=["check_user_exists", "hs", "register_user"])
	account_handler.check_user_exists.return_value = user_exists
	account_handler.register_user.return_value = "@alice:example.org"
	account_handler.hs.hostname = "example.org"
	if config:
		config_parsed = TokenAuthenticator.parse_config(config)
	else:
		config_parsed = TokenAuthenticator.parse_config({ "secret": "foxies" })
	return TokenAuthenticator(config_parsed, account_handler)

def get_token(username, exp_in = None, secret = "foxies", algorithm = "HS512"):
	k = {
		"k": base64.urlsafe_b64encode(secret.encode("utf-8")).decode("utf-8"),
		"kty": "oct",
	}
	key = jwt.JWK(**k)
	claims = {
		"sub": username
	}
	if exp_in != -1:
		if exp_in == None:
			claims["exp"] = int(time.time()) + 120
		else:
			claims["exp"] = int(time.time()) + exp_in
	token = jwt.JWT(header={"alg": algorithm}, claims=claims)
	token.make_signed_token(key)
	return token.serialize()
