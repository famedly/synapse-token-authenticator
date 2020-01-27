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

from token_authenticator import TokenAuthenticator
from twisted.trial import unittest
from twisted.internet import defer
from mock import Mock

class SimpleTestCase(unittest.TestCase):
	def setUp(self):
		account_handler = Mock(spec_set=["check_user_exists"])
		account_handler.check_user_exists.return_value = True
		config = TokenAuthenticator.parse_config({ "secret": "foxies" })
		self.auth_provider = TokenAuthenticator(config, account_handler)

	@defer.inlineCallbacks
	def test_wrong_login_type(self):
		result = yield self.auth_provider.check_auth("alice", "m.password", {"token": "blah"})
		self.assertIs(result, None)

#if __name__ == "__main__":
#	unittest.main()
