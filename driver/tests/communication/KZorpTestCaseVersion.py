#!/usr/bin/env python2.7
#
# Copyright (C) 2006-2012, BalaBit IT Ltd.
# This program/include file is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as published
# by the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program/include file is distributed in the hope that it will be
# useful, but WITHOUT ANY WARRANTY; without even the implied warranty
# of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation,Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
import testutil
from KZorpComm import *
import kzorp.messages as messages

class KZorpTestCaseGetVersion(KZorpComm):
    def _get_version_message_handler(self, msg):
        self._major_version = msg.major
        self._compat_version = msg.compat

    def setUp(self):
        get_version_message = messages.KZorpGetVersionMessage()
        self.send_message(get_version_message, message_handler = self._get_version_message_handler)

    def test_get_version(self):
        self.assertEqual(self._major_version, 4)
        self.assertEqual(self._compat_version, 6)

if __name__ == "__main__":
    testutil.main()
