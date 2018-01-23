#
# Copyright (C) 2006-2015 BalaBit IT Security, 2015-2017 BalaSys IT Security.
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
from KZorpComm import KZorpComm

import kzorp.messages as messages
import socket
import resource

class KZorpTestCaseDump(KZorpComm):
    def setUp(self):
        self.flush_all()

    def tearDown(self):
        self.flush_all()

    def _send_objects(self, add_messages):
        for add_message in add_messages:
            self.send_message(add_message)

    def _dump_objects(self):
        replies = []
        for reply in self.handle.dump(self._dump_message):
            replies.append(reply)
        return replies

    def _check_objects(self, add_messages):
        self.start_transaction()
        self._send_objects(add_messages)
        self.end_transaction()

        dumped_services = self._dump_objects()
        self.assertEqual(set(dumped_services), set(add_messages))

    @staticmethod
    def _get_netlink_packet_size():
        return resource.getpagesize()
