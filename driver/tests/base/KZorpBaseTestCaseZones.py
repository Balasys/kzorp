
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
from KZorpComm import KZorpComm
import testutil
import kzorp.netlink as netlink
import kzorp.messages as messages
import socket


class KZorpBaseTestCaseZones(KZorpComm):
    _dumped_zones = []

    def _dump_zone_handler(self, message):
        if message.command is not messages.KZNL_MSG_ADD_ZONE:
            return

        self._dumped_zones.append(message)

    def check_zone_num(self, num_zones = 0, in_transaction = True):
        self._dumped_zones = []

        if in_transaction == True:
            self.start_transaction()

        self.send_message(messages.KZorpGetZoneMessage(), message_handler = self._dump_zone_handler, dump = True)

        if in_transaction == True:
            self.end_transaction()

        self.assertEqual(num_zones, len(self._dumped_zones))

    def get_zone_attrs(self, message):
        self.assertEqual(message.command, messages.KZNL_MSG_ADD_ZONE)

        attrs = message.get_attributes()

        return attrs

    def send_add_zone_message(self, inet_zone):
       for m in inet_zone.buildKZorpMessage():
           self.send_message(m)

    def _check_zone_params(self, add_zone_message, zone_data):
        self.assertEqual(add_zone_message.name, zone_data['name'])
        self.assertEqual(add_zone_message.pname, zone_data['pname'])
        subnet_num = 1 if zone_data.has_key('address') else 0
        self.assertEqual(add_zone_message.subnet_num, subnet_num)

if __name__ == "__main__":
    testutil.main()
