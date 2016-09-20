#!/usr/bin/env python
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
from KZorpBaseTestCaseZones import KZorpBaseTestCaseZones
from KZorpBaseTestCaseCommon import KZorpTestCaseDump
import kzorp.messages as messages
import errno
import socket

class KZorpTestCaseZoneDump(KZorpTestCaseDump):
    _dump_message = messages.KZorpGetZoneMessage(None)

    def __create_several_zones_that_do_not_fit_into_one_netlink_packet(self):
        zone_name_format = 'zone_with_subnets_do_not_fit_into_one_netlink_packet_%d'
        zone_messages = []

        for zone_num in range(self._get_netlink_packet_size()):
            add_zone_message = messages.KZorpAddZoneMessage(zone_name_format % (zone_num, ), subnet_num = 0)
            zone_messages.append(add_zone_message)

        return zone_messages


    def __create_one_zone_with_subnets_do_not_fit_into_one_netlink_packet(self):
        zone_name = 'zone'
        zone_subnet_count_that_not_fit_in_netlink_packet = self._get_netlink_packet_size()
        zone_subnet_family = socket.AF_INET
        zone_subnet_format = '192.168.%d.%d'

        zone_messages = []

        add_zone_message = messages.KZorpAddZoneMessage(zone_name, subnet_num = zone_subnet_count_that_not_fit_in_netlink_packet)
        zone_messages.append(add_zone_message)

        for subnet_num in range(zone_subnet_count_that_not_fit_in_netlink_packet):
            add_zone_subnet_message = messages.KZorpAddZoneSubnetMessage(
                zone_name,
                family = zone_subnet_family,
                address = socket.inet_pton(zone_subnet_family, zone_subnet_format % (subnet_num % (2 ** 16) / 256, subnet_num % (2 ** 8), )),
                mask = socket.inet_pton(zone_subnet_family, testutil.size_to_mask(zone_subnet_family, 32))
            )
            zone_messages.append(add_zone_subnet_message)

        return zone_messages

    def test_one_zone_with_subnets_do_not_fit_into_one_netlink_packet(self):
        self._check_objects(self.__create_one_zone_with_subnets_do_not_fit_into_one_netlink_packet())

    def test_several_zones_that_do_not_fit_into_one_netlink_packet(self):
        self._check_objects(self.__create_several_zones_that_do_not_fit_into_one_netlink_packet())

class KZorpTestCaseZones(KZorpBaseTestCaseZones):
    _zones = [
               {'name' : 'root', 'pname' : None,   'address' : '10.0.100.1',     'mask' : 32, 'family' : socket.AF_INET},
               {'name' :    'b', 'pname' : 'root', 'address' : '10.0.102.1',     'mask' : 31, 'family' : socket.AF_INET},
               {'name' :    'c', 'pname' :    'b', 'address' : '10.0.103.1',     'mask' : 30, 'family' : socket.AF_INET},
               {'name' :    'd', 'pname' :    'b', 'address' : '10.0.104.1',     'mask' : 29, 'family' : socket.AF_INET},
               {'name' :    'e', 'pname' :    'b', 'address' : '10.0.105.1',     'mask' : 28, 'family' : socket.AF_INET},
               {'name' :    'f', 'pname' :    'b', 'address' : '10.0.106.1',     'mask' : 27, 'family' : socket.AF_INET},
               {'name' :    'g', 'pname' :    'f', 'address' : '10.0.107.1',     'mask' : 26, 'family' : socket.AF_INET},
               {'name' :    'h', 'pname' :    'g', 'address' : '10.0.108.1',     'mask' : 25, 'family' : socket.AF_INET},
               {'name' :    'i', 'pname' :    'g', 'address' : '10.0.109.1',     'mask' : 24, 'family' : socket.AF_INET},
               {'name' :    'j', 'pname' :    'g', 'address' : '10.0.110.1',     'mask' : 23, 'family' : socket.AF_INET},
             ]

    def newSetUp(self):
        self.start_transaction()

        for zone in self._zones:
            add_zone_message = messages.KZorpAddZoneMessage(zone['name'], pname = zone['pname'], subnet_num = 1)
            self.send_message(add_zone_message)

            family = zone['family']
            add_zone_subnet_message = messages.KZorpAddZoneSubnetMessage(zone['name'],
                                                                family = family,
                                                                address = socket.inet_pton(family, zone['address']),
                                                                mask = socket.inet_pton(family, testutil.size_to_mask(family, zone['mask'])))
            self.send_message(add_zone_subnet_message)

        self.end_transaction()
        self._index = -1
        self._add_zone_message = None
        self._add_zone_messages = []

    def setUp(self):
        self.internet_zone_name = 'internet'
        self.internet_subnet_family = socket.AF_INET
        self.internet_subnet_addr = socket.inet_pton(self.internet_subnet_family, '0.0.0.0')
        self.internet_subnet_mask = self.internet_subnet_addr

    def tearDown(self):
        self.flush_all()

    def test_add_zone(self):
        self.newSetUp()
        #set up and ter down test the zone addition
        self.check_zone_num(len(self._zones))

    def test_add_zone_errors(self):
        zones = [
                  {'desc' : 'nonexistent parent', 'name' :   'x1',  'pname' :  'x', 'error' : -errno.ENOENT},
                  {'desc' : 'no parent',          'name' :    'a',  'pname' : None, 'error' : 0},
                  {'desc' : 'existing name',      'name' :    'a',  'pname' : None, 'error' : -errno.EEXIST},
                  {'desc' : 'nonexistent name',   'name' :   'x2',  'pname' : None, 'error' : 0},
                  {'desc' : 'empty name',         'name' :     '',  'pname' : None, 'error' : -errno.EINVAL},
                  {'desc' : 'empty parent',       'name' : 'fake',  'pname' :   '', 'error' : -errno.EINVAL},
                ]

        #add_zone_message = messages.KZorpAddZoneMessage('a');
        #res = self.send_message(add_zone_message, assert_on_error = False)
        #self.assertEqual(res, -errno.ENOENT)
        #import pdb
        #pdb.set_trace()
        for zone in zones:
            self.start_transaction()
            add_zone_message = messages.KZorpAddZoneMessage(zone['name'], pname = zone['pname'])

            res = self.send_message(add_zone_message, assert_on_error = False)
            tr_res = self.end_transaction(assert_on_error=False)
            expected_result = zone['error']
            if expected_result == 0:
                self.assertEqual(res, 0)
                self.assertEqual(tr_res, 0)
            else:
                if res != 0:
                    self.assertEqual(res, expected_result)
                else:
                    self.assertEqual(tr_res, expected_result)

    def test_zero_subnet_is_valid(self):
        self.start_transaction()
        self.send_message(messages.KZorpAddZoneMessage('name', None, subnet_num = 0))
        self.end_transaction()

    def _add_zone_subnet_handler(self, msg):
        print msg
        if msg.command is messages.KZNL_MSG_ADD_ZONE_SUBNET:
            self._add_zone_subnet_msg = msg

    def _create_add_zone_subnet_internet(self, name):
        return messages.KZorpAddZoneSubnetMessage(name,
                                         self.internet_subnet_family,
                                         self.internet_subnet_addr,
                                         self.internet_subnet_mask)

    def _add_zone_with_internet_subnet(self):
        self.start_transaction()
        self.send_message(messages.KZorpAddZoneMessage(self.internet_zone_name, None, subnet_num = 1))
        add_zone_subnet_msg = self._create_add_zone_subnet_internet(self.internet_zone_name)
        self.send_message(add_zone_subnet_msg)
        self.end_transaction()

        self._check_add_zone_subnet_internet(add_zone_subnet_msg)

    def _check_add_zone_subnet_internet(self, msg):
        self.send_message(messages.KZorpGetZoneMessage(msg.zone_name),
                          message_handler = self._add_zone_subnet_handler)
        self.assertEqual(self._add_zone_subnet_msg, msg)

    def test_add_zone_subnet_in_same_transaction(self):
        self._add_zone_with_internet_subnet()

    def __test_add_zone_subnet_different_transaction(self):
        self.start_transaction()
        self.send_message(messages.KZorpAddZoneMessage(self.internet_zone_name, None, subnet_num = 0))
        self.end_transaction()

        self.start_transaction()
        add_zone_subnet_msg = self._create_add_zone_subnet_internet(self.internet_zone_name)
        self.send_message(add_zone_subnet_msg)
        self.end_transaction()

        self._check_add_zone_subnet_internet(add_zone_subnet_msg)

    def test_add_subnet_to_zone_with_zero_subnet_num(self):
        self.start_transaction()

        self.send_message(messages.KZorpAddZoneMessage('name', pname = None, subnet_num = 0))

        res = self.send_message(self._create_add_zone_subnet_internet('name'),
                                assert_on_error = False)
        self.assertEqual(res, -errno.ENOMEM)

        self.end_transaction()

    def _get_zone_message_handler(self, msg):
        self._add_zone_message = msg
        if msg.command is not messages.KZNL_MSG_ADD_ZONE:
            return

        self._index += 1

        self._check_zone_params(msg, self._zones[self._index])

    def test_get_zone_by_name(self):
        self.newSetUp()
        #get each created zone
        for zone in self._zones:
            zone_name = zone['name']
            self.send_message(messages.KZorpGetZoneMessage(zone_name), message_handler = self._get_zone_message_handler)
        self.assertNotEqual(self._index, len(self._zones))

        #get a not existent zone
        self.assertNotEqual(self._zones[0]['name'], 'nonexistent zone name')
        res = self.send_message(messages.KZorpGetZoneMessage('nonexistent zone name'), assert_on_error = False)
        self.assertEqual(res, -errno.ENOENT)

    def _get_zones_message_handler(self, msg):
        if msg.command is not messages.KZNL_MSG_ADD_ZONE:
            return

        self._add_zone_messages.append(msg)

    def test_get_zone_with_dump(self):
        self.newSetUp()
        #get the dump of zones
        self.send_message(messages.KZorpGetZoneMessage(None), message_handler = self._get_zones_message_handler, dump = True)
        self.assertEqual(len(self._add_zone_messages), len(self._zones))
        for add_zone_message in self._add_zone_messages:
            for i in range(len(self._zones)):
                if add_zone_message.name == self._zones[i]['name']:
                    self._check_zone_params(add_zone_message, self._zones[i])
                    break
            else:
                self.assert_(True, "zone with name %s could not find in the dump" % self.get_zone_uname(add_zone_message))


if __name__ == "__main__":
    testutil.main()
