#!/usr/bin/env python2.7
#
# Copyright (C) 2016-2016, BalaSys IT Ltd.
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
from KZorpBaseTestCaseDispatchers import KZorpBaseTestCaseDispatchers
from kzorp.netlink import NetlinkException

import testutil
import socket
import struct
import errno


class KZorpTestCaseZoneLookup(KZorpBaseTestCaseDispatchers):

    def tearDown(self):
        self.flush_all()

    def setUp(self):
        self.upload_zones()

    def lookup_zone(self, family, address):
        from kzorp.communication import Adapter
        from kzorp.messages import KZorpLookupZoneMessage
        with Adapter() as adapter:
            add_zone_message = adapter.send_message(KZorpLookupZoneMessage(family, socket.inet_pton(family, address)))
            return add_zone_message.name

    def upload_zones(self):
        self.start_transaction()
        self._addzones()
        self.end_transaction()

class KZorpTestCaseZoneInternetIPv4(object):

    def test_edge_values(self):
        self.assertEqual('internet', self.lookup_zone(socket.AF_INET, '0.0.0.0'))
        self.assertEqual('internet', self.lookup_zone(socket.AF_INET, '255.255.255.255'))

    def test_non_existance(self):
        with self.assertRaisesRegexp(NetlinkException, 'netlink error: %d' % (-errno.ENOENT, )) as e:
            self.lookup_zone(socket.AF_INET6, '::0')
        with self.assertRaisesRegexp(NetlinkException, 'netlink error: %d' % (-errno.ENOENT, )) as e:
            self.lookup_zone(socket.AF_INET6, 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')

class KZorpTestCaseZoneWithInternetIPv4(KZorpTestCaseZoneInternetIPv4, KZorpTestCaseZoneLookup):
    _zones = [
        {
            'name' : 'internet',
            'admin_parent' : None,
            'subnets' : [
                '0.0.0.0/0',
            ], 
            'family' : socket.AF_INET
        },
        {
            'name' : 'root',
            'admin_parent' : None,
            'subnets' : [
                '10.0.0.1/32',
            ], 
            'family' : socket.AF_INET
        },
        {
            'name' : 'non_root',
            'admin_parent' : 'internet',
            'subnets' : [
                '20.0.0.1/32',
            ], 
            'family' : socket.AF_INET
        },

    ]

    def test_non_internet_match(self):
        self.assertEqual('root', self.lookup_zone(socket.AF_INET, '10.0.0.1'))
        self.assertEqual('non_root', self.lookup_zone(socket.AF_INET, '20.0.0.1'))

    def test_fallback(self):
        self.assertEqual('internet', self.lookup_zone(socket.AF_INET, '30.0.0.0'))


class KZorpTestCaseZoneOnlyInternetIPv4(KZorpTestCaseZoneInternetIPv4, KZorpTestCaseZoneLookup):
    _zones = [
        {
            'name' : 'internet',
            'admin_parent' : None,
            'subnets' : [
                '0.0.0.0/0',
            ], 
            'family' : socket.AF_INET
        },
    ]

class KZorpTestCaseZoneWithoutInternetIPv4(KZorpTestCaseZoneInternetIPv4, KZorpTestCaseZoneLookup):
    _zones = [
        {
            'name' : 'root',
            'admin_parent' : None,
            'subnets' : [
                '10.0.0.1/32',
            ], 
            'family' : socket.AF_INET
        },
        {
            'name' : 'non_root',
            'admin_parent' : 'root',
            'subnets' : [
                '20.0.0.1/32',
            ], 
            'family' : socket.AF_INET
        },

    ]

    def test_edge_values(self):
        with self.assertRaisesRegexp(NetlinkException, 'netlink error: %d' % (-errno.ENOENT, )) as e:
            self.lookup_zone(socket.AF_INET, '0.0.0.0')
        with self.assertRaisesRegexp(NetlinkException, 'netlink error: %d' % (-errno.ENOENT, )) as e:
            self.lookup_zone(socket.AF_INET, '255.255.255.255')

class KZorpTestCaseZoneInternetIPv6(object):

    def test_edge_values(self):
        self.assertEqual('internet', self.lookup_zone(socket.AF_INET6, '::0'))
        self.assertEqual('internet', self.lookup_zone(socket.AF_INET6, 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'))

    def test_non_existance(self):
        with self.assertRaisesRegexp(NetlinkException, 'netlink error: %d' % (-errno.ENOENT, )) as e:
            self.lookup_zone(socket.AF_INET, '0.0.0.0')
        with self.assertRaisesRegexp(NetlinkException, 'netlink error: %d' % (-errno.ENOENT, )) as e:
            self.lookup_zone(socket.AF_INET, '255.255.255.255')

class KZorpTestCaseZoneWithInternetIPv6(KZorpTestCaseZoneInternetIPv6, KZorpTestCaseZoneLookup):
    _zones = [
        {
            'name' : 'internet',
            'admin_parent' : None,
            'subnets' : [
                '::0/0',
            ], 
            'family' : socket.AF_INET6
        },
        {
            'name' : 'root',
            'admin_parent' : None,
            'subnets' : [
                '10::1/128',
            ], 
            'family' : socket.AF_INET6
        },
        {
            'name' : 'non_root',
            'admin_parent' : 'internet',
            'subnets' : [
                '20::1/128',
            ], 
            'family' : socket.AF_INET6
        },

    ]

    def test_non_internet_match(self):
        self.assertEqual('root', self.lookup_zone(socket.AF_INET6, '10::1'))
        self.assertEqual('non_root', self.lookup_zone(socket.AF_INET6, '20::1'))

    def test_fallback(self):
        self.assertEqual('internet', self.lookup_zone(socket.AF_INET6, '30::0'))

class KZorpTestCaseZoneOnlyInternetIPv6(KZorpTestCaseZoneInternetIPv6, KZorpTestCaseZoneLookup):
    _zones = [
        {
            'name' : 'internet',
            'admin_parent' : None,
            'subnets' : [
                '::0/0',
            ], 
            'family' : socket.AF_INET6
        },
    ]

class KZorpTestCaseZoneWithoutInternetIPv6(KZorpTestCaseZoneInternetIPv6, KZorpTestCaseZoneLookup):
    _zones = [
        {
            'name' : 'root',
            'admin_parent' : None,
            'subnets' : [
                '10::1/128',
            ], 
            'family' : socket.AF_INET6
        },
        {
            'name' : 'non_root',
            'admin_parent' : 'root',
            'subnets' : [
                '20::1/128',
            ], 
            'family' : socket.AF_INET6
        },

    ]

    def test_edge_values(self):
        with self.assertRaisesRegexp(NetlinkException, 'netlink error: %d' % (-errno.ENOENT, )) as e:
            self.lookup_zone(socket.AF_INET6, '::0')
        with self.assertRaisesRegexp(NetlinkException, 'netlink error: %d' % (-errno.ENOENT, )) as e:
            self.lookup_zone(socket.AF_INET6, 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')


class KZorpTestCaseZoneEdges(KZorpTestCaseZoneLookup):

    ADDR_ZERO_FILLED = 0
    ADDR_ONE_FILLED = 0

    def _upload_zones_with_each_prefix(self, addr):
        self._zones = []

        for prefix in range(self.addr_size_in_bits + 1):
            zone_data = {
                'name' : 'zone_with_prefix_%d' % (prefix, ),
                'admin_parent' : None,
                'subnets' : [
                    '%s/%d' % (addr, prefix),
                ], 
                'family' : self.family
            }
            self._zones.append(zone_data)
               
        self.upload_zones()

    def create_zones_with_each_prefix(self):
        self.addr_size_in_bits = 32 if self.family == socket.AF_INET else 128
        self._addr_size_in_32_bits = self.addr_size_in_bits / 32
        addr_segment = 0 if self.test_type == self.ADDR_ZERO_FILLED else 0xffff
        addr_packed = struct.pack("!" + self._addr_size_in_32_bits * "I", *(self._addr_size_in_32_bits * [addr_segment, ]))
        self._upload_zones_with_each_prefix(socket.inet_ntop(self.family, addr_packed))

    def _get_zero_filled_segment_value(self, segment_count, segment_num, prefix_len_in_segment):
        if segment_num < segment_count:
           num = 0xffffffff
        elif segment_num == segment_count:
           num = (2 ** prefix_len_in_segment - 2 ** (prefix_len_in_segment - 1))
        if segment_num > segment_count:
           num = 0

        return num

    def _get_one_filled_segment_value(self, segment_count, segment_num, prefix_len_in_segment):
        if segment_num < segment_count:
           num = 0
        elif segment_num == segment_count:
           num = 2 ** 32 - 2 ** prefix_len
        if segment_num > segment_count:
           num = 0xffffffff

        return num

    def _get_addr_str(self, prefix_len):
        nums = []
        segment_count = prefix_len / 32
        prefix_len_in_segment = prefix_len - (segment_count * 32)
        for segment_num in reversed(range(self._addr_size_in_32_bits)):
            if self.test_type == self.ADDR_ZERO_FILLED:
                nums.append(self._get_zero_filled_segment_value(segment_count, segment_num, prefix_len_in_segment))
            elif self.test_type == self.ADDR_ONE_FILLED:
                nums.append(self._get_one_filled_segment_value(segment_count, segment_num, prefix_len_in_segment))
            else:
                raise ValueError
        addr_packed = struct.pack("!" + self._addr_size_in_32_bits * "I", *nums)
       
        return socket.inet_ntop(self.family, addr_packed)


    def _test_edge_values(self):
        for prefix_len in range(self.addr_size_in_bits + 1):
            addr_str = self._get_addr_str(prefix_len)
            zone_name = self.lookup_zone(self.family, addr_str)
            self.assertEqual('zone_with_prefix_%d' % (self.addr_size_in_bits - prefix_len), zone_name)


class KZorpTestCaseZoneEdgesIPv4WithOneFilledMask(KZorpTestCaseZoneEdges):

    def setUp(self):
        self.family = socket.AF_INET
        self.test_type = KZorpTestCaseZoneEdges.ADDR_ONE_FILLED
        self.create_zones_with_each_prefix()

    def test_edge_values(self):
        self._test_edge_values()


class KZorpTestCaseZoneEdgesIPv4WithZeroFilledMask(KZorpTestCaseZoneEdges):

    def setUp(self):
        self.family = socket.AF_INET
        self.test_type = KZorpTestCaseZoneEdges.ADDR_ZERO_FILLED
        self.create_zones_with_each_prefix()

    def test_edge_values(self):
        self._test_edge_values()


class KZorpTestCaseZoneEdgesIPv6WithOneFilledMask(KZorpTestCaseZoneEdges):

    def setUp(self):
        self.family = socket.AF_INET6
        self.test_type = KZorpTestCaseZoneEdges.ADDR_ONE_FILLED
        self.create_zones_with_each_prefix()

    def test_edge_values(self):
        self._test_edge_values()


class KZorpTestCaseZoneEdgesIPv6WithZeroFilledMask(KZorpTestCaseZoneEdges):

    def setUp(self):
        self.family = socket.AF_INET6
        self.test_type = KZorpTestCaseZoneEdges.ADDR_ZERO_FILLED
        self.create_zones_with_each_prefix()

    def test_edge_values(self):
        self._test_edge_values()

if __name__ == "__main__":
        testutil.main()
