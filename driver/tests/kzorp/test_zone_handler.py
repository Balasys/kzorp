#!/usr/bin/env python2.7

import unittest

import socket
import radix

from Zorp.Base import BaseZone
from Zorp.Zone import Zone
import kzorp.messages

class TestDynamicZoneHandler(unittest.TestCase):
    def setUp(self):
        BaseZone.zones = {}

    def _create_subnet_set_from_messages(self, add_zone_subnet_messages):
        subnets_from_messages = set()
        for msg in add_zone_subnet_messages:
            subnets_from_messages.add(socket.inet_ntop(msg.family, msg.address) + '/' + socket.inet_ntop(msg.family, msg.mask))
        return subnets_from_messages

class TestSetupZones(TestDynamicZoneHandler):
    def __check_initially_added_zones(self, zone_names_in_order=[], zone_subnets=[]):
        zone_handler = kzorp.messages.ZoneUpdateMessageCreator(BaseZone.zones.values(), None)
        messages = zone_handler.create_zone_static_address_initialization_messages()

        add_zone_messages = filter(lambda msg: msg.command == kzorp.messages.KZNL_MSG_ADD_ZONE, messages)
        self.assertEqual([msg.name for msg in add_zone_messages], zone_names_in_order)

        subnets_from_zones = set(zone_subnets)
        add_zone_subnet_messages = filter(lambda msg: msg.command == kzorp.messages.KZNL_MSG_ADD_ZONE_SUBNET, messages)
        subnets_from_messages = self._create_subnet_set_from_messages(add_zone_subnet_messages)
        self.assertEqual(subnets_from_messages, subnets_from_zones)

        self.assertEqual(len(add_zone_messages) + len(add_zone_subnet_messages), len(messages))

    def test_sanity(self):
        BaseZone('root')
        self.__check_initially_added_zones(['root'])

    def test_zone_addition_order(self):
        BaseZone('root')
        BaseZone('child', admin_parent='root')
        BaseZone('grandchild', admin_parent='child')
        self.__check_initially_added_zones(['root', 'child', 'grandchild'])

    def test_initial_zone_addition_if_there_are_static_addresses_only(self):
        BaseZone('root', addrs=['1.1.1.1/32', '2.2.2.2/32'])
        BaseZone('child', addrs=['1::/16', '2::/16'])
        self.__check_initially_added_zones(['root', 'child'], ['1.1.1.1/255.255.255.255', '2.2.2.2/255.255.255.255', '1::/ffff::', '2::/ffff::', ])

    def test_initial_zone_addition_if_there_are_dynamic_addresses_only(self):
        BaseZone('root', hostnames=['nohost', ])
        BaseZone('child', hostnames=['nohost', ])
        self.__check_initially_added_zones(['root', 'child'], [])

    def test_initial_zone_addition_if_there_are_both_static_and_dynamic_addresses(self):
        BaseZone('root', addrs=['1.1.1.1/32', ], hostnames=['nohost', ])
        BaseZone('child', addrs=['1::/16', ], hostnames=['nohost', ])
        self.__check_initially_added_zones(['root', 'child'], ['1.1.1.1/255.255.255.255', '1::/ffff::', ])

class MyResolverCache():
    host_one_hostname = 'host_with_all_one_ip'
    host_one_ipv4_addr = '.'.join(4 * ['1'])
    host_one_ipv6_addr = ':'.join(8 * ['1'])

    host_two_hostname = 'host_with_all_two_ip'
    host_two_ipv4_addr = '.'.join(4 * ['2'])
    host_two_ipv6_addr = ':'.join(8 * ['2'])

    conflicting_host_hostname = 'conflicting_host'
    conflicting_host_ipv4_addr = host_one_ipv4_addr
    conflicting_host_ipv6_addr = host_one_ipv6_addr

    non_conflicting_ipv4_addr = '.'.join(4 * ['101'])
    non_conflicting_ipv6_addr = ':'.join(8 * ['101'])

    unresolvable_hostname = 'unresolvablehost'

    def __init__(self):
       self.hostnames_to_ipv4_addresses = {
                                            MyResolverCache.host_one_hostname : set([MyResolverCache.host_one_ipv4_addr, ]),
                                            MyResolverCache.host_two_hostname : set([MyResolverCache.host_two_ipv4_addr, ]),
                                            MyResolverCache.conflicting_host_hostname : set([MyResolverCache.host_one_ipv4_addr, ]),
                                          }
       self.hostnames_to_ipv6_addresses = {
                                            MyResolverCache.host_one_hostname : set([MyResolverCache.host_one_ipv6_addr, ]),
                                            MyResolverCache.host_two_hostname : set([MyResolverCache.host_two_ipv6_addr, ]),
                                            MyResolverCache.conflicting_host_hostname : set([MyResolverCache.host_one_ipv6_addr, ]),
                                          }
       self.ipv4_addresses = {
                               MyResolverCache.host_one_ipv4_addr : MyResolverCache.host_one_hostname,
                               MyResolverCache.host_two_ipv4_addr : MyResolverCache.host_two_hostname,
                             }
       self.ipv6_addresses = {
                               MyResolverCache.host_one_ipv6_addr : MyResolverCache.host_one_hostname,
                               MyResolverCache.host_two_ipv6_addr : MyResolverCache.host_two_hostname,
                             }

    def addHost(self, hostname):
        pass

    def removeHost(self, hostname):
        pass

    def shouldUpdate(self):
        return True

    def lookupAddress(self, hostname):
        if hostname == MyResolverCache.unresolvable_hostname: raise KeyError
        return self.ipv4_addresses.get(hostname, []), self.ipv6_addresses.get(hostname, [])

    def lookupHostname(self, hostname):
        if hostname == MyResolverCache.unresolvable_hostname: raise KeyError
        return self.hostnames_to_ipv4_addresses.get(hostname, []), self.hostnames_to_ipv6_addresses.get(hostname, [])

class TestUpdateZones(TestDynamicZoneHandler):
    def setUp(self):
        super(TestUpdateZones, self).setUp()
        Zone.zone_subnet_tree = radix.Radix()

    def __get_subnets_from_addresses(self, addresses):
        return [address + '/255.255.255.255'
                if '.' in address
                else address + '/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
                for address in addresses]

    def __check_zone_update_messages(self, updatable_hostname, updatable_zones):
        updatable_zone_names = set(updatable_zones.keys())
        zone_handler = kzorp.messages.ZoneUpdateMessageCreator(BaseZone.zones.values(), MyResolverCache())
        messages = zone_handler.create_zone_update_messages(updatable_hostname)

        delete_zone_messages = filter(lambda msg: msg.command == kzorp.messages.KZNL_MSG_DELETE_ZONE, messages)
        delete_zone_messages = dict(map(lambda msg: (msg.name, msg), delete_zone_messages))
        self.assertEqual(set(delete_zone_messages.keys()), updatable_zone_names)

        add_zone_messages = filter(lambda msg: msg.command == kzorp.messages.KZNL_MSG_ADD_ZONE, messages)
        add_zone_messages = dict(map(lambda msg: (msg.name, msg), add_zone_messages))
        self.assertEqual(set(add_zone_messages.keys()), updatable_zone_names)

        for (zone_name, subnets) in updatable_zones.iteritems():
            add_zone_subnet_messages = filter(lambda msg: msg.command == kzorp.messages.KZNL_MSG_ADD_ZONE_SUBNET and \
                                                          msg.zone_name == zone_name,
                                              messages)
            subnets_from_messages = self._create_subnet_set_from_messages(add_zone_subnet_messages)
            self.assertEqual(subnets_from_messages, set(subnets))
            self.assertEqual(add_zone_messages[zone_name].subnet_num, len(subnets))

    def test_empty_zone_not_updated(self):
        zone = BaseZone('static_zone')
        self.__check_zone_update_messages(zone, {})

    def test_static_zone_not_updated(self):
        zone = BaseZone('static_zone', addrs=[MyResolverCache.host_one_ipv4_addr, ])
        self.__check_zone_update_messages(zone, {})

    def test_zone_with_dynamic_address_only(self):
        zone = BaseZone('dynamic_zone', hostnames=[MyResolverCache.host_one_hostname, ])
        updated_zones = {
                          'dynamic_zone' :
                          set(self.__get_subnets_from_addresses([ MyResolverCache.host_one_ipv4_addr,
                                                                  MyResolverCache.host_one_ipv6_addr, ])),
                        }
        self.__check_zone_update_messages(MyResolverCache.host_one_hostname, updated_zones)

    def test_zone_with_dynamic_and_static_addresses(self):
        zone = BaseZone('dynamic_zone',
                        addrs=MyResolverCache.non_conflicting_ipv4_addr,
                        hostnames=[MyResolverCache.host_one_hostname, ])
        updated_zones = {
                          'dynamic_zone' :
                          set(self.__get_subnets_from_addresses([ MyResolverCache.host_one_ipv4_addr,
                                                                  MyResolverCache.host_one_ipv6_addr,
                                                                  MyResolverCache.non_conflicting_ipv4_addr, ])),
                        }
        self.__check_zone_update_messages(MyResolverCache.host_one_hostname, updated_zones)

    def test_dynamic_zone_with_unresolvable_hostname(self):
        zone = BaseZone('dynamic_zone',
                        hostnames=[MyResolverCache.unresolvable_hostname, ])
        updated_zones = {
                          'dynamic_zone' :
                          set(),
                        }
        self.__check_zone_update_messages(MyResolverCache.unresolvable_hostname, updated_zones)

        zone = BaseZone('dynamic_zone',
                        addrs=[ MyResolverCache.non_conflicting_ipv4_addr, ],
                        hostnames=[ MyResolverCache.unresolvable_hostname, ])
        updated_zones = {
                          'dynamic_zone' :
                          set(self.__get_subnets_from_addresses([MyResolverCache.non_conflicting_ipv4_addr])),
                        }
        self.__check_zone_update_messages(MyResolverCache.unresolvable_hostname, updated_zones)

        zone = BaseZone('dynamic_zone',
                        addrs=[ MyResolverCache.non_conflicting_ipv4_addr, ],
                        hostnames=[ MyResolverCache.unresolvable_hostname, MyResolverCache.host_one_hostname, ])
        updated_zones = {
                          'dynamic_zone' :
                          set(self.__get_subnets_from_addresses([ MyResolverCache.host_one_ipv4_addr,
                                                                  MyResolverCache.host_one_ipv6_addr,
                                                                  MyResolverCache.non_conflicting_ipv4_addr, ])),
                        }
        self.__check_zone_update_messages(MyResolverCache.unresolvable_hostname, updated_zones)

    def test_dynamic_zone_conflicts_with_static_zone(self):
        Zone('static_zone', addrs=[MyResolverCache.host_one_ipv4_addr, ])

        zone = Zone('dynamic_only_zone_conflicts_with_static_zone_ipv4_address',
                    hostnames=[MyResolverCache.host_one_hostname, ])
        updated_zones = {
                          'dynamic_only_zone_conflicts_with_static_zone_ipv4_address' :
                          set(self.__get_subnets_from_addresses([MyResolverCache.host_one_ipv6_addr])),
                        }
        self.__check_zone_update_messages(MyResolverCache.host_one_hostname, updated_zones)

    def test_mixed_zone_conflicts_with_static_zone(self):
        Zone('static_zone', addrs=[MyResolverCache.host_one_ipv4_addr, ])

        zone = Zone('mixed_zone_conflicts_with_static_zone',
                    addrs=[MyResolverCache.non_conflicting_ipv4_addr, MyResolverCache.non_conflicting_ipv6_addr],
                    hostnames=[MyResolverCache.host_one_hostname, ])
        updated_zones = {
                          'mixed_zone_conflicts_with_static_zone' :
                          set(self.__get_subnets_from_addresses([MyResolverCache.host_one_ipv6_addr,
                                                                 MyResolverCache.non_conflicting_ipv4_addr,
                                                                 MyResolverCache.non_conflicting_ipv6_addr, ])),
                        }
        self.__check_zone_update_messages(MyResolverCache.host_one_hostname, updated_zones)

    def test_dynamic_only_zone_conflicts_with_dynamic_only_zone(self):
        BaseZone('dynamic_zone',
                 hostnames=[ MyResolverCache.host_one_hostname, MyResolverCache.host_two_hostname, ])

        zone = Zone('conflicting_dynamic_zone',
                    hostnames=[ MyResolverCache.conflicting_host_hostname, ])
        updated_zones = {
                         'dynamic_zone':
                          set(self.__get_subnets_from_addresses([MyResolverCache.host_two_ipv4_addr,
                                                                 MyResolverCache.host_two_ipv6_addr, ])),
                         'conflicting_dynamic_zone': set(),
                        }
        self.__check_zone_update_messages(MyResolverCache.conflicting_host_hostname, updated_zones)

    def test_dynamic_only_zone_conflicts_with_mixed_zone(self):
        BaseZone('dynamic_zone',
                 hostnames=[ MyResolverCache.host_one_hostname, ])

        zone = Zone('conflicting_dynamic_zone',
                    addrs=[MyResolverCache.non_conflicting_ipv4_addr, MyResolverCache.non_conflicting_ipv6_addr],
                    hostnames=[ MyResolverCache.conflicting_host_hostname, ])
        updated_zones = {
                         'dynamic_zone': set(),
                         'conflicting_dynamic_zone':
                          set(self.__get_subnets_from_addresses([MyResolverCache.non_conflicting_ipv4_addr,
                                                                 MyResolverCache.non_conflicting_ipv6_addr, ])),
                        }
        self.__check_zone_update_messages(MyResolverCache.conflicting_host_hostname, updated_zones)

    def test_mixed_zone_conflicts_with_dynamic_only_zone(self):
        BaseZone('dynamic_zone',
                 addrs=[MyResolverCache.non_conflicting_ipv4_addr, MyResolverCache.non_conflicting_ipv6_addr],
                 hostnames=[ MyResolverCache.host_one_hostname, ])

        zone = Zone('conflicting_dynamic_zone',
                    hostnames=[ MyResolverCache.conflicting_host_hostname, ])
        updated_zones = {
                         'dynamic_zone':
                          set(self.__get_subnets_from_addresses([MyResolverCache.non_conflicting_ipv4_addr,
                                                                 MyResolverCache.non_conflicting_ipv6_addr, ])),
                         'conflicting_dynamic_zone': set(),
                        }
        self.__check_zone_update_messages(MyResolverCache.conflicting_host_hostname, updated_zones)

    @unittest.skip("known bug in 5.0.0")
    def test_dynamic_conflicts_in_same_zone(self):
        zone = Zone('self_conflicting_dynamic_zone',
                    hostnames=[ MyResolverCache.host_one_hostname,
                                MyResolverCache.conflicting_host_hostname, ])
        updated_zones = {
                         'self_conflicting_dynamic_zone': set(),
                        }
        self.__check_zone_update_messages(MyResolverCache.conflicting_host_hostname, updated_zones)

if __name__ == '__main__':
    unittest.main()
