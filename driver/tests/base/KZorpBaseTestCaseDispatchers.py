
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
import socket
import testutil
import kzorp.messages as messages
import types
import os
import errno

class KZorpBaseTestCaseDispatchers(KZorpComm):
    _dumped_dispatchers = []
    _zones = [
               #{'name' : 'a6', 'name' :   'k6', 'pname' :   None, 'address' : 'fc00:0:101:1::', 'mask' : 64, 'family' : socket.AF_INET6},
               {'family' : socket.AF_INET, 'name' : 'internet', 'subnets' : ['0.0.0.0/0'], 'admin_parent' : None},
               {'family' : socket.AF_INET, 'name' : 'A',        'subnets' : ['10.99.101.0/25',   '10.99.201.0/25'], 'admin_parent' : None},
               {'family' : socket.AF_INET, 'name' : 'AA',       'subnets' : ['10.99.101.0/28',   '10.99.201.0/28'],                  'admin_parent' : 'A'},
               {'family' : socket.AF_INET, 'name' : 'AAA',      'subnets' : ['10.99.101.0/30',   '10.99.201.0/30'],                  'admin_parent' : 'AA'},
               {'family' : socket.AF_INET, 'name' : 'AAZ',      'subnets' : ['10.99.101.4/30',   '10.99.201.4/30'],                 'admin_parent' : 'AA'},
               {'family' : socket.AF_INET, 'name' : 'AB',       'subnets' : ['10.99.101.64/28',  '10.99.201.64/28'],                 'admin_parent' : 'A'},
               {'family' : socket.AF_INET, 'name' : 'ABA',      'subnets' : ['10.99.101.64/30',  '10.99.201.64/30'],                  'admin_parent' : 'AB'},
               {'family' : socket.AF_INET, 'name' : 'ABZ',      'subnets' : ['10.99.101.68/30',  '10.99.201.68/30'],                 'admin_parent' : 'AB'},
               {'family' : socket.AF_INET, 'name' : 'AY',       'subnets' : ['10.99.101.80/28',  '10.99.201.80/28'],                 'admin_parent' : 'A'},
               {'family' : socket.AF_INET, 'name' : 'AYA',      'subnets' : ['10.99.101.80/30',  '10.99.201.80/30'],                  'admin_parent' : 'AY'},
               {'family' : socket.AF_INET, 'name' : 'AYZ',      'subnets' : ['10.99.101.84/30',  '10.99.201.84/30'],                 'admin_parent' : 'AY'},
               {'family' : socket.AF_INET, 'name' : 'AZ',       'subnets' : ['10.99.101.16/28',  '10.99.201.16/28'],                 'admin_parent' : 'A'},
               {'family' : socket.AF_INET, 'name' : 'AZA',      'subnets' : ['10.99.101.16/30',  '10.99.201.16/30'],                  'admin_parent' : 'AZ'},
               {'family' : socket.AF_INET, 'name' : 'AZZ',      'subnets' : ['10.99.101.20/30',  '10.99.201.20/30'],                 'admin_parent' : 'AZ'},
               {'family' : socket.AF_INET, 'name' : 'Z',        'subnets' : ['10.99.101.128/25', '10.99.201.128/25'], 'admin_parent' : None},
               {'family' : socket.AF_INET, 'name' : 'ZA',       'subnets' : ['10.99.101.128/28', '10.99.201.128/28'],                  'admin_parent' : 'Z'},
               {'family' : socket.AF_INET, 'name' : 'ZAA',      'subnets' : ['10.99.101.128/30', '10.99.201.128/30'],                  'admin_parent' : 'ZA'},
               {'family' : socket.AF_INET, 'name' : 'ZAZ',      'subnets' : ['10.99.101.132/30', '10.99.201.132/30'],                 'admin_parent' : 'ZA'},
               {'family' : socket.AF_INET, 'name' : 'ZB',       'subnets' : ['10.99.101.192/28', '10.99.201.192/28'],                    'admin_parent' : 'Z'},
               {'family' : socket.AF_INET, 'name' : 'ZBA',      'subnets' : ['10.99.101.192/30', '10.99.201.192/30'],                  'admin_parent' : 'ZB'},
               {'family' : socket.AF_INET, 'name' : 'ZBZ',      'subnets' : ['10.99.101.196/30', '10.99.201.196/30'],                 'admin_parent' : 'ZB'},
               {'family' : socket.AF_INET, 'name' : 'ZY',       'subnets' : ['10.99.101.208/28', '10.99.201.208/28'],                'admin_parent' : 'Z'},
               {'family' : socket.AF_INET, 'name' : 'ZYA',      'subnets' : ['10.99.101.208/30', '10.99.201.208/30'],                  'admin_parent' : 'ZY'},
               {'family' : socket.AF_INET, 'name' : 'ZYZ',      'subnets' : ['10.99.101.212/30', '10.99.201.212/30'],                 'admin_parent' : 'ZY'},
               {'family' : socket.AF_INET, 'name' : 'ZZ',       'subnets' : ['10.99.101.144/28', '10.99.201.144/28'],                 'admin_parent' : 'Z'},
               {'family' : socket.AF_INET, 'name' : 'ZZA',      'subnets' : ['10.99.101.144/30', '10.99.201.144/30'],                  'admin_parent' : 'ZZ'},
               {'family' : socket.AF_INET, 'name' : 'ZZZ',      'subnets' : ['10.99.101.148/30', '10.99.201.148/30'],                 'admin_parent' : 'ZZ'},

               # imported Zone from Zorp.Zone
               {'family' : socket.AF_INET6, 'name' : 'IPv6_Zone_80',  'subnets' : ['fd00:bb:1030:1100:cc::/80'], 'admin_parent' : None},
               {'family' : socket.AF_INET6, 'name' : 'IPv6_Zone_96',  'subnets' : ['fd00:bb:1030:1100:cc:aa::/96'], 'admin_parent' : None},
               {'family' : socket.AF_INET6, 'name' : 'IPv6_Zone_96_2',  'subnets' : ['fd00:bb:1030:1100:cc:22::/96'], 'admin_parent' : None},
               {'family' : socket.AF_INET6, 'name' : 'IPv6_Zone_128',  'subnets' : ['fd00:bb:1030:1100:cc:aa:bb:dd/128'], 'admin_parent' : None},

             ]

    def test_subnet_arith(self):
        self.assertEqual(socket.inet_pton(socket.AF_INET,'192.168.1.1'), testutil.subnet_base(socket.AF_INET,'192.168.1.1/24'))
        self.assertEqual(socket.inet_pton(socket.AF_INET,'255.255.255.0'), testutil.subnet_mask(socket.AF_INET,'192.168.1.1/24'))
        self.assertEqual(socket.inet_pton(socket.AF_INET6,'fd00:bb:1030:1100:cc::'), testutil.subnet_base(socket.AF_INET6,'fd00:bb:1030:1100:cc::/80'))
        self.assertEqual(socket.inet_pton(socket.AF_INET6,'ffff:ffff:ffff:ffff:ffff:0000:0000:0000'), testutil.subnet_mask(socket.AF_INET6,'fd00:bb:1030:1100:cc::/80'))
      
    def _addzones(self):
      for zone in self._zones:
          #print "zone=%s\n"%(zone,)
          subnets = zone['subnets']
          self.send_message(messages.KZorpAddZoneMessage(
                            zone['name'],
                            pname=zone['admin_parent'],
                            subnet_num=len(subnets)))
          for subnet in subnets:
            self.send_message(messages.KZorpAddZoneSubnetMessage(
                              zone['name'],
                              family=zone['family'],
                              address = testutil.subnet_base(zone['family'], subnet),
                              mask = testutil.subnet_mask(zone['family'], subnet)))

    def _dump_dispatcher_handler(self, message):
        self._dumped_dispatchers.append(message)

    def check_dispatcher_num(self, num_dispatchers = 0, in_transaction = True):
        self._dumped_dispatchers = []

        if in_transaction == True:
            self.start_transaction()
        self.send_message(messages.KZorpGetDispatcherMessage(None), message_handler = self._dump_dispatcher_handler, dump = True)
        if in_transaction == True:
            self.end_transaction()

        self.assertEqual(num_dispatchers, len(self._dumped_dispatchers))

    def get_dispatcher_attrs(self, message):
        attrs = message.get_attributes()

        return attrs

    def get_dispatcher_name(self, message):
        attrs = self.get_dispatcher_attrs(message)
        if attrs.has_key(messages.KZNL_ATTR_DPT_NAME) == True:
            return messages.parse_name_attr(attrs[messages.KZNL_ATTR_DPT_NAME])

        return None

    def _check_dispatcher_params(self, add_dispatcher_message, dispatcher_data):
        self.assertEqual(self.get_dispatcher_name(add_dispatcher_message), dispatcher_data['name'])

        attrs = self.get_dispatcher_attrs(add_dispatcher_message)

        num_rules = messages.parse_n_dimension_attr(attrs[messages.KZNL_ATTR_DISPATCHER_N_DIMENSION_PARAMS])
        self.assertEqual(dispatcher_data['num_rules'], num_rules)

    def _check_add_rule_params(self, add_dispatcher_message, rule_data):

        attrs = add_dispatcher_message.get_attributes()
        dpt_name, rule_id, service, rules, count = messages.parse_rule_attrs(attrs)

        self.assertEqual(rule_data['rule_id'], rule_id)
        self.assertEqual(rule_data['service'], service)

        self.assertEqual(len(rule_data['entry_nums']), len(rules))

        for k, v in rule_data['entry_nums'].items():
            self.assertEqual(k in rules, True)
            self.assertEqual((rule_data['entry_nums'][k],), (rules[k],))

    def _check_add_rule_entry_params(self, add_dispatcher_message, rule_entry_data, rule_entry_index):

        attrs = add_dispatcher_message.get_attributes()
        dpt_name, rule_id, rule_entries = messages.parse_rule_entry_attrs(attrs)
        self.assertEqual(rule_entry_data['rule_id'], rule_id)
        for k, v in rule_entry_data['entry_values'].items():
            if rule_entry_data['entry_nums'][k] > rule_entry_index:
                self.assertEqual(k in rule_entries, True)
                if k in [messages.KZNL_ATTR_N_DIMENSION_SRC_IP, messages.KZNL_ATTR_N_DIMENSION_DST_IP, messages.KZNL_ATTR_N_DIMENSION_SRC_IP6, messages.KZNL_ATTR_N_DIMENSION_DST_IP6]:
                    (addr, mask) = rule_entries[k]
                    self.assertEqual(testutil.addr_packed(rule_entry_data['entry_values'][k][rule_entry_index]), addr)
                    self.assertEqual(testutil.netmask_packed(rule_entry_data['entry_values'][k][rule_entry_index]), mask)
                elif k == messages.KZNL_ATTR_N_DIMENSION_SRC_PORT or k == messages.KZNL_ATTR_N_DIMENSION_DST_PORT:
                    self.assertEqual(rule_entry_data['entry_values'][k][rule_entry_index], rule_entries[k])
                else:
                    self.assertEqual(rule_entry_data['entry_values'][k][rule_entry_index], rule_entries[k])

    def setup_service_dispatcher(self, services, dispatchers, add_zone = True, add_service = True):
        self._dumped_diszpancsers = []

        self.start_transaction()

        if add_zone:
            self._addzones()

        if add_service:
            for service in services:
                if type(service) == types.DictType:
                    service = service['name']
                self.send_message(messages.KZorpAddProxyServiceMessage(service))

        for dispatcher in dispatchers:
            message_add_dispatcher = messages.KZorpAddDispatcherMessage(dispatcher['name'],
                                                               dispatcher['num_rules']
                                                              )

            self.send_message(message_add_dispatcher, error_handler=lambda res: os.strerror(res)+" "+str(message_add_dispatcher))

            for rule in dispatcher['rules']:
                _max = 0
                for name, value in rule['entry_nums'].items():
                    if _max < value:
                        _max = value

                message_add_rule = messages.KZorpAddRuleMessage(dispatcher['name'],
                                                       rule['rule_id'],
                                                       rule['service'],
                                                       rule['entry_nums']
                                                       )
                self.send_message(message_add_rule)

                for i in range(_max):
                    data = {}
                    for dim_type in messages.N_DIMENSION_ATTRS:
                        if dim_type in rule['entry_nums'] and rule['entry_nums'][dim_type] > i:
                            if dim_type in [messages.KZNL_ATTR_N_DIMENSION_SRC_IP, messages.KZNL_ATTR_N_DIMENSION_DST_IP]:
                                subnet = rule['entry_values'][dim_type][i]
                                data[dim_type] = (testutil.addr_packed(subnet), testutil.netmask_packed(subnet))
                            elif dim_type in [messages.KZNL_ATTR_N_DIMENSION_SRC_IP6, messages.KZNL_ATTR_N_DIMENSION_DST_IP6]:
                                subnet = rule['entry_values'][dim_type][i]
                                data[dim_type] = (testutil.addr_packed6(subnet), testutil.netmask_packed6(subnet))
                            else:
                                data[dim_type] = rule['entry_values'][dim_type][i]
                    #print "rule=%s\ndispatcher=%s\ndata=%s\n"%(rule,dispatcher['name'],data)
                    message_add_rule_entry = messages.KZorpAddRuleEntryMessage(dispatcher['name'], rule['rule_id'], data)

                    self.send_message(message_add_rule_entry)

        self.end_transaction()

if __name__ == "__main__":
    testutil.main()
