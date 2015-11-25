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
import kzorp.messages as messages
import socket
import testutil
import errno
from functools import partial
from KZorpComm import KZorpComm
from KZorpBaseTestCaseCommon import KZorpTestCaseDump

class KZorpTestCaseServiceDump(KZorpTestCaseDump):
    _dump_message = messages.KZorpGetServiceMessage(None)

    def __create_service_messages_that_do_not_fit_into_one_nelink_packet(self):
        service_name_format = 'service_%d'

        service_messages = []

        for service_num in range(self._get_netlink_packet_size()):
            service_name = service_name_format % (service_num, )

            add_service_message = messages.KZorpAddForwardServiceMessage(service_name, messages.KZF_SVC_TRANSPARENT)
            service_messages.append(add_service_message)

        return service_messages

    def test_several_service_with_subnets_do_not_fit_into_one_netlink_packet(self):
        self._check_objects(self.__create_service_messages_that_do_not_fit_into_one_nelink_packet())


class KZorpTestCaseServices(KZorpComm):

    services = [
        (messages.KZorpAddProxyServiceMessage,
         { 'name': "test-proxy" }),

        (messages.KZorpAddForwardServiceMessage,
         { 'name': "test3", 'dst_family': socket.AF_INET, 'dst_ip': socket.inet_pton(socket.AF_INET, '1.2.3.4'), 'dst_port': 1 }),

        (messages.KZorpAddForwardServiceMessage,
         { 'name': "test6", 'dst_family': socket.AF_INET, 'dst_ip': socket.inet_pton(socket.AF_INET, '1.2.3.4'), 'dst_port': 1 }),

        (messages.KZorpAddProxyServiceMessage,
         {'name': 'test5', 'count': 303}),

        (messages.KZorpAddDenyServiceMessage,
         {'name': 'test-deny', 'logging': True, 'count': 33, 'ipv4_settings': messages.KZ_SVC_DENY_METHOD_V4_DROP, 'ipv6_settings': messages.KZ_SVC_DENY_METHOD_V6_DROP}),
        ]

    def check_svc_num(self, num_svc):
        _dumped_zones = []
        self.send_message(messages.KZorpGetServiceMessage(None), message_handler = _dumped_zones.append, dump = True)
        self.assertEqual(num_svc, len(_dumped_zones))

    def check_send(self, message, return_value):
        self.start_transaction()
        r = self.send_message(message, assert_on_error=False)
        self.end_transaction()
        self.assertEqual(return_value, r)

    def newSetUp(self):
        self.start_transaction()
        for service in self.services:
            self.send_message(service[0](**service[1]))
        self.end_transaction()

    def tearDown(self):
        self.flush_all();

    def test_get_service(self):
        def check_get_reply(self, service, reply):
            for (name, value) in service[1].items():
                self.assertEqual(getattr(reply, name), value)

        self.newSetUp()
        self.check_svc_num(len(self.services))
        self.assertEqual(-2, self.send_message(messages.KZorpGetServiceMessage("nonexistent"), assert_on_error=False))

        for service in self.services:
            self.send_message(messages.KZorpGetServiceMessage(service[1].get('name')), message_handler = partial(check_get_reply, self, service))

    def test_add_service_duplicated(self):
        self.newSetUp()
        service_cnt = len(self.services)
        #duplicated entry check: the matching service was in the same transaction
        self.start_transaction()
        self.send_message(messages.KZorpAddProxyServiceMessage("dupe1"))
        res = self.send_message(messages.KZorpAddProxyServiceMessage("dupe1"), assert_on_error=False)
        self.end_transaction()
        self.assertEqual(-errno.EEXIST, res)
        service_cnt += 1
        self.check_svc_num(service_cnt)

        #duplicated entry check: the matching service was already existing
        self.check_send(messages.KZorpAddProxyServiceMessage("dupe1"), -errno.EEXIST)
        self.check_svc_num(service_cnt)

    def test_add_service_invalid(self):

        class KZorpAddInvalidServiceMessage(messages.KZorpAddServiceMessage):
            type_string = "Invalid"

            def __init__(self, name):
                super(KZorpAddInvalidServiceMessage, self).__init__(name, messages.KZ_SVC_PROXY + 100, 0, 0)

                self._build_payload()

        self.newSetUp()
        service_cnt = len(self.services)
        #invalid service type
        self.check_send(KZorpAddInvalidServiceMessage("invalid_service_type"), -errno.EINVAL)
        self.check_svc_num(service_cnt)

    def test_add_service(self):

        self.newSetUp()
        service_cnt = len(self.services)

        #outside of transaction
        self.assertEqual(-errno.ENOENT, self.send_message(self.services[0][0](**self.services[0][1]), assert_on_error=False))
        self.check_svc_num(service_cnt)

    def test_add_service_flags(self):
        self.newSetUp()
        service_cnt = len(self.services)

        for i in range(2 * messages.KZF_SVC_LOGGING):
            self.check_send(messages.KZorpAddProxyServiceMessage("flag-%d" % i, i), 0)

        service_cnt += 2 * messages.KZF_SVC_LOGGING
        self.check_svc_num(service_cnt)

        # using undefined flags
        self.start_transaction()
        res = self.send_message(messages.KZorpAddProxyServiceMessage("flag-invalid", flags=0xfffffffc), assert_on_error=False)
        self.end_transaction()
        self.assertNotEqual(0, res)

    def test_add_service_nontransparent(self):
        self.newSetUp()
        service_cnt = len(self.services)
        self.check_send(messages.KZorpAddForwardServiceMessage("test-nontransparent-router", flags=0, count=0, dst_family=socket.AF_INET, dst_ip=socket.inet_pton(socket.AF_INET, '1.2.3.4'), dst_port=10010), 0)
        service_cnt += 1
        self.check_svc_num(service_cnt)

        self.check_send(messages.KZorpAddForwardServiceMessage("test-nontransparent-norouter", flags=0, count=0), -errno.EINVAL)
        self.check_svc_num(service_cnt)

    def _test_add_service_nat(self, nat_message_class):
        service_cnt = len(self.services)

        #adding a nat rule to a service added in the same transaction
        self.start_transaction()
        self.send_message(messages.KZorpAddForwardServiceMessage('test-nat', flags=messages.KZF_SVC_TRANSPARENT))
        self.send_message(nat_message_class('test-nat',
                                            nat_src=(messages.KZ_SVC_NAT_MAP_IPS + messages.KZ_SVC_NAT_MAP_PROTO_SPECIFIC, 12345688, 12345689, 1024, 1025),
                                            nat_map=(messages.KZ_SVC_NAT_MAP_IPS + messages.KZ_SVC_NAT_MAP_PROTO_SPECIFIC, 12345688, 12345689, 1024, 1025)))
        self.end_transaction()
        service_cnt += 2

        self.check_svc_num(service_cnt)

    def test_add_service_nat_dst(self):
        self.newSetUp()
        self._test_add_service_nat(messages.KZorpAddServiceDestinationNATMappingMessage)

    def test_add_service_nat_src(self):
        self.newSetUp()
        self._test_add_service_nat(messages.KZorpAddServiceSourceNATMappingMessage)

    def test_add_deny_service(self):
        response = []
        m = messages.KZorpAddDenyServiceMessage("denyservice", False, 0, messages.KZ_SVC_DENY_METHOD_V4_DROP, messages.KZ_SVC_DENY_METHOD_V6_DROP)
        self.start_transaction()
        self.send_message(m)
        self.end_transaction()
        self.start_transaction()
        self.send_message(messages.KZorpGetServiceMessage("denyservice"), message_handler = response.append, dump = True)
        self.end_transaction()

        self.assertEqual(1, len(response))

if __name__ == "__main__":
    testutil.main()
