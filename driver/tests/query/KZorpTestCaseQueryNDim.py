#!/usr/bin/env python2.7
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
from KZorpBaseTestCaseQuery import KZorpBaseTestCaseQuery
import testutil
import kzorp.messages as messages
import socket

class KZorpTestCaseQueryNDim(KZorpBaseTestCaseQuery):

    def __init__(self, *args):
        KZorpBaseTestCaseQuery.__init__(self, *args)

    def tearDown(self):
        self.flush_all()

    def _run_query2(self, queries):
        for query in queries:
            family = query['family']
            message_query = messages.KZorpQueryMessage(query['proto'],
                                              family,
                                              socket.inet_pton(family, query['saddr']),
                                              socket.inet_pton(family, query['daddr']),
                                              query['iface'],
                                              query['sport'],
                                              query['dport'])
            self.send_message(message_query, message_handler =
                            lambda msg: self.assertEqual(self.get_service_name(msg), query['service'], "Expected: %s, got %s for query %s" % (str(query['service']), str(self.get_service_name(msg)), str(query))))

    def _run_query(self, _queries, _answers):
        for query in _queries:
            family = query['family']
            message_query = messages.KZorpQueryMessage(query['proto'],
                                              query['family'],
                                              socket.inet_pton(family, query['saddr']),
                                              socket.inet_pton(family, query['daddr']),
                                              query['iface'],
                                              query['sport'],
                                              query['dport'])
            self.send_message(message_query, message_handler = self._query_message_handler)

        for i in range(len(_answers)):
            self.assertEqual(self.get_service_name(self._dumped_diszpancsers[i]), _answers[i])

        pass

    def test_n_dim_dispatcher_query(self):
        _dispatchers = [ { 'name' : 'n_dimension_with_ALL_rules', 'num_rules' : 2,
                         'rules' : [ { 'rule_id'      : 1, 'service' : 'Z_Z',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_IFACE : 1, messages.KZNL_ATTR_N_DIMENSION_PROTO : 1, messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : 2, messages.KZNL_ATTR_N_DIMENSION_DST_PORT : 1, messages.KZNL_ATTR_N_DIMENSION_SRC_IP : 2, messages.KZNL_ATTR_N_DIMENSION_SRC_ZONE : 3, messages.KZNL_ATTR_N_DIMENSION_DST_IP : 2, messages.KZNL_ATTR_N_DIMENSION_DST_ZONE : 1, messages.KZNL_ATTR_N_DIMENSION_IFGROUP : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_IFACE : ['dummy0'], messages.KZNL_ATTR_N_DIMENSION_PROTO : [socket.IPPROTO_TCP], messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : [(2,3), (4,5)], messages.KZNL_ATTR_N_DIMENSION_DST_PORT : [(5,6)], messages.KZNL_ATTR_N_DIMENSION_SRC_IP : ['10.99.201.5', '2.3.4.5/24'], messages.KZNL_ATTR_N_DIMENSION_SRC_ZONE : ['AAZ', 'ZZ', 'Z'], messages.KZNL_ATTR_N_DIMENSION_DST_IP : ['10.99.101.149/16', '4.5.6.7/8'], messages.KZNL_ATTR_N_DIMENSION_DST_ZONE : 'ZZZ', messages.KZNL_ATTR_N_DIMENSION_IFGROUP : [1]},
                                     },
                                     { 'rule_id'      : 2, 'service' : 'Z_Z',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_DST_ZONE : 2, messages.KZNL_ATTR_N_DIMENSION_DST_IP : 3, messages.KZNL_ATTR_N_DIMENSION_SRC_ZONE : 1, messages.KZNL_ATTR_N_DIMENSION_SRC_IP : 2, messages.KZNL_ATTR_N_DIMENSION_DST_PORT : 2, messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : 2, messages.KZNL_ATTR_N_DIMENSION_PROTO : 1, messages.KZNL_ATTR_N_DIMENSION_IFACE : 3 },
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_DST_ZONE : ['AZA', 'ZAZ'], messages.KZNL_ATTR_N_DIMENSION_DST_IP : ['8.7.6.5', '7.6.5.4/31', '9.8.7.6/25'], messages.KZNL_ATTR_N_DIMENSION_SRC_ZONE : 'ZZ', messages.KZNL_ATTR_N_DIMENSION_SRC_IP : ['5.4.3.2/32', '6.5.4.3/30'], messages.KZNL_ATTR_N_DIMENSION_DST_PORT : [(66,66),(100,200)], messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : [(23,24), (30, 40)], messages.KZNL_ATTR_N_DIMENSION_PROTO : [socket.IPPROTO_TCP], messages.KZNL_ATTR_N_DIMENSION_IFACE : ['dummy0', 'dummy1', 'dummy2'] }
                                     }
                                   ]
                       }
                     ]

        _services = ['Z_Z']

        _queries = [
                     { 'proto' : socket.IPPROTO_TCP, 'sport' : 2, 'saddr' : '10.99.201.5', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '10.99.101.149', 'iface' : 'dummy0'},
                   ]

        _answers = ['Z_Z']

        self.setup_service_dispatcher(_services, _dispatchers)
        self._run_query(_queries, _answers)

    def test_n_dim_iface_ifgroup_query(self):
        _dispatchers = [{ 'name' : 'n_dimension_specific', 'num_rules' : 2,
                          'rules' : [ { 'rule_id'      : 1, 'service' : 'A_A',
                                        'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_IFACE : 2},
                                        'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_IFACE : ['dummy0', 'dummy1'] }
                                      },
                                      { 'rule_id'      : 2, 'service' : 'AA_AA',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_IFGROUP : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_IFGROUP : [1] }
                                      },
                                    ]
                        }]

        _services = ['A_A', 'AA_AA']
        _queries = [
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy0'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy2'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy3'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy4'},
                   ]
        _answers = [ 'A_A', 'A_A', None, 'AA_AA', 'AA_AA',
                   ]

        self.setup_service_dispatcher(_services, _dispatchers)
        self._run_query(_queries, _answers)

    def test_n_dim_dst_iface_ifgroup_query(self):
        _dispatchers = [{ 'name' : 'n_dimension_specific', 'num_rules' : 2,
                          'rules' : [ { 'rule_id'      : 1, 'service' : 'A_A',
                                        'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_DST_IFACE : 2},
                                        'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_DST_IFACE : ['dummy0', 'dummy1'] }
                                      },
                                      { 'rule_id'      : 2, 'service' : 'AA_AA',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_DST_IFGROUP : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_DST_IFGROUP : [1] }
                                      },
                                    ]
                        }]

        _services = ['A_A', 'AA_AA']
        _queries = [
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '10.99.201.1', 'iface' : 'dummy0'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '10.99.202.2', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '10.99.203.3', 'iface' : 'dummy2'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '10.99.204.4', 'iface' : 'dummy3'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '10.99.205.5', 'iface' : 'dummy4'},
                   ]
        _answers = [ 'A_A', 'A_A', None, 'AA_AA', 'AA_AA',
                   ]

        self.setup_service_dispatcher(_services, _dispatchers)
        self._run_query(_queries, _answers)

    def test_n_dim_iface_ifgroup_empty_query(self):
        _dispatchers = [{ 'name' : 'n_dimension_specific', 'num_rules' : 3,
                          'rules' : [ { 'rule_id'      : 1, 'service' : 'A_A',
                                        'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_IFACE : 2},
                                        'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_IFACE : ['dummy0', 'dummy1'] }
                                      },
                                      { 'rule_id'      : 2, 'service' : 'AA_AA',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_IFGROUP : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_IFGROUP : [1] }
                                      },
                                      { 'rule_id'      : 3, 'service' : 'AAA_AAA',
                                        'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_IFACE : 0},
                                        'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_IFACE : [] }
                                      },

                                    ]
                        }]

        _services = ['A_A', 'AA_AA', 'AAA_AAA']
        _queries = [
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy2'},
                   ]
        _answers = [ 'AAA_AAA',
                   ]

        self.setup_service_dispatcher(_services, _dispatchers)
        self._run_query(_queries, _answers)

    def test_n_dim_dst_iface_ifgroup_empty_query(self):
        _dispatchers = [{ 'name' : 'n_dimension_specific', 'num_rules' : 3,
                          'rules' : [ { 'rule_id'      : 1, 'service' : 'A_A',
                                        'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_DST_IFACE : 2},
                                        'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_DST_IFACE : ['dummy0', 'dummy1'] }
                                      },
                                      { 'rule_id'      : 2, 'service' : 'AA_AA',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_DST_IFGROUP : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_DST_IFGROUP : [1] }
                                      },
                                      { 'rule_id'      : 3, 'service' : 'AAA_AAA',
                                        'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_DST_IFACE : 0},
                                        'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_DST_IFACE : [] }
                                      },

                                    ]
                        }]

        _services = ['A_A', 'AA_AA', 'AAA_AAA']
        _queries = [
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '10.99.203.3', 'iface' : 'dummy4'},
                   ]
        _answers = [ 'AAA_AAA',
                   ]

        self.setup_service_dispatcher(_services, _dispatchers)
        self._run_query(_queries, _answers)

    def test_n_dim_proto_query(self):
        _dispatchers = [{ 'name' : 'n_dimension_specific', 'num_rules' : 1,
                          'rules' : [ { 'rule_id'      : 2, 'service' : 'A_A',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_PROTO : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_PROTO : [socket.IPPROTO_TCP] }
                                      },
                                    ]
                        }]

        _services = ['A_A']
        _queries = [
                     { 'proto' : socket.IPPROTO_TCP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
                   ]
        _answers = [ 'A_A', None
                   ]

        self.setup_service_dispatcher(_services, _dispatchers)
        self._run_query(_queries, _answers)

    def test_n_dim_proto_empty_query(self):
        _dispatchers = [{ 'name' : 'n_dimension_specific', 'num_rules' : 2,
                          'rules' : [ { 'rule_id'      : 1, 'service' : 'A_A',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_PROTO : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_PROTO : [socket.IPPROTO_TCP] }
                                      },
                                      {'rule_id'      : 2, 'service' : 'AA_AA',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_PROTO : 0},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_PROTO : [] }
                                      },

                                    ]
                        }]

        _services = ['A_A', 'AA_AA']
        _queries = [
                     { 'proto' : socket.IPPROTO_TCP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
                   ]
        _answers = [ 'A_A', 'AA_AA'
                   ]

        self.setup_service_dispatcher(_services, _dispatchers)
        self._run_query(_queries, _answers)


    def test_n_dim_src_port_query(self):
        _dispatchers = [{ 'name' : 'n_dimension_specific', 'num_rules' : 1,
                          'rules' : [{ 'rule_id'      : 3, 'service' : 'A_A',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : 2},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : [(10,10), (60000, 65535)] }
                                     },
                                    ]
                        }]

        _services = ['A_A']
        _queries = [
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 10, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 60000, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 63000, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 65535, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 59999, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 9, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 11, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
                   ]
        _answers = [ 'A_A', 'A_A', 'A_A', 'A_A', None, None, None ]

        self.setup_service_dispatcher(_services, _dispatchers)
        self._run_query(_queries, _answers)

    def test_n_dim_src_port_empty_query(self):
        _dispatchers = [{ 'name' : 'n_dimension_specific', 'num_rules' : 2,
                          'rules' : [{ 'rule_id'      : 1, 'service' : 'A_A',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : 2},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : [(10,10), (60000, 65535)] }
                                     },
                                     { 'rule_id'      : 2, 'service' : 'AA_AA',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : 0},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : [] }
                                     },

                                    ]
                        }]

        _services = ['A_A', 'AA_AA']

        packet = dict(proto=socket.IPPROTO_UDP, saddr='1.1.1.1', family=socket.AF_INET, daddr='1.2.3.4', iface='dummy1')

        queries = [
            dict(packet, sport=10, dport=10, service='A_A'),
            dict(packet, sport=60000, dport=60000, service='A_A'),
            dict(packet, sport=63000, dport=63000, service='A_A'),
            dict(packet, sport=65535, dport=65535, service='A_A'),
            dict(packet, sport=59999, dport=59999, service='AA_AA'),
            dict(packet, sport=9, dport=9, service='AA_AA'),
            dict(packet, sport=11, dport=11, service='AA_AA'),
            ]
        self.setup_service_dispatcher(_services, _dispatchers)
        self._run_query2(queries)

    def test_n_dim_dst_port_query(self):
        _dispatchers = [{ 'name' : 'n_dimension_specific', 'num_rules' : 1,
                          'rules' : [{ 'rule_id'      : 3, 'service' : 'A_A',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_DST_PORT : 2},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_DST_PORT : [(10,10), (60000, 65535)] }
                                     },
                                    ]
                        }]

        _services = ['A_A']

        packet = dict(proto=socket.IPPROTO_UDP, sport=5, saddr='1.1.1.1', family=socket.AF_INET, daddr='1.2.3.4', iface='dummy1')
        queries = [
            dict(packet, dport=10, service='A_A'),
            dict(packet, dport=60000, service='A_A'),
            dict(packet, dport=63000, service='A_A'),
            dict(packet, dport=65535, service='A_A'),
            dict(packet, dport=59999, service=None),
            dict(packet, dport=9, service=None),
            dict(packet, dport=11, service=None),
            ]
        self.setup_service_dispatcher(_services, _dispatchers)
        self._run_query2(queries)

    def test_n_dim_dst_port_empty_query(self):
        _dispatchers = [{ 'name' : 'n_dimension_specific', 'num_rules' : 2,
                          'rules' : [{ 'rule_id'      : 1, 'service' : 'A_A',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_DST_PORT : 2},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_DST_PORT : [(10,10), (60000, 65535)] }
                                     },
                                     { 'rule_id'      : 2, 'service' : 'AA_AA',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_DST_PORT : 0},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_DST_PORT : [] }
                                     },

                                    ]
                        }]

        _services = ['A_A', 'AA_AA']

        packet = dict(proto=socket.IPPROTO_UDP, saddr='1.1.1.1', family=socket.AF_INET, daddr='1.2.3.4', iface='dummy1')

        queries = [
            dict(packet, sport=10, dport=10, service='A_A'),
            dict(packet, sport=60000, dport=60000, service='A_A'),
            dict(packet, sport=63000, dport=63000, service='A_A'),
            dict(packet, sport=65535, dport=65535, service='A_A'),
            dict(packet, sport=59999, dport=59999, service='AA_AA'),
            dict(packet, sport=9, dport=9, service='AA_AA'),
            dict(packet, sport=11, dport=11, service='AA_AA'),
            ]
        self.setup_service_dispatcher(_services, _dispatchers)
        self._run_query2(queries)


    def test_n_dim_src_ip_vs_src_zone_query(self):
        _dispatchers = [ { 'name' : 'n_dimension_precedency', 'num_rules' : 'set_below',
                         'rules' : [ { 'rule_id'      : 1, 'service' : 'IPv4_Subnet_1',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_SRC_IP : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_SRC_IP : ['10.99.201.169/32']},
                                     },
                                     { 'rule_id'      : 2, 'service' : 'IPv4_Zone_1',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_SRC_ZONE : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_SRC_ZONE : ['Z']},
                                     },
                                     { 'rule_id'      : 3, 'service' : 'IPv4_Subnet_2',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_SRC_IP : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_SRC_IP : ['10.99.201.0/24']},
                                     },
                                     { 'rule_id'      : 4, 'service' : 'IPv4_Zone_2',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_SRC_ZONE : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_SRC_ZONE : ['A']},
                                     },
                                     { 'rule_id'      : 5, 'service' : 'IPv4_Subnet_and_Zone',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_SRC_ZONE : 1, messages.KZNL_ATTR_N_DIMENSION_SRC_IP : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_SRC_ZONE : ['ZA'], messages.KZNL_ATTR_N_DIMENSION_SRC_IP : ['10.99.201.66/32']},
                                     },
                                     { 'rule_id'      : 6, 'service' : 'IPv6_Subnet_1',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_SRC_IP6 : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_SRC_IP6 : ['fd00:bb:1030:1100:cc:aa:bb:dd/128']},
                                     },
                                     { 'rule_id'      : 7, 'service' : 'IPv6_Subnet_2',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_SRC_IP6 : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_SRC_IP6 : ['fd00:bb:1030:1100:cc:aa:00:00/96']},
                                     },
                                     { 'rule_id'      : 8, 'service' : 'IPv6_Zone_80',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_SRC_ZONE : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_SRC_ZONE : ['IPv6_Zone_80'] }
                                     },
                                     { 'rule_id'      : 9, 'service' : 'IPv6_Zone_96',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_SRC_ZONE : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_SRC_ZONE : ['IPv6_Zone_96'] }
                                     },
                                     { 'rule_id'      : 10, 'service' : 'IPv6_Zone_128',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_SRC_ZONE : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_SRC_ZONE : ['IPv6_Zone_128'] }
                                     },
                                     { 'rule_id'      : 11, 'service' : 'IPv6_Subnet_and_Zone',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_SRC_ZONE : 1, messages.KZNL_ATTR_N_DIMENSION_SRC_IP6 : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_SRC_ZONE : ['IPv6_Zone_96_2'], messages.KZNL_ATTR_N_DIMENSION_SRC_IP6 : ['fd00:bb:1030:1100:cc:22:bb:cc/128']},
                                     },
                                   ]
                       }
                     ]

        _dispatchers[0]['num_rules'] = len(_dispatchers[0]['rules'])
        _services = []
        for rule in _dispatchers[0]['rules']:
            _services.append(rule['service'])
        _queries = []
        _answers = []
        # Test1: /32 subnet vs Zone
        _queries.append({ 'proto' : socket.IPPROTO_TCP, 'sport' : 6, 'saddr' : '10.99.201.169', 'dport' : 9, 'family' : socket.AF_INET, 'daddr' : '4.3.2.1', 'iface' : 'dummy0'})
        _answers.append('IPv4_Subnet_1')
        # Test2: /24 subnet vs Zone
        _queries.append({ 'proto' : socket.IPPROTO_TCP, 'sport' : 6, 'saddr' : '10.99.201.41', 'dport' : 9, 'family' : socket.AF_INET, 'daddr' : '4.3.2.1', 'iface' : 'dummy0'})
        _answers.append('IPv4_Subnet_2')
        # Test3: No match
        _queries.append({ 'proto' : socket.IPPROTO_TCP, 'sport' : 6, 'saddr' : '10.199.201.1', 'dport' : 9, 'family' : socket.AF_INET, 'daddr' : '4.3.2.1', 'iface' : 'dummy0'})
        _answers.append(None)
        # Test4: Zone match
        _queries.append({ 'proto' : socket.IPPROTO_TCP, 'sport' : 6, 'saddr' : '10.99.101.169', 'dport' : 9, 'family' : socket.AF_INET, 'daddr' : '4.3.2.1', 'iface' : 'dummy0'})
        _answers.append('IPv4_Zone_1')
        # Test5: Subnet match (if there is zone in the service)
        _queries.append({ 'proto' : socket.IPPROTO_TCP, 'sport' : 6, 'saddr' : '10.99.201.66', 'dport' : 9, 'family' : socket.AF_INET, 'daddr' : '4.3.2.1', 'iface' : 'dummy0'})
        _answers.append('IPv4_Subnet_and_Zone')
        # Test6: Zone match (if there is subnet in the service)
        _queries.append({ 'proto' : socket.IPPROTO_TCP, 'sport' : 6, 'saddr' : '10.99.101.137', 'dport' : 9, 'family' : socket.AF_INET, 'daddr' : '4.3.2.1', 'iface' : 'dummy0'})
        _answers.append('IPv4_Subnet_and_Zone')
        # Test7: /128 Subnet6 match vs Zone
        _queries.append({ 'proto' : socket.IPPROTO_TCP, 'sport' : 6, 'saddr' : 'fd00:bb:1030:1100:cc:aa:bb:dd', 'dport' : 9, 'family' : socket.AF_INET6, 'daddr' : 'f080::', 'iface' : 'dummy0'})
        _answers.append('IPv6_Subnet_1')
        # Test8: /90 Subnet6 match vs Zone
        _queries.append({ 'proto' : socket.IPPROTO_TCP, 'sport' : 6, 'saddr' : 'fd00:bb:1030:1100:cc:aa:11:11', 'dport' : 9, 'family' : socket.AF_INET6, 'daddr' : 'f080::', 'iface' : 'dummy0'})
        _answers.append('IPv6_Subnet_2')
        # Test9: No match IPv6
        _queries.append({ 'proto' : socket.IPPROTO_TCP, 'sport' : 6, 'saddr' : 'fd00:bb:1030:1100:11:aa:bb:dd', 'dport' : 9, 'family' : socket.AF_INET6, 'daddr' : 'f080::', 'iface' : 'dummy0'})
        _answers.append(None)
        # Test10: Zone6 match
        _queries.append({ 'proto' : socket.IPPROTO_TCP, 'sport' : 6, 'saddr' : 'fd00:bb:1030:1100:cc:cc:bb:dd', 'dport' : 9, 'family' : socket.AF_INET6, 'daddr' : 'f080::', 'iface' : 'dummy0'})
        _answers.append('IPv6_Zone_80')
        # Test11: Subnet6 match (if there is zone6 in the service)
        _queries.append({ 'proto' : socket.IPPROTO_TCP, 'sport' : 6, 'saddr' : 'fd00:bb:1030:1100:cc:22:bb:cc', 'dport' : 9, 'family' : socket.AF_INET6, 'daddr' : 'f080::', 'iface' : 'dummy0'})
        _answers.append('IPv6_Subnet_and_Zone')
        # Test12: Zone6 match (if there is subnet6 in the service)
        _queries.append({ 'proto' : socket.IPPROTO_TCP, 'sport' : 6, 'saddr' : 'fd00:bb:1030:1100:cc:22:22:22', 'dport' : 9, 'family' : socket.AF_INET6, 'daddr' : 'f080::', 'iface' : 'dummy0'})
        _answers.append('IPv6_Subnet_and_Zone')

        self.setup_service_dispatcher(_services, _dispatchers)
        self._run_query(_queries, _answers)

    def test_n_dim_src_ip_query(self):
        _dispatchers = [{ 'name' : 'n_dimension_specific', 'num_rules' : 7,
                          'rules' : [{ 'rule_id'      : 1, 'service' : 'A_A',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_SRC_IP : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_SRC_IP : ['1.2.3.0/24'] }
                                     },
                                     { 'rule_id'      : 2, 'service' : 'AA_AA',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_SRC_IP : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_SRC_IP : ['1.2.3.0/30'] }
                                     },
                                     { 'rule_id'      : 3, 'service' : 'AAA_AAA',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_SRC_IP : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_SRC_IP : ['1.2.3.0/31'] }
                                     },
                                     { 'rule_id'      : 4, 'service' : 'B_B',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_SRC_IP : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_SRC_IP : ['1.2.3.200'] }
                                     },
                                     { 'rule_id'      : 5, 'service' : 'C',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_SRC_IP : 1,
                                                          messages.KZNL_ATTR_N_DIMENSION_SRC_IP6 : 1
                                                        },
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_SRC_IP : ['2.0.0.0/8'],
                                                          messages.KZNL_ATTR_N_DIMENSION_SRC_IP6 : ['ffc0::1/127']
                                                        }
                                     },
                                     { 'rule_id'      : 6, 'service' : 'D',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_SRC_IP : 1,
                                                          messages.KZNL_ATTR_N_DIMENSION_SRC_IP6 : 2
                                                        },
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_SRC_IP : ['2.3.4.5/32'],
                                                          messages.KZNL_ATTR_N_DIMENSION_SRC_IP6 : ['ffc0::0/10', 'ffc0::3/128']
                                                        }
                                     },
                                     { 'rule_id'      : 7, 'service' : 'E',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_SRC_IP6 : 1 },
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_SRC_IP6 : ['ffc0::2/127'] }
                                     },
                                    ]
                        }]

        _services = ['A_A', 'AA_AA', 'AAA_AAA', 'B_B', 'C', 'D', 'E']

        ipv4_packet = dict(proto=socket.IPPROTO_TCP, sport=5, dport=5, iface='dummy1', family=socket.AF_INET, daddr='1.1.1.1')
        ipv6_packet = dict(proto=socket.IPPROTO_TCP, sport=5, dport=5, iface='dummy1', family=socket.AF_INET6, daddr='::')

        _queries = [
            dict(ipv4_packet, saddr='1.2.3.4', service='A_A'),
            dict(ipv4_packet, saddr='1.2.3.2', service='AA_AA'),
            dict(ipv4_packet, saddr='1.2.3.1', service='AAA_AAA'),
            dict(ipv4_packet, saddr='1.2.3.200', service='B_B'),
            dict(ipv4_packet, saddr='1.2.2.5', service=None),
            dict(ipv6_packet, saddr='1234::', service=None),
            dict(ipv6_packet, saddr='ffc0::1', service="C"),
            dict(ipv4_packet, saddr='2.3.4.5', service="D"),
            dict(ipv4_packet, saddr='2.3.4.6', service="C"),
            dict(ipv6_packet, saddr='ffc0::2', service="E"),
            dict(ipv6_packet, saddr='ffc0::3', service="D"),
            ]

        self.setup_service_dispatcher(_services, _dispatchers)
        self._run_query2(_queries)

    def test_n_dim_src_ip_empty_query(self):
        _dispatchers = [{ 'name' : 'n_dimension_specific', 'num_rules' : 5,
                          'rules' : [{ 'rule_id'      : 1, 'service' : 'A_A',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_SRC_IP : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_SRC_IP : ['1.2.3.0/24'] }
                                     },
                                     { 'rule_id'      : 2, 'service' : 'AA_AA',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_SRC_IP : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_SRC_IP : ['1.2.3.0/30'] }
                                     },
                                     { 'rule_id'      : 3, 'service' : 'AAA_AAA',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_SRC_IP : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_SRC_IP : ['1.2.3.0/31'] }
                                     },
                                     { 'rule_id'      : 4, 'service' : 'B_B',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_SRC_IP : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_SRC_IP : ['1.2.3.200'] }
                                     },
                                     { 'rule_id'      : 5, 'service' : 'BB_BB',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_SRC_IP : 0},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_SRC_IP : [] }
                                     },

                                    ]
                        }]

        _services = ['A_A', 'AA_AA', 'AAA_AAA', 'B_B', 'BB_BB']
        _queries = [
                     { 'proto' : socket.IPPROTO_TCP, 'sport' : 5, 'saddr' : '1.2.3.4', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.1.1.1', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_TCP, 'sport' : 5, 'saddr' : '1.2.3.2', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.1.1.1', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_TCP, 'sport' : 5, 'saddr' : '1.2.3.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.1.1.1', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_TCP, 'sport' : 5, 'saddr' : '1.2.3.200', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.1.1.1', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_TCP, 'sport' : 5, 'saddr' : '1.2.2.5', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.1.1.1', 'iface' : 'dummy1'},
                   ]
        _answers = [ 'A_A', 'AA_AA', 'AAA_AAA', 'B_B', 'BB_BB' ]

        ipv4_packet = dict(proto=socket.IPPROTO_TCP, sport=5, dport=5, iface='dummy1', family=socket.AF_INET, daddr='1.1.1.1')
        ipv6_packet = dict(proto=socket.IPPROTO_TCP, sport=5, dport=5, iface='dummy1', family=socket.AF_INET6, daddr='::')

        _queries = [
            dict(ipv4_packet, saddr='1.2.3.4', service='A_A'),
            dict(ipv4_packet, saddr='1.2.3.2', service='AA_AA'),
            dict(ipv4_packet, saddr='1.2.3.1', service='AAA_AAA'),
            dict(ipv4_packet, saddr='1.2.3.200', service='B_B'),
            dict(ipv4_packet, saddr='1.2.2.5', service='BB_BB'),
            dict(ipv6_packet, saddr='1234::', service='BB_BB'),
            ]
        self.setup_service_dispatcher(_services, _dispatchers)
        self._run_query2(_queries)


    def test_n_dim_src_zone_query(self):
        _dispatchers = [{ 'name' : 'n_dimension_specific', 'num_rules' : 8,
                          'rules' : [{ 'rule_id'      : 1, 'service' : 'A_A',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_SRC_ZONE : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_SRC_ZONE : ['ABA'] }
                                     },
                                     { 'rule_id'      : 2, 'service' : 'AA_AA',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_SRC_ZONE : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_SRC_ZONE : ['AB'] }
                                     },
                                     { 'rule_id'      : 3, 'service' : 'AAA_AAA',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_SRC_ZONE : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_SRC_ZONE : ['A'] }
                                     },
                                     { 'rule_id'      : 4, 'service' : 'B_B',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_SRC_ZONE : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_SRC_ZONE : ['AAZ'] }
                                     },
                                     { 'rule_id'      : 5, 'service' : 'BB_BB',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_SRC_ZONE : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_SRC_ZONE : ['AY'] }
                                     },
                                     { 'rule_id'      : 6, 'service' : 'IPv6_Zone_80',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_SRC_ZONE : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_SRC_ZONE : ['IPv6_Zone_80'] }
                                     },
                                     { 'rule_id'      : 7, 'service' : 'IPv6_Zone_96',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_SRC_ZONE : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_SRC_ZONE : ['IPv6_Zone_96'] }
                                     },
                                     { 'rule_id'      : 8, 'service' : 'IPv6_Zone_128',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_SRC_ZONE : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_SRC_ZONE : ['IPv6_Zone_128'] }
                                     },
                                    ]
                        }]

        _services = ['A_A', 'AA_AA', 'AAA_AAA', 'B_B', 'BB_BB', 'IPv6_Zone_80', 'IPv6_Zone_96', 'IPv6_Zone_128']
        _queries = [
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '10.99.201.65', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '10.99.201.5', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '10.99.201.85', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '10.99.201.21', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '10.99.201.69', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : 'fd00:bb:1030:1100:cc:aa:bb:dd', 'dport' : 5, 'family' : socket.AF_INET6, 'daddr' : 'ff80::', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : 'fd00:bb:1030:1100:cc:aa:cc:dd', 'dport' : 5, 'family' : socket.AF_INET6, 'daddr' : 'ff80::', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : 'fd00:bb:1030:1100:cc:cc:bb:dd', 'dport' : 5, 'family' : socket.AF_INET6, 'daddr' : 'ff80::', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : 'fd00:bb:1030:1100:dd:cc:bb:dd', 'dport' : 5, 'family' : socket.AF_INET6, 'daddr' : 'ff80::', 'iface' : 'dummy1'},
                   ]
        _answers = [ 'A_A', 'B_B', 'BB_BB', 'AAA_AAA', 'AA_AA', None, 'IPv6_Zone_128', 'IPv6_Zone_96', 'IPv6_Zone_80', None ]

        self.setup_service_dispatcher(_services, _dispatchers)
        self._run_query(_queries, _answers)


    def test_n_dim_src_zone_empty_query(self):
        _dispatchers = [{ 'name' : 'n_dimension_specific', 'num_rules' : 3,
                          'rules' : [{ 'rule_id'      : 1, 'service' : 'A_A',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_SRC_ZONE : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_SRC_ZONE : ['ABA'] }
                                     },
                                     { 'rule_id'      : 5, 'service' : 'AA_AA',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_SRC_ZONE : 0},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_SRC_ZONE : [] }
                                     },
                                     { 'rule_id'      : 8, 'service' : 'IPv6_Zone_128',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_SRC_ZONE : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_SRC_ZONE : ['IPv6_Zone_128'] }
                                     },
                                    ]
                        }]

        _services = ['A_A', 'AA_AA', 'IPv6_Zone_128']
        _queries = [
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '10.99.201.65', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '10.99.201.5', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '10.99.201.85', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '10.99.201.21', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '10.99.201.69', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : 'fd00:bb:1030:1100:cc:aa:bb:dd', 'dport' : 5, 'family' : socket.AF_INET6, 'daddr' : 'ff80::', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : 'fd00:bb:1030:1100:cc:aa:cc:dd', 'dport' : 5, 'family' : socket.AF_INET6, 'daddr' : 'ff80::', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : 'fd00:bb:1030:1100:cc:cc:bb:dd', 'dport' : 5, 'family' : socket.AF_INET6, 'daddr' : 'ff80::', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : 'fd00:bb:1030:1100:dd:cc:bb:dd', 'dport' : 5, 'family' : socket.AF_INET6, 'daddr' : 'ff80::', 'iface' : 'dummy1'},
                   ]
        _answers = [ 'A_A', 'AA_AA', 'AA_AA', 'AA_AA', 'AA_AA', 'AA_AA', 'IPv6_Zone_128', 'AA_AA', 'AA_AA', 'AA_AA' ]

        self.setup_service_dispatcher(_services, _dispatchers)
        self._run_query(_queries, _answers)


    def test_n_dim_dst_ip_vs_dst_zone_query(self):
        _dispatchers = [ { 'name' : 'n_dimension_precedency', 'num_rules' : 'set_below',
                         'rules' : [ { 'rule_id'      : 1, 'service' : 'IPv4_Subnet_1',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_DST_IP : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_DST_IP : ['10.99.201.169/32']},
                                     },
                                     { 'rule_id'      : 2, 'service' : 'IPv4_Zone_1',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_DST_ZONE : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_DST_ZONE : ['Z']},
                                     },
                                     { 'rule_id'      : 3, 'service' : 'IPv4_Subnet_2',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_DST_IP : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_DST_IP : ['10.99.201.0/24']},
                                     },
                                     { 'rule_id'      : 4, 'service' : 'IPv4_Zone_2',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_DST_ZONE : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_DST_ZONE : ['A']},
                                     },
                                     { 'rule_id'      : 5, 'service' : 'IPv4_Subnet_and_Zone',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_DST_ZONE : 1, messages.KZNL_ATTR_N_DIMENSION_DST_IP : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_DST_ZONE : ['ZA'], messages.KZNL_ATTR_N_DIMENSION_DST_IP : ['10.99.201.66/32']},
                                     },
                                     { 'rule_id'      : 6, 'service' : 'IPv6_Subnet_1',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_DST_IP6 : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_DST_IP6 : ['fd00:bb:1030:1100:cc:aa:bb:dd/128']},
                                     },
                                     { 'rule_id'      : 7, 'service' : 'IPv6_Subnet_2',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_DST_IP6 : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_DST_IP6 : ['fd00:bb:1030:1100:cc:aa:00:00/96']},
                                     },
                                     { 'rule_id'      : 8, 'service' : 'IPv6_Zone_80',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_DST_ZONE : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_DST_ZONE : ['IPv6_Zone_80'] }
                                     },
                                     { 'rule_id'      : 9, 'service' : 'IPv6_Zone_96',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_DST_ZONE : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_DST_ZONE : ['IPv6_Zone_96'] }
                                     },
                                     { 'rule_id'      : 10, 'service' : 'IPv6_Zone_128',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_DST_ZONE : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_DST_ZONE : ['IPv6_Zone_128'] }
                                     },
                                     { 'rule_id'      : 11, 'service' : 'IPv6_Subnet_and_Zone',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_DST_ZONE : 1, messages.KZNL_ATTR_N_DIMENSION_DST_IP6 : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_DST_ZONE : ['IPv6_Zone_96_2'], messages.KZNL_ATTR_N_DIMENSION_DST_IP6 : ['fd00:bb:1030:1100:cc:22:bb:cc/128']},
                                     },
                                   ]
                       }
                     ]

        _dispatchers[0]['num_rules'] = len(_dispatchers[0]['rules'])
        _services = []
        for rule in _dispatchers[0]['rules']:
            _services.append(rule['service'])
        _queries = []
        _answers = []
        # Test1: /32 subnet vs Zone
        _queries.append({ 'proto' : socket.IPPROTO_TCP, 'sport' : 6, 'daddr' : '10.99.201.169', 'dport' : 9, 'family' : socket.AF_INET, 'saddr' : '4.3.2.1', 'iface' : 'dummy0'})
        _answers.append('IPv4_Subnet_1')
        # Test2: /24 subnet vs Zone
        _queries.append({ 'proto' : socket.IPPROTO_TCP, 'sport' : 6, 'daddr' : '10.99.201.41', 'dport' : 9, 'family' : socket.AF_INET, 'saddr' : '4.3.2.1', 'iface' : 'dummy0'})
        _answers.append('IPv4_Subnet_2')
        # Test3: No match
        _queries.append({ 'proto' : socket.IPPROTO_TCP, 'sport' : 6, 'daddr' : '10.199.201.1', 'dport' : 9, 'family' : socket.AF_INET, 'saddr' : '4.3.2.1', 'iface' : 'dummy0'})
        _answers.append(None)
        # Test4: Zone match
        _queries.append({ 'proto' : socket.IPPROTO_TCP, 'sport' : 6, 'daddr' : '10.99.101.169', 'dport' : 9, 'family' : socket.AF_INET, 'saddr' : '4.3.2.1', 'iface' : 'dummy0'})
        _answers.append('IPv4_Zone_1')
        # Test5: Subnet match (if there is zone in the service)
        _queries.append({ 'proto' : socket.IPPROTO_TCP, 'sport' : 6, 'daddr' : '10.99.201.66', 'dport' : 9, 'family' : socket.AF_INET, 'saddr' : '4.3.2.1', 'iface' : 'dummy0'})
        _answers.append('IPv4_Subnet_and_Zone')
        # Test6: Zone match (if there is subnet in the service)
        _queries.append({ 'proto' : socket.IPPROTO_TCP, 'sport' : 6, 'daddr' : '10.99.101.137', 'dport' : 9, 'family' : socket.AF_INET, 'saddr' : '4.3.2.1', 'iface' : 'dummy0'})
        _answers.append('IPv4_Subnet_and_Zone')
        # Test7: /128 Subnet6 match vs Zone
        _queries.append({ 'proto' : socket.IPPROTO_TCP, 'sport' : 6, 'daddr' : 'fd00:bb:1030:1100:cc:aa:bb:dd', 'dport' : 9, 'family' : socket.AF_INET6, 'saddr' : 'f080::', 'iface' : 'dummy0'})
        _answers.append('IPv6_Subnet_1')
        # Test8: /90 Subnet6 match vs Zone
        _queries.append({ 'proto' : socket.IPPROTO_TCP, 'sport' : 6, 'daddr' : 'fd00:bb:1030:1100:cc:aa:11:11', 'dport' : 9, 'family' : socket.AF_INET6, 'saddr' : 'f080::', 'iface' : 'dummy0'})
        _answers.append('IPv6_Subnet_2')
        # Test9: No match IPv6
        _queries.append({ 'proto' : socket.IPPROTO_TCP, 'sport' : 6, 'daddr' : 'fd00:bb:1030:1100:11:aa:bb:dd', 'dport' : 9, 'family' : socket.AF_INET6, 'saddr' : 'f080::', 'iface' : 'dummy0'})
        _answers.append(None)
        # Test10: Zone6 match
        _queries.append({ 'proto' : socket.IPPROTO_TCP, 'sport' : 6, 'daddr' : 'fd00:bb:1030:1100:cc:cc:bb:dd', 'dport' : 9, 'family' : socket.AF_INET6, 'saddr' : 'f080::', 'iface' : 'dummy0'})
        _answers.append('IPv6_Zone_80')
        # Test11: Subnet6 match (if there is zone6 in the service)
        _queries.append({ 'proto' : socket.IPPROTO_TCP, 'sport' : 6, 'daddr' : 'fd00:bb:1030:1100:cc:22:bb:cc', 'dport' : 9, 'family' : socket.AF_INET6, 'saddr' : 'f080::', 'iface' : 'dummy0'})
        _answers.append('IPv6_Subnet_and_Zone')
        # Test12: Zone6 match (if there is subnet6 in the service)
        _queries.append({ 'proto' : socket.IPPROTO_TCP, 'sport' : 6, 'daddr' : 'fd00:bb:1030:1100:cc:22:22:22', 'dport' : 9, 'family' : socket.AF_INET6, 'saddr' : 'f080::', 'iface' : 'dummy0'})
        _answers.append('IPv6_Subnet_and_Zone')

        self.setup_service_dispatcher(_services, _dispatchers)
        self._run_query(_queries, _answers)

    def test_n_dim_dst_ip_query(self):
        _dispatchers = [{ 'name' : 'n_dimension_specific', 'num_rules' : 7,
                          'rules' : [{ 'rule_id'      : 1, 'service' : 'A_A',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_DST_IP : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_DST_IP : ['1.2.3.0/24'] }
                                     },
                                     { 'rule_id'      : 2, 'service' : 'AA_AA',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_DST_IP : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_DST_IP : ['1.2.3.0/30'] }
                                     },
                                     { 'rule_id'      : 3, 'service' : 'AAA_AAA',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_DST_IP : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_DST_IP : ['1.2.3.0/31'] }
                                     },
                                     { 'rule_id'      : 4, 'service' : 'B_B',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_DST_IP : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_DST_IP : ['1.2.3.200'] }
                                     },
                                     { 'rule_id'      : 5, 'service' : 'C',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_DST_IP : 1,
                                                          messages.KZNL_ATTR_N_DIMENSION_DST_IP6 : 1
                                                        },
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_DST_IP : ['2.0.0.0/8'],
                                                          messages.KZNL_ATTR_N_DIMENSION_DST_IP6 : ['ffc0::1/127']
                                                        }
                                     },
                                     { 'rule_id'      : 6, 'service' : 'D',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_DST_IP : 1,
                                                          messages.KZNL_ATTR_N_DIMENSION_DST_IP6 : 2
                                                        },
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_DST_IP : ['2.3.4.5/32'],
                                                          messages.KZNL_ATTR_N_DIMENSION_DST_IP6 : ['ffc0::0/10', 'ffc0::3/128']
                                                        }
                                     },
                                     { 'rule_id'      : 7, 'service' : 'E',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_DST_IP6 : 1 },
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_DST_IP6 : ['ffc0::2/127'] }
                                     },
                                    ]
                        }]

        _services = ['A_A', 'AA_AA', 'AAA_AAA', 'B_B', 'C', 'D', 'E']

        ipv4_packet = dict(proto=socket.IPPROTO_TCP, sport=5, dport=5, iface='dummy1', family=socket.AF_INET, saddr='1.1.1.1')
        ipv6_packet = dict(proto=socket.IPPROTO_TCP, sport=5, dport=5, iface='dummy1', family=socket.AF_INET6, saddr='::')

        _queries = [
            dict(ipv4_packet, daddr='1.2.3.4', service='A_A'),
            dict(ipv4_packet, daddr='1.2.3.2', service='AA_AA'),
            dict(ipv4_packet, daddr='1.2.3.1', service='AAA_AAA'),
            dict(ipv4_packet, daddr='1.2.3.200', service='B_B'),
            dict(ipv4_packet, daddr='1.2.2.5', service=None),
            dict(ipv6_packet, daddr='1234::', service=None),
            dict(ipv6_packet, daddr='ffc0::1', service="C"),
            dict(ipv4_packet, daddr='2.3.4.5', service="D"),
            dict(ipv4_packet, daddr='2.3.4.6', service="C"),
            dict(ipv6_packet, daddr='ffc0::2', service="E"),
            dict(ipv6_packet, daddr='ffc0::3', service="D"),
            ]

        self.setup_service_dispatcher(_services, _dispatchers)
        self._run_query2(_queries)

    def test_n_dim_dst_ip_empty_query(self):
        _dispatchers = [{ 'name' : 'n_dimension_specific', 'num_rules' : 2,
                          'rules' : [{ 'rule_id'      : 1, 'service' : 'Non-empty',
                                       'entry_nums'   : {
                                         messages.KZNL_ATTR_N_DIMENSION_DST_IP : 1,
                                         messages.KZNL_ATTR_N_DIMENSION_DST_IP6 : 1,
                                         },
                                       'entry_values' : {
                                         messages.KZNL_ATTR_N_DIMENSION_DST_IP : ['1.2.3.0/24'],
                                         messages.KZNL_ATTR_N_DIMENSION_DST_IP6 : ['1234::/128'],
                                         }
                                     },
                                     { 'rule_id'      : 5, 'service' : 'Empty',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_DST_IP : 0},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_DST_IP : [] }
                                     },
                                    ]
                        }]

        _services = ['Non-empty', 'Empty']
        ipv4_packet = dict(proto=socket.IPPROTO_TCP, sport=5, dport=5, iface='dummy1', family=socket.AF_INET, saddr='1.1.1.1')
        ipv6_packet = dict(proto=socket.IPPROTO_TCP, sport=5, dport=5, iface='dummy1', family=socket.AF_INET6, saddr='::')

        queries = [
            dict(ipv4_packet, daddr='1.2.3.4', service='Non-empty'),
            dict(ipv4_packet, daddr='1.2.2.5', service='Empty'),
            dict(ipv6_packet, daddr='1234::', service='Non-empty'),
            dict(ipv6_packet, daddr='1235::', service='Empty'),
            ]
        self.setup_service_dispatcher(_services, _dispatchers)
        self._run_query2(queries)


    def test_n_dim_dst_zone_query(self):
        _dispatchers = [{ 'name' : 'n_dimension_specific', 'num_rules' : 8,
                          'rules' : [{ 'rule_id'      : 1, 'service' : 'A_A',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_DST_ZONE : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_DST_ZONE : ['ABA'] }
                                     },
                                     { 'rule_id'      : 2, 'service' : 'AA_AA',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_DST_ZONE : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_DST_ZONE : ['AB'] }
                                     },
                                     { 'rule_id'      : 3, 'service' : 'AAA_AAA',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_DST_ZONE : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_DST_ZONE : ['A'] }
                                     },
                                     { 'rule_id'      : 4, 'service' : 'B_B',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_DST_ZONE : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_DST_ZONE : ['AAZ'] }
                                     },
                                     { 'rule_id'      : 5, 'service' : 'BB_BB',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_DST_ZONE : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_DST_ZONE : ['AY'] }
                                     },
                                     { 'rule_id'      : 6, 'service' : 'IPv6_Zone_80',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_DST_ZONE : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_DST_ZONE : ['IPv6_Zone_80'] }
                                     },
                                     { 'rule_id'      : 7, 'service' : 'IPv6_Zone_96',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_DST_ZONE : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_DST_ZONE : ['IPv6_Zone_96'] }
                                     },
                                     { 'rule_id'      : 8, 'service' : 'IPv6_Zone_128',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_DST_ZONE : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_DST_ZONE : ['IPv6_Zone_128'] }
                                     },
                                    ]
                        }]

        _services = ['A_A', 'AA_AA', 'AAA_AAA', 'B_B', 'BB_BB', 'IPv6_Zone_80', 'IPv6_Zone_96', 'IPv6_Zone_128']
        _queries = [
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '10.99.201.65', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '10.99.201.5', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '10.99.201.85', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '10.99.201.21', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '10.99.201.69', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.1.1.1', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : 'fd00::', 'dport' : 5, 'family' : socket.AF_INET6, 'daddr' : 'fd00:bb:1030:1100:cc:aa:bb:dd', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : 'fd00::', 'dport' : 5, 'family' : socket.AF_INET6, 'daddr' : 'fd00:bb:1030:1100:cc:aa:cc:dd', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : 'fd00::', 'dport' : 5, 'family' : socket.AF_INET6, 'daddr' : 'fd00:bb:1030:1100:cc:cc:bb:dd', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : 'fd00::', 'dport' : 5, 'family' : socket.AF_INET6, 'daddr' : 'fd00:bb:1030:1100:dd:cc:bb:dd', 'iface' : 'dummy1'},
                   ]
        _answers = [ 'A_A', 'B_B', 'BB_BB', 'AAA_AAA', 'AA_AA', None, 'IPv6_Zone_128', 'IPv6_Zone_96', 'IPv6_Zone_80', None ]

        self.setup_service_dispatcher(_services, _dispatchers)
        self._run_query(_queries, _answers)


    def test_n_dim_dst_zone_empty_query(self):
        _dispatchers = [{ 'name' : 'n_dimension_specific', 'num_rules' : 3,
                          'rules' : [{ 'rule_id'      : 1, 'service' : 'A_A',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_DST_ZONE : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_DST_ZONE : ['ABA'] }
                                     },
                                     { 'rule_id'      : 5, 'service' : 'AA_AA',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_DST_ZONE : 0},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_DST_ZONE : [] }
                                     },
                                     { 'rule_id'      : 8, 'service' : 'IPv6_Zone_128',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_DST_ZONE : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_DST_ZONE : ['IPv6_Zone_128'] }
                                     },
                                    ]
                        }]

        _services = ['A_A', 'AA_AA', 'IPv6_Zone_128']
        _queries = [
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '10.99.201.65', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '10.99.201.5', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '10.99.201.85', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '10.99.201.21', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '10.99.201.69', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.1.1.1', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : 'fd00::', 'dport' : 5, 'family' : socket.AF_INET6, 'daddr' : 'fd00:bb:1030:1100:cc:aa:bb:dd', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : 'fd00::', 'dport' : 5, 'family' : socket.AF_INET6, 'daddr' : 'fd00:bb:1030:1100:cc:aa:cc:dd', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : 'fd00::', 'dport' : 5, 'family' : socket.AF_INET6, 'daddr' : 'fd00:bb:1030:1100:cc:cc:bb:dd', 'iface' : 'dummy1'},
                     { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : 'fd00::', 'dport' : 5, 'family' : socket.AF_INET6, 'daddr' : 'fd00:bb:1030:1100:dd:cc:bb:dd', 'iface' : 'dummy1'},
                   ]
        _answers = [ 'A_A', 'AA_AA', 'AA_AA', 'AA_AA', 'AA_AA', 'AA_AA', 'IPv6_Zone_128', 'AA_AA', 'AA_AA', 'AA_AA' ]

        self.setup_service_dispatcher(_services, _dispatchers)
        self._run_query(_queries, _answers)


    def test_n_dim_precedency_query(self):
        _dispatchers = [ { 'name' : 'n_dimension_precedency', 'num_rules' : 'set_below',
                         'rules' : [ { 'rule_id'      : 1, 'service' : 'GoodEnough',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_IFACE : 1, messages.KZNL_ATTR_N_DIMENSION_PROTO : 1, messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : 1, messages.KZNL_ATTR_N_DIMENSION_DST_PORT : 1, messages.KZNL_ATTR_N_DIMENSION_SRC_IP : 1, messages.KZNL_ATTR_N_DIMENSION_DST_IP : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_IFACE : ['dummy0'], messages.KZNL_ATTR_N_DIMENSION_PROTO : [socket.IPPROTO_TCP], messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : [(6,6)], messages.KZNL_ATTR_N_DIMENSION_DST_PORT : [(9,9)], messages.KZNL_ATTR_N_DIMENSION_SRC_IP : ['1.2.3.4/32'], messages.KZNL_ATTR_N_DIMENSION_DST_IP : ['10.99.201.1/32']},
                                     },
                                     { 'rule_id'      : 2, 'service' : 'X_Interface',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_IFACE : 1, messages.KZNL_ATTR_N_DIMENSION_PROTO : 1, messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : 1, messages.KZNL_ATTR_N_DIMENSION_DST_PORT : 1, messages.KZNL_ATTR_N_DIMENSION_SRC_IP : 1, messages.KZNL_ATTR_N_DIMENSION_DST_IP : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_IFACE : ['dummy1'], messages.KZNL_ATTR_N_DIMENSION_PROTO : [socket.IPPROTO_TCP], messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : [(6,6)], messages.KZNL_ATTR_N_DIMENSION_DST_PORT : [(9,9)], messages.KZNL_ATTR_N_DIMENSION_SRC_IP : ['1.2.3.4/32'], messages.KZNL_ATTR_N_DIMENSION_DST_IP : ['10.99.201.1/32']},
                                     },
                                     { 'rule_id'      : 3, 'service' : 'X_InterfaceGroup',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_IFGROUP : 1, messages.KZNL_ATTR_N_DIMENSION_PROTO : 1, messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : 1, messages.KZNL_ATTR_N_DIMENSION_DST_PORT : 1, messages.KZNL_ATTR_N_DIMENSION_SRC_IP : 1, messages.KZNL_ATTR_N_DIMENSION_DST_IP : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_IFGROUP : [2], messages.KZNL_ATTR_N_DIMENSION_PROTO : [socket.IPPROTO_TCP], messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : [(6,6)], messages.KZNL_ATTR_N_DIMENSION_DST_PORT : [(9,9)], messages.KZNL_ATTR_N_DIMENSION_SRC_IP : ['1.2.3.4/32'], messages.KZNL_ATTR_N_DIMENSION_DST_IP : ['10.99.201.1/32']},
                                     },
                                     { 'rule_id'      : 4, 'service' : 'X_Proto',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_IFACE : 1, messages.KZNL_ATTR_N_DIMENSION_PROTO : 1, messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : 1, messages.KZNL_ATTR_N_DIMENSION_DST_PORT : 1, messages.KZNL_ATTR_N_DIMENSION_SRC_IP : 1, messages.KZNL_ATTR_N_DIMENSION_DST_IP : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_IFACE : ['dummy0'], messages.KZNL_ATTR_N_DIMENSION_PROTO : [socket.IPPROTO_UDP], messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : [(6,6)], messages.KZNL_ATTR_N_DIMENSION_DST_PORT : [(9,9)], messages.KZNL_ATTR_N_DIMENSION_SRC_IP : ['1.2.3.4/32'], messages.KZNL_ATTR_N_DIMENSION_DST_IP : ['10.99.201.1/32']},
                                     },
                                     { 'rule_id'      : 5, 'service' : 'X_SrcPort',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_IFACE : 1, messages.KZNL_ATTR_N_DIMENSION_PROTO : 1, messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : 1, messages.KZNL_ATTR_N_DIMENSION_DST_PORT : 1, messages.KZNL_ATTR_N_DIMENSION_SRC_IP : 1, messages.KZNL_ATTR_N_DIMENSION_DST_IP : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_IFACE : ['dummy0'], messages.KZNL_ATTR_N_DIMENSION_PROTO : [socket.IPPROTO_TCP], messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : [(7,7)], messages.KZNL_ATTR_N_DIMENSION_DST_PORT : [(9,9)], messages.KZNL_ATTR_N_DIMENSION_SRC_IP : ['1.2.3.4/32'], messages.KZNL_ATTR_N_DIMENSION_DST_IP : ['10.99.201.1/32']},
                                     },
                                     { 'rule_id'      : 6, 'service' : 'X_DstPort',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_IFACE : 1, messages.KZNL_ATTR_N_DIMENSION_PROTO : 1, messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : 1, messages.KZNL_ATTR_N_DIMENSION_DST_PORT : 1, messages.KZNL_ATTR_N_DIMENSION_SRC_IP : 1, messages.KZNL_ATTR_N_DIMENSION_DST_IP : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_IFACE : ['dummy0'], messages.KZNL_ATTR_N_DIMENSION_PROTO : [socket.IPPROTO_TCP], messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : [(6,6)], messages.KZNL_ATTR_N_DIMENSION_DST_PORT : [(8,8)], messages.KZNL_ATTR_N_DIMENSION_SRC_IP : ['1.2.3.4/32'], messages.KZNL_ATTR_N_DIMENSION_DST_IP : ['10.99.201.1/32']},
                                     },
                                     { 'rule_id'      : 7, 'service' : 'X_SrcIP',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_IFACE : 1, messages.KZNL_ATTR_N_DIMENSION_PROTO : 1, messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : 1, messages.KZNL_ATTR_N_DIMENSION_DST_PORT : 1, messages.KZNL_ATTR_N_DIMENSION_SRC_IP : 1, messages.KZNL_ATTR_N_DIMENSION_DST_IP : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_IFACE : ['dummy0'], messages.KZNL_ATTR_N_DIMENSION_PROTO : [socket.IPPROTO_TCP], messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : [(6,6)], messages.KZNL_ATTR_N_DIMENSION_DST_PORT : [(9,9)], messages.KZNL_ATTR_N_DIMENSION_SRC_IP : ['1.2.3.5/32'], messages.KZNL_ATTR_N_DIMENSION_DST_IP : ['10.99.201.1/32']},
                                     },
                                     { 'rule_id'      : 8, 'service' : 'X_DstIP',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_IFACE : 1, messages.KZNL_ATTR_N_DIMENSION_PROTO : 1, messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : 1, messages.KZNL_ATTR_N_DIMENSION_DST_PORT : 1, messages.KZNL_ATTR_N_DIMENSION_SRC_IP : 1, messages.KZNL_ATTR_N_DIMENSION_DST_IP : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_IFACE : ['dummy0'], messages.KZNL_ATTR_N_DIMENSION_PROTO : [socket.IPPROTO_TCP], messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : [(6,6)], messages.KZNL_ATTR_N_DIMENSION_DST_PORT : [(9,9)], messages.KZNL_ATTR_N_DIMENSION_SRC_IP : ['1.2.3.4/32'], messages.KZNL_ATTR_N_DIMENSION_DST_IP : ['4.3.2.5/32']},
                                     },
                                     { 'rule_id'      : 9, 'service' : 'InterfaceGroup',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_IFGROUP : 1, messages.KZNL_ATTR_N_DIMENSION_PROTO : 1, messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : 1, messages.KZNL_ATTR_N_DIMENSION_DST_PORT : 1, messages.KZNL_ATTR_N_DIMENSION_SRC_IP : 1, messages.KZNL_ATTR_N_DIMENSION_DST_IP : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_IFGROUP : [1], messages.KZNL_ATTR_N_DIMENSION_PROTO : [socket.IPPROTO_TCP], messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : [(6,6)], messages.KZNL_ATTR_N_DIMENSION_DST_PORT : [(9,9)], messages.KZNL_ATTR_N_DIMENSION_SRC_IP : ['1.2.3.4/32'], messages.KZNL_ATTR_N_DIMENSION_DST_IP : ['10.99.201.1/32']},
                                     },
                                     { 'rule_id'      : 10, 'service' : 'SrcZone',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_IFACE : 1, messages.KZNL_ATTR_N_DIMENSION_PROTO : 1, messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : 1, messages.KZNL_ATTR_N_DIMENSION_DST_PORT : 1, messages.KZNL_ATTR_N_DIMENSION_SRC_ZONE : 1, messages.KZNL_ATTR_N_DIMENSION_DST_IP : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_IFACE : ['dummy0'], messages.KZNL_ATTR_N_DIMENSION_PROTO : [socket.IPPROTO_TCP], messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : [(6,6)], messages.KZNL_ATTR_N_DIMENSION_DST_PORT : [(9,9)], messages.KZNL_ATTR_N_DIMENSION_SRC_ZONE : ['A'], messages.KZNL_ATTR_N_DIMENSION_DST_IP : ['10.99.201.1/32']},
                                     },
                                     { 'rule_id'      : 11, 'service' : 'X_SrcZone',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_IFACE : 1, messages.KZNL_ATTR_N_DIMENSION_PROTO : 1, messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : 1, messages.KZNL_ATTR_N_DIMENSION_DST_PORT : 1, messages.KZNL_ATTR_N_DIMENSION_SRC_ZONE : 1, messages.KZNL_ATTR_N_DIMENSION_DST_IP : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_IFACE : ['dummy0'], messages.KZNL_ATTR_N_DIMENSION_PROTO : [socket.IPPROTO_TCP], messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : [(6,6)], messages.KZNL_ATTR_N_DIMENSION_DST_PORT : [(9,9)], messages.KZNL_ATTR_N_DIMENSION_SRC_ZONE : ['Z'], messages.KZNL_ATTR_N_DIMENSION_DST_IP : ['10.99.201.1/32']},
                                     },
                                     { 'rule_id'      : 12, 'service' : 'DstZone',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_IFACE : 1, messages.KZNL_ATTR_N_DIMENSION_PROTO : 1, messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : 1, messages.KZNL_ATTR_N_DIMENSION_DST_PORT : 1, messages.KZNL_ATTR_N_DIMENSION_SRC_IP : 1, messages.KZNL_ATTR_N_DIMENSION_DST_ZONE : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_IFACE : ['dummy0'], messages.KZNL_ATTR_N_DIMENSION_PROTO : [socket.IPPROTO_TCP], messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : [(6,6)], messages.KZNL_ATTR_N_DIMENSION_DST_PORT : [(9,9)], messages.KZNL_ATTR_N_DIMENSION_SRC_IP : ['1.2.3.4/32'], messages.KZNL_ATTR_N_DIMENSION_DST_ZONE : ['A']},
                                     },
                                     { 'rule_id'      : 13, 'service' : 'X_DstZone',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_IFACE : 1, messages.KZNL_ATTR_N_DIMENSION_PROTO : 1, messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : 1, messages.KZNL_ATTR_N_DIMENSION_DST_PORT : 1, messages.KZNL_ATTR_N_DIMENSION_SRC_IP : 1, messages.KZNL_ATTR_N_DIMENSION_DST_ZONE : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_IFACE : ['dummy0'], messages.KZNL_ATTR_N_DIMENSION_PROTO : [socket.IPPROTO_TCP], messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : [(6,6)], messages.KZNL_ATTR_N_DIMENSION_DST_PORT : [(9,9)], messages.KZNL_ATTR_N_DIMENSION_SRC_IP : ['1.2.3.4/32'], messages.KZNL_ATTR_N_DIMENSION_DST_ZONE : ['Z']},
                                     },
                                     { 'rule_id'      : 14, 'service' : 'SrcIP',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_IFACE : 1, messages.KZNL_ATTR_N_DIMENSION_PROTO : 1, messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : 1, messages.KZNL_ATTR_N_DIMENSION_DST_PORT : 1, messages.KZNL_ATTR_N_DIMENSION_SRC_IP : 1, messages.KZNL_ATTR_N_DIMENSION_DST_IP : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_IFACE : ['dummy0'], messages.KZNL_ATTR_N_DIMENSION_PROTO : [socket.IPPROTO_TCP], messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : [(6,6)], messages.KZNL_ATTR_N_DIMENSION_DST_PORT : [(9,9)], messages.KZNL_ATTR_N_DIMENSION_SRC_IP : ['10.99.201.169/32'], messages.KZNL_ATTR_N_DIMENSION_DST_IP : ['10.99.201.1/32']},
                                     },
                                     { 'rule_id'      : 15, 'service' : 'DstIP',
                                       'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_IFACE : 1, messages.KZNL_ATTR_N_DIMENSION_PROTO : 1, messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : 1, messages.KZNL_ATTR_N_DIMENSION_DST_PORT : 1, messages.KZNL_ATTR_N_DIMENSION_SRC_IP : 1, messages.KZNL_ATTR_N_DIMENSION_DST_IP : 1},
                                       'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_IFACE : ['dummy0'], messages.KZNL_ATTR_N_DIMENSION_PROTO : [socket.IPPROTO_TCP], messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : [(6,6)], messages.KZNL_ATTR_N_DIMENSION_DST_PORT : [(9,9)], messages.KZNL_ATTR_N_DIMENSION_SRC_IP : ['1.2.3.4/32'], messages.KZNL_ATTR_N_DIMENSION_DST_IP : ['10.99.201.169/32']},
                                     },
                                     { 'rule_id'      : 16, 'service' : 'X_DstIface',
                                      'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_IFACE : 1, messages.KZNL_ATTR_N_DIMENSION_PROTO : 1, messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : 1, messages.KZNL_ATTR_N_DIMENSION_DST_PORT : 1, messages.KZNL_ATTR_N_DIMENSION_SRC_IP : 1, messages.KZNL_ATTR_N_DIMENSION_DST_IFACE : 1},
                                      'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_IFACE : ['dummy0'], messages.KZNL_ATTR_N_DIMENSION_PROTO : [socket.IPPROTO_TCP], messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : [(6,6)], messages.KZNL_ATTR_N_DIMENSION_DST_PORT : [(9,9)], messages.KZNL_ATTR_N_DIMENSION_SRC_IP : ['1.2.3.4/32'], messages.KZNL_ATTR_N_DIMENSION_DST_IFACE : ['dummy0']},
                                     },
                                     { 'rule_id'      : 17, 'service' : 'X_DstIfaceGroup',
                                      'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_IFACE : 1, messages.KZNL_ATTR_N_DIMENSION_PROTO : 1, messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : 1, messages.KZNL_ATTR_N_DIMENSION_DST_PORT : 1, messages.KZNL_ATTR_N_DIMENSION_SRC_IP : 1, messages.KZNL_ATTR_N_DIMENSION_DST_IFGROUP : 1},
                                      'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_IFACE : ['dummy0'], messages.KZNL_ATTR_N_DIMENSION_PROTO : [socket.IPPROTO_TCP], messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : [(6,6)], messages.KZNL_ATTR_N_DIMENSION_DST_PORT : [(9,9)], messages.KZNL_ATTR_N_DIMENSION_SRC_IP : ['1.2.3.4/32'], messages.KZNL_ATTR_N_DIMENSION_DST_IFGROUP : [2]},
                                     },
                                     { 'rule_id'      : 18, 'service' : 'DstIface',
                                      'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_IFACE : 1, messages.KZNL_ATTR_N_DIMENSION_PROTO : 1, messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : 1, messages.KZNL_ATTR_N_DIMENSION_DST_PORT : 1, messages.KZNL_ATTR_N_DIMENSION_SRC_IP : 1, messages.KZNL_ATTR_N_DIMENSION_DST_IFACE : 1},
                                      'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_IFACE : ['dummy4'], messages.KZNL_ATTR_N_DIMENSION_PROTO : [socket.IPPROTO_TCP], messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : [(6,6)], messages.KZNL_ATTR_N_DIMENSION_DST_PORT : [(9,9)], messages.KZNL_ATTR_N_DIMENSION_SRC_IP : ['1.2.3.4/32'], messages.KZNL_ATTR_N_DIMENSION_DST_IFACE : ['dummy4']},
                                     },
                                     { 'rule_id'      : 19, 'service' : 'X_DstIfaceGroup2',
                                      'entry_nums'   : { messages.KZNL_ATTR_N_DIMENSION_IFACE : 1, messages.KZNL_ATTR_N_DIMENSION_PROTO : 1, messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : 1, messages.KZNL_ATTR_N_DIMENSION_DST_PORT : 1, messages.KZNL_ATTR_N_DIMENSION_SRC_IP : 1, messages.KZNL_ATTR_N_DIMENSION_DST_IFGROUP : 1},
                                      'entry_values' : { messages.KZNL_ATTR_N_DIMENSION_IFACE : ['dummy4'], messages.KZNL_ATTR_N_DIMENSION_PROTO : [socket.IPPROTO_TCP], messages.KZNL_ATTR_N_DIMENSION_SRC_PORT : [(6,6)], messages.KZNL_ATTR_N_DIMENSION_DST_PORT : [(9,9)], messages.KZNL_ATTR_N_DIMENSION_SRC_IP : ['1.2.3.4/32'], messages.KZNL_ATTR_N_DIMENSION_DST_IFGROUP : [1]},
                                     },
                                   ]
                       }
                     ]

        _dispatchers[0]['num_rules'] = len(_dispatchers[0]['rules'])
        _services = []
        for rule in _dispatchers[0]['rules']:
            _services.append(rule['service'])
        _queries = []
        _answers = []
        query_param = { 'proto' : socket.IPPROTO_TCP, 'sport' : 6, 'saddr' : '1.2.3.4', 'dport' : 9, 'family' : socket.AF_INET, 'daddr' : '10.99.201.1', 'iface' : 'dummy0'}
        for i in range(9):
            _queries.append(query_param)
            _answers.append('GoodEnough')

        _queries.append({ 'proto' : socket.IPPROTO_TCP, 'sport' : 6, 'saddr' : '1.2.3.4', 'dport' : 9, 'family' : socket.AF_INET, 'daddr' : '10.99.201.1', 'iface' : 'dummy4'})
        _answers.append('InterfaceGroup')

        _queries.append({ 'proto' : socket.IPPROTO_TCP, 'sport' : 6, 'saddr' : '10.99.201.41', 'dport' : 9, 'family' : socket.AF_INET, 'daddr' : '10.99.201.1', 'iface' : 'dummy0'})
        _answers.append('SrcZone')

        _queries.append({ 'proto' : socket.IPPROTO_TCP, 'sport' : 6, 'saddr' : '1.2.3.4', 'dport' : 9, 'family' : socket.AF_INET, 'daddr' : '10.99.201.41', 'iface' : 'dummy0'})
        _answers.append('DstZone')

        _queries.append({ 'proto' : socket.IPPROTO_TCP, 'sport' : 6, 'saddr' : '10.99.201.169', 'dport' : 9, 'family' : socket.AF_INET, 'daddr' : '10.99.201.1', 'iface' : 'dummy0'})
        _answers.append('SrcIP')

        _queries.append({ 'proto' : socket.IPPROTO_TCP, 'sport' : 6, 'saddr' : '1.2.3.4', 'dport' : 9, 'family' : socket.AF_INET, 'daddr' : '10.99.201.169', 'iface' : 'dummy0'})
        _answers.append('DstIP')

        # FIXME TODO: DST_IFACE is not scope of techpreview
        #_queries.append({ 'proto' : socket.IPPROTO_TCP, 'sport' : 6, 'saddr' : '1.2.3.4', 'dport' : 9, 'family' : socket.AF_INET, 'daddr' : '10.99.205.5', 'iface' : 'dummy4'})
        #_answers.append('DstIface')

        self.setup_service_dispatcher(_services, _dispatchers)
        self._run_query(_queries, _answers)

    def test_eval_with_empty_ruleset(self):
        _queries = [
                     { 'proto' : socket.IPPROTO_TCP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy0'},
                   ]
        _answers = [ None ]

        self._run_query(_queries, _answers)

    def test_eval_with_zero_score(self):
        _rules = [{ 'name' : 'n_dimension_specific', 'num_rules' : 1,
                    'rules' : [
                                {
                                  'rule_id'      : 1, 'service' : 'service',
                                  'entry_nums'   : { },
                                  'entry_values' : { }
                                },
                             ]
                 }]

        _services = [ 'service' ]
        _queries = [
                     { 'proto' : socket.IPPROTO_TCP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy0'},
                   ]
        _answers = [ 'service' ]

        self.setup_service_dispatcher(_services, _rules)
        self._run_query(_queries, _answers)

    def test_eval_with_colliding_rules(self):
        _rules = [{ 'name' : 'n_dimension_specific', 'num_rules' : 3,
                    'rules' : [
                                {
                                  'rule_id'      : 2, 'service' : 'service2',
                                  'entry_nums'   : { },
                                  'entry_values' : { }
                                },
                                {
                                  'rule_id'      : 3, 'service' : 'service3',
                                  'entry_nums'   : { },
                                  'entry_values' : { }
                                },
                                {
                                  'rule_id'      : 4, 'service' : 'service4',
                                  'entry_nums'   : { },
                                  'entry_values' : { }
                                },
                             ]
                 }]

        _services = [ 'service2', 'service3', 'service4' ]
        _queries = [
                     { 'proto' : socket.IPPROTO_TCP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy0'},
                   ]
        _answers = [ 'service2' ]

        self.setup_service_dispatcher(_services, _rules)
        self._run_query(_queries, _answers)

    def test_eval_with_huge_number_of_colliding_rules(self):
        _rule_number = 128
        _rules = [{ 'name' : 'n_dimension_specific', 'num_rules' : _rule_number,
                    'rules' : [
                             ]
                 }]
        _services = [ ]

        for i in range(_rule_number):
            _service_name = 'service%s' % (i + 1)
            _rules[0]['rules'].append({
                                       'rule_id'      : i + 1, 'service' : _service_name,
                                       'entry_nums'   : { },
                                       'entry_values' : { }
                                      })

            _services.append(_service_name)

        _queries = [
                     { 'proto' : socket.IPPROTO_TCP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy0'},
                   ]
        _answers = [ 'service1' ]

        self.setup_service_dispatcher(_services, _rules)
        self._run_query(_queries, _answers)

if __name__ == "__main__":
        testutil.main()

