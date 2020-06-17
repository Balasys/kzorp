#!/usr/bin/env python2.7
import unittest
import sys
import os
import time
import imp
import mock
from mock import Mock

from kzorp.netlink import NetlinkException

sys.dont_write_bytecode = True

def find_file(paths, filename):
    for path in paths:
        filepath = os.path.join(path, filename)
        if os.path.isfile(filepath):
            return filepath
    raise AssertionError('Cannot find file on any paths: ' +  filename)


class TestKZorpd(unittest.TestCase):
    kzorpd_module = None

    @classmethod
    def setUpClass(cls):
        modules_mocked = (
            'radix', 'systemd', 'systemd.daemon',
            'Zorp', 'Zorp.InstancesConf', 'Zorp.Zone', 'Zorp.Common', 'Zorp.ResolverCache', 'Zorp.Subnet',
            'zorpctl', 'zorpctl.ZorpctlConf'
        )
        with mock.patch.dict(sys.modules, dict.fromkeys(modules_mocked, Mock())):
            cls.kzorpd_module = imp.load_source('kzorpd', find_file(sys.path, 'kzorpd'))
            cls.kzorpd_module.ZoneDownloadFactory.init(manage_caps=False)

    def test_zone_updates(self):
        ZONE_INIT_MSG = 'zone_dynamic_address_initialization_message'
        ZONE_UPD_MSG = 'zone_update_message; zone={}'

        daemon = self.kzorpd_module.Daemon()
        daemon.__del__ = Mock()
        daemon.zone_handler = Mock()
        daemon.zone_handler.create_zone_dynamic_address_initialization_messages.return_value = ZONE_INIT_MSG
        daemon.zone_handler.create_zone_update_messages.side_effect = lambda x: ZONE_UPD_MSG.format(x)
        zone_updater = Mock()
        zone_updater.__enter__ = Mock(return_value=zone_updater)
        zone_updater.__exit__ = Mock(return_value=None)
        with mock.patch.object(self.kzorpd_module.ZoneDownloadFactory, 'makeZoneDownload', return_value=zone_updater):
            daemon.dnscache.hosts = {'testhost3'}
            daemon.dnscache.update.return_value = None
            daemon._update_dnscache()
            zone_updater.update.assert_called_once_with(ZONE_INIT_MSG)

            zone_updater.update.reset_mock()
            daemon.dnscache.update.return_value = []
            daemon._update_dnscache()
            zone_updater.update.assert_not_called()

            zone_updater.update.reset_mock()
            daemon.dnscache.update.return_value = ['testhost']
            daemon._update_dnscache()
            zone_updater.update.assert_called_once_with(ZONE_UPD_MSG.format('testhost'))

            zone_updater.update.reset_mock()
            daemon.dnscache.update.return_value = ['testhost', 'testhost2']
            daemon._update_dnscache()
            zone_updater.update.assert_any_call(ZONE_UPD_MSG.format('testhost'))
            zone_updater.update.assert_any_call(ZONE_UPD_MSG.format('testhost2'))

            zone_updater.update.reset_mock()
            daemon.dnscache.update.side_effect = Exception('blah')
            daemon._update_dnscache()
            zone_updater.update.assert_called_once_with(ZONE_INIT_MSG)
            daemon.dnscache.update.side_effect = None

            daemon.dnscache.update.return_value = ['testhost']
            zone_updater.update.side_effect = NetlinkException('blah')
            daemon._update_dnscache()
            self.assertTrue(daemon.forced_update)
            zone_updater.update.side_effect = None

            zone_updater.update.reset_mock()
            daemon.dnscache.update.return_value = []
            daemon._update_dnscache()
            zone_updater.update.assert_called_once_with(ZONE_UPD_MSG.format('testhost3'))
            self.assertFalse(daemon.forced_update)

    def test_next_update_times(self):
        daemon = self.kzorpd_module.Daemon()
        daemon.__del__ = Mock()

        test_values = (
            (None, None),
            ('test', -time.time()),
            ('test', 0),
            ('test', 30),
            ('test', 60),
            ('test', 300),
        )
        for hostname, ttl in test_values:
            now = time.time()
            daemon.dnscache.getNextExpiration.return_value = (hostname, None if ttl is None else now + ttl)
            daemon._update_dnscache()
            expected_time = now + (ttl if ttl and ttl > daemon.min_sleep_in_sec else daemon.min_sleep_in_sec)
            self.assertAlmostEqual(daemon.next_update_time, expected_time, places=0)

        now = time.time()
        daemon.dnscache.getNextExpiration.side_effect = Exception()
        daemon._update_dnscache()
        self.assertAlmostEqual(daemon.next_update_time, now + daemon.min_sleep_in_sec, places=0)


if __name__ == '__main__':
    unittest.main()
