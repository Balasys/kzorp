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
from KZorpBaseTestCaseZones import KZorpBaseTestCaseZones
import testutil
import errno
import kzorp.messages as messages

class KZorpTestCaseTransaction(KZorpBaseTestCaseZones):
    def tearDown(self):
        self.flush_all()

    def test_transactions(self):
        # Start a transaction
        self.start_transaction(True, messages.KZ_INSTANCE_GLOBAL, 123456789L)

        # Start the transaction again without end transaction
        message = messages.KZorpStartTransactionMessage(messages.KZ_INSTANCE_GLOBAL, 987654321L)
        res = self.send_message(message, False)
        self.assertEqual(res, -errno.EINVAL)

        # Commit the transaction without any change
        self.end_transaction()

        # Commit the transaction again out of the transaction
        res = self.send_message(messages.KZorpCommitTransactionMessage(), False)
        self.assertEqual(res, -errno.ENOENT)

    def test_transaction_collision(self):
        self.start_transaction()

        message = messages.KZorpStartTransactionMessage(messages.KZ_INSTANCE_GLOBAL)
        res = self.send_message(message, False)
        self.assertEqual(res, -errno.EINVAL)

        self.end_transaction()

    def test_transaction_abort(self):
        self.start_transaction()
        self.send_message(messages.KZorpAddZoneMessage('zone'))
        self.end_transaction()
        self.check_zone_num(1)

        # Start a transaction
        self.start_transaction()

        self.send_message(messages.KZorpAddZoneMessage('a'))
        self.check_zone_num(1, False)

        # Abort the transaction
        self.reopen_handle()

        self.check_zone_num(1, False)

if __name__ == "__main__":
    testutil.main()
