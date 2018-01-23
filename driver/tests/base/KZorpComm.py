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

import unittest
import kzorp.netlink as netlink
import kzorp.messages as messages
import kzorp.communication as communication
import testutil
import os

class KZorpComm(unittest.TestCase):
    handle = None
    _flushables = [
                    messages.KZorpFlushDispatchersMessage,
                    messages.KZorpFlushServicesMessage,
                    messages.KZorpFlushZonesMessage,
                    messages.KZorpFlushBindsMessage
                  ]

    def __init__(self, *args):
        unittest.TestCase.__init__(self, *args)
        self.create_handle()
        self._in_transaction = False

    def __del__(self):
        self.close_handle()

    def create_handle(self):
        if self.handle == None:
            self.handle = communication.Handle()
            self.assertNotEqual(self.handle, None)

    def close_handle(self):
        if self.handle:
            self.handle.close()
            self.handle = None

    def reopen_handle(self):
        self.close_handle()
        self.create_handle()

    def send_message(self, message, assert_on_error = True, message_handler = None, dump = False, error_handler=None):
        self.assertNotEqual(message, None)
        self.assertNotEqual(self.handle, None)
        #print "send_message: ", message

        try:
            res = 0
            if dump:
                for reply_message in self.handle.dump(message):
                    if message_handler is not None:
                        message_handler(reply_message)
            else:
                reply_message = self.handle.exchange(message)
                reply_messages = reply_message if isinstance(reply_message, list) else [reply_message, ]
                for reply_message in reply_messages:
                    if message_handler is not None:
                        message_handler(reply_message)
        except netlink.NetlinkException as e:
            #print "exception", e
            res = e.detail
            if assert_on_error:
                if error_handler:
                    error_handler(e.detail)
                else:
                    self.assertEqual(res, 0, "talk with KZorp failed: result='%d' error='%s'" % (res, os.strerror(-res)))

        return res

    def start_transaction(self, assert_on_error = True, instance_name = messages.KZ_INSTANCE_GLOBAL, cookie = 0L):
        self.send_message(messages.KZorpStartTransactionMessage(instance_name), assert_on_error=assert_on_error)
        self._in_transaction = True

    def end_transaction(self, assert_on_error = True, instance_name = messages.KZ_INSTANCE_GLOBAL):
        res = self.send_message(messages.KZorpCommitTransactionMessage(), assert_on_error=assert_on_error)
        self._in_transaction = False
        return res

    def flush_all(self):
        if self._in_transaction:
            self.reopen_handle()
            self._in_transaction = False

        for message_class in self._flushables:
            self.start_transaction()
            self.send_message(message_class())
            self.end_transaction()

    def test_handle(self):
      self.create_handle()
      self.start_transaction()
      self.end_transaction()
      self.flush_all()
      self.reopen_handle()


if __name__ == "__main__":
    testutil.main()
