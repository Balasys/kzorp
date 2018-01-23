############################################################################
##
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
##
############################################################################

import Globals
import random
import kzorp.messages
import kzorp.communication
from Zorp import *

_kzorp_handle = None

def downloadServices(h):
    # download services
    kzorp.communication.exchangeMessage(h, kzorp.messages.KZorpFlushServicesMessage())

    for service in Globals.services.values():
        messages = service.buildKZorpMessage()
        kzorp.communication.exchangeMessages(h, messages)

def downloadDispatchers(h):
    kzorp.communication.exchangeMessage(h, kzorp.messages.KZorpFlushDispatchersMessage())

    for dispatch in Globals.dispatches:
        try:
            messages = dispatch.buildKZorpMessage()
            kzorp.communication.exchangeMessages(h, messages)
        except:
            log(None, CORE_ERROR, 0, "Error occured during Dispatcher upload to KZorp; dispatcher='%s', error='%s'" % (dispatch.bindto[0].format(), sys.exc_value))
            raise


def downloadBindAddresses(h):
    for dispatch in Globals.dispatches:
        try:
            messages = dispatch.buildKZorpBindMessage()
            kzorp.communication.exchangeMessages(h, messages)
        except:
            log(None, CORE_ERROR, 0, "Error occured during bind address upload to KZorp; dispatcher='%s', error='%s'" % (dispatch.bindto[0].format(), sys.exc_value))
            raise

def createAddZoneMessageFromZone(zone):
    subnet_num = len(zone.subnets) + len(zone.hostnames)
    pname = zone.admin_parent.name if zone.admin_parent else None
    return kzorp.messages.KZorpAddZoneMessage(zone.name, pname, subnet_num = subnet_num)

def createAddZoneSubnetMessagesFromZoneAddresses(zone):
    add_zone_subnet_messages = []
    for subnet in zone.subnets:
        add_zone_subnet_message = kzorp.messages.KZorpAddZoneSubnetMessage(zone.name,
                                                                                subnet.get_family(),
                                                                                subnet.addr_packed(),
                                                                                subnet.netmask_packed())
        add_zone_subnet_messages.append(add_zone_subnet_message)
    return add_zone_subnet_messages

def downloadStaticZones(zones):
    h = kzorp.communication.Handle()
    kzorp.communication.startTransaction(h, kzorp.messages.KZ_INSTANCE_GLOBAL)
    try:
        for zone in sorted(zones, cmp=lambda z1, z2: cmp(z1.getDepth(), z2.getDepth())):
            kzorp.communication.exchangeMessages(h, (createAddZoneMessageFromZone(zone), ))
            kzorp.communication.exchangeMessages(h, createAddZoneSubnetMessagesFromZoneAddresses(zone))

        kzorp.communication.commitTransaction(h)
    except:
        h.close()
        raise


class ZoneDownload(kzorp.communication.Adapter):
    def __init__(self):
        super(ZoneDownload, self).__init__()

    def initial(self, messages):
        self.send_messages_in_transaction([kzorp.messages.KZorpFlushZonesMessage(), ] + messages)

    def update(self, messages):
        self.send_messages_in_transaction(messages)


class RuleDownload(kzorp.communication.Adapter):
    def __init__(self, instance_name):
        super(RuleDownload, self).__init__(instance_name)

    def initial(self, messages):
        self.send_messages_in_transaction([kzorp.messages.KZorpFlushDispatchersMessage(), kzorp.messages.KZorpFlushServicesMessage(), ] + messages)

    def update(self, messages):
        self.send_messages_in_transaction(messages)


class ServiceDownload(kzorp.communication.Adapter):
    def __init__(self, instance_name):
        super(ServiceDownload, self).__init__(instance_name)

    def initial(self, messages):
        self.send_messages_in_transaction([kzorp.messages.KZorpFlushServicesMessage(), ] + messages)

    def update(self, messages):
        self.send_messages_in_transaction(messages)


class BindDownload(kzorp.communication.Adapter):
    def __init__(self, instance_name):
        super(BindDownload, self).__init__(instance_name)

    def initial(self, messages):
        self.send_messages_in_transaction([kzorp.messages.KZorpFlushBindsMessage(), ] + messages)

    def update(self, messages):
        self.send_messages_in_transaction(messages)

    def __del__(self):
        """kZorp handle must not be closed as the kZorp removes the
        downloaded values when it notices that the handle has been closed.
        """
        self.kzorp_handle = None


def downloadKZorpConfig(instance_name, is_master):
    if is_master:
        with RuleDownload(instance_name) as rule_download:
            messages = []
            for service in Globals.services.values():
                message = service.buildKZorpMessage()
                messages.extend(message)
            for dispatch in Globals.dispatches:
                messages.append(kzorp.messages.KZorpAddDispatcherMessage(dispatch.session_id, Globals.rules.length))
                for rule in Globals.rules:
                    message = rule.buildKZorpMessage(dispatch.session_id)
                    messages.extend(message)
            rule_download.initial(messages)

    with BindDownload(instance_name) as bind_download:
        messages = []
        for dispatch in Globals.dispatches:
            messages.extend(dispatch.buildKZorpBindMessage())
        bind_download.initial(messages)

        # When a kZorp handle is closed kZorp removes binds which were added
        # by messages came on this handle.
        #
        # This function called when Zorp is started or reloaded.
        #
        # During the start _kzorp_handle is initialized.
        #
        # During the reload new Python interpreter is created so _kzorp_handle
        # not overwritten, deinit callback closes another kZorp handled which
        # had been created by the old Python interpreter.
        global _kzorp_handle
        _kzorp_handle = bind_download.kzorp_handle

def flushKZorpConfig(instance_name):
    log(None, CORE_DEBUG, 6, "Flush kZorp config; instance='%s'" % (instance_name))

    with RuleDownload(instance_name) as rule_download:
        rule_download.initial([])
    with ServiceDownload(instance_name) as service_download:
        service_download.initial([])

def closeKZorpHandle():
    global _kzorp_handle
    if _kzorp_handle:
        log(None, CORE_DEBUG, 6, "Close kZorp handle, binds are going to be removed by kZorp")
        _kzorp_handle.close()
        _kzorp_handle = None

Globals.deinit_callbacks.append(closeKZorpHandle)
