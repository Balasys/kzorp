
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
import os
import sys
import glob
import unittest
import socket
import struct

import kzorp.messages as messages
import kzorp.netlink as netlink

def inet_aton(a):
    r = 0L
    for n in a.split("."):
        r = (r << 8) + int(n)
    return r

def size_to_mask(family, size):
    if family == socket.AF_INET:
        max_size = 32
    elif family == socket.AF_INET6:
        max_size = 128
    else:
        raise ValueError, "address family not supported; family='%d'" % family

    if size > max_size:
        raise ValueError, "network size is greater than the maximal size; size='%d', max_size='%d'" % (size, max_size)

    packed_mask = ''
    actual_size = 0
    while actual_size + 8 < size:
        packed_mask += '\xff'
        actual_size = actual_size + 8

    if actual_size <= size:
        packed_mask += chr((0xff << (8 - (size - actual_size))) & 0xff)
        actual_size = actual_size + 8

    while actual_size < max_size:
        packed_mask += '\x00'
        actual_size = actual_size + 8

    return socket.inet_ntop(family, packed_mask)

def subnet_base(family,subnet):
  ip,mask=subnet.split('/')
  return socket.inet_pton(family,ip)

def subnet_mask(family,subnet):
  ip,mask=subnet.split('/')
  return socket.inet_pton(family,size_to_mask(family,int(mask)))

def packed_1operand(a, f):
    """<function internal="yes">apply second argument to each character of the packed string 'a', converted to int</function>"""
    return map(lambda x: chr(f(ord(x)) & 0xff), a)

def packed_2operand(a, b, f):
    """<function internal="yes">apply the third argument to each character in both first and second arguments</function>"""
    return "".join(map(lambda t: chr(f(ord(t[0]), ord(t[1]))), zip(a, b)))

def packed_mask(addr, mask):
    """
    <function internal="yes"/>
    """
    return packed_2operand(addr, mask, lambda a, b: a & b)

def calculate_mask(bits):
    ret = ""
    while bits > 0:
        n = min(bits, 8)
        v = chr(((1 << n) - 1) << (8 - n))
        ret += v
        bits = bits - n

    return ret.ljust(16, chr(0))

def addr_packed6(addr):
  parts=addr.split("/")
  if len(parts) == 2:
    mask_bits = int(parts[1])
  else:
    mask_bits = 128
  mask = calculate_mask(mask_bits)

  return packed_mask(socket.inet_pton(socket.AF_INET6, parts[0]), mask)


def netmask_packed6(addr):
  parts=addr.split("/")
  if len(parts) == 2:
    mask_bits = int(parts[1])
  else:
    mask_bits = 128
  return calculate_mask(mask_bits)

def addr_packed(addr):
  parts=addr.split("/")
  return socket.inet_aton(parts[0])

def netmask_packed(addr):
  parts=addr.split("/")
  try:
    mask_bits = int(parts[1])
  except IndexError:
    mask_bits = 32
  return struct.pack(">I", ((1 << mask_bits) - 1) << (32 - mask_bits))


attrmap = {
            messages.KZNL_ATTR_SVC_NAME: (messages.create_name_attr, messages.parse_name_attr),
            messages.KZNL_ATTR_SVC_PARAMS: (messages.create_service_params_attr, messages.parse_service_params_attr),
            messages.KZNL_ATTR_SVC_ROUTER_DST_ADDR: (messages.create_inet_addr_attr, messages.parse_inet_addr_attr),
            messages.KZNL_ATTR_SVC_ROUTER_DST_PORT: (messages.create_port_attr, messages.parse_port_attr),
            messages.KZNL_ATTR_SVC_NAT_SRC_MIN_IP: (messages.create_inet_addr_attr, messages.parse_inet_addr_attr),
            messages.KZNL_ATTR_SVC_NAT_SRC_MAX_IP: (messages.create_inet_addr_attr, messages.parse_inet_addr_attr),
            messages.KZNL_ATTR_SVC_NAT_DST_MIN_IP: (messages.create_inet_addr_attr, messages.parse_inet_addr_attr),
            messages.KZNL_ATTR_SVC_NAT_DST_MAX_IP: (messages.create_inet_addr_attr, messages.parse_inet_addr_attr),
            messages.KZNL_ATTR_SVC_NAT_MAP_MIN_IP: (messages.create_inet_addr_attr, messages.parse_inet_addr_attr),
            messages.KZNL_ATTR_SVC_NAT_MAP_MAX_IP: (messages.create_inet_addr_attr, messages.parse_inet_addr_attr),
            messages.KZNL_ATTR_ACCOUNTING_COUNTER_NUM: (netlink.NetlinkAttribute.create_be32, netlink.NetlinkAttribute.parse_be32),
          }

def create_attr(type, *attr):
    return attrmap[type][0](type, *attr)

def parse_attr(type, attr):
    if not attr.has_key(type):
        return None
    return attrmap[type][1](attr[type])

def service_get_flags(transparent, forge_addr):
    flags = 0
    if (transparent): flags |= KZF_SVC_TRANSPARENT
    if (forge_addr): flags |= KZF_SVC_FORGE_ADDR
    return flags




def main():
    if os.getenv("USER") != "root":
        print "ERROR: You need to be root to run the unit test"
        sys.exit(1)

    if glob.glob('/var/run/zorp/*.pid'):
        print "ERROR: pidfile(s) exist in /var/run/zorp directory. Zorp is running?"
        print "       You should stop Zorp and/or delete pid files from /var/run/zorp"
        print "       in order to run this test."
        sys.exit(1)
    unittest.main()


