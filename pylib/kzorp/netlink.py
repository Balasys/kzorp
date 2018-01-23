
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
import socket
import struct
import ctypes
import errno

class NetlinkBaseException(Exception):
    def __init__(self, detail):
        self.what = ''
        self.detail = detail

    def __str__(self):
        return '%s: %s' % (self.what, self.detail)

class NetlinkException(NetlinkBaseException):
    def __init__(self, detail):
        super(NetlinkException, self).__init__(detail)
        self.what = 'netlink error'

class NetlinkAttributeException(NetlinkBaseException):
    def __init__(self, detail):
        super(NetlinkAttributeException, self).__init__(detail)
        self.what = 'netlink attribute error'
        self.detail = detail

class PacketException(NetlinkBaseException):
    def __init__(self, detail):
        super(PacketException, self).__init__(detail)
        self.what = 'packet parsing error'

# netlink message type values
NLM_F_REQUEST = 1
NLM_F_MULTI   = 2
NLM_F_ACK     = 4
NLM_F_ECHO    = 8

# modifiers to GET request
NLM_F_ROOT   = 0x100
NLM_F_MATCH  = 0x200
NLM_F_ATOMIC = 0x400
NLM_F_DUMP   = NLM_F_ROOT | NLM_F_MATCH

# modifiers to NEW request
NLM_F_REPLACE = 0x100
NLM_F_EXCL    = 0x200
NLM_F_CREATE  = 0x400
NLM_F_APPEND  = 0x800

# netlink generic message types
NLMSG_NOOP    = 1
NLMSG_ERROR   = 2
NLMSG_DONE    = 3
NLMSG_OVERRUN = 4

NLMSG_MIN_TYPE = 0x10

NLA_F_NESTED          = (1 << 15)
NLA_F_NET_BYTEORDER   = (1 << 14)
NLA_TYPE_MASK         = ctypes.c_uint(~(NLA_F_NESTED | NLA_F_NET_BYTEORDER)).value

NETLINK_GENERIC           = 16

# attribute alignment
NFA_ALIGNTO = 4

MAX_NLMSGSIZE = 65535

# generic netlink constants
GENL_NAMSIZ = 16     # length of family name
GENL_ID_CTRL = NLMSG_MIN_TYPE

# controller commands
CTRL_CMD_UNSPEC = 0
CTRL_CMD_NEWFAMILY = 1
CTRL_CMD_DELFAMILY = 2
CTRL_CMD_GETFAMILY = 3
CTRL_CMD_NEWOPS = 4
CTRL_CMD_DELOPS = 5
CTRL_CMD_GETOPS = 6
CTRL_CMD_NEWMCAST_GRP = 7
CTRL_CMD_DELMCAST_GRP = 8
CTRL_CMD_GETMCAST_GRP = 9     # unused
CTRL_CMD_MAX = 10             # always keep last

# generic netlink controller attribute types
CTRL_ATTR_UNSPEC = 0
CTRL_ATTR_FAMILY_ID = 1
CTRL_ATTR_FAMILY_NAME = 2
CTRL_ATTR_VERSION = 3
CTRL_ATTR_HDRSIZE = 4
CTRL_ATTR_MAXATTR = 5
CTRL_ATTR_OPS = 6
CTRL_ATTR_MCAST_GROUPS = 7
CTRL_ATTR_MAX = 8             # always keep last

def nfa_align(len):
    return (len + NFA_ALIGNTO - 1) & ~(NFA_ALIGNTO - 1)

class NetlinkAttributeFactory(object):
    @staticmethod
    def create(message_type, **kw):
        return NetlinkAttribute(message_type, **kw)

class NetlinkAttribute(object):
    def __init__(self, type, **kw):
        data = kw.pop('data', None)
        attrs = kw.pop('attrs', None)

        if data == None and attrs == None:
            raise NetlinkAttributeException, "either data or attr must be set"
        if data != None and attrs != None:
            raise NetlinkAttributeException, "only data or attr should be set"

        self.type = type
        self.nested = attrs != None
        if self.nested:
            self.type |= NLA_F_NESTED
        self.__buf = data
        self.__pos = 0
        self.__attrs = attrs

    def __eq__(self, other):
        if self.type != other.type:
            return False
        if self.nested != other.nested:
            return False

        if self.nested:
            res = self.__attrs == other.__attrs
        else:
            res = str(self.__buf) == str(other.__buf)
        return res

    def get_data(self):
        if self.nested == True:
            raise NetlinkAttributeException, "get data of nested attribute"

        return self.__buf

    def read_data(self, length):
        buf = self.get_data()[self.__pos : self.__pos + length]
        if len(buf) != length:
            raise PacketException, "attribute payload too short"
        self.__pos = self.__pos + length
        return buf

    def get_attributes(self):
        if self.nested == False:
            raise NetlinkAttributeException, "get nested attribute of normal attribute"

        return self.__attrs

    def dump(self):
        if self.nested == True:
            data = ""
            for attr in self.__attrs:
                data += attr.dump()
        else:
            data = self.__buf

        alen = nfa_align(len(data))
        flen = alen - len(data)
        header = struct.pack('HH', alen + 4, self.type)
        data = "".join((header, data, '\0' * flen))

        return data

    @classmethod
    def __parse_impl(cls, factory, buf, index):
        attrs = {}

        while index < len(buf):
            header = buf[index:index + 4]
            if len(header) < 4:
                raise PacketException, "message too short to contain an attribute header"

            (length, type) = struct.unpack('HH', header)
            if length < 4:
                raise PacketException, "invalid attribute length specified in attribute header: too short to contain the header itself"
            data = buf[index + 4:index + length]
            if len(data) + 4 != length:
                raise PacketException, "message too short to contain an attribute of the specified size"

            nla_type = type & ctypes.c_uint(~NLA_TYPE_MASK).value
            type = type & NLA_TYPE_MASK

            if nla_type & NLA_F_NESTED:
                nested_attrs = cls.__parse_impl(factory, data, 0)
                attr = factory.create(type, attrs=nested_attrs.values())
                index = index + nfa_align(length)
            else:
                data = data.ljust(nfa_align(length), chr(0))
                attr = factory.create(type, data=data)
                index = index + nfa_align(length)
            if attrs.has_key(type):
                raise PacketException, "message contains multiple attributes of the same type"
            attrs[type] = attr

        return attrs

    @classmethod
    def parse(cls, factory, buf):
        return cls.__parse_impl(factory, buf, 0)

    @classmethod
    def create_string(cls, type, value):
        return cls(type, data=struct.pack(repr(len(value)) + "s", value))

    @classmethod
    def create_string_zero_terminated(cls, type, value):
        return cls.create_string(type, value + b'\x00')

    @classmethod
    def create_u16(cls, type, value):
        return cls(type, data=struct.pack('H', value))

    def parse_u16(self):
        return struct.unpack("H", self.read_data(2))[0]

    @classmethod
    def create_be16(cls, type, value):
        return cls(type, data=struct.pack('>H', value))

    def parse_be16(self):
        return struct.unpack('>H', self.read_data(2))[0]

    @classmethod
    def create_int8(cls, type, value):
        return cls(type, data=struct.pack('B', value))

    def parse_int8(self):
        return struct.unpack('B', self.read_data(1))[0]

    @classmethod
    def create_be32(cls, type, value):
        return cls(type, data=struct.pack('>I', value))

    def parse_be32(self):
        return struct.unpack('>I', self.read_data(4))[0]

    @classmethod
    def create_be64(cls, type, value):
        return cls(type, data=struct.pack('>Q', long(value)))

    def parse_be64(self):
        return struct.unpack('>Q', self.read_data(8))[0]

class GenericNetlinkMessageFactory(object):

    @staticmethod
    def create(command, version, data):
        return GenericNetlinkMessage(command, version, data)

class GenericNetlinkMessage(object):

    def __init__(self, command, version, data=""):
        self.command = command
        self.version = version
        self.__buf = data
        self.__attrs = None

    def __eq__(self, other):
        #xor, check if any one of them are None
        if bool(self) != bool(other):
            return False
        return self.get_attributes() == other.get_attributes()

    def __str__(self):
        return "command: %d, version: %s" % (self.command, self.version)

    def get_attributes(self, factory=NetlinkAttributeFactory):
        return NetlinkAttribute.parse(factory, self.__buf)

    def append_attribute(self, attribute):
        self.__buf = "".join((self.__buf, attribute.dump()))

    def dump(self):
        header = struct.pack('BBH', self.command, self.version, 0)
        return "".join((header, self.__buf))

    @staticmethod
    def parse(factory, buf):
        if len(buf) < 4:
            raise PacketException, "message too short to contain a generic netlink header"
        (command, version, _reserved) = struct.unpack('BBH', buf[:4])
        m = factory.create(command, version, buf[4:])
        return m

class GenericNetlinkControlMessageFactory(GenericNetlinkMessageFactory):

    @staticmethod
    def create(command, version, data):
        if command == GenericNetlinkNewFamilyMessage.command:
            return GenericNetlinkNewFamilyMessage(command, version, data).parse()
        else:
            raise NetlinkException, "unexpected command received: %d" % (command, )

class GenericNetlinkGetFamilyMessage(GenericNetlinkMessage):

    command = CTRL_CMD_GETFAMILY

    def __init__(self, family_name):
        super(GenericNetlinkGetFamilyMessage, self).__init__(self.command, 1)

        self.family_name = family_name
        self.append_attribute(NetlinkAttribute.create_string_zero_terminated(CTRL_ATTR_FAMILY_NAME, family_name))


class GenericNetlinkNewFamilyMessage(GenericNetlinkMessage):

    command = CTRL_CMD_NEWFAMILY

    def parse(self):
        attrs = self.get_attributes()
        self.family_id = attrs[CTRL_ATTR_FAMILY_ID].parse_u16()

        return self

class NetlinkMessage(object):

    def __init__(self, type, flags, seq, pid, payload):
        self.type = type
        self.flags = flags
        self.seq = seq
        self.pid = pid
        self.__payload = payload

    def get_errorcode(self):
        # the error message consists of an error code plus the header of the
        # message triggering the error
        if len(self.__payload) < (4 + 16):
            raise PacketException, "message too short to contain an error header"
        (error,) = struct.unpack('i', self.__payload[:4])
        return error

    @property
    def payload(self):
        return self.__payload

    def parse(self, factory):
        return GenericNetlinkMessage.parse(factory, self.__payload)

    def dump(self):
        # length of generic netlink message header is 16 bytes
        length = len(self.__payload) + 16
        header = struct.pack('IHHII', length, self.type, self.flags, self.seq, self.pid)
        return "".join((header, self.__payload))


class Handle(object):
    def __init__(self, family_name):
        # socket
        self._fd = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
        self._fd.bind((0, 0))
        self._seq_no = 0
        # get local netlink port id
        self._netlink_port_id = self._fd.getsockname()[0]
        self._family_id = GENL_ID_CTRL

        self._lookup_genetlink_family_id(family_name)

    def _lookup_genetlink_family_id(self, family_name):
        msg = GenericNetlinkGetFamilyMessage(family_name)
        for reply in self.talk(msg, factory=GenericNetlinkControlMessageFactory):
            self._family_id = reply.family_id

    @staticmethod
    def parse_messages(buf):
        i = 0
        while i < len(buf):
            header = buf[i:i + 16]
            i = i + 16
            if len(header) < 16:
                raise PacketException, "packet too short to contain a netlink message header"
            (length, type, flags, seq, pid) = struct.unpack('IHHII', header)
            if (length < 16):
                raise PacketException, "invalid length specified in netlink header: too short to contain a netlink message header"
            length = length - 16
            data = buf[i:i + length]
            i = i + length

            # length check
            if len(data) < length:
                raise PacketException, "packet too short to contain a message of the specified size"

            yield NetlinkMessage(type, flags, seq, pid, data)

    def close(self):
        self._fd.close()

    def _create_netlink_message(self, flags, generic_netlink_message):
        self._seq_no = self._seq_no + 1
        return NetlinkMessage(self._family_id, flags, self._seq_no, self._netlink_port_id, generic_netlink_message.dump())

    def send(self, message, is_dump_request=False):
        if is_dump_request:
            flags = NLM_F_REQUEST | NLM_F_DUMP
        else:
            flags = NLM_F_REQUEST | NLM_F_ACK

        netlink_message = self._create_netlink_message(flags, message)
        data = netlink_message.dump()
        if self._fd.send(data) != len(data):
            raise NetlinkException, -errno.EPIPE

    def listen(self):
        quit = False
        status = 0
        while not quit:
            (answer, peer) = self._fd.recvfrom(MAX_NLMSGSIZE)

            for m in self.parse_messages(answer):
                # check for special messages
                if m.type == NLMSG_DONE:
                    quit = True
                    break
                if m.type == NLMSG_ERROR:
                    error = m.get_errorcode()
                    if error < 0:
                        raise NetlinkException, error
                    else:
                        quit = True
                        break

                yield m

    def talk(self, message, is_dump_request=False, factory=None):
        self.send(message, is_dump_request)
        for m in self.listen():
            msg = GenericNetlinkMessage.parse(factory, m.payload)
            yield msg
