# Copyright (c) 2025-Present MatrixEditor
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# pyright: reportInvalidTypeForm=false, reportCallIssue=false
#
# Notes:
#   - Implementation of the MySQL protocol according to the online documentation.
#     https://dev.mysql.com/doc/dev/mysql-server/latest/PAGE_PROTOCOL.html

import enum

from typing import Any
from collections import OrderedDict

from caterpillar.py import (
    CString,
    Const,
    Prefixed,
    String,
    pack,
    struct,
    this,
    uint24,
    uint8,
    Bytes,
    LittleEndian,
    uint16,
    uint32,
    uint64,
    singleton,
    unpack,
)
from caterpillar.exception import DynamicSizeError, StructException

from dementor.servers import (
    ThreadingTCPServer,
    ServerThread,
    BaseProtoHandler,
    create_tls_context,
)
from dementor.logger import ProtocolLogger
from dementor.config.attr import Attribute as A, ATTR_TLS, ATTR_CERT, ATTR_KEY
from dementor.config.toml import TomlConfig
from dementor.database import _CLEARTEXT


class MySQLConfig(TomlConfig):
    _section_ = "MySQL"
    _fields_ = [
        A("mysql_port", "Port", 3306),
        A("mysql_plugin_name", "AuthPlugin", "mysql_clear_password"),
        A("mysql_version", "ServerVersion", "8.0.42"),
        A("mysql_error_code", "ErrorCode", 1045),
        A("mysql_error_message", "ErrorMessage", "Access denied for user"),
        ATTR_CERT,
        ATTR_KEY,
        ATTR_TLS,
    ]


def apply_config(session):
    session.mysql_config = TomlConfig.build_config(MySQLConfig)


def create_server_threads(session):
    return [
        ServerThread(
            session,
            MySQLServer,
            server_address=(session.bind_address, session.mysql_config.mysql_port),
        )
    ] if session.mysql_enabled else []


# --- MySQL Protocol ---

# Capabilities
CLIENT_LONG_PASSWORD = 1
CLIENT_FOUND_ROWS = 2
CLIENT_LONG_FLAG = 4
CLIENT_CONNECT_WITH_DB = 8
CLIENT_NO_SCHEMA = 16
CLIENT_COMPRESS = 32
CLIENT_ODBC = 64
CLIENT_LOCAL_FILES = 128
CLIENT_IGNORE_SPACE = 256
CLIENT_PROTOCOL_41 = 512
CLIENT_INTERACTIVE = 1024
CLIENT_SSL = 2048
CLIENT_IGNORE_SIGPIPE = 4096
CLIENT_TRANSACTIONS = 8192
CLIENT_RESERVED = 16384
CLIENT_RESERVED2 = 32768
CLIENT_MULTI_STATEMENTS = 1 << 16
CLIENT_MULTI_RESULTS = 1 << 17
CLIENT_PS_MULTI_RESULTS = 1 << 18
CLIENT_PLUGIN_AUTH = 1 << 19
CLIENT_CONNECT_ATTRS = 1 << 20
CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 1 << 21
CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS = 1 << 22
CLIENT_SESSION_TRACK = 1 << 23
CLIENT_DEPRECATE_EOF = 1 << 24
CLIENT_OPTIONAL_RESULTSET_METADATA = 1 << 25
CLIENT_ZSTD_COMPRESSION_ALGORITHM = 1 << 26
CLIENT_QUERY_ATTRIBUTES = 1 << 27
MULTI_FACTOR_AUTHENTICATION = 1 << 28
CLIENT_CAPABILITY_EXTENSION = 1 << 29
CLIENT_SSL_VERIFY_SERVER_CERT = 1 << 30
CLIENT_REMEMBER_OPTIONS = 1 << 31


class SERVER_STATUS_flags_enum(enum.IntEnum):
    __struct__ = uint16

    SERVER_STATUS_IN_TRANS = 1
    SERVER_STATUS_AUTOCOMMIT = 2
    SERVER_MORE_RESULTS_EXISTS = 8
    SERVER_QUERY_NO_GOOD_INDEX_USED = 16
    SERVER_QUERY_NO_INDEX_USED = 32
    SERVER_STATUS_CURSOR_EXISTS = 64
    SERVER_STATUS_LAST_ROW_SENT = 128
    SERVER_STATUS_DB_DROPPED = 256
    SERVER_STATUS_NO_BACKSLASH_ESCAPES = 512
    SERVER_STATUS_METADATA_CHANGED = 1024
    SERVER_QUERY_WAS_SLOW = 2048
    SERVER_PS_OUT_PARAMS = 4096
    SERVER_STATUS_IN_TRANS_READONLY = 8192
    SERVER_SESSION_STATE_CHANGED = 1 << 14


# [Protocol::LengthEncodedInteger]
# An integer that consumes 1, 3, 4, or 9 bytes, depending on its numeric value
# GT / Eq     LT      Stored as
# 0           251     1-byte integer
# 251         216     0xFC + 2-byte integer
# 216         224     0xFD + 3-byte integer
# 224         264     0xFE + 8-byte integer
@singleton
class LengthEncodedInteger:
    def __type__(self):
        return int

    def __size__(self, context):
        raise DynamicSizeError("LengthEncodedInteger is dynamic")

    def __unpack__(self, context):
        (size,) = context._io.read(1)
        if 0 <= size < 251:
            return size

        match size:
            case 0xFC:
                return uint16.unpack_single(context)

            case 0xFD:
                return uint24.unpack_single(context)

            case 0xFE:
                return uint64.unpack_single(context)

            case _:
                raise StructException("invalid length-encoded integer")

    def __pack__(self, value: int, context):
        prefix = None
        if value < 251:
            target = uint8
        elif value < 0x10000:
            prefix = b"\xfc"
            target = uint16
        elif value < 0x1000000:
            prefix = b"\xfd"
            target = uint24
        else:
            prefix = b"\xfe"
            target = uint64

        if prefix:
            context._io.write(prefix)

        target.pack_single(value, context)


# [Protocol::Packet]
@struct(order=LittleEndian)
class Packet:
    # Length of the payload. The number of bytes in the packet beyond the
    # initial 4 bytes that make up the packet header.
    payload_length: uint24

    # The sequence-id is incremented with each packet and may wrap around.
    # It starts at 0 and is reset to 0 when a new command begins in the
    # Command Phase.
    sequence_id: uint8

    # payload of the packet
    payload: Bytes(this.payload_length)


# [ERR_Packet]
@struct(order=LittleEndian)
class ERR_Packet:
    header: Const(0xFF, uint8)
    error_code: uint16
    error_message: String(...)


def _auth_plugin_length(context):
    # Rest of the plugin provided data (scramble), $len=MAX(13, length of auth-plugin-data - 8)
    if _has_auth_plugin_data(context):
        return max(13, context._obj.auth_plugin_data_len - 8)

    return 0


def _has_auth_plugin_data(context):
    flags = context._obj.flags_lower | (context._obj.flags_upper << 16)
    return flags & CLIENT_PLUGIN_AUTH != 0


# [Protocol::HandshakeV10]
@struct(order=LittleEndian)
class HandshakeV10:
    protocol_version: Const(10, uint8)
    server_version: CString()

    # a.k.a. connection id
    thread_id: uint32 = 0

    # first 8 bytes of the plugin provided data (scramble)
    salt: Bytes(8)

    # 0x00 byte, terminating the first part of a scramble
    filler: Const(0x00, uint8)

    # Why does it have to be that complicated?
    # The lower 2 bytes of the Capabilities Flags
    flags_lower: uint16 = 0x000

    # default server a_protocol_character_set, only the lower 8-bits
    character_set: uint8 = 0x3F
    status_flags: SERVER_STATUS_flags_enum = 0x00
    flags_upper: uint16 = 0x000

    # length of the combined auth_plugin_data (scramble), if
    # auth_plugin_data_len is > 0
    auth_plugin_data_len: uint8 = 0x00
    reserved: Bytes(10) = b"\0" * 10

    # Rest of the plugin provided data (scramble), $len=MAX(13, length of
    # auth-plugin-data - 8)
    salt2: Bytes(_auth_plugin_length)

    # name of the auth_method that the auth_plugin_data belongs to
    auth_plugin_name: CString() // _has_auth_plugin_data

    def set_flags(self, flags):
        self.flags_lower = flags & 0xFFFF
        self.flags_upper = (flags >> 16) & 0xFFFF

    def get_flags(self):
        return self.flags_lower | (self.flags_upper << 16)


def _client_connect_db(context):
    return context._obj.client_flags & CLIENT_CONNECT_WITH_DB != 0


def _client_auth_plugin(context):
    return context._obj.client_flags & CLIENT_PLUGIN_AUTH != 0


def _client_connect_attrs(context):
    return context._obj.client_flags & CLIENT_CONNECT_ATTRS != 0


# [Protocol::SSLRequest]
@struct(order=LittleEndian)
class SSLRequest:
    capabilities: uint32
    max_packet_size: uint32
    character_set: uint8
    # everything else is not used


@struct(order=LittleEndian)
class ConnectionAttribute:
    # will be stored as bytes rather than string
    key: Prefixed(LengthEncodedInteger)
    value: Prefixed(LengthEncodedInteger)


# [Protocol::HandshakeResponse]
@struct(order=LittleEndian)
class HandshakeResponse:
    client_flags: uint32
    max_packet_size: uint32
    charset: uint8

    # filler to the size of the handhshake response packet. All 0s.
    filler: Bytes(23) = b"\0" * 23

    # 	login user name
    username: CString()

    # opaque authentication response data generated by Authentication Method
    # indicated by the plugin name field.
    # NOTE: we always assume a length encoded integer
    auth_response: Prefixed(LengthEncodedInteger)

    # initial database for the connection. This string should be interpreted
    # using the character set indicated by character set field.
    database: CString() // _client_connect_db
    client_plugin_name: CString() // _client_auth_plugin

    # From the docs:
    # if capabilities & CLIENT_CONNECT_ATTRS {
    #   int<lenenc> length of all key-values
    #   string<lenenc> Name of the 1st client attribute
    #   string<lenenc> Value of the 1st client attribute
    # .. (if more data in length of all key-values, more keys and values parts)
    # }
    conn_attrs: (
        Prefixed(LengthEncodedInteger, ConnectionAttribute[...])
    ) // _client_connect_attrs
    # zstd_compression_level is dropped here


# --- MySQL Handler ---
class MySQLHandler(BaseProtoHandler):
    @property
    def mysql_config(self):
        return self.config.mysql_config

    def proto_logger(self) -> ProtocolLogger:
        return ProtocolLogger(
            extra={
                "protocol": "MySQL",
                "protocol_color": "medium_orchid3",
                "host": self.client_host,
                "port": self.server.server_address[1],
            }
        )

    def push(self, payload, prev_id: int | None = None) -> None:
        data = pack(payload)
        packet = Packet(
            payload_length=len(data),
            sequence_id=prev_id + 1 if prev_id is not None else 0,
            payload=data,
        )
        self.send(pack(packet))

    def recv_unpack(self) -> Any:
        try:
            data = self.recv(8192)
            if not data:
                return None

            return unpack(Packet, data)
        except OSError:
            raise  # will terminate the connection

        except Exception as e:
            self.logger.error(f"Failed to decode MySQL packet: {e}")
            return None

    def setup(self) -> None:
        # plugin = self.config.mysql_config.mysql_plugin_name
        plugin = "mysql_clear_password"
        self.logger.display(
            f"New Connection to MySQL Server (requesting handshake for {plugin})"
        )

    def finish(self) -> None:
        self.logger.debug("Connection to MySQL Server closed")

    def handle_data(self, data, transport) -> None:
        transport.settimeout(2)
        # Connection Phase:
        # It starts with the client connect()ing to the server which may send a
        # ERR packet and finish the handshake or send a Initial Handshake Packet
        # which the client answers with a Handshake Response Packet.
        flags = 0xFFFFFFFF
        flags ^= CLIENT_CAPABILITY_EXTENSION
        if not self.mysql_config.use_ssl:
            flags ^= CLIENT_SSL
            flags ^= CLIENT_SSL_VERIFY_SERVER_CERT

        # NOTE: the configuration value won't have any effect here for now
        plugin_name = "mysql_clear_password"
        greeting = HandshakeV10(
            server_version=self.mysql_config.mysql_version,
            thread_id=10,
            salt=b"A" * 8,
            status_flags=SERVER_STATUS_flags_enum.SERVER_STATUS_AUTOCOMMIT,
            auth_plugin_data_len=21,  # REVISIT: maybe add automatic calculation here
            salt2=b"A" * 12 + b"\0",
            auth_plugin_name=plugin_name,
        )
        greeting.set_flags(flags)
        self.push(greeting)

        packet = self.recv_unpack()
        if packet is None:
            return

        # After this, optionally, the client can request an SSL connection to be established
        # with the Protocol::SSLRequest packet and then the client sends the Protocol::HandshakeResponse
        # packet.
        try:
            ssl_request: SSLRequest = unpack(SSLRequest, packet.payload)
        except Exception as e:
            return self.logger.error(f"Failed to decode MySQL SSLRequest: {e}")

        if ssl_request.capabilities & CLIENT_SSL != 0:
            if not self.mysql_config.use_ssl:
                self.logger.fail(
                    "Client requested SSL, but MySQL server is not configured to use SSL"
                )
                return  # terminate connection
            else:
                self.logger.display("Client is requesting upgrade to SSL")

            self.context = create_tls_context(
                self.mysql_config, self.server, force=True
            )
            if self.context is None:
                return

            self.request = self.context.wrap_socket(transport, server_side=True)
            packet = self.recv_unpack()
            if packet is None:
                return

        try:
            response: HandshakeResponse = unpack(HandshakeResponse, packet.payload)
        except Exception as e:
            return self.logger.error(f"Failed to decode MySQL HandshakeResponse: {e}")

        resp_plugin_name = response.client_plugin_name or plugin_name
        if resp_plugin_name != plugin_name:
            self.logger.fail(
                f"Expected authentication plugin {plugin_name}, but got {resp_plugin_name} from client"
            )

        method = getattr(self, resp_plugin_name, None)
        if method:
            method(greeting, response)
        else:
            self.logger.debug(f"Unknown authentication plugin: {resp_plugin_name}")

    def mysql_clear_password(self, greeting: HandshakeV10, response: HandshakeResponse):
        username = response.username
        password = response.auth_response.decode(errors="replace").strip("\x00")

        extras = {
            conn_attr.key.decode(errors="replace"): conn_attr.value.decode(
                errors="replace"
            )
            for conn_attr in (response.conn_attrs or [])
        }
        if response.database:
            extras["database"] = response.database

        self.config.db.add_auth(
            client=self.client_address,
            username=username,
            password=password,
            logger=self.logger,
            credtype=_CLEARTEXT,
            extras=OrderedDict(sorted(extras.items())),
        )

        error = ERR_Packet(
            error_code=self.mysql_config.mysql_error_code,
            error_message=f"#28000{self.mysql_config.mysql_error_message}",
        )
        self.push(error)


class MySQLServer(ThreadingTCPServer):
    default_port = 3306
    default_handler_class = MySQLHandler
    service_name = "MySQL"
