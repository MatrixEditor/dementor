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
#
# Reference:
#   - https://x.org/releases/X11R7.7/doc/xproto/x11protocol.html
# pyright: reportInvalidTypeForm=false, reportCallIssue=false, reportGeneralTypeIssues=false
from caterpillar import py

from dementor.config.toml import Attribute as A, TomlConfig
from dementor.logger import ProtocolLogger
from dementor.servers import BaseProtoHandler, ThreadingTCPServer, ServerThread
from dementor.database import _NO_USER


class X11Config(TomlConfig):
    _section_ = "X11"
    _fields_ = [
        A("x11_ports", "PortRange", None),
        A("x11_error_reason", "ErrorMessage", "Access denied"),
    ]

    def set_x11_ports(self, port_range: str | range | dict):
        self.x11_ports = None
        match port_range:
            case range():
                self.x11_ports = port_range
            case dict():
                self.x11_ports = range(
                    port_range.get("start", 6000), port_range.get("end", 6005)
                )
            case str():
                values = port_range.split("-")
                if len(values) == 2:
                    self.x11_ports = range(int(values[0]), int(values[1]))

        if not self.x11_ports:
            self.x11_ports = range(6000, 6005)


def apply_config(session):
    session.x11_config = TomlConfig.build_config(X11Config)


def create_server_threads(session):
    servers = []
    if session.x11_enabled:
        for port in session.x11_config.x11_ports:
            servers.append(
                ServerThread(
                    session,
                    X11Server,
                    server_address=(session.bind_address, port),
                )
            )
    return servers


# --- Protocol definitions ---
# Chapter 3. Common Types
# Only necessary types are specified here - a complete list can be taken from
# the reference
BYTE = py.uint8
CARD8 = py.uint8
CARD16 = py.uint16
CARD32 = py.uint32
STRING8 = py.Bytes

# Chapter 8. Connection Setup


# [Connection Initiation]
# The value 102 (ASCII uppercase B) means values are transmitted most significant byte first,
# and value 154 (ASCII lowercase l) means values are transmitted least significant byte first.
X_CONN_LE = ord("l")
X_CONN_BE = ord("B")
X_CONN_REMOTE_LE = ord("r")
X_CONN_REMOTE_BE = ord("R")
X_AUTH_MISSING = "Authorization required, but no authorization protocol specified"


# If the number of unused bytes is variable, the encode-form typically is:
#    p               unused, p=pad(E)
# where E is some expression, and pad(E) is the number of bytes needed to round E up to a multiple of four.
#    pad(E) = (4 - (E mod 4)) mod 4
def pad(E):
    def _wrap(context):
        size = E(context)
        return (4 - (size % 4)) % 4

    return _wrap


def xConnClient_set_length(context):
    self = context._obj
    self.nbytesAuthProto = len(self.authProto)
    self.nbytesAuthString = len(self.authString)


@py.struct(order=py.LittleEndian)
class xConnClientPrefixLE:
    byteOrder: py.Const(X_CONN_LE, CARD8)
    _pad: py.padding[1]
    # The version numbers indicate what version of the protocol the client expects the server to implement.
    majorVersion: CARD16
    minorVersion: CARD16

    _aset_length: py.Action(pack=xConnClient_set_length)
    nbytesAuthProto: CARD16
    nbytesAuthString: CARD16
    _pad2: py.padding[2]
    # The authorization name indicates what authorization (and authentication) protocol the client expects
    # the server to use, and the data is specific to that protocol. Specification of valid authorization
    # mechanisms is not part of the core X protocol. A server that does not implement the protocol the
    # client expects or that only implements the host-based mechanism may simply ignore this information.
    # If both name and data strings are empty, this is to be interpreted as "no explicit authorization."
    authProto: STRING8(py.this.nbytesAuthProto)
    _pad3: py.padding[pad(py.this.nbytesAuthProto)]
    authString: STRING8(py.this.nbytesAuthString)
    _pad4: py.padding[pad(py.this.nbytesAuthString)]


@py.struct(order=py.BigEndian)
class xConnClientPrefixBE:
    byteOrder: py.Const(X_CONN_BE, CARD8)
    _pad: py.padding[1]
    majorVersion: CARD16
    minorVersion: CARD16
    _aset_length: py.Action(pack=xConnClient_set_length)
    nbytesAuthProto: CARD16
    nbytesAuthString: CARD16
    _pad2: py.padding[2]
    authProto: STRING8(py.this.nbytesAuthProto)
    _pad3: py.padding[pad(py.this.nbytesAuthProto)]
    authString: STRING8(py.this.nbytesAuthString)
    _pad4: py.padding[pad(py.this.nbytesAuthString)]


# [Server Response]
X_CONN_FAILED = 0
X_CONN_SUCCESS = 1
X_CONN_AUTHENTICATE = 2


# nformation received by the client if the connection is refused:
# 1     0                 Failed
# 1     n                 length of reason in bytes
# 2     CARD16            protocol-major-version
# 2     CARD16            protocol-minor-version
# 2     (n+p)/4           length in 4-byte units of "additional data"
# n     STRING8           reason
# p                       unused, p=pad(n)
def xConnSetup_set_length(context):
    self = context._obj
    self.lengthReason = len(self.reason)
    pad = (4 - (self.lengthReason % 4)) % 4
    self.length = (self.lengthReason + pad) // 4


@py.struct(order=py.LittleEndian)
class xConnSetupPrefixLE:
    _aset_length: py.Action(pack=xConnSetup_set_length)

    # Taken from Xproto.h#L286:
    # The protocol also defines a case of success == Authenticate, but
    # that doesn't seem to have ever been implemented by the X Consortium.
    success: CARD8 = X_CONN_SUCCESS
    lengthReason: BYTE = 0
    majorVersion: CARD16
    minorVersion: CARD16
    length: CARD16 = 0
    reason: STRING8(py.this.lengthReason)
    _pad: py.padding[pad(py.this.lengthReason)] = None


@py.struct(order=py.BigEndian)
class xConnSetupPrefixBE:
    _aset_length: py.Action(pack=xConnSetup_set_length)
    success: CARD8 = X_CONN_SUCCESS
    lengthReason: BYTE = 0
    majorVersion: CARD16
    minorVersion: CARD16
    length: CARD16 = 0
    reason: STRING8(py.this.lengthReason)
    _pad: py.padding[pad(py.this.lengthReason)] = None


# -- Server and Handler ---
class X11Handler(BaseProtoHandler):
    def proto_logger(self) -> ProtocolLogger:
        return ProtocolLogger(
            extra={
                "protocol": "X11",
                "protocol_color": "light_sky_blue1",
                "host": self.client_host,
                "port": self.server.server_address[1],
            }
        )

    def handle_data(self, data, transport) -> None:
        data = self.recv(8192)
        if not data:
            return

        self.logger.debug(f"({chr(data[0])!r}) {data.hex()}", is_client=True)
        match chr(data[0]):
            case "l" | "r":  # Xserver implementation uses 'r' for remote
                RequestTy = xConnClientPrefixLE
                ResponseTy = xConnSetupPrefixLE
                endian_name = "LE"
            case "B" | "R":
                RequestTy = xConnClientPrefixBE
                ResponseTy = xConnSetupPrefixBE
                endian_name = "BE"
            case _:
                return self.logger.warning(
                    f"Unknown byteorder type in X11 request: '{data[0]:#x}'"
                )

        try:
            request: RequestTy = py.unpack(RequestTy, data)
        except Exception as e:
            return self.logger.error(f"Invalid X11 request: {e}")

        error_message = X_AUTH_MISSING
        if request.authProto:
            self.config.db.add_auth(
                client=self.client_address,
                credtype=request.authProto.decode(errors="replace").strip(),
                username=_NO_USER,
                password=request.authString.hex(),
                logger=self.logger,
                custom=True,
            )
            error_message = self.config.x11_config.x11_error_reason
        else:
            self.logger.display(
                f"[i]Anonymous[/i] X11 request from {self.client_host} (version: "
                f"{request.majorVersion}.{request.minorVersion})"
            )

        resp = ResponseTy(
            success=X_CONN_FAILED,
            reason=error_message.encode(errors="replace"),
            majorVersion=request.majorVersion,
            minorVersion=request.minorVersion,
        )
        data = py.pack(resp)
        self.logger.debug(f"({endian_name}) {data.hex()}", is_server=True)
        self.send(data)


class X11Server(ThreadingTCPServer):
    default_port = 6000
    default_handler_class = X11Handler
    service_name = "X11"
