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
# pyright: reportUninitializedInstanceVariable=false
# pyright: reportAny=false, reportExplicitAny=false
import contextlib
import typing

from socket import socket
from typing import ClassVar
from typing_extensions import override

from dementor.loader import BaseProtocolModule, DEFAULT_ATTR
from dementor.config.session import SessionConfig
from dementor.config.toml import TomlConfig, Attribute as A
from dementor.log.logger import ProtocolLogger
from dementor.servers import (
    BaseProtoHandler,
    ThreadingTCPServer,
    ServerThread,
    BaseServerThread,
)
from dementor.db import CLEARTEXT

__proto__ = ["FTP"]

ReplyCodes: dict[int, bytes] = {
    220: b"220 Service ready for new user.",  # Service ready
    230: b"230 User logged in, proceed.",  # Successful login
    331: b"331 User name okay, need password.",  # Username accepted
    501: b"501 Syntax error in parameters or arguments.",
    502: b"502 Command not implemented.",
    530: b"530 Not logged in.",
    221: b"221 Service closing control connection.",
}


class FTPServerConfig(TomlConfig):
    _section_ = "FTP"
    _fields_ = [A("ftp_port", "Port")]

    if typing.TYPE_CHECKING:  # pragma: no cover
        ftp_port: int


class FTP(BaseProtocolModule[FTPServerConfig]):
    name = "FTP"
    config_ty = FTPServerConfig
    config_attr = DEFAULT_ATTR
    config_enabled_attr = DEFAULT_ATTR
    config_list = True

    @override
    def create_server_thread(
        self, session: SessionConfig, server_config: FTPServerConfig
    ) -> BaseServerThread[FTPServerConfig]:
        return ServerThread(
            session,
            server_config,
            FTPServer,
            server_address=(session.bind_address, server_config.ftp_port),
        )


class FTPHandler(BaseProtoHandler):
    @override
    def proto_logger(self) -> ProtocolLogger:
        """
        Return a :class:`ProtocolLogger` pre-populated with FTP-specific fields.

        :return: Configured ``ProtocolLogger`` instance.
        :rtype: ProtocolLogger
        """
        return ProtocolLogger(
            extra={
                "protocol": "FTP",
                "protocol_color": "medium_purple2",
                "host": self.client_host,
                "port": self.server_port,
            }
        )

    @override
    def handle_data(self, data: bytes | None, transport: socket) -> None:
        self.reply(220)

        while True:
            raw: bytes = self.request.recv(1024)
            if not raw:
                # Client closed the connection.
                break

            parts = raw.strip().split(None, 1)
            cmd = parts[0].upper() if parts else b""
            if cmd == b"USER":
                username = (
                    parts[1].decode(errors="replace").strip() if len(parts) > 1 else ""
                )
                if not username:
                    self.reply(501)
                    continue

                self.reply(331)
                raw = self.request.recv(1024)
                if not raw:
                    break

                parts = raw.strip().split(None, 1)
                if parts[0].upper() != b"PASS":
                    self.reply(501)
                    continue

                password = (
                    parts[1].decode(errors="replace").strip() if len(parts) > 1 else ""
                )

                self.config.db.add_auth(
                    client=self.client_address,
                    credtype=CLEARTEXT,
                    username=username,
                    password=password,
                    logger=self.logger,
                )
                # # Command not implemented rather than error
                self.reply(502)
                break

            self.reply(501)

        with contextlib.suppress(Exception):
            self.reply(221)

    def reply(self, code: int) -> None:
        try:
            self.request.sendall(ReplyCodes[code] + b"\r\n")
        except OSError as exc:
            self.logger.debug(f"Failed to send FTP reply {code}: {exc}")


class FTPServer(ThreadingTCPServer):
    default_port: ClassVar[int] = 21
    default_handler_class: ClassVar[type[FTPHandler]] = FTPHandler
    service_name: str = "FTP"
