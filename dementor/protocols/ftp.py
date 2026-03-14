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
from dementor.config.session import SessionConfig
from dementor.config.toml import TomlConfig, Attribute as A
from dementor.config.util import get_value
from dementor.log.logger import ProtocolLogger
from dementor.servers import BaseProtoHandler, ThreadingTCPServer, ServerThread
from dementor.db import _CLEARTEXT  # pyright: ignore[reportPrivateUsage]

# --------------------------------------------------------------------------- #
# RFC-959 reply codes used by this minimal implementation.
# --------------------------------------------------------------------------- #
ReplyCodes: dict[int, bytes] = {
    220: b"220 Service ready for new user.",  # Service ready
    230: b"230 User logged in, proceed.",  # Successful login
    331: b"331 User name okay, need password.",  # Username accepted
    501: b"501 Syntax error in parameters or arguments.",
    502: b"502 Command not implemented.",
    530: b"530 Not logged in.",
    221: b"221 Service closing control connection.",
}


# --------------------------------------------------------------------------- #
# Configuration handling
# --------------------------------------------------------------------------- #
class FTPServerConfig(TomlConfig):
    """
    Configuration container for a single FTP server instance.

    The configuration is read from the ``[FTP]`` section of the TOML file.
    Only the listening port is required.

    :param ftp_port: TCP port on which the FTP server should listen,
        defaults to the standard FTP port ``21``.
    :type ftp_port: int
    """

    _section_: ClassVar[str] = "FTP"
    _fields_: ClassVar[list[A]] = [A("ftp_port", "Port")]

    if typing.TYPE_CHECKING:  # pragma: no cover
        ftp_port: int


def apply_config(session: SessionConfig) -> None:
    """
    Load FTP server configuration and store it on *session*.

    ``session.ftp_config`` becomes a list of :class:`FTPServerConfig`
    objects - one per ``[FTP.Server]`` stanza in the TOML file.

    :param session: Current session object.
    :type session: :class:`dementor.config.session.SessionConfig`
    """
    session.ftp_config = []
    if session.ftp_enabled:  # pragma: no branch
        for server_cfg in get_value("FTP", "Server", default=[]):
            session.ftp_config.append(FTPServerConfig(server_cfg))


def create_server_threads(session: SessionConfig) -> list[ServerThread]:
    """Build :class:`ServerThread` objects for each configured FTP server.

    :param session: Session containing the ``ftp_config`` list.
    :type session: :class:`dementor.config.session.SessionConfig`
    :return: List of ready-to-start :class:`ServerThread` objects.
    :rtype: list[ServerThread]
    """
    return [
        ServerThread(
            session,
            FTPServer,
            server_address=("", cfg.ftp_port),
        )
        for cfg in session.ftp_config
    ]


# --------------------------------------------------------------------------- #
# FTP request handling
# --------------------------------------------------------------------------- #
class FTPHandler(BaseProtoHandler):
    """
    Minimal FTP request handler.

    The handler sends the initial ``220`` greeting, then processes a very
    small login sequence (``USER`` → ``PASS``).  All other commands result
    in a ``501`` reply.

    :class:`ProtocolLogger` is used to attach FTP-specific metadata to log
    records.
    """

    # ------------------------------------------------------------------- #
    # Logging helper
    # ------------------------------------------------------------------- #
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

    # ------------------------------------------------------------------- #
    # Core request processing
    # ------------------------------------------------------------------- #
    @override
    def handle_data(self, data: bytes | None, transport: socket) -> None:
        """Process client commands after a TCP connection is accepted."""
        # -----------------------------------------------------------------
        # 1. Send the initial greeting as required by RFC-959.
        # -----------------------------------------------------------------
        self.reply(220)

        while True:
            raw: bytes = self.request.recv(1024)
            if not raw:
                # Client closed the connection.
                break

            # Strip CRLF and split on whitespace; FTP commands are case-insensitive.
            parts = raw.strip().split(None, 1)  # e.g. [b'USER', b'alice']
            cmd = parts[0].upper() if parts else b""

            # -----------------------------------------------------------------
            # USER command handling
            # -----------------------------------------------------------------
            if cmd == b"USER":
                username = (
                    parts[1].decode(errors="replace").strip() if len(parts) > 1 else ""
                )
                if not username:
                    self.reply(501)  # Empty username → syntax error
                    continue

                self.reply(331)  # Password required
                # -------------------------------------------------------------
                # Expect PASS command next; loop back to receive it.
                # -------------------------------------------------------------
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
                    credtype=_CLEARTEXT,  # intentional clear-text
                    username=username,
                    password=password,
                    logger=self.logger,
                )
                # # Command not implemented rather than error
                self.reply(502)
                break

            # -----------------------------------------------------------------
            # Any other command is treated as a syntax error.
            # -----------------------------------------------------------------
            self.reply(501)

        # Send a polite closing message before the socket is closed by the
        # server framework (optional, but makes the dialogue look more genuine).
        with contextlib.suppress(Exception):
            self.reply(221)

    # ------------------------------------------------------------------- #
    # Helper to send a reply line.
    # ------------------------------------------------------------------- #
    def reply(self, code: int) -> None:
        """
        Send a one-line FTP reply identified by *code*.

        The reply string is taken from :data:`ReplyCodes` and terminated with
        CRLF as required by the protocol.

        :param code: Numeric FTP reply code (e.g. ``220``).
        :type code: int
        :raises KeyError: If *code* is not present in :data:`ReplyCodes`.
        """
        try:
            self.request.sendall(ReplyCodes[code] + b"\r\n")
        except OSError as exc:
            # Logging the failure helps debugging but we do not re-raise,
            # because the connection is likely already broken.
            self.logger.debug(f"Failed to send FTP reply {code}: {exc}")


# --------------------------------------------------------------------------- #
# Server class - thin wrapper around ``ThreadingTCPServer``.
# --------------------------------------------------------------------------- #
class FTPServer(ThreadingTCPServer):
    """
    TCP server that accepts FTP connections.

    Only the class-level defaults are defined here; all functional behaviour
    is provided by :class:`ThreadingTCPServer` and :class:`FTPHandler`.
    """

    default_port: ClassVar[int] = 21
    default_handler_class: ClassVar[type[FTPHandler]] = FTPHandler
    service_name: str = "FTP"
