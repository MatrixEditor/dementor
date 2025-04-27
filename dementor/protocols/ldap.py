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
import ssl

from typing import Any, List, Tuple

from impacket import ntlm
from impacket.ntlm import NTLMAuthChallengeResponse, NTLMAuthNegotiate
from impacket.ldap.ldap import BindRequest, SearchRequest
from impacket.ldap.ldapasn1 import (
    BindResponse,
    LDAPMessage,
    PartialAttribute,
    PartialAttributeList,
    SearchResultDone,
    ResultCode,
    SearchResultEntry,
    UnbindRequest,
)
from pyasn1.codec.ber import encoder as BEREncoder, decoder as BERDecoder

from dementor.config.toml import TomlConfig, Attribute as A
from dementor.config.session import SessionConfig
from dementor.config.util import get_value
from dementor.logger import ProtocolLogger
from dementor.servers import (
    ThreadingTCPServer,
    ThreadingUDPServer,
    BaseProtoHandler,
    ServerThread,
)
from dementor.database import _CLEARTEXT
from dementor.protocols.ntlm import (
    NTLM_AUTH_CreateChallenge,
    NTLM_AUTH_format_host,
    NTLM_report_auth,
    NTLM_split_fqdn,
)

# Taken from Microsoft's spec:
# - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3ed61e6c-cfdc-487d-9f02-5a3397be3772
LDAP_CAPABILITIES = [
    # LDAP_CAP_ACTIVE_DIRECTORY_OID
    # The presence of this capability indicates that the LDAP server is running
    # Active Directory and is running as AD DS.
    "1.2.840.113556.1.4.800",
    # LDAP_CAP_ACTIVE_DIRECTORY_LDAP_INTEG_OID
    # The presence of this capability indicates that the LDAP server on the DC is
    # capable of signing and sealing on an NTLM authenticated connection, and that
    # the server is capable of performing subsequent binds on a signed or sealed
    # connection.
    "1.2.840.113556.1.4.1791",
    # NOTE: We use the earliest version possible
    # LDAP_CAP_ACTIVE_DIRECTORY_V51_OID
    # On an Active Directory DC operating as AD DS, the presence of this capability
    # indicates that the LDAP server is running at least the Windows Server 2003
    # operating system version of Active Directory.
    "1.2.840.113556.1.4.1670",
]

LDAP_DEFAULT_MECH = [
    # SASL:
    # GSS-SPNEGO, in turn, uses Kerberos or NTLM as the underlying authentication protocol.
    "GSS-SPNEGO",
    # GSSAPI, in turn, always uses Kerberos as the underlying authentication protocol.
    "GSSAPI",
    "EXTERNAL",  # NOT IMPLEMENTED
    "DIGEST-MD5",  # NOT IMPLEMENTED
]


class LDAPServerConfig(TomlConfig):
    _section_ = "LDAP"
    _fields_ = [
        A("ldap_port", "Port"),
        A("ldap_udp", "Connectionless"),
        A("ldap_caps", "Capabilities", LDAP_CAPABILITIES),
        A("ldap_mech", "SASLMechanisms", LDAP_DEFAULT_MECH),
        A("ldap_timeout", "Timeout", 0),
        A("ldap_fqdn", "FQDN", "DEMENTOR", section_local=False),
        A("ldap_tls", "TLS", False),
        A("ldap_tls_key", "Key", None, section_local=False),
        A("ldap_tls_cert", "Cert", None, section_local=False),
        A("ldap_error_code", "ErrorCode", "unwillingToPerform"),
    ]

    def set_ldap_error_code(self, value: str | int):
        if isinstance(value, int):
            self.ldap_error_code = value
        else:
            # TODO: add error reporting
            self.ldap_error_code = ResultCode.namedValues[str(value)]


def apply_config(session) -> None:
    ldap_config = []
    if session.ldap_enabled:
        for server_config in get_value("LDAP", "Server", default=[]):
            ldap_config.append(LDAPServerConfig(server_config))

    session.ldap_config = ldap_config


def create_server_threads(session) -> list:
    servers = []
    for config in session.ldap_config if session.ldap_enabled else []:
        server_cls = CLDAPServer if config.ldap_udp else LDAPServer
        servers.append(
            ServerThread(
                session,
                server_cls,
                server_address=("", config.ldap_port),
                server_config=config,
            )
        )

    return servers


class LDAPTerminateSession(Exception):
    pass


class LDAPHandler(BaseProtoHandler):
    def proto_logger(self) -> ProtocolLogger:
        return ProtocolLogger(
            extra={
                "protocol": "LDAP",
                "protocol_color": "violet",
                "host": self.client_host,
                "port": self.server.server_address[1],
            }
        )

    def handle_NTLM_Negotiate(
        self, req: LDAPMessage, nego_token_raw: bytes
    ) -> None | bool:
        negotiate = NTLMAuthNegotiate()
        negotiate.fromString(nego_token_raw)

        host_format = NTLM_AUTH_format_host(negotiate)
        self.logger.debug("Starting NTLM-auth: %s", host_format)

        fqdn = self.server.server_config.ldap_fqdn
        if "." in fqdn:
            name, domain = fqdn.split(".", 1)
        else:
            name, domain = fqdn, ""

        ntlm_challenge = NTLM_AUTH_CreateChallenge(
            negotiate,
            name,
            domain,
            self.config.ntlm_challange,
            disable_ess=not self.config.ntlm_ess,
        )
        # return bind success with challenge message
        self.send(self.server.bind_result(req, matched_dn=ntlm_challenge.getData()))
        # raise LDAPTerminateSession

    def handle_NTLM_Auth(self, req: LDAPMessage, blob: bytes) -> None | bool:
        auth_message = NTLMAuthChallengeResponse()
        auth_message.fromString(blob)
        NTLM_report_auth(
            auth_token=auth_message,
            challenge=self.config.ntlm_challange,
            client=self.client_address,
            logger=self.logger,
            session=self.config,
        )
        self.send(
            self.server.bind_result(
                req,
                reason=self.server.server_config.ldap_error_code,
            )
        )
        raise LDAPTerminateSession

    def handle_bindRequest(
        self,
        message: LDAPMessage,
        bind_req: BindRequest,
    ) -> LDAPMessage | List[LDAPMessage] | None | bool:
        self.logger.debug(f"Got bind request from {self.client_host}")
        response = None
        bind_req = message["protocolOp"].getComponent()
        bind_name = str(bind_req["name"])
        bind_auth = bind_req["authentication"].getComponent()
        match bind_req["authentication"].getName().lower():
            case "simple":
                # we should allow simple binds so that clients can fetch
                # capabilities
                if not bind_name and not str(bind_auth):
                    response = self.server.bind_result(message)
                else:
                    response = self.server.bind_result(message, reason=0x01)
                    self.config.db.add_auth(
                        client=self.client_address,
                        credtype=_CLEARTEXT,
                        username=bind_name,
                        password=str(bind_auth),
                        logger=self.logger,
                    )

            case "sicilynegotiate":
                # NTLM sets the name of the bindrequest to NTLM
                self.mech_name = bind_name.lower()
                if self.mech_name == "ntlm":
                    return self.handle_NTLM_Negotiate(message, bytes(bind_auth))

            case "sicilyresponse":
                if self.mech_name == "ntlm":
                    return self.handle_NTLM_Auth(message, bytes(bind_auth))

            case "sasl":
                mech_name = str(bind_auth["mechanism"]).replace("-", "_")
                method = getattr(self, f"handle_sasl_{mech_name.upper()}", None)

                if method:
                    response = method(message, bind_auth)
                else:
                    response = self.server.bind_result(message, reason=0x01)

        self.send(response)

    # [RFC4178] https://datatracker.ietf.org/doc/html/rfc4178 4616]
    def handle_sasl_GSS_SPNEGO(self, message, bind_auth):
        # we expect this to be a NTLM message
        data = bytes(bind_auth["credentials"])
        if not data.startswith(b"NTLMSSP"):
            self.logger.debug(f"Unsupported SASL mechanism: {data.hex()}")
            return False

        # negotiate message will have message type 0x01
        if data[8] == 0x01:
            token = ntlm.NTLMAuthNegotiate()
            token.fromString(data)
            ntlm_challenge = NTLM_AUTH_CreateChallenge(
                token,
                *NTLM_split_fqdn(self.server.server_config.ldap_fqdn),
                challenge=self.config.ntlm_challange,
                disable_ess=not self.config.ntlm_ess,
            )
            return self.send(
                self.server.bind_result(
                    req=message,
                    reason=14,  # saslBindInProgress
                    sasl_credentials=ntlm_challenge.getData(),
                )
            )

        elif data[8] == 0x03:  # AUTH
            token = ntlm.NTLMAuthChallengeResponse()
            token.fromString(data)
            NTLM_report_auth(
                auth_token=token,
                challenge=self.config.ntlm_challange,
                client=self.client_address,
                logger=self.logger,
                session=self.config,
            )
            return self.send(
                self.server.bind_result(
                    req=message,
                    reason=self.server.server_config.ldap_error_code,
                )
            )
        raise LDAPTerminateSession  # terminate connection

    def handle_unbindRequest(
        self,
        message: LDAPMessage,
        unbind_req: UnbindRequest,
    ) -> bool:
        # terminate connection
        raise LDAPTerminateSession

    def handle_searchRequest(
        self,
        message: LDAPMessage,
        search_req: SearchRequest,
    ) -> List[LDAPMessage]:
        # handle capabilities
        search_req = message["protocolOp"].getComponent()
        search_filter = search_req["filter"]
        response = []
        if (
            search_filter.getName() == "present"
            and str(search_filter.getComponent()).lower() == "objectclass"
        ):
            attrs = list(map(lambda x: str(x).lower(), search_req["attributes"]))
            if "supportedcapabilities" in attrs:
                # only respond to supportedCapabilities
                response.append(self.server.list_capabilities(message))

            if "supportedsaslmechanisms" in attrs:
                # only respond to supportedSASLMechanisms
                response.append(self.server.list_sasl_mechs(message))

        response.append(self.server.search_done(message))
        self.send(response)

    def handle_data(self, data, transport) -> None:
        if self.server.server_config.ldap_timeout:
            transport.settimeout(self.server.server_config.ldap_timeout)

        self.mech_name = None

        while True:
            message = self.recv(8192)
            if not message:
                break

            func_name = f"handle_{message['protocolOp'].getName()}"
            method = getattr(self, func_name, None)
            if method is not None:
                try:
                    method(message, message["protocolOp"].getComponent())
                except LDAPTerminateSession:
                    break

    def recv(self, size: int) -> LDAPMessage | None:
        try:
            data = super().recv(8192)  # UDP returns same data again
        except TimeoutError:
            # close connection
            return None

        try:
            message, _ = BERDecoder.decode(data, asn1Spec=LDAPMessage())
        except Exception as e:
            self.logger.error(f"Failed to decode LDAP packet: {e}")
            return

        return message

    def send(self, data) -> None:
        # TODO: add debug logging
        if data is not None:
            if isinstance(data, list):
                data = b"".join([BEREncoder.encode(x) for x in data])
            else:
                data = BEREncoder.encode(data)
            return super().send(data)


class LDAPServerMixin:
    server_config: Any

    def list_capabilities(self, req: LDAPMessage) -> LDAPMessage:
        entry = self.search_entry(
            "supportedCapabilities",
            self.server_config.ldap_caps,
        )
        return self.new_message(req, entry)

    def list_sasl_mechs(self, req: LDAPMessage) -> LDAPMessage:
        entry = self.search_entry(
            "supportedSASLMechanisms",
            self.server_config.ldap_mech,
        )
        return self.new_message(req, entry)

    def search_done(self, req, result_code: int = 0x00) -> LDAPMessage:
        result = SearchResultDone()
        result["resultCode"] = 0x00  # SUCCESS
        result["matchedDN"] = ""
        result["diagnosticMessage"] = ""
        return self.new_message(req, result)

    def search_entry(self, entry_type: str, vals: List[str]) -> SearchResultEntry:
        entry = SearchResultEntry()
        entry["objectName"] = ""  # <root>

        attributes = PartialAttributeList()
        attrib = PartialAttribute()
        attrib["type"] = entry_type
        attrib["vals"].extend(vals)
        attributes.append(attrib)
        entry["attributes"] = attributes
        return entry

    def bind_result(
        self,
        req,
        reason: int = 0x00,
        matched_dn: str | bytes | None = None,
        sasl_credentials: bytes | None = None,
    ) -> LDAPMessage:
        bind = BindResponse()
        bind["resultCode"] = reason  # SUCCESS
        bind["matchedDN"] = matched_dn or ""
        bind["diagnosticMessage"] = ""
        if sasl_credentials:
            bind["serverSaslCreds"] = sasl_credentials
        return self.new_message(req, bind)

    def new_message(self, req, op) -> LDAPMessage:
        message = LDAPMessage()
        message["messageID"] = req["messageID"]
        message["protocolOp"].setComponentByType(op.getTagSet(), op)
        return message


class LDAPServer(ThreadingTCPServer, LDAPServerMixin):
    default_port = 389
    default_handler_class = LDAPHandler
    service_name = "LDAP"

    def __init__(
        self,
        config: SessionConfig,
        server_address: Tuple[str, int] | None = None,
        RequestHandlerClass: type | None = None,
        server_config: LDAPServerConfig | None = None,
    ) -> None:
        self.server_config = server_config
        super().__init__(config, server_address, RequestHandlerClass)

    def server_bind(self) -> None:
        if self.server_config.ldap_tls:
            cert_path = self.server_config.ldap_tls_cert
            key_path = self.server_config.ldap_tls_key
            self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.context.load_cert_chain(cert_path, key_path)
            # TODO: raise error
            if cert_path and key_path:
                self.socket = self.context.wrap_socket(self.socket, server_side=True)

        super().server_bind()


class CLDAPServer(ThreadingUDPServer, LDAPServerMixin):
    default_port = 389
    default_handler_class = LDAPHandler
    service_name = "CLDAP"

    def __init__(
        self,
        config: SessionConfig,
        server_address: Tuple[str, int] | None = None,
        RequestHandlerClass: type | None = None,
        server_config: LDAPServerConfig | None = None,
    ) -> None:
        self.server_config = server_config
        super().__init__(config, server_address, RequestHandlerClass)
