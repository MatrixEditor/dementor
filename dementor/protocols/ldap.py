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
# Supported Authentication Mechanisms (per MS-ADTS §5.1.1.1):
# - Simple Bind: Anonymous, unauthenticated, and name/password authentication
# - Sicily Protocol: Microsoft extension for NTLM authentication over LDAP
# - SASL Mechanisms:
#   - GSS-SPNEGO: SPNEGO negotiation (typically NTLM)
#   - DIGEST-MD5: Digest authentication
#   - PLAIN: Cleartext authentication
#   - NTLM: Direct NTLM (non-SPNEGO)

# References:
# - RFC 4511: Lightweight Directory Access Protocol (LDAP): The Protocol
# - RFC 4513: LDAP Authentication Methods and Security Mechanisms
# - RFC 2831: Using Digest Authentication as a SASL Mechanism
# - RFC 4178: SPNEGO Negotiation Mechanism
# - RFC 4616: The PLAIN SASL Mechanism
# - [MS-ADTS]: Active Directory Technical Specification
# - [MS-NLMP]: NT LAN Manager (NTLM) Authentication Protocol
import secrets

import os
import socket
import ssl
import time

from enum import Enum
from typing import TYPE_CHECKING, Any
from urllib.request import parse_http_list, parse_keqv_list


from caterpillar.py import BigEndian, uint32
from impacket import ntlm
from impacket.ldap.ldapasn1 import (
    BindRequest,
    BindResponse,
    ExtendedRequest,
    ExtendedResponse,
    LDAPMessage,
    LDAPString,
    PartialAttribute,
    PartialAttributeList,
    ResultCode,
    SearchRequest,
    SearchResultDone,
    SearchResultEntry,
    LDAPDN,
    UnbindRequest,
)
from impacket.ntlm import NTLMAuthChallengeResponse, NTLMAuthNegotiate, NTLMAuthChallenge
from pyasn1.codec.ber import decoder as BERDecoder
from pyasn1.codec.ber import encoder as BEREncoder
from pyasn1.error import PyAsn1Error
from pyasn1.type import univ, tag
from pyasn1.type.namedtype import NamedType, NamedTypes
from typing_extensions import override

from dementor.config.attr import (
    ATTR_CERT,
    ATTR_KEY,
    ATTR_TLS,
    SELFSIGNED_COMMON_ATTRS,
)
from dementor.config.session import SessionConfig
from dementor.config.toml import Attribute as A
from dementor.config.toml import TomlConfig
from dementor.config.tls import generate_self_signed_cert
from dementor.config.util import HostValue, HostFallbackValue
from dementor.db import CLEARTEXT, DIGEST_MD5
from dementor.loader import DEFAULT_ATTR, BaseProtocolModule
from dementor.log import hexdump
from dementor.log.logger import ProtocolLogger
from dementor.protocols.ntlm import (
    ATTR_NTLM_CHALLENGE,
    ATTR_NTLM_DISABLE_ESS,
    ATTR_NTLM_DISABLE_NTLMV2,
    ntlm_auth_create_challenge,
    ntlm_report_auth,
    ntlm_split_fqdn,
    ntlm_build_challenge_message,
)
from dementor.protocols.spnego import SPNEGO_NTLMSSP_MECH, SPNEGONegotiator
from dementor.servers import (
    BaseProtoHandler,
    BaseServerThread,
    ServerThread,
    ThreadingTCPServer,
    ThreadingUDPServer,
)

if TYPE_CHECKING:
    from tempfile import TemporaryDirectory
    from collections.abc import Callable


LDAP_CAPABILITIES: list[str] = [
    # MS-ADTS §3.1.1.3.3.1: LDAP_CAP_ACTIVE_DIRECTORY_OID
    # Indicates the server is an Active Directory Domain Controller.
    "1.2.840.113556.1.4.800",
    # MS-ADTS §3.1.1.3.3.2: LDAP_CAP_ACTIVE_DIRECTORY_LDAP_INTEG_OID
    # Indicates support for LDAP integrity and privacy via SASL signing/sealing.
    "1.2.840.113556.1.4.1791",
    # MS-ADTS §3.1.1.3.3.3: LDAP_CAP_ACTIVE_DIRECTORY_V51_OID
    # Indicates Windows Server 2003 or later AD capabilities.
    "1.2.840.113556.1.4.1670",
]

LDAP_DEFAULT_MECH: list[str] = [
    # RFC 4178: SPNEGO (Simple and Protected GSS-API Negotiation Mechanism)
    "GSS-SPNEGO",
    # RFC 2831: DIGEST-MD5 SASL mechanism (DEPRECATED per RFC 6331)
    "DIGEST-MD5",
    # RFC 4616: PLAIN SASL mechanism
    "PLAIN",
    # Direct NTLM (non-SPNEGO wrapped)
    "NTLM",
]

LDAP_CHANNEL_BINDING_TYPES: list[str] = [
    "tls-unique",
    "tls-server-end-point",
]

LDAP_SASL_QOP_OPTIONS: list[str] = [
    "auth",
    "auth-int",
    "auth-conf",
]

DIGEST_MD5_REALM: str = "dementor"
DIGEST_MD5_QOP: str = "auth"
DIGEST_MD5_ALGORITHM: str = "md5-sess"
DIGEST_MD5_CHARSET: str = "utf-8"
DIGEST_MD5_MAXBUF: str = "65536"

LDAP_SUCCESS: int = 0x00
LDAP_OPERATIONS_ERROR: int = 0x01
LDAP_PROTOCOL_ERROR: int = 0x02
LDAP_AUTH_METHOD_NOT_SUPPORTED: int = 0x07
LDAP_UNSUPPORTED_LDAP_VERSION: int = 0x0C
LDAP_CONFIDENTIALITY_REQUIRED: int = 0x0D
LDAP_SASL_BIND_IN_PROGRESS: int = 0x0E
LDAP_UNWILLING_TO_PERFORM: int = 0x10
LDAP_INVALID_CREDENTIALS: int = 0x31

LDAP_STARTTLS_OID: str = "1.3.6.1.4.1.1466.20037"
DEFAULT_DOMAIN: str = "example.com"


class LDAPTerminateSession(Exception):
    """Raised internally to terminate an LDAP session after the final response is sent."""


class LDAPServerConfig(TomlConfig):
    _section_ = "LDAP"
    _fields_ = [
        # Network configuration
        A("ldap_port", "Port"),
        A("ldap_udp", "Connectionless", False),
        # Server capabilities
        A("ldap_caps", "Capabilities", LDAP_CAPABILITIES),
        A("ldap_mech", "SASLMechanisms", LDAP_DEFAULT_MECH),
        # Connection settings
        A("ldap_timeout", "Timeout", 0),
        A(
            "ldap_fqdn",
            "Host",
            None,
            section_local=False,
            factory=HostFallbackValue(HostValue.HOST, "DEMENTOR"),
        ),
        # TLS configuration
        ATTR_TLS,
        ATTR_KEY,
        ATTR_CERT,
        *SELFSIGNED_COMMON_ATTRS,
        # REVISIT: Security options
        A("ldap_channel_binding", "ChannelBinding", False),
        A("ldap_require_signing", "RequireSigning", False),
        A("ldap_require_sealing", "RequireSealing", False),
        A(
            "ldap_channel_binding_types",
            "ChannelBindingTypes",
            LDAP_CHANNEL_BINDING_TYPES,
        ),
        A("ldap_sasl_qop_options", "SASLQoPOptions", LDAP_SASL_QOP_OPTIONS),
        # Error handling
        A("ldap_error_code", "ErrorCode", "unwillingToPerform"),
        # NTLM configuration
        ATTR_NTLM_CHALLENGE,
        ATTR_NTLM_DISABLE_ESS,
        ATTR_NTLM_DISABLE_NTLMV2,
    ]

    if TYPE_CHECKING:
        ldap_port: int
        ldap_udp: bool
        ldap_caps: list[str]
        ldap_mech: list[str]
        ldap_timeout: int
        ldap_fqdn: str
        use_ssl: bool
        keyfile: str | None
        certfile: str | None
        ldap_error_code: int
        self_signed: bool
        cert_cn: str
        cert_org: str
        cert_country: str
        cert_state: str
        cert_locality: str
        cert_validity_days: int
        ldap_channel_binding: bool
        ldap_require_signing: bool
        ldap_require_sealing: bool
        ldap_channel_binding_types: list[str]
        ldap_sasl_qop_options: list[str]
        ntlm_challenge: bytes
        ntlm_disable_ess: bool
        ntlm_disable_ntlmv2: bool

    def set_ldap_error_code(self, value: str | int) -> None:
        if isinstance(value, int):
            self.ldap_error_code = value
        else:
            self.ldap_error_code = ResultCode.namedValues[str(value)]

    def service_name(self) -> str:
        return ("C" if self.ldap_udp else "") + "LDAP" + ("S" if self.use_ssl else "")

    def _parse_domain_to_dn(self, domain: str) -> str:
        if not domain:
            return ""
        parts = domain.split(".")
        return ",".join(f"DC={part}" for part in parts if part)


class SASLAuthState(Enum):
    INITIAL = "initial"
    CHALLENGE_SENT = "challenge_sent"
    RESPONSE_RECEIVED = "response_received"
    COMPLETE = "complete"
    FAILED = "failed"


class SASLMechanismState:
    def __init__(self, mechanism: str) -> None:
        self.mechanism: str = mechanism
        self.state: SASLAuthState = SASLAuthState.INITIAL
        self.challenge_data: bytes | None = None
        self.response_data: bytes | None = None
        self.context: dict[str, Any] = {}

    def transition(self, new_state: SASLAuthState) -> None:
        valid_transitions: dict[SASLAuthState, list[SASLAuthState]] = {
            SASLAuthState.INITIAL: [SASLAuthState.CHALLENGE_SENT, SASLAuthState.FAILED],
            SASLAuthState.CHALLENGE_SENT: [
                SASLAuthState.RESPONSE_RECEIVED,
                SASLAuthState.FAILED,
            ],
            SASLAuthState.RESPONSE_RECEIVED: [
                SASLAuthState.COMPLETE,
                SASLAuthState.CHALLENGE_SENT,  # Multi-step mechanisms (e.g., NTLM)
                SASLAuthState.FAILED,
            ],
            SASLAuthState.COMPLETE: [],  # Terminal state
            SASLAuthState.FAILED: [],  # Terminal state
        }

        if new_state not in valid_transitions.get(self.state, []):
            raise ValueError(
                f"Invalid state transition for {self.mechanism}: "
                + f"{self.state.value} -> {new_state.value}"
            )

        self.state = new_state


class AuthorizationState(Enum):
    ANONYMOUS = "anonymous"
    AUTHENTICATED = "authenticated"
    SASL_IN_PROGRESS = "sasl_in_progress"


class SessionAuthState:
    def __init__(self) -> None:
        self.state: AuthorizationState = AuthorizationState.ANONYMOUS
        self.authenticated_identity: str | None = None
        self.authentication_method: str | None = None
        self.tls_active: bool = False
        self.sasl_active: bool = False
        self.channel_binding_active: bool = False
        self.channel_binding_type: str | None = None
        self.signing_active: bool = False
        self.sealing_active: bool = False
        self.negotiated_qop: str | None = None
        self.created_at: float = time.time()

    def authenticate(self, identity: str, method: str) -> None:
        self.state = AuthorizationState.AUTHENTICATED
        self.authenticated_identity = identity
        self.authentication_method = method

    def reset_to_anonymous(self) -> None:
        self.state = AuthorizationState.ANONYMOUS
        self.authenticated_identity = None
        self.authentication_method = None

    def enable_tls(self) -> None:
        self.tls_active = True

    def enable_sasl(self) -> None:
        self.sasl_active = True

    def enable_channel_binding(self, binding_type: str) -> None:
        self.channel_binding_active = True
        self.channel_binding_type = binding_type

    def enable_signing(self) -> None:
        self.signing_active = True

    def enable_sealing(self) -> None:
        self.sealing_active = True

    def apply_negotiated_qop(self, qop: str) -> None:
        self.negotiated_qop = qop
        if qop == "auth-int":
            self.enable_signing()
        elif qop == "auth-conf":
            self.enable_signing()
            self.enable_sealing()

    def is_authenticated(self) -> bool:
        return self.state == AuthorizationState.AUTHENTICATED


class LDAPServerMixin:
    """Mixin class providing LDAP server response utilities."""

    server_config: LDAPServerConfig
    context: ssl.SSLContext | None

    def search_done(
        self, req: LDAPMessage, result_code: int = LDAP_SUCCESS
    ) -> LDAPMessage:
        """Generate SearchResultDone message."""
        result = SearchResultDone()
        result["resultCode"] = result_code
        result["matchedDN"] = ""
        result["diagnosticMessage"] = ""
        return self.new_message(req, result)

    def create_root_dse_entry(self, requested_attrs: list[str]) -> dict[str, list[str]]:
        attributes = {}

        def add_if_requested(attr_name: str, values: list[str]) -> None:
            if (
                not requested_attrs
                or attr_name.lower() in requested_attrs
                or "*" in requested_attrs
            ):
                attributes[attr_name] = values

        add_if_requested("supportedCapabilities", self.server_config.ldap_caps)

        # Ensure mechanisms are returned in the format expected by Windows clients
        mechs = self.server_config.ldap_mech.copy()
        if "SASL" in mechs:
            mechs.remove("SASL")
        add_if_requested("supportedSASLMechanisms", mechs)

        add_if_requested(
            "supportedChannelBindingTypes", self.server_config.ldap_channel_binding_types
        )
        add_if_requested(
            "supportedSASLQoPOptions", self.server_config.ldap_sasl_qop_options
        )

        dns_hostname, dns_domain = ntlm_split_fqdn(self.server_config.ldap_fqdn)
        add_if_requested("dnsHostName", [dns_hostname])

        naming_context = self.server_config._parse_domain_to_dn(dns_domain)
        add_if_requested("defaultNamingContext", [naming_context])

        config_context = f"CN=Configuration,{naming_context}"
        add_if_requested("configurationNamingContext", [config_context])

        domain_labels = dns_domain.split(".")
        root_domain = (
            ".".join(domain_labels[-2:]) if len(domain_labels) >= 2 else dns_domain
        )
        root_context = self.server_config._parse_domain_to_dn(root_domain)
        add_if_requested("rootDomainNamingContext", [root_context])

        add_if_requested("supportedLDAPVersion", ["3", "2"])
        add_if_requested("namingContexts", [naming_context])
        return attributes

    def search_entry_list(self, entries: dict[str, list[str]]) -> SearchResultEntry:
        search_entry = SearchResultEntry()
        search_entry["objectName"] = ""

        attributes = PartialAttributeList()
        for entry_type, values in entries.items():
            attrib = PartialAttribute()
            attrib["type"] = entry_type
            attrib["vals"].extend(values)
            attributes.append(attrib)

        search_entry["attributes"] = attributes
        return search_entry

    def bind_result(
        self,
        req: LDAPMessage,
        reason: int = LDAP_SUCCESS,
        matched_dn: str | bytes | None = None,
        sasl_credentials: bytes | None = None,
    ) -> LDAPMessage:
        bind = BindResponse()
        bind["resultCode"] = reason
        bind["matchedDN"] = matched_dn or ""
        bind["diagnosticMessage"] = ""
        if sasl_credentials:
            bind["serverSaslCreds"] = sasl_credentials
        return self.new_message(req, bind)

    def extended_result(
        self,
        req: LDAPMessage,
        reason: int = LDAP_SUCCESS,
        response_name: str | None = None,
        response_value: bytes | None = None,
    ) -> LDAPMessage:
        extended = ExtendedResponse()
        extended["resultCode"] = reason
        extended["matchedDN"] = ""
        extended["diagnosticMessage"] = ""
        if response_name:
            extended["responseName"] = response_name
        if response_value:
            extended["responseValue"] = response_value
        return self.new_message(req, extended)

    def new_message(self, req: LDAPMessage, op: Any) -> LDAPMessage:
        message = LDAPMessage()
        message["messageID"] = req["messageID"]
        message["protocolOp"].setComponentByType(op.getTagSet(), op)
        return message


ldap_logger = ProtocolLogger(
    extra={
        "protocol": "LDAP",
        "protocol_color": "violet",
    }
)


class LDAPServer(ThreadingTCPServer, LDAPServerMixin):
    """TCP-based LDAP server implementation."""

    default_port: int = 389
    service_name: str = "LDAP"
    default_handler_class: type[BaseProtoHandler] | None = None

    def __init__(
        self,
        config: SessionConfig,
        server_address: tuple[str, int] | None = None,
        RequestHandlerClass: type[BaseProtoHandler] | None = None,
        server_config: LDAPServerConfig | None = None,
    ) -> None:
        if not server_config:
            server_config = config.ldap_config[0]

        self.server_config: LDAPServerConfig = server_config
        self._generated_temp_cert: bool = False
        self._temp_dir: TemporaryDirectory[str] | None = None
        super().__init__(config, server_address, RequestHandlerClass)

    def generate_self_signed_cert(self) -> None:
        ldap_logger.display(
            "Generating self-signed certificate for LDAP server",
            port=self.server_config.ldap_port,
            protocol=self.server_config.service_name(),
            host=" ",
        )

        cert_path, key_path, temp_dir = generate_self_signed_cert(
            cn=self.server_config.cert_cn,
            org=self.server_config.cert_org,
            country=self.server_config.cert_country,
            state=self.server_config.cert_state,
            locality=self.server_config.cert_locality,
            validity_days=self.server_config.cert_validity_days,
        )

        self.server_config.certfile = cert_path
        self.server_config.keyfile = key_path
        self._temp_dir = temp_dir
        self._generated_temp_cert = True

        ldap_logger.debug(
            f"Self-signed certificate generated: CN={self.server_config.cert_cn}, "
            f"validity={self.server_config.cert_validity_days} days"
        )

    def setup_ssl_context(self, transport: socket.socket | None = None) -> None:
        cert_path = self.server_config.certfile
        key_path = self.server_config.keyfile
        transport = transport or self.socket
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        if (
            not cert_path
            or not key_path
            or not os.path.exists(cert_path)
            or not os.path.exists(key_path)
        ):
            if not self.server_config.self_signed:
                ldap_logger.error(
                    "LDAP certificate or key not found and self-signed generation is disabled. "
                    + "Set SelfSigned=true in [Globals] or [LDAP] section to enable automatic generation."
                )
                return

            ldap_logger.debug(
                "Certificates not found - generating self-signed certificate using global config"
            )
            self.generate_self_signed_cert()
            cert_path = self.server_config.certfile
            key_path = self.server_config.keyfile

        self.context.load_cert_chain(cert_path, key_path)
        self.context.verify_mode = ssl.VerifyMode.CERT_NONE
        self.socket = self.context.wrap_socket(transport, server_side=True)

        ldap_logger.debug(f"TLS context initialized with certificate: {cert_path}")

    def server_bind(self) -> None:
        if self.server_config.use_ssl:
            self.setup_ssl_context()

        super().server_bind()

    def server_close(self) -> None:
        if self._generated_temp_cert and self._temp_dir:
            self._temp_dir.cleanup()
            self._generated_temp_cert = False
            self._temp_dir = None
        super().server_close()


class CLDAPServer(ThreadingUDPServer, LDAPServerMixin):
    """UDP-based CLDAP (Connectionless LDAP) server implementation."""

    default_port: int = 389
    service_name: str = "CLDAP"
    default_handler_class: type[BaseProtoHandler] | None = None

    def __init__(
        self,
        config: SessionConfig,
        server_address: tuple[str, int] | None = None,
        RequestHandlerClass: type[BaseProtoHandler] | None = None,
        server_config: LDAPServerConfig | None = None,
    ) -> None:
        self.server_config: LDAPServerConfig = server_config  # type: ignore[assignment]
        super().__init__(config, server_address, RequestHandlerClass)


# Sicily Bind Response (MS-ADTS §5.1.1.1.3)
class SicilyBindResponse(univ.Sequence):
    """SicilyBindResponse structure for package discovery."""

    tagSet = univ.Sequence.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 1)
    )
    componentType = NamedTypes(
        NamedType("resultCode", ResultCode()),
        NamedType("serverCreds", LDAPDN()),
        NamedType("diagnosticMessage", LDAPString()),
    )


class LDAPHandler(BaseProtoHandler["LDAPServer"]):
    """Base handler for LDAP protocol messages."""

    server: "LDAPServer"

    def __init__(
        self,
        config: SessionConfig,
        request: socket.socket | tuple[bytes, socket.socket],
        client_address: tuple[str, int],
        server: LDAPServerMixin,
    ) -> None:
        self.spnego_negotiator = SPNEGONegotiator(
            supported_mechs=[SPNEGO_NTLMSSP_MECH],
            mech_handlers={
                SPNEGO_NTLMSSP_MECH: self._handle_spnego_ntlm_mech,
            },
        )
        self.sasl_state: SASLMechanismState | None = None
        self.auth_state: SessionAuthState = SessionAuthState()
        self._ntlm_challenge: NTLMAuthChallenge | None = None
        self.mech_name: str | None = None
        self.digest_md5_state: dict[str, str] | None = None
        super().__init__(config, request, client_address, server)

    def proto_logger(self) -> ProtocolLogger:
        port: int = self.server.server_config.ldap_port
        use_ssl: bool = self.server.server_config.use_ssl
        return ProtocolLogger(
            extra={
                "protocol": "LDAP" + ("S" if use_ssl else ""),
                "protocol_color": "violet",
                "host": self.client_host,
                "port": port,
            }
        )

    def _is_encrypted_message(self, data: bytes) -> bool:
        if not (self.auth_state.signing_active or self.auth_state.sealing_active):
            return False

        if len(data) < 4:
            return False

        try:
            length = uint32.from_bytes(data[:4], order=BigEndian)
            return data[0] != 0x30 and length == len(data) - 4
        except Exception:
            return False

    @override
    def recv(self, size: int) -> LDAPMessage | None:  # type: ignore[override]  # ty:ignore[invalid-method-override]
        try:
            data = super().recv(8192)
            if not data:
                return None
        except (TimeoutError, BlockingIOError) as e:
            self.logger.debug(f"Receive error (timeout/empty): {e}")
            return None

        if self._is_encrypted_message(data):
            self.logger.warning(
                "Received encrypted SASL message - discarding and terminating connection"
            )
            raise LDAPTerminateSession

        try:
            message, _ = BERDecoder.decode(data, asn1Spec=LDAPMessage())
        except Exception as e:
            self.logger.fail("Received invalid LDAP - terminating connection...")
            self.logger.debug(
                f"Invalid LDAP packet: {e.__class__!s}\n"
                f"{hexdump.hexdump(data) if data else '<no-data>'}"
            )
            return None
        else:
            return message

    @override
    def send(self, data: LDAPMessage | list[LDAPMessage] | None) -> None:  # type: ignore[override]  # ty:ignore[invalid-method-override]
        if data is None:
            return

        if isinstance(data, list):
            encoded_messages: list[bytes] = []
            for msg in data:
                encoded = BEREncoder.encode(msg)
                encoded_messages.append(encoded)
                self.logger.debug(
                    f"Encoded message type: {msg['protocolOp'].getName()}, size: {len(encoded)}"
                )
            final_data = b"".join(encoded_messages)
            self.logger.debug(
                f"Sending {len(data)} LDAP messages, total size: {len(final_data)}"
            )
        else:
            final_data = BEREncoder.encode(data)
            self.logger.debug(
                f"Sending single LDAP message, type: {data['protocolOp'].getName()}, "
                f"size: {len(final_data)}"
            )

        super().send(final_data)

    @override
    def handle_data(self, data: bytes | None, transport: socket.socket) -> None:
        """Main message processing loop for LDAP connections."""
        if self.server.server_config.ldap_timeout:
            transport.settimeout(self.server.server_config.ldap_timeout)
            self.logger.debug(
                f"Set connection timeout to {self.server.server_config.ldap_timeout} seconds"
            )

        while True:
            message = self.recv(8192)
            if not message:
                self.logger.debug("No more messages or connection closed")
                break

            func_name = f"handle_{message['protocolOp'].getName()}"
            self.logger.debug(f"Dispatching to handler: {func_name}")

            method: Callable[[LDAPMessage, Any], Any] | None = getattr(
                self, func_name, None
            )
            if method is not None:
                try:
                    _ = method(message, message["protocolOp"].getComponent())
                except LDAPTerminateSession:
                    self.logger.debug("Handler requested session termination")
                    break
                except Exception as e:
                    self.logger.fail(f"Handler {func_name} failed: {e}")
                    self.logger.exception("Error info:")
                    error_response = self.server.bind_result(
                        message, reason=LDAP_OPERATIONS_ERROR
                    )
                    self.send(error_response)
            else:
                self.logger.debug(f"No handler found for operation: {func_name}")
                error_response = self.server.bind_result(
                    message, reason=LDAP_UNWILLING_TO_PERFORM
                )
                self.send(error_response)

    def _handle_spnego_ntlm_mech(
        self, mech_token: bytes | None, is_initiate: bool
    ) -> tuple[bytes | None, bool]:
        """Handle NTLM mechanism within SPNEGO."""
        if is_initiate:
            if mech_token:
                token = ntlm.NTLMAuthNegotiate()
                token.fromString(mech_token)
            else:
                token = ntlm.NTLMAuthNegotiate()

            host = HostValue(self.server.server_config.ldap_fqdn)
            ntlm_challenge = ntlm_build_challenge_message(
                token,
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
                log=self.logger,
            )
            return ntlm_challenge.getData(), False

        if mech_token:
            token = ntlm.NTLMAuthChallengeResponse()
            token.fromString(mech_token)
            ntlm_report_auth(
                auth_token=token,
                challenge=self.server.server_config.ntlm_challenge,
                client=self.client_address,
                logger=self.logger,
                session=self.config,
            )
        return None, True

    def _normalize_sasl_mechanism(self, mech_name: str) -> str:
        return mech_name.upper().replace("-", "_").strip()

    def _parse_cleartext_user(
        self, bind_name: str
    ) -> tuple[str, str | None, dict[str, str]]:
        extras: dict[str, str] = {}

        if "\\" in bind_name and not bind_name.lower().startswith("cn="):
            domain, user = bind_name.split("\\", 1)
            return user, domain, extras

        if (
            "@" in bind_name
            and "\\" not in bind_name
            and "=" not in bind_name
            and "," not in bind_name
        ):
            user, domain = bind_name.rsplit("@", 1)
            return user, domain, extras

        if "=" in bind_name and "," in bind_name:
            extras["dn"] = bind_name
            for part in bind_name.split(","):
                if "=" not in part:
                    continue
                key, val = part.split("=", 1)
                key = key.strip().lower()
                val = val.strip()
                if key in ("cn", "uid", "samaccountname", "user", "name"):
                    return val, None, extras
            return bind_name, None, extras

        # Simple username with no domain
        return bind_name, None, extras

    def handle_bindRequest(
        self, message: LDAPMessage, bind_req: BindRequest
    ) -> LDAPMessage | None:
        self.logger.debug(f"LDAP Bind Request from {self.client_address}")
        self.logger.debug(f"Bind message ID: {message['messageID']}")

        bind_req = message["protocolOp"].getComponent()
        version = int(bind_req["version"])
        bind_name = str(bind_req["name"])
        bind_auth = bind_req["authentication"].getComponent()

        self.logger.debug(f"Bind version: {version}, name: {bind_name!r}")
        self.logger.debug(f"Authentication type: {bind_req['authentication'].getName()}")

        if version != 3:
            self.logger.debug(f"Unsupported LDAP version: {version}")
            return self.server.bind_result(message, reason=LDAP_UNSUPPORTED_LDAP_VERSION)

        auth_type = bind_req["authentication"].getName().lower()

        if auth_type == "sasl":
            mech_name_raw = str(bind_auth["mechanism"])
            mech_name = self._normalize_sasl_mechanism(mech_name_raw)
            if self.sasl_state and self.sasl_state.mechanism != mech_name:
                self.logger.debug(
                    f"SASL mechanism changed from {self.sasl_state.mechanism} to {mech_name} - resetting state"
                )
                self.sasl_state = None
                self.auth_state.reset_to_anonymous()
        elif self.sasl_state:
            self.logger.debug(
                "Non-SASL bind received while SASL state active - resetting state"
            )
            self.sasl_state = None
            self.auth_state.reset_to_anonymous()
        else:
            self.auth_state.reset_to_anonymous()

        response: LDAPMessage | list[LDAPMessage] | None = None

        match auth_type:
            case "simple":
                response = self._handle_simple_bind(message, bind_name, str(bind_auth))
            case "sicilynegotiate":
                return self._handle_sicily_negotiate(message, bind_name, bytes(bind_auth))
            case "sicilyresponse":
                return self._handle_sicily_response(message, bytes(bind_auth))
            case "sicilypackagediscovery":
                response = self._handle_sicily_package_discovery(message)
            case "sasl":
                response = self._handle_sasl_bind(message, bind_auth)

        if response:
            result_code = (
                response["protocolOp"].getComponent()["resultCode"]
                if not isinstance(response, list)
                else response[0]["protocolOp"].getComponent()["resultCode"]
            )
            self.logger.debug(f"Sending bind response with result code: {result_code}")
            self.send(response)

        return None

    def _handle_simple_bind(
        self, message: LDAPMessage, bind_name: str, bind_password: str
    ) -> LDAPMessage:
        self.logger.debug("Processing simple authentication")

        if not bind_name and not bind_password:
            self.logger.debug("Anonymous bind request")
            return self.server.bind_result(message)

        if bind_name and not bind_password:
            self.logger.debug(f"Unauthenticated bind for DN: {bind_name}")
            return self.server.bind_result(message)

        self.logger.debug(
            f"Simple bind credentials: DN={bind_name}, password length={len(bind_password)}"
        )

        username, domain, extras = self._parse_cleartext_user(bind_name)
        self.config.db.add_auth(
            client=self.client_address,
            credtype=CLEARTEXT,
            username=username,
            password=bind_password,
            domain=domain,
            logger=self.logger,
            extras=extras,
        )

        if (
            self.server.server_config.ldap_require_signing
            or self.server.server_config.ldap_require_sealing
        ) and not self.auth_state.tls_active:
            self.logger.debug(
                "Simple bind rejected: signing/sealing required but TLS not active"
            )
            response = self.server.bind_result(
                message, reason=LDAP_CONFIDENTIALITY_REQUIRED
            )
            self.send(response)
            raise LDAPTerminateSession

        self.auth_state.authenticate(bind_name, "simple")
        response = self.server.bind_result(
            message, reason=self.server.server_config.ldap_error_code
        )
        self.send(response)
        raise LDAPTerminateSession

    def _handle_sicily_negotiate(
        self, message: LDAPMessage, bind_name: str, nego_token_raw: bytes
    ) -> None:
        self.logger.debug("Processing Sicily negotiate (NTLM)")

        # Normalize mechanism name - empty string means NTLM
        self.mech_name = bind_name.lower().strip() if bind_name else "ntlm"

        self.logger.debug(f"Sicily mechanism: {self.mech_name!r}")
        if self.mech_name in ("ntlm", ""):
            negotiate = NTLMAuthNegotiate()
            negotiate.fromString(nego_token_raw)

            fqdn = self.server.server_config.ldap_fqdn
            ntlm_challenge = ntlm_auth_create_challenge(
                negotiate,
                *ntlm_split_fqdn(fqdn),
                challenge=self.server.server_config.ntlm_challenge,
                disable_ess=self.server.server_config.ntlm_disable_ess,
                disable_ntlmv2=self.server.server_config.ntlm_disable_ntlmv2,
            )

            self.logger.debug(
                f"Sicily NTLM challenge generated, length: {len(ntlm_challenge.getData())}"
            )
            self.send(
                self.server.bind_result(message, matched_dn=ntlm_challenge.getData())
            )
            return

        self.logger.debug(f"Unsupported Sicily mechanism: {self.mech_name}")
        self.send(self.server.bind_result(message, reason=LDAP_AUTH_METHOD_NOT_SUPPORTED))

    def _handle_sicily_response(self, message: LDAPMessage, blob: bytes) -> None:
        self.logger.debug("Processing Sicily response (NTLM)")
        if self.mech_name == "ntlm":
            self.logger.debug("NTLM authenticate phase")
            auth_message = NTLMAuthChallengeResponse()
            auth_message.fromString(blob)
            ntlm_report_auth(
                auth_token=auth_message,
                challenge=self.server.server_config.ntlm_challenge,
                client=self.client_address,
                logger=self.logger,
                session=self.config,
                negotiate_fields=getattr(self, "negotiate_fields", None),
            )
            self.send(
                self.server.bind_result(
                    message,
                    reason=self.server.server_config.ldap_error_code,
                )
            )
            raise LDAPTerminateSession

    def _handle_sicily_package_discovery(self, message: LDAPMessage) -> LDAPMessage:
        self.logger.debug("Sicily package discovery: Returning supported packages (NTLM)")

        sicily_response = SicilyBindResponse()
        sicily_response["resultCode"] = 0

        sicily_response["serverCreds"] = b"NTLM"
        sicily_response["diagnosticMessage"] = b""
        return self.server.new_message(message, sicily_response)

    def _handle_sasl_bind(
        self, message: LDAPMessage, bind_auth: Any
    ) -> LDAPMessage | None:
        mech_name_raw = str(bind_auth["mechanism"])
        mech_name = self._normalize_sasl_mechanism(mech_name_raw)

        self.logger.debug(
            f"Processing SASL mechanism: {mech_name_raw!r} (normalized: {mech_name})"
        )
        self.logger.debug(
            f"Current SASL state: {self.sasl_state.state.value if self.sasl_state else 'None'}"
        )
        self.logger.debug(f"Current auth state: {self.auth_state.state.value}")
        self.logger.debug(f"TLS active: {self.auth_state.tls_active}")

        if self.sasl_state:
            if self.sasl_state.mechanism != mech_name:
                self.logger.debug(
                    f"SASL mechanism mismatch: expected {self.sasl_state.mechanism}, got {mech_name}"
                )
                self.sasl_state.transition(SASLAuthState.FAILED)
                return self.server.bind_result(message, reason=LDAP_OPERATIONS_ERROR)

            if self.sasl_state.state == SASLAuthState.CHALLENGE_SENT:
                self.logger.debug(f"SASL {mech_name}: Processing response to challenge")
                self.sasl_state.response_data = bytes(bind_auth["credentials"])
                self.sasl_state.transition(SASLAuthState.RESPONSE_RECEIVED)

                method = getattr(self, f"_handle_sasl_{mech_name.upper()}", None)
                if method:
                    return method(message, bind_auth)

                self.logger.debug(f"Unsupported SASL mechanism: {mech_name}")
                return self.server.bind_result(message, reason=LDAP_OPERATIONS_ERROR)

            self.logger.debug(
                f"SASL {mech_name}: Unexpected state {self.sasl_state.state.value}"
            )
            return self.server.bind_result(message, reason=LDAP_OPERATIONS_ERROR)

        self.logger.debug(f"SASL {mech_name}: Starting new negotiation")
        self.sasl_state = SASLMechanismState(mech_name)

        method = getattr(self, f"_handle_sasl_{mech_name.upper()}", None)
        if method:
            self.logger.debug(f"Dispatching to handler: _handle_sasl_{mech_name.upper()}")
            response = method(message, bind_auth)
            self.sasl_state.transition(SASLAuthState.CHALLENGE_SENT)
            return response

        self.logger.debug(f"Unsupported SASL mechanism: {mech_name}")
        self.sasl_state.transition(SASLAuthState.FAILED)
        return self.server.bind_result(message, reason=LDAP_OPERATIONS_ERROR)

    def handle_searchRequest(
        self, message: LDAPMessage, search_req: SearchRequest
    ) -> list[LDAPMessage]:
        self.logger.debug(f"LDAP Search Request from {self.client_address}")
        self.logger.debug(f"Search message ID: {message['messageID']}")

        search_req = message["protocolOp"].getComponent()
        base_dn = str(search_req["baseObject"])
        scope = int(search_req["scope"])
        filter_obj = search_req["filter"]
        attributes = [str(attr) for attr in search_req["attributes"]]

        self.logger.debug(
            f"Search base: {base_dn!r}, scope: {scope}, filter: {filter_obj.getName()}"
        )
        self.logger.debug(f"Requested attributes: {attributes}")

        if scope not in (0, 1, 2):
            self.logger.debug(f"Invalid search scope: {scope}")
            error_result = self.server.search_done(message, LDAP_PROTOCOL_ERROR)
            self.send(error_result)
            return [error_result]

        response: list[LDAPMessage] = []

        if (
            filter_obj.getName() == "present"
            and str(filter_obj.getComponent()).lower() == "objectclass"
        ):
            if base_dn == "":
                self.logger.debug("Processing root DSE query")
                req_attrs = [attr.lower() for attr in attributes]

                # Create single consolidated entry instead of multiple entries
                root_dse = self.server.create_root_dse_entry(req_attrs)
                search_entry = self.server.search_entry_list(root_dse)
                response.append(self.server.new_message(message, search_entry))

                self.logger.debug(
                    f"Root DSE entry created with {len(root_dse)} attributes"
                )

            else:
                self.logger.debug(f"Unsupported query base: {base_dn}")
        else:
            self.logger.debug(
                "Search query not supported (only present filter on objectClass implemented)"
            )

        response.append(self.server.search_done(message))
        self.logger.debug(f"Sending {len(response)} search response messages")
        self.send(response)
        return response

    def handle_extendedReq(
        self, message: LDAPMessage, extended_req: ExtendedRequest
    ) -> None:
        self.logger.debug(f"LDAP Extended Request from {self.client_address}")
        self.logger.debug(f"Extended message ID: {message['messageID']}")

        req_oid = str(extended_req["requestName"])
        req_value = extended_req["requestValue"]
        if req_value.hasValue():
            req_value = bytes(req_value)
            self.logger.debug(f"Extended OID: {req_oid}, value length: {len(req_value)}")
        else:
            self.logger.debug(f"Extended OID: {req_oid}, no value")

        if req_oid == LDAP_STARTTLS_OID:
            # Handle StartTLS Extended Operation per RFC 4513 §3.
            # StartTLS upgrades an existing LDAP connection to use TLS encryption.
            #
            # Protocol flow (RFC 4513 §3.1):
            #   1. Client sends StartTLS extended request
            #   2. Server sends success response
            #   3. Client and server perform TLS handshake
            #   4. Connection is now encrypted, authentication can proceed
            #
            # Restrictions (RFC 4513 §3.1.1):
            #   - MUST NOT be used if TLS is already active
            #   - MUST NOT be used during SASL negotiation
            #   - MUST NOT be used after successful bind (some implementations)
            #
            # Per RFC 5929: After StartTLS, channel binding can bind SASL auth
            # to the TLS channel, preventing relay attacks.
            self.logger.debug("Processing StartTLS extended operation")

            # RFC 4513 §3.1.1: StartTLS MUST NOT be used if TLS is already active
            if hasattr(self.request, "context") and self.request.context:
                self.logger.debug(
                    "StartTLS: TLS already active - rejecting per RFC 4513 §3.1.1"
                )
                response = self.server.extended_result(
                    message, reason=LDAP_OPERATIONS_ERROR
                )
            # RFC 4513 §3.1.2: StartTLS MUST NOT be used during SASL negotiation
            elif (
                self.sasl_state and self.sasl_state.state == SASLAuthState.CHALLENGE_SENT
            ):
                self.logger.debug(
                    f"StartTLS: SASL {self.sasl_state.mechanism} negotiation in progress - rejecting"
                )
                response = self.server.extended_result(
                    message, reason=LDAP_OPERATIONS_ERROR
                )
            else:
                self.logger.debug("StartTLS: Sending success response")
                response = self.server.extended_result(message)
                self.send(response)

                try:
                    self.server.setup_ssl_context(self.request)
                    self.logger.debug("StartTLS: Connection successfully upgraded to TLS")
                    self.auth_state.enable_tls()
                    if self.server.server_config.ldap_channel_binding:
                        self.auth_state.enable_channel_binding("tls-unique")
                        self.logger.debug(
                            "StartTLS: Channel binding enabled (tls-unique)"
                        )
                except Exception as e:
                    self.logger.fail(f"StartTLS failed: {e}")
                    raise LDAPTerminateSession from None
                return
        else:
            self.logger.debug(f"Unsupported extended operation: {req_oid}")
            response = self.server.extended_result(
                message, reason=LDAP_UNWILLING_TO_PERFORM
            )

        self.logger.debug(
            f"Sending extended response with result code: {response['protocolOp'].getComponent()['resultCode']}"
        )
        self.send(response)

    def handle_unbindRequest(
        self,
        message: LDAPMessage,
        unbind_req: UnbindRequest,
    ) -> bool:
        raise LDAPTerminateSession

    def _handle_sasl_GSS_SPNEGO(
        self, message: LDAPMessage, bind_auth: Any
    ) -> LDAPMessage | None:
        data = bytes(bind_auth["credentials"])
        self.logger.debug(f"GSS-SPNEGO: Received token, length={len(data)}")

        try:
            response_token, negotiation_complete = self.spnego_negotiator.process_token(
                data
            )
        except ValueError as e:
            self.logger.debug(
                f"GSS-SPNEGO: SPNEGO parsing failed, falling back to direct NTLM: {e}"
            )
            return self._handle_direct_ntlm(message, data)

        if negotiation_complete:
            if (
                self.server.server_config.ldap_channel_binding
                and not self.auth_state.channel_binding_active
            ):
                self.logger.debug("GSS-SPNEGO: Channel binding required but not active")
                response = self.server.bind_result(
                    message, reason=LDAP_INVALID_CREDENTIALS
                )
                self.send(response)
                raise LDAPTerminateSession

            if self.server.server_config.ldap_require_sealing:
                if not self.auth_state.sealing_active:
                    self.logger.debug("GSS-SPNEGO: Sealing required but not negotiated")
                    response = self.server.bind_result(
                        message, reason=LDAP_CONFIDENTIALITY_REQUIRED
                    )
                    self.send(response)
                    raise LDAPTerminateSession
            elif (
                self.server.server_config.ldap_require_signing
                and not self.auth_state.signing_active
            ):
                self.logger.debug("GSS-SPNEGO: Signing required but not negotiated")
                response = self.server.bind_result(
                    message, reason=LDAP_CONFIDENTIALITY_REQUIRED
                )
                self.send(response)
                raise LDAPTerminateSession

            if response_token:
                response = self.server.bind_result(
                    message,
                    reason=self.server.server_config.ldap_error_code,
                    sasl_credentials=response_token,
                )
            else:
                response = self.server.bind_result(
                    message,
                    reason=self.server.server_config.ldap_error_code,
                )
            self.send(response)
            raise LDAPTerminateSession

        if response_token:
            self.send(
                self.server.bind_result(
                    message,
                    reason=LDAP_SASL_BIND_IN_PROGRESS,
                    sasl_credentials=response_token,
                )
            )
        else:
            self.send(self.server.bind_result(message, reason=LDAP_SASL_BIND_IN_PROGRESS))
        return None

    def _handle_direct_ntlm(
        self, message: LDAPMessage, data: bytes
    ) -> LDAPMessage | None:
        try:
            if not data.startswith(b"NTLMSSP\x00"):
                self.logger.debug(
                    "Direct NTLM: token does not start with NTLMSSP signature"
                )
                return self.server.bind_result(
                    message, reason=LDAP_AUTH_METHOD_NOT_SUPPORTED
                )

            if len(data) < 9:
                self.logger.debug(
                    "Direct NTLM: token too short to determine message type"
                )
                return self.server.bind_result(
                    message, reason=LDAP_AUTH_METHOD_NOT_SUPPORTED
                )

            msg_type = data[8]
            if msg_type == 1:
                self.logger.debug("Direct NTLM: detected NTLM negotiate message")
                return self._handle_ntlm_negotiate(message, data)

            if msg_type == 3:
                self.logger.debug("Direct NTLM: detected NTLM authenticate message")
                return self._handle_ntlm_auth(message, data)

            self.logger.debug(f"Direct NTLM: unsupported NTLM message type {msg_type}")
            return self.server.bind_result(message, reason=LDAP_AUTH_METHOD_NOT_SUPPORTED)

        except Exception as e:
            self.logger.debug(f"Direct NTLM: failed to parse token: {e}")
            return self.server.bind_result(message, reason=LDAP_AUTH_METHOD_NOT_SUPPORTED)

    def _handle_ntlm_negotiate(self, message: LDAPMessage, nego_token_raw: bytes) -> None:
        negotiate = NTLMAuthNegotiate()
        negotiate.fromString(nego_token_raw)

        fqdn = self.server.server_config.ldap_fqdn
        ntlm_challenge = ntlm_auth_create_challenge(
            negotiate,
            *ntlm_split_fqdn(fqdn),
            challenge=self.server.server_config.ntlm_challenge,
            disable_ess=self.server.server_config.ntlm_disable_ess,
            disable_ntlmv2=self.server.server_config.ntlm_disable_ntlmv2,
        )
        self.send(self.server.bind_result(message, matched_dn=ntlm_challenge.getData()))

    def _handle_ntlm_auth(self, message: LDAPMessage, blob: bytes) -> None:
        auth_message = NTLMAuthChallengeResponse()
        auth_message.fromString(blob)
        ntlm_report_auth(
            auth_token=auth_message,
            challenge=self.server.server_config.ntlm_challenge,
            client=self.client_address,
            logger=self.logger,
            session=self.config,
        )
        self.send(
            self.server.bind_result(
                message,
                reason=self.server.server_config.ldap_error_code,
            )
        )
        raise LDAPTerminateSession

    def _handle_sasl_DIGEST_MD5(
        self, message: LDAPMessage, bind_auth: Any
    ) -> LDAPMessage | None:
        try:
            credentials = bytes(bind_auth["credentials"])
            self.logger.debug(f"DIGEST-MD5: Received credentials: {credentials!r}")
        except (PyAsn1Error, KeyError):
            credentials = b""

        if not credentials:
            self.logger.debug("DIGEST-MD5: Sending initial challenge")
            nonce = f"+Upgraded+v1{secrets.token_hex(32)}"

            _, realm = ntlm_split_fqdn(self.server.server_config.ldap_fqdn)
            self.digest_md5_state = {
                "nonce": nonce,
            }

            qop_options = (
                self.server.server_config.ldap_sasl_qop_options or LDAP_SASL_QOP_OPTIONS
            )
            qop_string = ",".join(qop_options)
            # NOTE: the order of these attributes matter for windows clients
            challenge_parts = [
                f'qop="{qop_string}"',
                'cipher="3des,rc4"',
                f"algorithm={DIGEST_MD5_ALGORITHM}",  # must be md5-sess
                f'nonce="{nonce}"',
                f"charset={DIGEST_MD5_CHARSET}",  # SHOULD be utf-8
                f'realm="{realm}"',
            ]
            challenge = ",".join(challenge_parts)

            self.logger.debug(f"DIGEST-MD5: Challenge sent: {challenge}")
            self.send(
                self.server.bind_result(
                    message,
                    reason=LDAP_SASL_BIND_IN_PROGRESS,
                    sasl_credentials=challenge.encode("utf-8"),
                )
            )
            return None

        response_str = credentials.decode("utf-8", errors="replace")
        self.logger.debug(f"DIGEST-MD5: Client response: {response_str}")

        parsed_response = self._parse_digest_response(response_str)

        if not parsed_response:
            self.logger.debug("DIGEST-MD5: Failed to parse response")
            self.send(self.server.bind_result(message, reason=LDAP_INVALID_CREDENTIALS))
            raise LDAPTerminateSession

        expected_nonce = (
            self.digest_md5_state.get("nonce") if self.digest_md5_state else None
        )
        if parsed_response.get("nonce") != expected_nonce:
            self.logger.debug(
                "DIGEST-MD5: Nonce mismatch or missing state - possible replay attack"
            )
            self.send(self.server.bind_result(message, reason=LDAP_INVALID_CREDENTIALS))
            raise LDAPTerminateSession

        username = parsed_response.get("username", "")
        realm = parsed_response.get("realm", DIGEST_MD5_REALM)
        method = "AUTHENTICATE"
        digest_uri = parsed_response.get("digest-uri", "")
        nonce = parsed_response.get("nonce", "")
        cnonce = parsed_response.get("cnonce", "")
        nc = parsed_response.get("nc", "")
        qop = parsed_response.get("qop", "")
        response = parsed_response.get("response", "")

        digest_hash = f"$sip$***{username}*{realm}*{method}**{digest_uri}**{nonce}*{cnonce}*{nc}*{qop}*{DIGEST_MD5_ALGORITHM}*{response}"

        domain = parsed_response.get("realm")
        extras = {
            "nonce": nonce,
            "cnonce": cnonce,
            "nc": nc,
            "qop": qop,
            "digest-uri": digest_uri,
        }

        self.logger.fail(
            "DIGEST-MD5 (md5-sess) hash captured but NOT CRACKABLE "
            + "with current hashcat versions. See hashcat/issues/2359"
        )
        self.config.db.add_auth(
            client=self.client_address,
            credtype=DIGEST_MD5,
            username=username,
            password=digest_hash,
            domain=domain,
            logger=self.logger,
            extras=extras,
        )

        self.logger.debug(
            "DIGEST-MD5: Captured digest response for offline analysis "
            + "(WARNING: not currently crackable with hashcat)"
        )
        if qop and qop in ["auth", "auth-int", "auth-conf"]:
            self.auth_state.apply_negotiated_qop(qop)
            self.logger.debug(f"DIGEST-MD5: Negotiated QOP: {qop}")

        if self.server.server_config.ldap_require_sealing:
            if qop != "auth-conf":
                self.logger.debug(
                    f"DIGEST-MD5: Sealing required but client negotiated QOP={qop}"
                )
                self.send(
                    self.server.bind_result(message, reason=LDAP_CONFIDENTIALITY_REQUIRED)
                )
                raise LDAPTerminateSession
        elif self.server.server_config.ldap_require_signing and qop not in [
            "auth-int",
            "auth-conf",
        ]:
            self.logger.debug(
                f"DIGEST-MD5: Signing required but client negotiated QOP={qop}"
            )
            self.send(
                self.server.bind_result(message, reason=LDAP_CONFIDENTIALITY_REQUIRED)
            )
            raise LDAPTerminateSession

        self.digest_md5_state = None

        self.send(
            self.server.bind_result(
                message, reason=self.server.server_config.ldap_error_code
            )
        )
        raise LDAPTerminateSession

    def _parse_digest_response(self, response_str: str) -> dict[str, str] | None:
        """Parse DIGEST-MD5 client response string into directive dictionary."""
        try:
            directives = parse_http_list(response_str)
            parsed = parse_keqv_list(directives)
        except ValueError as e:
            self.logger.debug(f"DIGEST-MD5: Failed to parse response: {e}")
            return None
        else:
            return parsed

    def _handle_sasl_PLAIN(
        self, message: LDAPMessage, bind_auth: Any
    ) -> LDAPMessage | None:
        """Handle SASL PLAIN mechanism.

        Per RFC 4616: PLAIN transmits credentials in cleartext.
        MUST only be used over TLS.

        :raises LDAPTerminateSession: After sending response
        """
        credentials = bytes(bind_auth["credentials"])
        self.logger.debug(f"SASL PLAIN: Received credentials: {credentials!r}")

        try:
            parts = credentials.split(b"\x00", 2)
            if len(parts) != 3:
                self.logger.debug(
                    "SASL PLAIN: Invalid credential format (expected 3 parts)"
                )
                return self.server.bind_result(message, reason=LDAP_INVALID_CREDENTIALS)

        except (ValueError, AttributeError) as e:
            self.logger.debug(f"SASL PLAIN: Failed to parse credentials: {e}")
            return self.server.bind_result(message, reason=LDAP_INVALID_CREDENTIALS)
        else:
            authzid, authcid, passwd = parts
            authzid = authzid.decode("utf-8", errors="replace") if authzid else ""
            authcid = authcid.decode("utf-8", errors="replace")
            passwd = passwd.decode("utf-8", errors="replace")

            self.logger.debug(
                f"SASL PLAIN: authzid='{authzid}', authcid='{authcid}', passwd length={len(passwd)}"
            )

            username, domain, extras = self._parse_cleartext_user(authcid)
            self.config.db.add_auth(
                client=self.client_address,
                credtype=CLEARTEXT,
                username=username,
                password=passwd,
                domain=domain,
                logger=self.logger,
                extras=extras,
            )
            if (
                self.server.server_config.ldap_require_signing
                or self.server.server_config.ldap_require_sealing
            ) and not self.auth_state.tls_active:
                self.logger.debug(
                    "SASL PLAIN rejected: signing/sealing required but TLS not active"
                )
                response = self.server.bind_result(
                    message, reason=LDAP_CONFIDENTIALITY_REQUIRED
                )
                self.send(response)
                raise LDAPTerminateSession

            response = self.server.bind_result(
                message, reason=self.server.server_config.ldap_error_code
            )
            self.send(response)

        raise LDAPTerminateSession

    def _handle_sasl_NTLM(
        self, message: LDAPMessage, bind_auth: Any
    ) -> LDAPMessage | None:
        credentials = bytes(bind_auth["credentials"])
        self.logger.debug(f"SASL NTLM: Received token, length={len(credentials)}")

        if not self.sasl_state:
            self.logger.debug("SASL NTLM: Invalid state")
            return None

        if not credentials.startswith(b"NTLMSSP\x00"):
            self.logger.debug("SASL NTLM: Invalid NTLM signature")
            self.sasl_state.transition(SASLAuthState.FAILED)
            return self.server.bind_result(message, reason=LDAP_AUTH_METHOD_NOT_SUPPORTED)

        if len(credentials) < 9:
            self.logger.debug("SASL NTLM: Token too short")
            self.sasl_state.transition(SASLAuthState.FAILED)
            return self.server.bind_result(message, reason=LDAP_AUTH_METHOD_NOT_SUPPORTED)

        msg_type = credentials[8]

        if msg_type == 1:
            self.logger.debug("SASL NTLM: Negotiate message")
            return self._handle_sasl_ntlm_negotiate(message, credentials)
        if msg_type == 3:
            self.logger.debug("SASL NTLM: Authenticate message")
            return self._handle_sasl_ntlm_authenticate(message, credentials)

        self.logger.debug(f"SASL NTLM: Unsupported message type {msg_type}")
        self.sasl_state.transition(SASLAuthState.FAILED)
        return self.server.bind_result(message, reason=LDAP_AUTH_METHOD_NOT_SUPPORTED)

    def _handle_sasl_ntlm_negotiate(
        self, message: LDAPMessage, negotiate_data: bytes
    ) -> LDAPMessage | None:
        try:
            negotiate = NTLMAuthNegotiate()
            negotiate.fromString(negotiate_data)
        except Exception as e:
            self.logger.debug(f"SASL NTLM: Failed to parse negotiate: {e}")
            if self.sasl_state:
                self.sasl_state.transition(SASLAuthState.FAILED)
            return self.server.bind_result(message, reason=LDAP_AUTH_METHOD_NOT_SUPPORTED)

        fqdn = self.server.server_config.ldap_fqdn
        ntlm_challenge = ntlm_auth_create_challenge(
            negotiate,
            *ntlm_split_fqdn(fqdn),
            challenge=self.server.server_config.ntlm_challenge,
            disable_ess=self.server.server_config.ntlm_disable_ess,
            disable_ntlmv2=self.server.server_config.ntlm_disable_ntlmv2,
        )

        if self.sasl_state:
            self.sasl_state.challenge_data = ntlm_challenge.getData()
            self.sasl_state.transition(SASLAuthState.CHALLENGE_SENT)

        self.logger.debug("SASL NTLM: Sending challenge")
        return self.server.bind_result(
            message,
            reason=LDAP_SASL_BIND_IN_PROGRESS,
            sasl_credentials=ntlm_challenge.getData(),
        )

    def _handle_sasl_ntlm_authenticate(
        self, message: LDAPMessage, authenticate_data: bytes
    ) -> LDAPMessage:
        try:
            auth_message = NTLMAuthChallengeResponse()
            auth_message.fromString(authenticate_data)
        except Exception as e:
            self.logger.debug(f"SASL NTLM: Failed to parse authenticate: {e}")
            if self.sasl_state:
                self.sasl_state.transition(SASLAuthState.FAILED)
            return self.server.bind_result(message, reason=LDAP_AUTH_METHOD_NOT_SUPPORTED)

        ntlm_report_auth(
            auth_token=auth_message,
            challenge=self.server.server_config.ntlm_challenge,
            client=self.client_address,
            logger=self.logger,
            session=self.config,
        )

        if self.sasl_state:
            self.sasl_state.transition(SASLAuthState.COMPLETE)

        if (
            self.server.server_config.ldap_channel_binding
            and not self.auth_state.channel_binding_active
        ):
            self.logger.debug("SASL NTLM: Channel binding required but not active")
            return self.server.bind_result(message, reason=LDAP_INVALID_CREDENTIALS)

        if self.server.server_config.ldap_require_sealing:
            if not self.auth_state.sealing_active:
                self.logger.debug("SASL NTLM: Sealing required but not negotiated")
                return self.server.bind_result(
                    message, reason=LDAP_CONFIDENTIALITY_REQUIRED
                )
        elif (
            self.server.server_config.ldap_require_signing
            and not self.auth_state.signing_active
        ):
            self.logger.debug("SASL NTLM: Signing required but not negotiated")
            return self.server.bind_result(message, reason=LDAP_CONFIDENTIALITY_REQUIRED)

        self.logger.debug("SASL NTLM: Authentication complete")
        return self.server.bind_result(
            message, reason=self.server.server_config.ldap_error_code
        )


# Set default handler class after LDAPHandler is defined
LDAPServer.default_handler_class = LDAPHandler
CLDAPServer.default_handler_class = LDAPHandler


class LDAP(BaseProtocolModule[LDAPServerConfig]):
    name: str = "LDAP"
    config_ty = LDAPServerConfig
    config_attr = DEFAULT_ATTR
    config_enabled_attr = DEFAULT_ATTR
    config_list = True

    @override
    def create_server_thread(
        self, session: SessionConfig, server_config: LDAPServerConfig
    ) -> BaseServerThread[LDAPServerConfig]:
        server_cls = CLDAPServer if server_config.ldap_udp else LDAPServer
        return ServerThread(
            session,
            server_config,
            server_cls,
            server_address=(session.bind_address, server_config.ldap_port),
            include_server_config=True,
        )


__proto__ = ["LDAP"]
