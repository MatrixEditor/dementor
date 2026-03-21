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
"""
LDAP Protocol Server Implementation.

This module implements an LDAPv3 server compliant with RFC 4511 (LDAPv3),
focusing on authentication mechanisms as per RFC 4513 and Microsoft Active
Directory Technical Specification [MS-ADTS].

Supported Authentication Mechanisms (per MS-ADTS §5.1.1.1):
- Simple Bind: Anonymous, unauthenticated, and name/password authentication
- Sicily Protocol: Microsoft extension for NTLM authentication over LDAP
- SASL Mechanisms:
  - GSS-SPNEGO: SPNEGO negotiation (typically NTLM)
  - DIGEST-MD5: Digest authentication
  - PLAIN: Cleartext authentication
  - NTLM: Direct NTLM (non-SPNEGO)

References:
- RFC 4511: Lightweight Directory Access Protocol (LDAP): The Protocol
- RFC 4513: LDAP Authentication Methods and Security Mechanisms
- RFC 2831: Using Digest Authentication as a SASL Mechanism
- RFC 4178: SPNEGO Negotiation Mechanism
- RFC 4616: The PLAIN SASL Mechanism
- [MS-ADTS]: Active Directory Technical Specification
- [MS-NLMP]: NT LAN Manager (NTLM) Authentication Protocol

"""

import secrets

import base64
import os
import socket
import ssl
import time

from enum import Enum
from typing import TYPE_CHECKING, Any
from urllib.request import parse_http_list, parse_keqv_list
from collections.abc import Sequence, Callable

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
    ATTR_CERT_CN,
    ATTR_CERT_COUNTRY,
    ATTR_CERT_LOCALITY,
    ATTR_CERT_ORG,
    ATTR_CERT_STATE,
    ATTR_CERT_VALIDITY_DAYS,
    ATTR_KEY,
    ATTR_SELF_SIGNED,
    ATTR_TLS,
)
from dementor.config.session import SessionConfig
from dementor.config.toml import Attribute as A
from dementor.config.toml import TomlConfig
from dementor.config.util import generate_self_signed_cert
from dementor.db import _CLEARTEXT
from dementor.loader import DEFAULT_ATTR, BaseProtocolModule
from dementor.log import hexdump
from dementor.log.logger import ProtocolLogger
from dementor.protocols.ntlm import (
    ATTR_NTLM_CHALLENGE,
    ATTR_NTLM_DISABLE_ESS,
    ATTR_NTLM_DISABLE_NTLMV2,
    NTLM_AUTH_CreateChallenge,
    NTLM_report_auth,
    NTLM_split_fqdn,
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


# ===========================================================================
# LDAP Server Capabilities (RFC 4512 §5.1, MS-ADTS §3.1.1.3.3)
# ===========================================================================
# Per RFC 4512 §5.1: The root DSE's 'supportedCapabilities' attribute lists
# the OIDs of capabilities that the server supports. These OIDs identify
# features beyond the base LDAP protocol.
#
# MS-ADTS §3.1.1.3.3 defines Active Directory-specific capability OIDs that
# indicate the server is an AD DC and supports AD-specific features.

LDAP_CAPABILITIES: list[str] = [
    # MS-ADTS §3.1.1.3.3.1: LDAP_CAP_ACTIVE_DIRECTORY_OID
    # Indicates the server is an Active Directory Domain Controller.
    # Clients use this to detect AD vs. generic LDAP servers.
    "1.2.840.113556.1.4.800",
    # MS-ADTS §3.1.1.3.3.2: LDAP_CAP_ACTIVE_DIRECTORY_LDAP_INTEG_OID
    # Indicates support for LDAP integrity and privacy via SASL signing/sealing.
    # Required for secure LDAP communications per MS-ADTS §5.1.1.1.1.
    "1.2.840.113556.1.4.1791",
    # MS-ADTS §3.1.1.3.3.3: LDAP_CAP_ACTIVE_DIRECTORY_V51_OID
    # Indicates Windows Server 2003 or later AD capabilities.
    # Enables features like dynamic objects and application partitions.
    "1.2.840.113556.1.4.1670",
]

# ===========================================================================
# SASL Mechanisms (RFC 4513 §5.2.1.5, MS-ADTS §5.1.1.1)
# ===========================================================================
# Per RFC 4513 §5.2.1.5: The root DSE's 'supportedSASLMechanisms' attribute
# lists the SASL mechanisms the server supports for authentication.
#
# MS-ADTS §5.1.1.1 defines the authentication methods supported by AD:
# - Simple Bind (§5.1.1.1.1): Anonymous, unauthenticated, name/password
# - SASL (§5.1.1.1.2): GSS-SPNEGO, DIGEST-MD5, EXTERNAL, etc.
# - Sicily (§5.1.1.1.3): Microsoft proprietary NTLM over LDAP

LDAP_DEFAULT_MECH: list[str] = [
    # RFC 4178: SPNEGO (Simple and Protected GSS-API Negotiation Mechanism)
    # Most common mechanism for Windows clients, typically negotiates NTLM or Kerberos.
    # MS-ADTS §5.1.1.1.2.1: GSS-SPNEGO wraps NTLMSSP for NTLM authentication.
    "GSS-SPNEGO",
    # RFC 2831: DIGEST-MD5 SASL mechanism (DEPRECATED per RFC 6331)
    # Challenge-response authentication using MD5 hashing.
    # Still supported for legacy client compatibility.
    "DIGEST-MD5",
    # RFC 4616: PLAIN SASL mechanism
    # Cleartext username/password authentication.
    # MUST only be used over TLS per RFC 4616 §4 to prevent credential exposure.
    "PLAIN",
    # Direct NTLM (non-SPNEGO wrapped)
    # Microsoft extension allowing NTLM authentication without SPNEGO wrapper.
    # Used by some legacy Windows clients.
    "NTLM",
]

# ===========================================================================
# Channel Binding Types (RFC 5929 §4)
# ===========================================================================
# Per RFC 5929: Channel bindings allow authentication mechanisms to bind
# to the underlying secure channel (TLS), preventing man-in-the-middle attacks.
#
# MS-ADTS §5.1.1.1.1.4: AD supports channel binding to prevent LDAP relay attacks.

LDAP_CHANNEL_BINDING_TYPES: list[str] = [
    # RFC 5929 §4.1: 'tls-unique' channel binding type
    # Uses the TLS Finished message from the first handshake.
    # Most secure option but requires TLS renegotiation support.
    "tls-unique",
    # RFC 5929 §4.2: 'tls-server-end-point' channel binding type
    # Uses a hash of the server's TLS certificate.
    # More widely supported, works without TLS renegotiation.
    "tls-server-end-point",
]

# ===========================================================================
# SASL Quality of Protection (RFC 4513 §5.2.4)
# ===========================================================================
# Per RFC 4513 §5.2.4: SASL mechanisms can negotiate a security layer that
# provides integrity protection and/or confidentiality for subsequent LDAP
# operations after successful authentication.
#
# MS-ADTS §5.1.1.1.1.3: AD supports signing (integrity) and sealing (encryption)
# via SASL security layers.

LDAP_SASL_QOP_OPTIONS: list[str] = [
    # RFC 2831 §2.1.2.1: Authentication only
    # No integrity or confidentiality protection after authentication.
    # Credentials are protected during auth, but subsequent LDAP ops are not.
    "auth",
    # RFC 2831 §2.1.2.1: Authentication with integrity protection
    # Each LDAP message is signed with a MAC to detect tampering.
    # Provides integrity but not confidentiality (messages visible to eavesdroppers).
    "auth-int",
    # RFC 2831 §2.1.2.1: Authentication with confidentiality
    # Each LDAP message is encrypted and signed.
    # Provides both integrity and confidentiality (strongest protection).
    "auth-conf",
]

# ===========================================================================
# DIGEST-MD5 Constants (RFC 2831)
# ===========================================================================
# Per RFC 2831: DIGEST-MD5 is a SASL mechanism using HTTP Digest Authentication.
# NOTE: DIGEST-MD5 is DEPRECATED per RFC 6331 due to security concerns, but
# still supported for legacy client compatibility.

# RFC 2831 §2.1.1: The realm directive identifies the protection space.
# Typically the DNS domain name. Can be overridden by server configuration.
DIGEST_MD5_REALM: str = "dementor"

# RFC 2831 §2.1.2.1: Quality of Protection (qop) directive.
# "auth" = authentication only (no integrity/confidentiality layer).
DIGEST_MD5_QOP: str = "auth"

# RFC 2831 §2.1.1: Algorithm directive specifies the hash algorithm.
# "md5-sess" = session-based MD5 (more secure than plain "md5").
DIGEST_MD5_ALGORITHM: str = "md5-sess"

# RFC 2831 §2.1.1: Charset directive for username/password encoding.
# "utf-8" is the standard charset per RFC 2831 §2.1.1.
DIGEST_MD5_CHARSET: str = "utf-8"

# RFC 2831 §2.1.2.1: Maximum buffer size for integrity/confidentiality layers.
# 65536 bytes is a common default value.
DIGEST_MD5_MAXBUF: str = "65536"

# ===========================================================================
# LDAP Result Codes (RFC 4511 Appendix A)
# ===========================================================================
# Per RFC 4511 Appendix A: Result codes indicate the outcome of LDAP operations.
# These are returned in LDAPResult structures (BindResponse, SearchResultDone, etc.).

# RFC 4511 Appendix A.1: Operation completed successfully.
LDAP_SUCCESS: int = 0x00

# RFC 4511 Appendix A.2: Server encountered an internal error.
LDAP_OPERATIONS_ERROR: int = 0x01

# RFC 4511 Appendix A.3: Client sent a malformed or invalid request.
LDAP_PROTOCOL_ERROR: int = 0x02

# RFC 4511 Appendix A.8: The authentication method is not supported.
# Returned when client requests unsupported SASL mechanism or bind type.
LDAP_AUTH_METHOD_NOT_SUPPORTED: int = 0x07

# RFC 4511 Appendix A.13: The LDAP protocol version is not supported.
# This implementation only supports LDAPv3 (version 3).
LDAP_UNSUPPORTED_LDAP_VERSION: int = 0x0C

# RFC 4511 Appendix A.14: Operation requires confidentiality (TLS/SASL encryption).
# Returned when server policy requires encryption but connection is not secured.
LDAP_CONFIDENTIALITY_REQUIRED: int = 0x0D

# RFC 4511 Appendix A.15: SASL bind is in progress (multi-step authentication).
# Per RFC 4513 §5.2.1: SASL mechanisms may require multiple bind requests.
LDAP_SASL_BIND_IN_PROGRESS: int = 0x0E

# RFC 4511 Appendix A.17: Server is unwilling to perform the operation.
# Generic error for operations the server chooses not to support.
LDAP_UNWILLING_TO_PERFORM: int = 0x10

# RFC 4511 Appendix A.50: Invalid credentials provided during bind.
# Returned for failed simple bind or SASL authentication.
LDAP_INVALID_CREDENTIALS: int = 0x31

# ===========================================================================
# Extended Operation OIDs (RFC 4511 §4.12)
# ===========================================================================
# Per RFC 4511 §4.12: Extended operations allow additional functionality
# beyond the core LDAP protocol. Each operation is identified by an OID.

# RFC 4511 §4.14 / RFC 4513 §3: StartTLS Extended Operation
# OID: 1.3.6.1.4.1.1466.20037
# Upgrades an existing LDAP connection to use TLS encryption.
# Per RFC 4513 §3.1.1: StartTLS MUST NOT be used if TLS is already active.
# Per RFC 4513 §3.1.2: StartTLS MUST NOT be used during SASL negotiation.
LDAP_STARTTLS_OID: str = "1.3.6.1.4.1.1466.20037"

# ===========================================================================
# Default Domain
# ===========================================================================

DEFAULT_DOMAIN: str = "example.com"


# ===========================================================================
# Exceptions
# ===========================================================================
class LDAPTerminateSession(Exception):
    """Exception raised to terminate an LDAP session gracefully."""


# ===========================================================================
# Configuration
# ===========================================================================
class LDAPServerConfig(TomlConfig):
    """Configuration class for LDAP server settings.

    Defines configurable parameters for LDAP server behavior, including
    port, TLS settings, supported capabilities, SASL mechanisms, and
    channel binding/signing options.
    """

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
        A("ldap_fqdn", "FQDN", "DEMENTOR", section_local=False),
        # Active Directory naming contexts
        A("ldap_dns_hostname", "DNSHostName", None),
        A("ldap_domain", "Domain", DEFAULT_DOMAIN),
        # TLS configuration
        ATTR_TLS,
        ATTR_KEY,
        ATTR_CERT,
        ATTR_SELF_SIGNED,
        ATTR_CERT_CN,
        ATTR_CERT_COUNTRY,
        ATTR_CERT_LOCALITY,
        ATTR_CERT_ORG,
        ATTR_CERT_STATE,
        ATTR_CERT_VALIDITY_DAYS,
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
        ldap_dns_hostname: str | None
        ldap_domain: str
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
        """Set the LDAP error code for bind responses."""
        if isinstance(value, int):
            self.ldap_error_code = value
        else:
            self.ldap_error_code = ResultCode.namedValues[str(value)]

    def _parse_domain_to_dn(self, domain: str) -> str:
        """Parse a domain name into LDAP DN format.

        - "example.com" → "DC=example,DC=com"
        - "sub.example.com" → "DC=sub,DC=example,DC=com"
        """
        if not domain:
            return ""
        parts = domain.split(".")
        return ",".join(f"DC={part}" for part in parts if part)


# ===========================================================================
# SASL State Machine (RFC 4513 §5.2.1.2)
# ===========================================================================
class SASLAuthState(Enum):
    """SASL authentication state machine states per RFC 4513 §5.2.1.2.

    Per RFC 4513 §5.2.1.2: SASL authentication is a multi-step process where
    the client and server exchange challenges and responses until authentication
    succeeds or fails.

    State Transitions:
    - INITIAL → CHALLENGE_SENT: Server sends initial challenge
    - CHALLENGE_SENT → RESPONSE_RECEIVED: Client sends response
    - RESPONSE_RECEIVED → COMPLETE: Authentication succeeds
    - RESPONSE_RECEIVED → CHALLENGE_SENT: Additional challenge needed (multi-step)
    - Any state → FAILED: Authentication fails
    """

    # Initial state before any SASL exchange
    INITIAL = "initial"

    # Server has sent a challenge to the client
    # Per RFC 4513 §5.2.1.2: Server returns saslBindInProgress (14)
    CHALLENGE_SENT = "challenge_sent"

    # Client has sent a response to the server's challenge
    RESPONSE_RECEIVED = "response_received"

    # Authentication completed successfully
    # Per RFC 4513 §5.2.1.2: Server returns success (0)
    COMPLETE = "complete"

    # Authentication failed
    # Per RFC 4513 §5.2.1.2: Server returns appropriate error code
    FAILED = "failed"


class SASLMechanismState:
    """Tracks state for a single SASL mechanism negotiation.

    Per RFC 4513 §5.2.1: SASL authentication may require multiple bind requests
    to complete. This class maintains state across those requests.

    Per RFC 4513 §5.2.1.2: The server must track the authentication state and
    ensure proper sequencing of challenges and responses.
    """

    def __init__(self, mechanism: str) -> None:
        """Initialize SASL mechanism state.

        Args:
            mechanism: Normalized SASL mechanism name (e.g., "GSS_SPNEGO")
            timeout: State expiration timeout in seconds (default: 300 = 5 minutes)
                    Per RFC 4513 §5.2.1.2: Servers SHOULD limit authentication time
        """
        self.mechanism: str = mechanism
        self.state: SASLAuthState = SASLAuthState.INITIAL
        self.challenge_data: bytes | None = None
        self.response_data: bytes | None = None
        self.context: dict[str, Any] = {}

    def transition(self, new_state: SASLAuthState) -> None:
        """Transition to a new state with validation.

        Per RFC 4513 §5.2.1.2: SASL authentication follows a specific sequence.
        This method enforces valid state transitions to prevent protocol violations.

        Valid transitions:
        - INITIAL → CHALLENGE_SENT: Server sends initial challenge
        - INITIAL → FAILED: Authentication fails immediately
        - CHALLENGE_SENT → RESPONSE_RECEIVED: Client responds to challenge
        - CHALLENGE_SENT → FAILED: Client fails to respond properly
        - RESPONSE_RECEIVED → COMPLETE: Authentication succeeds
        - RESPONSE_RECEIVED → CHALLENGE_SENT: Multi-step auth needs another round
        - RESPONSE_RECEIVED → FAILED: Authentication fails
        - COMPLETE/FAILED: Terminal states, no further transitions

        Raises:
            ValueError: If transition is invalid per RFC 4513 §5.2.1.2
        """
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
                f"{self.state.value} -> {new_state.value}"
            )

        self.state = new_state


class AuthorizationState(Enum):
    """Authorization state per RFC 4513 §4.

    Per RFC 4513 §4: An LDAP session has an associated authorization state that
    determines what operations the client is permitted to perform.

    Authorization States:
    - Anonymous: No authentication, limited access (RFC 4513 §4.1)
    - Authenticated: Successfully authenticated, full access based on identity
    - SASL In Progress: Multi-step SASL authentication underway
    """

    # RFC 4513 §4.1: Anonymous authentication state
    # Client has not authenticated or used anonymous bind.
    # Access is limited to publicly readable data.
    ANONYMOUS = "anonymous"

    # RFC 4513 §4.2: Authenticated state
    # Client has successfully completed authentication.
    # Access is determined by the authenticated identity's permissions.
    AUTHENTICATED = "authenticated"

    # RFC 4513 §5.2.1: SASL authentication in progress
    # Multi-step SASL mechanism is being negotiated.
    # Client has limited access until authentication completes.
    SASL_IN_PROGRESS = "sasl_in_progress"


class SessionAuthState:
    """Tracks authorization state for an LDAP session per RFC 4513 §4.

    Per RFC 4513 §4: Each LDAP session has an authorization state that tracks:
    - The current authorization state (anonymous, authenticated, etc.)
    - The authenticated identity (if any)
    - The authentication method used
    - Security layers active on the connection (TLS, SASL, etc.)

    Per MS-ADTS §5.1.1.1.1: AD tracks additional security properties:
    - Signing (integrity protection) status
    - Sealing (encryption) status
    - Channel binding status
    """

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
        """Transition to authenticated state."""
        self.state = AuthorizationState.AUTHENTICATED
        self.authenticated_identity = identity
        self.authentication_method = method

    def reset_to_anonymous(self) -> None:
        """Reset to anonymous state per RFC 4513 §4."""
        self.state = AuthorizationState.ANONYMOUS
        self.authenticated_identity = None
        self.authentication_method = None

    def enable_tls(self) -> None:
        """Mark TLS as active on the connection."""
        self.tls_active = True

    def enable_sasl(self) -> None:
        """Mark SASL security layer as active."""
        self.sasl_active = True

    def enable_channel_binding(self, binding_type: str) -> None:
        """Enable channel binding on the connection."""
        self.channel_binding_active = True
        self.channel_binding_type = binding_type

    def enable_signing(self) -> None:
        """Enable SASL signing (integrity protection)."""
        self.signing_active = True

    def enable_sealing(self) -> None:
        """Enable SASL sealing (encryption)."""
        self.sealing_active = True

    def set_negotiated_qop(self, qop: str) -> None:
        """Set the negotiated quality of protection."""
        self.negotiated_qop = qop
        if qop == "auth-int":
            self.enable_signing()
        elif qop == "auth-conf":
            self.enable_signing()
            self.enable_sealing()

    def is_authenticated(self) -> bool:
        """Check if session is in authenticated state."""
        return self.state == AuthorizationState.AUTHENTICATED


# ===========================================================================
# Server Mixin
# ===========================================================================


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
        """Create a consolidated root DSE entry with all requested attributes."""
        attributes = {}

        # Helper to add attribute if requested
        def add_if_requested(attr_name: str, values: list[str]) -> None:
            if (
                not requested_attrs
                or attr_name.lower() in requested_attrs
                or "*" in requested_attrs
            ):
                attributes[attr_name] = values

        # Add all standard root DSE attributes
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

        dns_hostname = (
            self.server_config.ldap_dns_hostname or self.server_config.ldap_fqdn
        )
        add_if_requested("dnsHostName", [dns_hostname])

        naming_context = self.server_config._parse_domain_to_dn(
            self.server_config.ldap_domain
        )
        add_if_requested("defaultNamingContext", [naming_context])

        config_context = f"CN=Configuration,{naming_context}"
        add_if_requested("configurationNamingContext", [config_context])

        domain_parts = self.server_config.ldap_domain.split(".")
        root_domain = (
            ".".join(domain_parts[-2:])
            if len(domain_parts) >= 2
            else self.server_config.ldap_domain
        )
        root_context = self.server_config._parse_domain_to_dn(root_domain)
        add_if_requested("rootDomainNamingContext", [root_context])

        # Add additional AD-specific attributes
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
        """Generate BindResponse message."""
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
        """Generate ExtendedResponse message."""
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
        """Create a new LDAPMessage with the same message ID as the request."""
        message = LDAPMessage()
        message["messageID"] = req["messageID"]
        message["protocolOp"].setComponentByType(op.getTagSet(), op)
        return message


# ===========================================================================
# LDAP Server Classes
# ===========================================================================

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
        """Generate a self-signed certificate and private key for LDAP server."""
        ldap_logger.display(
            "Generating self-signed certificate for LDAP server",
            port=self.server_config.ldap_port,
            protocol="LDAP" + ("S" if self.server_config.use_ssl else ""),
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
                    "Set SelfSigned=true in [Globals] or [LDAP] section to enable automatic generation."
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
        """Initialize server socket and TLS context if configured."""
        if self.server_config.use_ssl:
            self.setup_ssl_context()

        super().server_bind()

    def server_close(self) -> None:
        """Clean up temporary certificate directory if generated."""
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


# ===========================================================================
# Sicily Bind Response (MS-ADTS §5.1.1.1.3)
# ===========================================================================


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


# ===========================================================================
# LDAP Handler
# ===========================================================================


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
        """Initialize the protocol handler."""
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
        """Create a protocol logger with LDAP-specific context."""
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
        """Detect if received data appears to be an encrypted SASL message."""
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
    def recv(self, size: int) -> LDAPMessage | None:  # type: ignore[override]
        """Receive and decode an LDAP message from the client."""
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
    def send(self, data: LDAPMessage | list[LDAPMessage] | None) -> None:  # ty:ignore[invalid-method-override]
        """Send an LDAP message or list of messages to the client."""
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

            ntlm_challenge = NTLM_AUTH_CreateChallenge(
                token,
                *NTLM_split_fqdn(self.server.server_config.ldap_fqdn),
                challenge=self.server.server_config.ntlm_challenge,
                disable_ess=self.server.server_config.ntlm_disable_ess,
                disable_ntlmv2=self.server.server_config.ntlm_disable_ntlmv2,
            )
            return ntlm_challenge.getData(), False

        if mech_token:
            token = ntlm.NTLMAuthChallengeResponse()
            token.fromString(mech_token)
            NTLM_report_auth(
                auth_token=token,
                challenge=self.server.server_config.ntlm_challenge,
                client=self.client_address,
                logger=self.logger,
                session=self.config,
            )
        return None, True

    def _normalize_sasl_mechanism(self, mech_name: str) -> str:
        """Normalize SASL mechanism name for handler lookup.

        Per RFC 4422 §3.1: SASL mechanism names are case-insensitive and may
        contain hyphens. However, Python method names cannot contain hyphens.

        This method normalizes mechanism names to match Python method naming:
        - Convert to uppercase (RFC 4422 §3.1: case-insensitive)
        - Replace hyphens with underscores (Python naming convention)
        - Strip whitespace

        Examples:
            'GSS-SPNEGO' → 'GSS_SPNEGO'
            'digest-md5' → 'DIGEST_MD5'
            'PLAIN' → 'PLAIN'

        Returns:
            Normalized mechanism name suitable for method lookup
        """
        return mech_name.upper().replace("-", "_").strip()

    def _parse_cleartext_user(
        self, bind_name: str
    ) -> tuple[str, str | None, dict[str, str]]:
        r"""Parse cleartext bind name into username + optional domain.

        Per RFC 4513 §5.1.1: Simple bind uses a DN or other string as the name.
        Per MS-ADTS §5.1.1.1.1: AD supports multiple name formats:
        - Distinguished Name (DN): "CN=user,DC=domain,DC=com"
        - User Principal Name (UPN): "user@domain.com"
        - Down-level logon name: "DOMAIN\user"

        This method parses these formats to extract username and domain.

        Supported Formats:
        1. Windows down-level: "DOMAIN\user" → (user, DOMAIN)
        2. UPN format: "user@domain.com" → (user, domain.com)
        3. LDAP DN: "CN=John Doe,DC=example,DC=com" → (John Doe, None, {dn: ...})
        4. Simple username: "user" → (user, None)

        Returns:
            Tuple of (username, domain, extras_dict)
            - username: Extracted username
            - domain: Extracted domain (None if not present)
            - extras: Additional metadata (e.g., full DN)
        """
        extras: dict[str, str] = {}

        # MS-ADTS §5.1.1.1.1.1: Windows down-level logon name format "DOMAIN\user"
        # Check for backslash but exclude LDAP DNs (which may contain escaped backslashes)
        if "\\" in bind_name and not bind_name.lower().startswith("cn="):
            domain, user = bind_name.split("\\", 1)
            return user, domain, extras

        # MS-ADTS §5.1.1.1.1.2: User Principal Name (UPN) format "user@domain.com"
        # Ensure it's not a DN (no = or ,) and not a down-level name (no \)
        if (
            "@" in bind_name
            and "\\" not in bind_name
            and "=" not in bind_name
            and "," not in bind_name
        ):
            user, domain = bind_name.rsplit("@", 1)
            return user, domain, extras

        # RFC 4514: LDAP Distinguished Name (DN) format
        # Example: "CN=John Doe,OU=Users,DC=example,DC=com"
        if "=" in bind_name and "," in bind_name:
            extras["dn"] = bind_name
            # Extract username from common name attributes
            for part in bind_name.split(","):
                if "=" not in part:
                    continue
                key, val = part.split("=", 1)
                key = key.strip().lower()
                val = val.strip()
                # Check common username attributes per RFC 4519
                if key in ("cn", "uid", "samaccountname", "user", "name"):
                    return val, None, extras
            # If no recognizable username attribute, use full DN
            return bind_name, None, extras

        # Simple username with no domain
        return bind_name, None, extras

    # ===========================================================================
    # Operation Handlers
    # ===========================================================================

    def handle_bindRequest(
        self, message: LDAPMessage, bind_req: BindRequest
    ) -> LDAPMessage | None:
        """Handle LDAP Bind Request per RFC 4511 §4.2.

        Per RFC 4511 §4.2: The Bind operation authenticates the client to the server.
        It establishes the authorization identity for subsequent operations.

        Per RFC 4513 §5: LDAP supports multiple authentication methods:
        - Simple Bind (§5.1): Anonymous, unauthenticated, or name/password
        - SASL (§5.2): Pluggable authentication mechanisms
        - Sicily (MS-ADTS §5.1.1.1.3): Microsoft NTLM extension

        Per RFC 4511 §4.2.1: Bind request contains:
        - version: LDAP protocol version (must be 3 for LDAPv3)
        - name: DN or other identifier (empty for anonymous)
        - authentication: Simple password, SASL, or other method

        Returns:
            None (response is sent directly to client)
        """
        self.logger.debug(f"LDAP Bind Request from {self.client_address}")
        self.logger.debug(f"Bind message ID: {message['messageID']}")

        bind_req = message["protocolOp"].getComponent()
        version = int(bind_req["version"])
        bind_name = str(bind_req["name"])
        bind_auth = bind_req["authentication"].getComponent()

        self.logger.debug(f"Bind version: {version}, name: {bind_name!r}")
        self.logger.debug(f"Authentication type: {bind_req['authentication'].getName()}")

        # RFC 4511 §4.2.1: Version must be 3 for LDAPv3
        # This implementation does not support LDAPv2 (deprecated per RFC 3494)
        if version != 3:
            self.logger.debug(f"Unsupported LDAP version: {version}")
            return self.server.bind_result(message, reason=LDAP_UNSUPPORTED_LDAP_VERSION)

        auth_type = bind_req["authentication"].getName().lower()

        # Reset authorization state for new bind per RFC 4513 §4
        # But preserve SASL state if continuing same mechanism
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
        """Handle simple bind authentication per RFC 4513 §5.1.

        Per RFC 4513 §5.1: Simple bind supports three authentication types:
        1. Anonymous (§5.1.1): Empty name and password → anonymous access
        2. Unauthenticated (§5.1.2): Name but empty password → anonymous access
        3. Name/Password (§5.1.3): Both name and password → authenticated access

        Per RFC 4513 §5.1.4: Simple bind with password SHOULD only be used over
        TLS to prevent credential exposure. However, we accept unencrypted simple
        binds to capture credentials.

        Security Considerations (RFC 4513 §6.1):
        - Simple bind transmits password in cleartext (unless over TLS)
        - Vulnerable to eavesdropping and replay attacks
        - Should be disabled in production environments without TLS
        """
        self.logger.debug("Processing simple authentication")

        # RFC 4513 §5.1.1: Anonymous authentication
        # Both name and password are empty → anonymous bind
        if not bind_name and not bind_password:
            self.logger.debug("Anonymous bind request")
            return self.server.bind_result(message)

        # RFC 4513 §5.1.2: Unauthenticated authentication
        # Name is present but password is empty → treated as anonymous
        # Per RFC 4513 §5.1.2: Servers SHOULD NOT grant access based on DN alone
        if bind_name and not bind_password:
            self.logger.debug(f"Unauthenticated bind for DN: {bind_name}")
            return self.server.bind_result(message)

        self.logger.debug(
            f"Simple bind credentials: DN={bind_name}, password length={len(bind_password)}"
        )

        username, domain, extras = self._parse_cleartext_user(bind_name)
        self.config.db.add_auth(
            client=self.client_address,
            credtype=_CLEARTEXT,
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
        r"""Handle Sicily negotiate (NTLM negotiate phase) per MS-ADTS §5.1.1.1.3.

        Per MS-ADTS §5.1.1.1.3: The Sicily protocol is a Microsoft extension that
        allows NTLM authentication over LDAP without SASL wrapping.

        Sicily Protocol Flow (MS-ADTS §5.1.1.1.3):
        1. Package Discovery: Client requests supported auth packages
        2. Negotiate: Client sends NTLM NEGOTIATE_MESSAGE
        3. Challenge: Server responds with NTLM CHALLENGE_MESSAGE
        4. Authenticate: Client sends NTLM AUTHENTICATE_MESSAGE

        This method handles step 2 (Negotiate phase):
        - Receives NTLM NEGOTIATE_MESSAGE from client
        - Generates NTLM CHALLENGE_MESSAGE
        - Returns challenge in BindResponse.matchedDN field

        Per MS-NLMP §3.1.5.1: NEGOTIATE_MESSAGE contains:
        - NTLM signature ("NTLMSSP\0")
        - Message type (0x00000001)
        - Negotiation flags (capabilities)
        - Optional domain/workstation names
        """
        self.logger.debug("Processing Sicily negotiate (NTLM)")

        # Normalize mechanism name - empty string means NTLM
        self.mech_name = bind_name.lower().strip() if bind_name else "ntlm"

        self.logger.debug(f"Sicily mechanism: {self.mech_name!r}")
        if self.mech_name in ("ntlm", ""):
            negotiate = NTLMAuthNegotiate()
            negotiate.fromString(nego_token_raw)

            fqdn = self.server.server_config.ldap_fqdn
            name, domain = fqdn.split(".", 1) if "." in fqdn else (fqdn, "")

            ntlm_challenge = NTLM_AUTH_CreateChallenge(
                negotiate,
                name,
                domain,
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
        r"""Handle Sicily response (NTLM authenticate phase) per MS-ADTS §5.1.1.1.3.

        This method handles step 4 of the Sicily protocol (Authenticate phase):
        - Receives NTLM AUTHENTICATE_MESSAGE from client
        - Extracts and logs credentials (username, domain, NTLM hashes)
        - Returns bind response

        Per MS-NLMP §3.1.5.3: AUTHENTICATE_MESSAGE contains:
        - NTLM signature ("NTLMSSP\0")
        - Message type (0x00000003)
        - LM response (legacy, often empty)
        - NTLM response (NTLMv1 or NTLMv2)
        - Domain name, username, workstation name
        - Session key (if negotiated)

        The NTLM response can be cracked offline to recover the password.
        """
        self.logger.debug("Processing Sicily response (NTLM)")
        if self.mech_name == "ntlm":
            self.logger.debug("NTLM authenticate phase")
            auth_message = NTLMAuthChallengeResponse()
            auth_message.fromString(blob)
            NTLM_report_auth(
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

    def _handle_sicily_package_discovery(self, message: LDAPMessage) -> LDAPMessage:
        """Handle Sicily package discovery per MS-ADTS §5.1.1.1.3.

        This method handles step 1 of the Sicily protocol (Package Discovery):
        - Client sends sicilyPackageDiscovery bind request
        - Server responds with list of supported authentication packages
        - Response is encoded as SicilyBindResponse in serverSaslCreds

        Per MS-ADTS §5.1.1.1.3: The server returns a list of supported packages.
        Common packages include:
        - "NTLM": NT LAN Manager authentication

        SicilyBindResponse Structure (MS-ADTS §5.1.1.1.3):
        - resultCode: 0 for success
        - serverCreds: Comma or semicolon-separated list of package names
        - errorMessage: Empty for success
        """
        self.logger.debug("Sicily package discovery: Returning supported packages (NTLM)")

        sicily_response = SicilyBindResponse()
        sicily_response["resultCode"] = 0

        # Return only NTLM - Windows clients may not recognize SICILY as a package name
        # The SICILY protocol itself is the transport, not a separate auth package
        sicily_response["serverCreds"] = b"NTLM"
        sicily_response["diagnosticMessage"] = b""
        return self.server.new_message(message, sicily_response)

    def _handle_sasl_bind(
        self, message: LDAPMessage, bind_auth: Any
    ) -> LDAPMessage | None:
        """Handle SASL bind request."""
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
        """Handle LDAP Search Request per RFC 4511 §4.5.

        Per RFC 4511 §4.5: The Search operation searches the directory for entries
        matching specified criteria and returns requested attributes.

        Search Request Parameters (RFC 4511 §4.5.1):
        - baseObject: DN where search starts (empty string = root DSE)
        - scope: Search scope (base=0, one=1, sub=2)
        - filter: Criteria for matching entries
        - attributes: List of attributes to return (empty = all)

        Root DSE (RFC 4512 §5.1):
        - Special entry with DN "" (empty string)
        - Contains server capabilities and configuration
        - Accessible without authentication
        - Attributes include:
          * supportedLDAPVersion: LDAP versions supported
          * supportedSASLMechanisms: SASL mechanisms available
          * supportedCapabilities: Server capability OIDs
          * namingContexts: Available directory partitions
          * defaultNamingContext: Default partition (MS-ADTS)
          * configurationNamingContext: Configuration partition (MS-ADTS)
          * rootDomainNamingContext: Root domain partition (MS-ADTS)

        Search Scopes (RFC 4511 §4.5.1.2):
        - baseObject (0): Search only the base entry
        - singleLevel (1): Search immediate children only
        - wholeSubtree (2): Search base and all descendants

        This implementation supports limited search functionality:
        - Root DSE queries (base DN = "")
        - Basic hostname/DN queries
        - Does not implement full directory tree traversal
        """
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
        """Handle LDAP Extended Request per RFC 4511 §4.12.

        Per RFC 4511 §4.12: Extended operations provide a mechanism for defining
        additional operations beyond the core LDAP protocol. Each operation is
        identified by a unique OID.

        This implementation supports:
        - StartTLS (RFC 4511 §4.14 / RFC 4513 §3): Upgrade connection to TLS

        Extended Request Format (RFC 4511 §4.12):
        - requestName: OID identifying the operation
        - requestValue: Optional operation-specific data

        Extended Response Format (RFC 4511 §4.12):
        - resultCode: Success/failure indication
        - responseName: Optional OID (typically echoes request)
        - responseValue: Optional operation-specific result data
        """
        self.logger.debug(f"LDAP Extended Request from {self.client_address}")
        self.logger.debug(f"Extended message ID: {message['messageID']}")

        req_oid = str(extended_req["requestName"])
        req_value = extended_req["requestValue"]
        if req_value.hasValue():
            req_value = bytes(req_value)
            self.logger.debug(f"Extended OID: {req_oid}, value length: {len(req_value)}")
        else:
            self.logger.debug(f"Extended OID: {req_oid}, no value")

        print(req_oid)
        if req_oid == LDAP_STARTTLS_OID:
            """Handle StartTLS Extended Operation per RFC 4513 §3.

            Per RFC 4513 §3: StartTLS upgrades an existing LDAP connection to use
            TLS encryption. This protects subsequent operations from eavesdropping.

            StartTLS Protocol Flow (RFC 4513 §3.1):
            1. Client sends StartTLS extended request
            2. Server sends success response
            3. Client and server perform TLS handshake
            4. Connection is now encrypted, authentication can proceed

            Restrictions (RFC 4513 §3.1.1):
            - MUST NOT be used if TLS is already active
            - MUST NOT be used during SASL negotiation
            - MUST NOT be used after successful bind (some implementations)

            Per RFC 5929: After StartTLS, channel binding can be used to bind
            SASL authentication to the TLS channel, preventing relay attacks.
            """
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
        # terminate connection
        raise LDAPTerminateSession

    # ===========================================================================
    # SASL Mechanism Handlers
    # ===========================================================================

    def _handle_sasl_GSS_SPNEGO(
        self, message: LDAPMessage, bind_auth: Any
    ) -> LDAPMessage | None:
        """Handle SASL GSS-SPNEGO mechanism."""
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
        """Fallback handler when SPNEGO parsing fails."""
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
                return self._handle_NTLM_Negotiate(message, data)

            if msg_type == 3:
                self.logger.debug("Direct NTLM: detected NTLM authenticate message")
                return self._handle_NTLM_Auth(message, data)

            self.logger.debug(f"Direct NTLM: unsupported NTLM message type {msg_type}")
            return self.server.bind_result(message, reason=LDAP_AUTH_METHOD_NOT_SUPPORTED)

        except Exception as e:
            self.logger.debug(f"Direct NTLM: failed to parse token: {e}")
            return self.server.bind_result(message, reason=LDAP_AUTH_METHOD_NOT_SUPPORTED)

    def _handle_NTLM_Negotiate(self, message: LDAPMessage, nego_token_raw: bytes) -> None:
        """Handle NTLM Negotiate message."""
        negotiate = NTLMAuthNegotiate()
        negotiate.fromString(nego_token_raw)

        fqdn = self.server.server_config.ldap_fqdn
        name, domain = fqdn.split(".", 1) if "." in fqdn else (fqdn, "")

        ntlm_challenge = NTLM_AUTH_CreateChallenge(
            negotiate,
            name,
            domain,
            challenge=self.server.server_config.ntlm_challenge,
            disable_ess=self.server.server_config.ntlm_disable_ess,
            disable_ntlmv2=self.server.server_config.ntlm_disable_ntlmv2,
        )
        self.send(self.server.bind_result(message, matched_dn=ntlm_challenge.getData()))
        return None

    def _handle_NTLM_Auth(self, message: LDAPMessage, blob: bytes) -> None:
        """Handle NTLM Authenticate message."""
        auth_message = NTLMAuthChallengeResponse()
        auth_message.fromString(blob)
        NTLM_report_auth(
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
        """Handle SASL DIGEST-MD5 mechanism per RFC 2831.

        Per RFC 2831: DIGEST-MD5 is a SASL mechanism based on HTTP Digest Authentication.
        NOTE: DIGEST-MD5 is DEPRECATED per RFC 6331 due to security issues, but still
        supported for legacy client compatibility.

        DIGEST-MD5 Protocol Flow (RFC 2831 §2.1):
        1. Client sends empty initial response (or no response)
        2. Server sends challenge with realm, nonce, qop, etc.
        3. Client sends response with username, realm, nonce, digest, etc.
        4. Server verifies digest and sends success/failure

        Challenge Format (RFC 2831 §2.1.1):
        - realm: Protection space (typically DNS domain)
        - nonce: Server-generated random value (prevents replay)
        - qop: Quality of protection options (auth, auth-int, auth-conf)
        - algorithm: Hash algorithm (md5-sess recommended)
        - charset: Character encoding (utf-8)
        - maxbuf: Maximum buffer size for integrity/confidentiality layers

        Response Format (RFC 2831 §2.1.2):
        - username: User's identity
        - realm: Selected realm from challenge
        - nonce: Echoed from challenge
        - cnonce: Client-generated nonce
        - nc: Nonce count (prevents replay)
        - qop: Selected quality of protection
        - digest-uri: Service and host (e.g., "ldap/server.example.com")
        - response: MD5 digest proving knowledge of password

        Security Considerations (RFC 2831 §4):
        - Vulnerable to dictionary attacks (password not transmitted but digest is)
        - md5-sess algorithm is weak (MD5 is cryptographically broken)
        - Deprecated in favor of SCRAM mechanisms (RFC 5802)
        """
        try:
            credentials = bytes(bind_auth["credentials"])
            self.logger.debug(f"DIGEST-MD5: Received credentials: {credentials!r}")
        except (PyAsn1Error, KeyError):
            credentials = b""

        # RFC 2831 §2.1: Client may send empty initial response
        # Server responds with challenge containing realm, nonce, qop, etc.
        if not credentials or len(credentials) == 0:
            self.logger.debug("DIGEST-MD5: Sending initial challenge")
            nonce = f"+Upgraded+v1{secrets.token_hex(32)}"
            timestamp = str(int(time.time()))

            # Use configured domain as realm instead of hardcoded value
            realm = self.server.server_config.ldap_domain or DIGEST_MD5_REALM
            self.digest_md5_state = {
                "nonce": nonce,
                "timestamp": timestamp,
                "realm": realm,
            }

            # Only offer QoP options that are actually supported
            # Windows clients work best with just "auth"
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
                    sasl_credentials=challenge.encode("utf-8"),  # Ensure UTF-8 encoding
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
            "DIGEST-MD5 (md5-sess) hash captured but NOT CRACKABLE with current hashcat versions. See hashcat/issues/2359"
        )
        self.config.db.add_auth(
            client=self.client_address,
            credtype="digest-md5",
            username=username,
            password=digest_hash,
            domain=domain,
            logger=self.logger,
            extras=extras,
        )

        self.logger.debug(
            "DIGEST-MD5: Captured digest response for offline analysis (WARNING: not currently crackable with hashcat)"
        )
        if qop and qop in ["auth", "auth-int", "auth-conf"]:
            self.auth_state.set_negotiated_qop(qop)
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
        except Exception as e:
            self.logger.debug(f"DIGEST-MD5: Failed to parse response: {e}")
            return None
        else:
            return parsed

    def _handle_sasl_PLAIN(
        self, message: LDAPMessage, bind_auth: Any
    ) -> LDAPMessage | None:
        """Handle SASL PLAIN mechanism."""
        credentials = bytes(bind_auth["credentials"])
        self.logger.debug(f"SASL PLAIN: Received credentials: {credentials!r}")

        try:
            parts = credentials.split(b"\x00", 2)
            if len(parts) != 3:
                self.logger.debug(
                    "SASL PLAIN: Invalid credential format (expected 3 parts)"
                )
                return self.server.bind_result(message, reason=LDAP_INVALID_CREDENTIALS)

        except Exception as e:
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
                credtype="plain",
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
        """Handle SASL NTLM mechanism (direct, not wrapped in SPNEGO)."""
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
        """Handle NTLM Negotiate message in SASL NTLM."""
        try:
            negotiate = NTLMAuthNegotiate()
            negotiate.fromString(negotiate_data)
        except Exception as e:
            self.logger.debug(f"SASL NTLM: Failed to parse negotiate: {e}")
            if self.sasl_state:
                self.sasl_state.transition(SASLAuthState.FAILED)
            return self.server.bind_result(message, reason=LDAP_AUTH_METHOD_NOT_SUPPORTED)

        fqdn = self.server.server_config.ldap_fqdn
        name, domain = fqdn.split(".", 1) if "." in fqdn else (fqdn, "")

        ntlm_challenge = NTLM_AUTH_CreateChallenge(
            negotiate,
            name,
            domain,
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
        """Handle NTLM Authenticate message in SASL NTLM."""
        try:
            auth_message = NTLMAuthChallengeResponse()
            auth_message.fromString(authenticate_data)
        except Exception as e:
            self.logger.debug(f"SASL NTLM: Failed to parse authenticate: {e}")
            if self.sasl_state:
                self.sasl_state.transition(SASLAuthState.FAILED)
            return self.server.bind_result(message, reason=LDAP_AUTH_METHOD_NOT_SUPPORTED)

        NTLM_report_auth(
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


# ===========================================================================
# Protocol Module
# ===========================================================================


class LDAP(BaseProtocolModule[LDAPServerConfig]):
    """LDAP Protocol Module.

    Manages LDAP server instances, supporting both TCP (LDAP) and UDP (CLDAP)
    connections. Handles server thread creation and configuration.

    Implemented Operations (RFC 4511):
    - Bind: Simple auth, NTLM via Sicily, SASL mechanisms (GSS-SPNEGO, DIGEST-MD5, PLAIN, NTLM)
    - Search: Limited to root DSE queries for capabilities/mechanisms
    - Extended: StartTLS only
    - Unbind: Connection termination

    Authentication Mechanisms (MS-ADTS §5.1.1.1):
    - Simple Bind: Anonymous, unauthenticated, and credentialed binds
    - Sicily: Microsoft NTLM authentication extension
    - SASL: GSS-SPNEGO (NTLM), DIGEST-MD5, PLAIN, NTLM
    """

    name: str = "LDAP"
    config_ty = LDAPServerConfig
    config_attr = DEFAULT_ATTR
    config_enabled_attr = DEFAULT_ATTR
    config_list = True

    @override
    def create_server_thread(
        self, session: SessionConfig, server_config: LDAPServerConfig
    ) -> BaseServerThread[LDAPServerConfig]:
        """Create a server thread for LDAP or CLDAP based on configuration."""
        server_cls = CLDAPServer if server_config.ldap_udp else LDAPServer
        return ServerThread(
            session,
            server_config,
            server_cls,
            server_address=(session.bind_address, server_config.ldap_port),
            include_server_config=True,
        )


__proto__ = ["LDAP"]
