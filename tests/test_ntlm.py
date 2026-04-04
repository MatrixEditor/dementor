"""Unit tests for dementor.protocols.ntlm — NTLM authentication helpers.

Tests cover every public and private function in ntlm.py, organized by tier:
  Tier 1 (pure functions): no mocking needed
  Tier 2 (mock-dependent): require impacket objects or MagicMock
"""

from __future__ import annotations

import struct
from unittest.mock import MagicMock

import pytest
from impacket import ntlm

from dementor.protocols.ntlm import (
    NTLM_ESS_ZERO_PAD,
    NTLM_FILETIME_EPOCH_OFFSET,
    NTLM_REVISION_W2K3,
    NTLM_TRANSPORT_CLEARTEXT,
    NTLM_TRANSPORT_RAW,
    NTLM_V1,
    NTLM_V1_ESS,
    NTLM_V2,
    NTLM_V2_LM,
    NTLM_VERSION_PLACEHOLDER,
    NTLM_build_challenge_message,
    NTLM_decode_string,
    NTLM_encode_string,
    NTLM_handle_authenticate_message,
    NTLM_handle_legacy_raw_auth,
    NTLM_handle_negotiate_message,
    NTLM_timestamp,
    NTLM_to_hashcat,
    _classify_hash_type,
    _compute_dummy_lm_responses,
    _config_version_to_bytes,
    _decode_ntlmssp_os_version,
    _is_anonymous_authenticate,
    _log_ntlmv2_blob,
)

# Fixed 8-byte challenge for deterministic tests
CHALLENGE = b"\x01\x02\x03\x04\x05\x06\x07\x08"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_logger():
    lg = MagicMock()
    lg.extra = {"protocol": "SMB"}
    lg.format_inline = MagicMock(return_value="")
    return lg


@pytest.fixture
def mock_session():
    s = MagicMock()
    s.db.add_auth = MagicMock()
    s.db.add_host = MagicMock()
    return s


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_ntlm_negotiate(flags: int) -> ntlm.NTLMAuthNegotiate:
    """Build a real NTLMAuthNegotiate with given flags."""
    neg = ntlm.NTLMAuthNegotiate()
    neg["flags"] = flags
    # impacket requires os_version when NTLMSSP_NEGOTIATE_VERSION (0x02000000) is set
    if flags & ntlm.NTLMSSP_NEGOTIATE_VERSION:
        neg["os_version"] = b"\x0a\x00\x00\x00\x00\x00\x00\x0f"  # Win10 placeholder
    data = neg.getData()
    parsed = ntlm.NTLMAuthNegotiate()
    parsed.fromString(data)
    return parsed


def _build_ntlm_authenticate(
    *,
    flags: int = ntlm.NTLMSSP_NEGOTIATE_UNICODE,
    user_name: bytes = b"",
    domain_name: bytes = b"",
    nt_response: bytes = b"",
    lm_response: bytes = b"",
    host_name: bytes = b"",
) -> ntlm.NTLMAuthChallengeResponse:
    """Build a real NTLMAuthChallengeResponse by constructing raw wire bytes.

    impacket's NTLMAuthChallengeResponse.__init__ tries to compute the actual
    NTLM response from password/hash, so we bypass it by building the wire
    format manually and parsing with fromString().
    """
    # Fixed header: signature(8) + type(4) + 6×security_buffer(8 each) + flags(4) = 64
    header_len = 8 + 4 + (8 * 6) + 4  # = 64

    # Payload order: domain, user, host, lanman, ntlm, session_key
    session_key = b""
    payloads = [domain_name, user_name, host_name, lm_response, nt_response, session_key]

    # Compute offsets
    offset = header_len
    offsets = []
    for p in payloads:
        offsets.append(offset)
        offset += len(p)

    # Build wire bytes
    data = b"NTLMSSP\x00"  # Signature
    data += struct.pack("<L", 3)  # MessageType = AUTHENTICATE
    # LmChallengeResponse security buffer
    data += struct.pack("<HHL", len(lm_response), len(lm_response), offsets[3])
    # NtChallengeResponse security buffer
    data += struct.pack("<HHL", len(nt_response), len(nt_response), offsets[4])
    # DomainName security buffer
    data += struct.pack("<HHL", len(domain_name), len(domain_name), offsets[0])
    # UserName security buffer
    data += struct.pack("<HHL", len(user_name), len(user_name), offsets[1])
    # Workstation security buffer
    data += struct.pack("<HHL", len(host_name), len(host_name), offsets[2])
    # EncryptedRandomSessionKey security buffer
    data += struct.pack("<HHL", len(session_key), len(session_key), offsets[5])
    # NegotiateFlags
    data += struct.pack("<L", flags)
    # Payloads
    for p in payloads:
        data += p

    parsed = ntlm.NTLMAuthChallengeResponse()
    parsed.fromString(data)
    return parsed


# ===========================================================================
# Tier 1: Pure Functions
# ===========================================================================


class TestNTLMTimestamp:
    """NTLM_timestamp() at line 1607."""

    def test_returns_positive_int(self):
        assert NTLM_timestamp() > 0

    def test_after_epoch_offset(self):
        assert NTLM_timestamp() > NTLM_FILETIME_EPOCH_OFFSET

    def test_monotonic(self):
        t1 = NTLM_timestamp()
        t2 = NTLM_timestamp()
        assert t2 >= t1


class TestConfigVersionToBytes:
    """_config_version_to_bytes(value) at line 171."""

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (None, NTLM_VERSION_PLACEHOLDER),
            ("", NTLM_VERSION_PLACEHOLDER),
            ("0.0.0", NTLM_VERSION_PLACEHOLDER),
            (
                "10.0.19041",
                bytes([10, 0])
                + (19041).to_bytes(2, "little")
                + b"\x00\x00\x00"
                + bytes([NTLM_REVISION_W2K3]),
            ),
            (
                "6.1.7601",
                bytes([6, 1])
                + (7601).to_bytes(2, "little")
                + b"\x00\x00\x00"
                + bytes([NTLM_REVISION_W2K3]),
            ),
            (
                "10.0.20348",
                bytes([10, 0])
                + (20348).to_bytes(2, "little")
                + b"\x00\x00\x00"
                + bytes([NTLM_REVISION_W2K3]),
            ),
            # Single-part version
            (
                "10",
                bytes([10, 0, 0, 0]) + b"\x00\x00\x00" + bytes([NTLM_REVISION_W2K3]),
            ),
            # Two-part version
            (
                "6.3",
                bytes([6, 3, 0, 0]) + b"\x00\x00\x00" + bytes([NTLM_REVISION_W2K3]),
            ),
            # Overflow: major 256 & 0xFF = 0
            (
                "256.0.0",
                bytes([0, 0, 0, 0]) + b"\x00\x00\x00" + bytes([NTLM_REVISION_W2K3]),
            ),
            # Overflow: build 65536 & 0xFFFF = 0
            (
                "10.0.65536",
                bytes([10, 0, 0, 0]) + b"\x00\x00\x00" + bytes([NTLM_REVISION_W2K3]),
            ),
        ],
        ids=[
            "none",
            "empty",
            "zero",
            "win10_19041",
            "win7_7601",
            "srv2022_20348",
            "major_only",
            "major_minor",
            "overflow_major",
            "overflow_build",
        ],
    )
    def test_version(self, value, expected):
        result = _config_version_to_bytes(value)
        assert len(result) == 8
        assert result == expected


class TestNTLMDecodeString:
    """NTLM_decode_string(data, negotiate_flags, is_negotiate_oem) at line 357."""

    UNICODE = ntlm.NTLMSSP_NEGOTIATE_UNICODE

    @pytest.mark.parametrize(
        ("data", "flags", "is_oem", "expected"),
        [
            (None, 0, False, ""),
            (b"", 0, False, ""),
            ("Test".encode("utf-16-le"), ntlm.NTLMSSP_NEGOTIATE_UNICODE, False, "Test"),
            (b"Test", 0, False, "Test"),  # cp437 fallback
            (b"Test", ntlm.NTLMSSP_NEGOTIATE_UNICODE, True, "Test"),  # oem overrides
            ("Hi\x00".encode("utf-16-le"), ntlm.NTLMSSP_NEGOTIATE_UNICODE, False, "Hi"),
            (
                "\u00e9".encode("utf-16-le"),
                ntlm.NTLMSSP_NEGOTIATE_UNICODE,
                False,
                "\u00e9",
            ),
            (b"\x80\x81", 0, False, "\u00c7\u00fc"),  # cp437 special chars
            (b"\xff\xfe", 0, True, "\ufffd\ufffd"),  # bad ASCII -> replacement
        ],
        ids=[
            "none",
            "empty",
            "unicode_utf16",
            "no_flag_cp437",
            "oem_overrides_flag",
            "trailing_null_stripped",
            "non_ascii_unicode",
            "cp437_special",
            "bad_ascii_replacement",
        ],
    )
    def test_decode(self, data, flags, is_oem, expected):
        result = NTLM_decode_string(data, flags, is_oem)
        assert result == expected


class TestNTLMEncodeString:
    """NTLM_encode_string(string, negotiate_flags) at line 397."""

    @pytest.mark.parametrize(
        ("string", "flags", "expected"),
        [
            (None, ntlm.NTLMSSP_NEGOTIATE_UNICODE, b""),
            ("", ntlm.NTLMSSP_NEGOTIATE_UNICODE, b""),
            ("DEMENTOR", ntlm.NTLMSSP_NEGOTIATE_UNICODE, "DEMENTOR".encode("utf-16le")),
            ("DEMENTOR", 0, b"DEMENTOR"),  # OEM
            ("\u00e9", ntlm.NTLMSSP_NEGOTIATE_UNICODE, "\u00e9".encode("utf-16le")),
            ("\u00e9", 0, "\u00e9".encode("cp437", errors="replace")),
        ],
        ids=[
            "none",
            "empty",
            "unicode_encoding",
            "oem_encoding",
            "unicode_non_ascii",
            "oem_non_ascii",
        ],
    )
    def test_encode(self, string, flags, expected):
        assert NTLM_encode_string(string, flags) == expected

    def test_roundtrip_unicode(self):
        flags = ntlm.NTLMSSP_NEGOTIATE_UNICODE
        original = "Test123"
        encoded = NTLM_encode_string(original, flags)
        decoded = NTLM_decode_string(encoded, flags)
        assert decoded == original


class TestClassifyHashType:
    """_classify_hash_type(nt_response, lm_response, negotiate_flags) at line 1116."""

    ESS_FLAG = ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY

    @pytest.mark.parametrize(
        ("nt_len", "lm_pattern", "flags", "expected"),
        [
            # v2: nt > 24 bytes
            (48, b"\x00" * 24, 0, NTLM_V2),
            # v1-ESS: nt=24, lm=CChal(8)+Z(16)
            (
                24,
                b"\xaa" * 8 + b"\x00" * 16,
                ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY,
                NTLM_V1_ESS,
            ),
            # v1: nt=24, random lm
            (24, b"\xbb" * 24, 0, NTLM_V1),
            # ESS flag set but lm doesn't match -> v1 (LM overrides flag)
            (24, b"\xcc" * 24, ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY, NTLM_V1),
            # lm matches but no ESS flag -> v1-ESS (LM authoritative)
            (24, b"\xdd" * 8 + b"\x00" * 16, 0, NTLM_V1_ESS),
            # Boundary: exactly 25 bytes -> v2
            (25, b"\x00" * 24, 0, NTLM_V2),
            # Boundary: exactly 24 bytes, no ESS -> v1
            (24, b"\xee" * 24, 0, NTLM_V1),
            # ESS zero pad with non-zero client challenge
            (24, b"\xff" * 8 + b"\x00" * 16, 0, NTLM_V1_ESS),
        ],
        ids=[
            "v2_long_nt",
            "v1_ess_lm_pattern_with_flag",
            "v1_plain",
            "ess_flag_no_lm_match",
            "lm_match_no_flag",
            "v2_boundary_25",
            "v1_boundary_24",
            "ess_zero_pad_nonzero_cchal",
        ],
    )
    def test_classify(self, nt_len, lm_pattern, flags, expected):
        nt = b"\x11" * nt_len
        result = _classify_hash_type(nt, lm_pattern, flags)
        assert result == expected

    def test_none_nt_response(self):
        assert _classify_hash_type(None, b"\x00" * 24, 0) == NTLM_V1

    def test_none_lm_response(self):
        assert (
            _classify_hash_type(
                b"\x11" * 24, None, ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
            )
            == NTLM_V1
        )

    def test_none_flags(self):
        # negotiate_flags=None -> TypeError caught, ess_by_flag=False
        result = _classify_hash_type(b"\x11" * 24, b"\xaa" * 24, None)
        assert result == NTLM_V1


class TestComputeDummyLmResponses:
    """_compute_dummy_lm_responses(server_challenge) at line 1185."""

    def test_returns_set_of_two(self):
        result = _compute_dummy_lm_responses(CHALLENGE)
        assert isinstance(result, set)
        assert len(result) == 2

    def test_each_is_24_bytes(self):
        for r in _compute_dummy_lm_responses(CHALLENGE):
            assert len(r) == 24

    def test_different_challenges_produce_different_sets(self):
        s1 = _compute_dummy_lm_responses(CHALLENGE)
        s2 = _compute_dummy_lm_responses(b"\xff" * 8)
        assert s1 != s2

    def test_contains_desl_of_null_hash(self):
        result = _compute_dummy_lm_responses(CHALLENGE)
        null_desl = ntlm.ntlmssp_DES_encrypt(NTLM_ESS_ZERO_PAD, CHALLENGE)
        assert null_desl in result


class TestNTLMToHashcat:
    """NTLM_to_hashcat(...) at line 1231 — THE MOST CRITICAL function."""

    # -- NetNTLMv2 (hashcat -m 5600) -----------------------------------------

    def test_v2_primary_hash_format(self):
        nt_proof = b"\xaa" * 16
        blob = b"\xbb" * 32
        nt_response = nt_proof + blob
        result = NTLM_to_hashcat(
            CHALLENGE, "user", "domain", b"\x00" * 24, nt_response, 0
        )
        assert len(result) == 1  # Z(24) LM suppressed
        label, line = result[0]
        assert label == NTLM_V2
        parts = line.split(":")
        assert len(parts) == 6
        assert parts[0] == "user"
        assert parts[1] == ""  # empty (::)
        assert parts[2] == "domain"
        assert parts[3] == CHALLENGE.hex()
        assert parts[4] == nt_proof.hex()
        assert parts[5] == blob.hex()

    def test_v2_with_lmv2_companion(self):
        nt_response = b"\xaa" * 48
        lm_proof = b"\xcc" * 16
        lm_cchal = b"\xdd" * 8
        lm_response = lm_proof + lm_cchal
        result = NTLM_to_hashcat(CHALLENGE, "user", "domain", lm_response, nt_response, 0)
        assert len(result) == 2
        assert result[0][0] == NTLM_V2
        assert result[1][0] == NTLM_V2_LM
        lm_parts = result[1][1].split(":")
        assert lm_parts[4] == lm_proof.hex()
        assert lm_parts[5] == lm_cchal.hex()

    def test_v2_lm_suppressed_when_null(self):
        nt_response = b"\xaa" * 48
        lm_response = b"\x00" * 24
        result = NTLM_to_hashcat(CHALLENGE, "user", "domain", lm_response, nt_response, 0)
        assert len(result) == 1
        assert result[0][0] == NTLM_V2

    def test_v2_lm_wrong_length_skipped(self):
        nt_response = b"\xaa" * 48
        lm_response = b"\xcc" * 16  # wrong length
        result = NTLM_to_hashcat(CHALLENGE, "user", "domain", lm_response, nt_response, 0)
        assert len(result) == 1

    def test_v2_server_challenge_hex_16_chars(self):
        nt_response = b"\xaa" * 48
        result = NTLM_to_hashcat(
            CHALLENGE, "user", "domain", b"\x00" * 24, nt_response, 0
        )
        parts = result[0][1].split(":")
        assert len(parts[3]) == 16  # 8 bytes = 16 hex chars

    def test_v2_ntproofstr_hex_32_chars(self):
        nt_response = b"\xaa" * 48
        result = NTLM_to_hashcat(
            CHALLENGE, "user", "domain", b"\x00" * 24, nt_response, 0
        )
        parts = result[0][1].split(":")
        assert len(parts[4]) == 32  # 16 bytes = 32 hex chars

    def test_v2_user_domain_are_strings(self):
        nt_response = b"\xaa" * 48
        result = NTLM_to_hashcat(CHALLENGE, "Admin", "CORP", b"\x00" * 24, nt_response, 0)
        parts = result[0][1].split(":")
        assert parts[0] == "Admin"
        assert parts[2] == "CORP"

    def test_v2_user_as_bytes_decoded(self):
        nt_response = b"\xaa" * 48
        user_bytes = "Admin".encode("utf-16-le")
        result = NTLM_to_hashcat(
            CHALLENGE,
            user_bytes,
            "CORP",
            b"\x00" * 24,
            nt_response,
            ntlm.NTLMSSP_NEGOTIATE_UNICODE,
        )
        parts = result[0][1].split(":")
        assert parts[0] == "Admin"

    # -- NetNTLMv1-ESS (hashcat -m 5500) ------------------------------------

    def test_v1ess_hash_format(self):
        client_challenge = b"\xdd" * 8
        lm_response = client_challenge + b"\x00" * 16
        nt_response = b"\xee" * 24
        result = NTLM_to_hashcat(CHALLENGE, "user", "domain", lm_response, nt_response, 0)
        assert len(result) == 1
        label, line = result[0]
        assert label == NTLM_V1_ESS
        parts = line.split(":")
        assert len(parts) == 6

    def test_v1ess_lm_field_48_hex(self):
        lm_response = b"\xdd" * 8 + b"\x00" * 16
        nt_response = b"\xee" * 24
        result = NTLM_to_hashcat(CHALLENGE, "user", "domain", lm_response, nt_response, 0)
        parts = result[0][1].split(":")
        # LM field = CChal(8) + Z(16) = 24 bytes = 48 hex chars
        assert len(parts[3]) == 48

    def test_v1ess_nt_field_48_hex(self):
        lm_response = b"\xdd" * 8 + b"\x00" * 16
        nt_response = b"\xee" * 24
        result = NTLM_to_hashcat(CHALLENGE, "user", "domain", lm_response, nt_response, 0)
        parts = result[0][1].split(":")
        assert len(parts[4]) == 48  # 24 bytes = 48 hex chars

    def test_v1ess_server_challenge_raw(self):
        lm_response = b"\xdd" * 8 + b"\x00" * 16
        nt_response = b"\xee" * 24
        result = NTLM_to_hashcat(CHALLENGE, "user", "domain", lm_response, nt_response, 0)
        parts = result[0][1].split(":")
        # Must be raw ServerChallenge, NOT pre-computed FinalChallenge
        assert parts[5] == CHALLENGE.hex()

    # -- NetNTLMv1 (hashcat -m 5500) ----------------------------------------

    def test_v1_with_real_lm(self):
        nt_response = b"\xaa" * 24
        lm_response = b"\xbb" * 24
        result = NTLM_to_hashcat(CHALLENGE, "user", "domain", lm_response, nt_response, 0)
        assert len(result) == 1
        label, line = result[0]
        assert label == NTLM_V1
        parts = line.split(":")
        assert parts[3] == lm_response.hex()  # LM slot populated

    def test_v1_level2_duplication_lm_empty(self):
        shared = b"\xaa" * 24
        result = NTLM_to_hashcat(CHALLENGE, "user", "domain", shared, shared, 0)
        parts = result[0][1].split(":")
        assert parts[3] == ""  # LM slot empty

    def test_v1_dummy_lm_null_hash(self):
        nt_response = b"\xaa" * 24
        dummy_null = ntlm.ntlmssp_DES_encrypt(NTLM_ESS_ZERO_PAD, CHALLENGE)
        result = NTLM_to_hashcat(CHALLENGE, "user", "domain", dummy_null, nt_response, 0)
        parts = result[0][1].split(":")
        assert parts[3] == ""

    def test_v1_dummy_lm_default_hash(self):
        nt_response = b"\xaa" * 24
        dummy_default = ntlm.ntlmssp_DES_encrypt(ntlm.DEFAULT_LM_HASH, CHALLENGE)
        result = NTLM_to_hashcat(
            CHALLENGE, "user", "domain", dummy_default, nt_response, 0
        )
        parts = result[0][1].split(":")
        assert parts[3] == ""

    def test_v1_hashcat_format_six_tokens(self):
        nt_response = b"\xaa" * 24
        lm_response = b"\xbb" * 24
        result = NTLM_to_hashcat(CHALLENGE, "user", "domain", lm_response, nt_response, 0)
        parts = result[0][1].split(":")
        assert len(parts) == 6

    # -- Edge cases ----------------------------------------------------------

    def test_empty_nt_response_returns_empty(self):
        result = NTLM_to_hashcat(CHALLENGE, "user", "domain", b"", b"", 0)
        assert result == []

    def test_none_nt_response_returns_empty(self):
        result = NTLM_to_hashcat(CHALLENGE, "user", "domain", None, None, 0)
        assert result == []

    def test_bad_challenge_7_raises(self):
        with pytest.raises(ValueError, match="8 bytes"):
            NTLM_to_hashcat(b"\x00" * 7, "u", "d", b"", b"\xaa" * 24, 0)

    def test_bad_challenge_9_raises(self):
        with pytest.raises(ValueError, match="8 bytes"):
            NTLM_to_hashcat(b"\x00" * 9, "u", "d", b"", b"\xaa" * 24, 0)

    def test_user_as_string(self):
        nt_response = b"\xaa" * 48
        result = NTLM_to_hashcat(
            CHALLENGE, "TestUser", "TestDomain", b"\x00" * 24, nt_response, 0
        )
        parts = result[0][1].split(":")
        assert parts[0] == "TestUser"
        assert parts[2] == "TestDomain"


# ===========================================================================
# Tier 2: Mock-Dependent Functions
# ===========================================================================


class TestIsAnonymousAuthenticate:
    """_is_anonymous_authenticate(token) at line 472."""

    def test_structural_anonymous_all_empty(self):
        token = _build_ntlm_authenticate(user_name=b"", nt_response=b"", lm_response=b"")
        assert _is_anonymous_authenticate(token) is True

    def test_structural_anonymous_lm_z1(self):
        token = _build_ntlm_authenticate(
            user_name=b"", nt_response=b"", lm_response=b"\x00"
        )
        assert _is_anonymous_authenticate(token) is True

    def test_flag_anonymous(self):
        token = _build_ntlm_authenticate(
            flags=ntlm.NTLMSSP_NEGOTIATE_UNICODE | 0x00000800,  # ANONYMOUS flag
            user_name=b"",
            nt_response=b"",
            lm_response=b"",
        )
        assert _is_anonymous_authenticate(token) is True

    def test_non_anonymous_with_user(self):
        token = _build_ntlm_authenticate(
            user_name="admin".encode("utf-16-le"),
            nt_response=b"\xaa" * 24,
            lm_response=b"\xbb" * 24,
        )
        assert _is_anonymous_authenticate(token) is False

    def test_non_anonymous_with_nt(self):
        token = _build_ntlm_authenticate(
            user_name=b"", nt_response=b"\xaa" * 24, lm_response=b""
        )
        assert _is_anonymous_authenticate(token) is False

    def test_non_anonymous_with_lm(self):
        token = _build_ntlm_authenticate(
            user_name=b"", nt_response=b"", lm_response=b"\xbb" * 24
        )
        assert _is_anonymous_authenticate(token) is False

    def test_exception_returns_false(self):
        """Fail-open: parse error returns False so we don't drop captures."""
        mock_token = MagicMock()
        mock_token.__getitem__ = MagicMock(side_effect=KeyError("bad"))
        assert _is_anonymous_authenticate(mock_token) is False

    def test_both_flag_and_structural(self):
        token = _build_ntlm_authenticate(
            flags=ntlm.NTLMSSP_NEGOTIATE_UNICODE | 0x00000800,
            user_name=b"",
            nt_response=b"",
            lm_response=b"",
        )
        assert _is_anonymous_authenticate(token) is True


class TestDecodeNtlmsspOsVersion:
    """_decode_ntlmssp_os_version(token) at line 418."""

    def _make_version_bytes(self, major: int, minor: int, build: int) -> bytes:
        return (
            struct.pack("<BBH", major, minor, build)
            + b"\x00\x00\x00"
            + bytes([NTLM_REVISION_W2K3])
        )

    def test_all_zero_version(self):
        token = MagicMock()
        token.fields = {"Version": True}
        token.__getitem__ = MagicMock(return_value=b"\x00" * 8)
        assert _decode_ntlmssp_os_version(token) == ""

    def test_known_build_19041(self):
        token = MagicMock()
        ver = self._make_version_bytes(10, 0, 19041)
        token.fields = {"Version": True}
        token.__getitem__ = MagicMock(return_value=ver)
        result = _decode_ntlmssp_os_version(token)
        assert "19041" in result

    def test_known_build_7601(self):
        token = MagicMock()
        ver = self._make_version_bytes(6, 1, 7601)
        token.fields = {"Version": True}
        token.__getitem__ = MagicMock(return_value=ver)
        result = _decode_ntlmssp_os_version(token)
        assert "7601" in result

    def test_unknown_build(self):
        token = MagicMock()
        ver = self._make_version_bytes(5, 1, 12345)
        token.fields = {"Version": True}
        token.__getitem__ = MagicMock(return_value=ver)
        result = _decode_ntlmssp_os_version(token)
        assert "12345" in result

    def test_no_version_field(self):
        token = MagicMock()
        token.fields = {}
        result = _decode_ntlmssp_os_version(token)
        assert result == ""

    def test_malformed_version(self):
        token = MagicMock()
        token.fields = {"Version": True}
        token.__getitem__ = MagicMock(return_value=b"\x01")  # too short
        result = _decode_ntlmssp_os_version(token)
        # Should not crash, returns empty or partial
        assert isinstance(result, str)


class TestNTLMBuildChallengeMessage:
    """NTLM_build_challenge_message(token, *, ...) at line 587."""

    def _build(self, client_flags: int, **kwargs):
        token = _build_ntlm_negotiate(client_flags)
        defaults = {
            "challenge": CHALLENGE,
            "nb_computer": "DEMENTOR",
            "nb_domain": "WORKGROUP",
        }
        defaults.update(kwargs)
        return NTLM_build_challenge_message(token, **defaults)

    def test_challenge_in_response(self):
        msg = self._build(ntlm.NTLMSSP_NEGOTIATE_UNICODE)
        assert msg["challenge"] == CHALLENGE

    def test_bad_challenge_length_raises(self):
        token = _build_ntlm_negotiate(ntlm.NTLMSSP_NEGOTIATE_UNICODE)
        with pytest.raises(ValueError, match="8 bytes"):
            NTLM_build_challenge_message(token, challenge=b"\x00" * 7)

    def test_unicode_flag_echoed(self):
        msg = self._build(ntlm.NTLMSSP_NEGOTIATE_UNICODE)
        assert msg["flags"] & ntlm.NTLMSSP_NEGOTIATE_UNICODE

    def test_oem_flag_echoed(self):
        msg = self._build(ntlm.NTLM_NEGOTIATE_OEM)
        assert msg["flags"] & ntlm.NTLM_NEGOTIATE_OEM

    def test_sign_seal_echoed(self):
        flags = ntlm.NTLMSSP_NEGOTIATE_SIGN | ntlm.NTLMSSP_NEGOTIATE_SEAL
        msg = self._build(flags | ntlm.NTLMSSP_NEGOTIATE_UNICODE)
        assert msg["flags"] & ntlm.NTLMSSP_NEGOTIATE_SIGN
        assert msg["flags"] & ntlm.NTLMSSP_NEGOTIATE_SEAL

    def test_56_128_key_exch_echoed(self):
        flags = (
            ntlm.NTLMSSP_NEGOTIATE_56
            | ntlm.NTLMSSP_NEGOTIATE_128
            | ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH
            | ntlm.NTLMSSP_NEGOTIATE_UNICODE
        )
        msg = self._build(flags)
        assert msg["flags"] & ntlm.NTLMSSP_NEGOTIATE_56
        assert msg["flags"] & ntlm.NTLMSSP_NEGOTIATE_128
        assert msg["flags"] & ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH

    def test_ess_echoed(self):
        flags = (
            ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
            | ntlm.NTLMSSP_NEGOTIATE_UNICODE
        )
        msg = self._build(flags)
        assert msg["flags"] & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY

    def test_ess_stripped_when_disabled(self):
        flags = (
            ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
            | ntlm.NTLMSSP_NEGOTIATE_UNICODE
        )
        msg = self._build(flags, disable_ess=True)
        assert not (msg["flags"] & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY)

    def test_ess_lm_key_mutual_exclusivity(self):
        flags = (
            ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
            | ntlm.NTLMSSP_NEGOTIATE_LM_KEY
            | ntlm.NTLMSSP_NEGOTIATE_UNICODE
        )
        msg = self._build(flags)
        assert msg["flags"] & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        assert not (msg["flags"] & ntlm.NTLMSSP_NEGOTIATE_LM_KEY)

    def test_lm_key_when_no_ess(self):
        flags = ntlm.NTLMSSP_NEGOTIATE_LM_KEY | ntlm.NTLMSSP_NEGOTIATE_UNICODE
        msg = self._build(flags)
        assert msg["flags"] & ntlm.NTLMSSP_NEGOTIATE_LM_KEY

    def test_target_type_server(self):
        msg = self._build(
            ntlm.NTLMSSP_NEGOTIATE_UNICODE,
            target_type="server",
            nb_computer="SRV1",
        )
        target_name = msg["domain_name"].decode("utf-16-le")
        assert target_name == "SRV1"
        assert msg["flags"] & ntlm.NTLMSSP_TARGET_TYPE_SERVER

    def test_target_type_domain(self):
        msg = self._build(
            ntlm.NTLMSSP_NEGOTIATE_UNICODE,
            target_type="domain",
            nb_domain="DOM1",
        )
        target_name = msg["domain_name"].decode("utf-16-le")
        assert target_name == "DOM1"
        assert msg["flags"] & ntlm.NTLMSSP_TARGET_TYPE_DOMAIN

    def test_av_pairs_present(self):
        msg = self._build(
            ntlm.NTLMSSP_NEGOTIATE_UNICODE,
            disable_ntlmv2=False,
            dns_computer="srv.dom.com",
            dns_domain="dom.com",
        )
        # TargetInfoFields should not be empty
        target_info = msg["TargetInfoFields"]
        assert len(target_info) > 0
        assert msg["flags"] & ntlm.NTLMSSP_NEGOTIATE_TARGET_INFO

    def test_av_pairs_absent_disable_v2(self):
        msg = self._build(
            ntlm.NTLMSSP_NEGOTIATE_UNICODE,
            disable_ntlmv2=True,
        )
        assert msg["TargetInfoFields_len"] == 0
        assert not (msg["flags"] & ntlm.NTLMSSP_NEGOTIATE_TARGET_INFO)

    def test_mandatory_flags(self):
        msg = self._build(0)  # minimal client flags
        assert msg["flags"] & ntlm.NTLMSSP_NEGOTIATE_NTLM
        assert msg["flags"] & ntlm.NTLMSSP_NEGOTIATE_ALWAYS_SIGN
        assert msg["flags"] & ntlm.NTLMSSP_REQUEST_TARGET

    def test_version_echoed(self):
        flags = ntlm.NTLMSSP_NEGOTIATE_VERSION | ntlm.NTLMSSP_NEGOTIATE_UNICODE
        # Must build negotiate with os_version since impacket requires it with VERSION flag
        neg = ntlm.NTLMAuthNegotiate()
        neg["flags"] = flags
        neg["os_version"] = b"\x0a\x00\x00\x00\x00\x00\x00\x0f"  # Win10
        data = neg.getData()
        token = ntlm.NTLMAuthNegotiate()
        token.fromString(data)
        msg = NTLM_build_challenge_message(token, challenge=CHALLENGE)
        assert msg["flags"] & ntlm.NTLMSSP_NEGOTIATE_VERSION


class TestNTLMHandleNegotiateMessage:
    """NTLM_handle_negotiate_message(negotiate, logger) at line 517."""

    def test_returns_dict(self, mock_logger):
        neg = _build_ntlm_negotiate(ntlm.NTLMSSP_NEGOTIATE_UNICODE)
        result = NTLM_handle_negotiate_message(neg, mock_logger)
        assert isinstance(result, dict)

    def test_empty_fields_omitted(self, mock_logger):
        neg = _build_ntlm_negotiate(ntlm.NTLMSSP_NEGOTIATE_UNICODE)
        result = NTLM_handle_negotiate_message(neg, mock_logger)
        # Minimal negotiate has no workstation/domain
        for k in ("name", "domain"):
            if k in result:
                assert result[k] != ""

    def test_logger_debug_called(self, mock_logger):
        neg = _build_ntlm_negotiate(ntlm.NTLMSSP_NEGOTIATE_UNICODE)
        NTLM_handle_negotiate_message(neg, mock_logger)
        assert mock_logger.debug.called

    def test_no_version_no_os_key(self, mock_logger):
        # Without VERSION flag, os field should be empty/absent
        neg = _build_ntlm_negotiate(ntlm.NTLMSSP_NEGOTIATE_UNICODE)
        result = NTLM_handle_negotiate_message(neg, mock_logger)
        if "os" in result:
            assert result["os"] == ""

    def test_malformed_no_crash(self, mock_logger):
        # Bogus token
        token = MagicMock()
        token.__getitem__ = MagicMock(side_effect=KeyError("bad"))
        token.fields = {}
        # Should not raise
        result = NTLM_handle_negotiate_message(token, mock_logger)
        assert isinstance(result, dict)


class TestNTLMHandleAuthenticateMessage:
    """NTLM_handle_authenticate_message(auth_token, *, ...) at line 909."""

    def test_anonymous_returns_false(self, mock_logger, mock_session):
        token = _build_ntlm_authenticate(user_name=b"", nt_response=b"", lm_response=b"")
        result = NTLM_handle_authenticate_message(
            token,
            challenge=CHALLENGE,
            client=("10.0.0.1", 12345),
            session=mock_session,
            logger=mock_logger,
        )
        assert result is False
        mock_session.db.add_auth.assert_not_called()

    def test_valid_v2_returns_true(self, mock_logger, mock_session):
        nt_response = b"\xaa" * 48
        lm_response = b"\x00" * 24
        token = _build_ntlm_authenticate(
            flags=ntlm.NTLMSSP_NEGOTIATE_UNICODE,
            user_name="admin".encode("utf-16-le"),
            domain_name="CORP".encode("utf-16-le"),
            nt_response=nt_response,
            lm_response=lm_response,
        )
        result = NTLM_handle_authenticate_message(
            token,
            challenge=CHALLENGE,
            client=("10.0.0.1", 12345),
            session=mock_session,
            logger=mock_logger,
        )
        assert result is True
        assert mock_session.db.add_auth.called

    def test_valid_v1_returns_true(self, mock_logger, mock_session):
        token = _build_ntlm_authenticate(
            flags=ntlm.NTLMSSP_NEGOTIATE_UNICODE,
            user_name="admin".encode("utf-16-le"),
            nt_response=b"\xaa" * 24,
            lm_response=b"\xbb" * 24,
        )
        result = NTLM_handle_authenticate_message(
            token,
            challenge=CHALLENGE,
            client=("10.0.0.1", 12345),
            session=mock_session,
            logger=mock_logger,
        )
        assert result is True

    def test_empty_nt_response_returns_false(self, mock_logger, mock_session):
        token = _build_ntlm_authenticate(
            flags=ntlm.NTLMSSP_NEGOTIATE_UNICODE,
            user_name="admin".encode("utf-16-le"),
            nt_response=b"",
            lm_response=b"",
        )
        result = NTLM_handle_authenticate_message(
            token,
            challenge=CHALLENGE,
            client=("10.0.0.1", 12345),
            session=mock_session,
            logger=mock_logger,
        )
        assert result is False

    def test_v2_with_lmv2_companion_calls_db_twice(self, mock_logger, mock_session):
        nt_response = b"\xaa" * 48
        lm_proof = b"\xcc" * 16
        lm_cchal = b"\xdd" * 8
        lm_response = lm_proof + lm_cchal
        token = _build_ntlm_authenticate(
            flags=ntlm.NTLMSSP_NEGOTIATE_UNICODE,
            user_name="admin".encode("utf-16-le"),
            nt_response=nt_response,
            lm_response=lm_response,
        )
        NTLM_handle_authenticate_message(
            token,
            challenge=CHALLENGE,
            client=("10.0.0.1", 12345),
            session=mock_session,
            logger=mock_logger,
        )
        assert mock_session.db.add_auth.call_count == 2

    def test_bad_challenge_returns_false(self, mock_logger, mock_session):
        token = _build_ntlm_authenticate(
            flags=ntlm.NTLMSSP_NEGOTIATE_UNICODE,
            user_name="admin".encode("utf-16-le"),
            nt_response=b"\xaa" * 24,
        )
        result = NTLM_handle_authenticate_message(
            token,
            challenge=b"\x00" * 7,  # bad
            client=("10.0.0.1", 12345),
            session=mock_session,
            logger=mock_logger,
        )
        assert result is False

    def test_extras_passed_through(self, mock_logger, mock_session):
        token = _build_ntlm_authenticate(
            flags=ntlm.NTLMSSP_NEGOTIATE_UNICODE,
            user_name="admin".encode("utf-16-le"),
            nt_response=b"\xaa" * 24,
            lm_response=b"\xbb" * 24,
        )
        extras = {"custom_key": "custom_value"}
        NTLM_handle_authenticate_message(
            token,
            challenge=CHALLENGE,
            client=("10.0.0.1", 12345),
            session=mock_session,
            logger=mock_logger,
            extras=extras,
        )
        # extras dict should be passed to db.add_auth
        call_kwargs = mock_session.db.add_auth.call_args
        assert "extras" in call_kwargs.kwargs or len(call_kwargs.args) > 0

    def test_negotiate_fields_merged(self, mock_logger, mock_session):
        token = _build_ntlm_authenticate(
            flags=ntlm.NTLMSSP_NEGOTIATE_UNICODE,
            user_name="admin".encode("utf-16-le"),
            nt_response=b"\xaa" * 24,
            lm_response=b"\xbb" * 24,
        )
        neg_fields = {"os": "Windows 10 Build 19041"}
        result = NTLM_handle_authenticate_message(
            token,
            challenge=CHALLENGE,
            client=("10.0.0.1", 12345),
            session=mock_session,
            logger=mock_logger,
            negotiate_fields=neg_fields,
        )
        assert result is True
        # Should have logged with merged fields (no crash)

    def test_none_extras_handled(self, mock_logger, mock_session):
        token = _build_ntlm_authenticate(
            flags=ntlm.NTLMSSP_NEGOTIATE_UNICODE,
            user_name="admin".encode("utf-16-le"),
            nt_response=b"\xaa" * 24,
        )
        # extras=None should not crash
        result = NTLM_handle_authenticate_message(
            token,
            challenge=CHALLENGE,
            client=("10.0.0.1", 12345),
            session=mock_session,
            logger=mock_logger,
            extras=None,
        )
        assert result is True


class TestNTLMHandleLegacyRawAuth:
    """NTLM_handle_legacy_raw_auth(*, ...) at line 1461."""

    def test_cleartext_captured(self, mock_logger, mock_session):
        NTLM_handle_legacy_raw_auth(
            user_name="admin",
            domain_name="CORP",
            lm_response=b"",
            nt_response=b"",
            challenge=CHALLENGE,
            client=("10.0.0.1", 12345),
            session=mock_session,
            logger=mock_logger,
            transport=NTLM_TRANSPORT_CLEARTEXT,
            cleartext_password="Password1!",  # noqa: S106
        )
        mock_session.db.add_auth.assert_called_once()
        call_kwargs = mock_session.db.add_auth.call_args
        assert call_kwargs.kwargs.get("credtype") == "Cleartext" or "Cleartext" in str(
            call_kwargs
        )

    def test_cleartext_empty_skips(self, mock_logger, mock_session):
        NTLM_handle_legacy_raw_auth(
            user_name="admin",
            domain_name="CORP",
            lm_response=b"",
            nt_response=b"",
            challenge=CHALLENGE,
            client=("10.0.0.1", 12345),
            session=mock_session,
            logger=mock_logger,
            transport=NTLM_TRANSPORT_CLEARTEXT,
            cleartext_password="",
        )
        mock_session.db.add_auth.assert_not_called()

    def test_raw_v1_captured(self, mock_logger, mock_session):
        NTLM_handle_legacy_raw_auth(
            user_name="admin",
            domain_name="CORP",
            lm_response=b"\xbb" * 24,
            nt_response=b"\xaa" * 24,
            challenge=CHALLENGE,
            client=("10.0.0.1", 12345),
            session=mock_session,
            logger=mock_logger,
            transport=NTLM_TRANSPORT_RAW,
        )
        assert mock_session.db.add_auth.called

    def test_raw_anonymous_skips(self, mock_logger, mock_session):
        NTLM_handle_legacy_raw_auth(
            user_name="",
            domain_name="",
            lm_response=b"",
            nt_response=b"",
            challenge=CHALLENGE,
            client=("10.0.0.1", 12345),
            session=mock_session,
            logger=mock_logger,
            transport=NTLM_TRANSPORT_RAW,
        )
        mock_session.db.add_auth.assert_not_called()

    def test_raw_anonymous_z1_skips(self, mock_logger, mock_session):
        NTLM_handle_legacy_raw_auth(
            user_name="",
            domain_name="",
            lm_response=b"\x00",
            nt_response=b"",
            challenge=CHALLENGE,
            client=("10.0.0.1", 12345),
            session=mock_session,
            logger=mock_logger,
            transport=NTLM_TRANSPORT_RAW,
        )
        mock_session.db.add_auth.assert_not_called()

    def test_raw_both_empty_skips(self, mock_logger, mock_session):
        NTLM_handle_legacy_raw_auth(
            user_name="admin",
            domain_name="CORP",
            lm_response=b"",
            nt_response=b"",
            challenge=CHALLENGE,
            client=("10.0.0.1", 12345),
            session=mock_session,
            logger=mock_logger,
            transport=NTLM_TRANSPORT_RAW,
        )
        mock_session.db.add_auth.assert_not_called()

    def test_bad_challenge_no_crash(self, mock_logger, mock_session):
        # 7-byte challenge should log error, not crash
        NTLM_handle_legacy_raw_auth(
            user_name="admin",
            domain_name="CORP",
            lm_response=b"\xbb" * 24,
            nt_response=b"\xaa" * 24,
            challenge=b"\x00" * 7,
            client=("10.0.0.1", 12345),
            session=mock_session,
            logger=mock_logger,
            transport=NTLM_TRANSPORT_RAW,
        )
        # Should not crash — ValueError caught internally

    def test_user_bytes_decoded(self, mock_logger, mock_session):
        NTLM_handle_legacy_raw_auth(
            user_name=b"Admin",
            domain_name=b"CORP",
            lm_response=b"\xbb" * 24,
            nt_response=b"\xaa" * 24,
            challenge=CHALLENGE,
            client=("10.0.0.1", 12345),
            session=mock_session,
            logger=mock_logger,
            transport=NTLM_TRANSPORT_RAW,
        )
        assert mock_session.db.add_auth.called


class TestLogNtlmv2Blob:
    """_log_ntlmv2_blob(auth_token, log) at line 816."""

    def test_v1_returns_none(self, mock_logger):
        token = _build_ntlm_authenticate(nt_response=b"\xaa" * 24)
        result = _log_ntlmv2_blob(token, mock_logger)
        assert result is None

    def test_short_blob_returns_none(self, mock_logger):
        # NTProofStr(16) + 1 byte = 17 total, too short for blob
        token = _build_ntlm_authenticate(nt_response=b"\xaa" * 17)
        result = _log_ntlmv2_blob(token, mock_logger)
        assert result is None

    def test_v2_no_spn_returns_none(self, mock_logger):
        # NTProofStr(16) + minimal blob without SPN AV_PAIR
        # Build a minimal blob: 28 bytes header + MsvAvEOL(4 bytes)
        blob_header = b"\x01\x01" + b"\x00" * 6  # Resp type + reserved
        blob_header += b"\x00" * 8  # TimeStamp
        blob_header += b"\x00" * 8  # ClientChallenge
        blob_header += b"\x00" * 4  # Reserved
        # MsvAvEOL: type=0x0000, len=0x0000
        av_eol = b"\x00\x00\x00\x00"
        blob = blob_header + av_eol
        nt_response = b"\xaa" * 16 + blob  # NTProofStr + blob
        token = _build_ntlm_authenticate(nt_response=nt_response)
        result = _log_ntlmv2_blob(token, mock_logger)
        assert result is None

    def test_v2_with_spn_returns_string(self, mock_logger):
        # Build a blob with SPN AV_PAIR (type=0x0009)
        blob_header = b"\x01\x01" + b"\x00" * 6
        blob_header += b"\x00" * 8  # TimeStamp
        blob_header += b"\x00" * 8  # ClientChallenge
        blob_header += b"\x00" * 4  # Reserved
        # MsvAvTargetName: type=0x0009, len=20
        spn = "cifs/server".encode("utf-16-le")
        av_spn = struct.pack("<HH", 0x0009, len(spn)) + spn
        av_eol = b"\x00\x00\x00\x00"
        blob = blob_header + av_spn + av_eol
        nt_response = b"\xaa" * 16 + blob
        token = _build_ntlm_authenticate(nt_response=nt_response)
        result = _log_ntlmv2_blob(token, mock_logger)
        assert result is not None
        assert "cifs/server" in result

    def test_logger_called_with_blob_info(self, mock_logger):
        blob_header = b"\x01\x01" + b"\x00" * 6
        blob_header += b"\x00" * 8
        blob_header += b"\x00" * 8
        blob_header += b"\x00" * 4
        av_eol = b"\x00\x00\x00\x00"
        blob = blob_header + av_eol
        nt_response = b"\xaa" * 16 + blob
        token = _build_ntlm_authenticate(nt_response=nt_response)
        _log_ntlmv2_blob(token, mock_logger)
        assert mock_logger.debug.called


# ===========================================================================
# Tier 3: Real Windows Packet Capture Vectors (smb_filtered.pcapng)
# ===========================================================================

# Each tuple: (id, challenge, user, domain, nt_response, lm_response, flags,
#              expected_hash_type, has_lmv2_companion)
# Extracted from real Windows-to-Windows SMB authentication exchanges.
PCAP_VECTORS = [
    # XP SP3 -> XP SP0: NetNTLMv1-ESS (v5.1.2600) — TCP-flow-matched challenge
    (
        "XPSP3",
        bytes.fromhex("a2bb534e5d77cde7"),
        "Test",
        "XPSP3-MALAMUTE",
        bytes.fromhex("50b697cd64e774ee719fa5c7c2db871cefb9dfc7fb2e7236"),
        bytes.fromhex("4cd624a45ccbdebe00000000000000000000000000000000"),
        0xA2888205,
        "NetNTLMv1-ESS",
        False,
    ),
    # XP SP0 -> XP SP3: NetNTLMv1-ESS (no VERSION) — TCP-flow-matched challenge
    (
        "XPSP0",
        bytes.fromhex("61c6ccdc55be7307"),
        "Test",
        "XPSP0-BERNARD",
        bytes.fromhex("6ece9be82829b0264fd07c792137e7551385094865ca3bf1"),
        bytes.fromhex("a544876672e84c1300000000000000000000000000000000"),
        0xE0888215,
        "NetNTLMv1-ESS",
        False,
    ),
    # Vista -> XP SP3: NetNTLMv2 + LMv2 companion (v6.0.6002, no MsvAvTimestamp)
    (
        "Vista",
        bytes.fromhex("2ab3f203169ea297"),
        "Administrator",
        "SNOW",
        bytes.fromhex(
            "433dbce80f16d981c629e7a3b87ace860101000000000000680930d8beb8dc01e306139d895cb8c40000000002001c00580050005300500033002d004d0041004c0041004d0055005400450001001c00580050005300500033002d004d0041004c0041004d0055005400450004001c00580050005300500033002d004d0041004c0041004d0055005400450003001c00580050005300500033002d004d0041004c0041004d0055005400450008003000300000000000000000000000003000009378996a60eb5ec0254916b77b1583cd9500aa9625a3fe0ba7d82576f5fa17df0000000000000000"
        ),
        bytes.fromhex("9fbe84e81eab221a03b2dcb6efc1145ee306139d895cb8c4"),
        0xE2888215,
        "NetNTLMv2",
        True,
    ),
    # Win7 -> XP SP3: NetNTLMv2, LM=Z(24) (v6.1.7601, MsvAvTimestamp present)
    (
        "Win7",
        bytes.fromhex("e01ee29643b37d13"),
        "Administrator",
        "SNOW",
        bytes.fromhex(
            "b9601d7fe46d090e801157b1aa291bf8010100000000000072345bdabeb8dc017af3b1e54f4ff3d70000000002001c00580050005300500033002d004d0041004c0041004d0055005400450001001c00580050005300500033002d004d0041004c0041004d0055005400450004001c00580050005300500033002d004d0041004c0041004d0055005400450003001c00580050005300500033002d004d0041004c0041004d0055005400450008003000300000000000000000000000003000006f16daea222ab7a45cf22017187aaa69d59690dea1e41c27e5ef423625ab357b0a0010000000000000000000000000000000000009001c0063006900660073002f00310030002e0030002e0030002e00320031000000000000000000"
        ),
        bytes.fromhex("000000000000000000000000000000000000000000000000"),
        0xE2888215,
        "NetNTLMv2",
        False,
    ),
    # Win81 -> XP SP3: NetNTLMv2, LM=Z(24) (v6.3.9600)
    (
        "Win81",
        bytes.fromhex("729f411d13926f9c"),
        "Administrator",
        "SNOW",
        bytes.fromhex(
            "72041379cbeb2ee47ad12c83303b19c10101000000000000fee8dddcbeb8dc01b2478b0cb029f2a80000000002001c00580050005300500033002d004d0041004c0041004d0055005400450001001c00580050005300500033002d004d0041004c0041004d0055005400450004001c00580050005300500033002d004d0041004c0041004d0055005400450003001c00580050005300500033002d004d0041004c0041004d0055005400450008003000300000000000000000000000003000006526ef50a079cf4bf567d0ea54ce8f5157234bcded4a3931f3553b6488624ec70a0010000000000000000000000000000000000009001c0063006900660073002f00310030002e0030002e0030002e00320031000000000000000000"
        ),
        bytes.fromhex("000000000000000000000000000000000000000000000000"),
        0xE2888215,
        "NetNTLMv2",
        False,
    ),
    # Win10 -> Vista: NetNTLMv2, LM=Z(24) (v10.0.19041)
    (
        "Win10",
        bytes.fromhex("0fad4ccfd62e4cf3"),
        "Administrator",
        "SNOW",
        bytes.fromhex(
            "3662ed95c7fee9e882726dc6140958ee0101000000000000ec85dcdebeb8dc017b682ed1f12957fd000000000200080053004e004f00570001001a00560049005300540041002d004300480049004e004f004f004b000400100073006e006f0077002e006c006100620003002c00560049005300540041002d004300480049004e004f004f004b002e0073006e006f0077002e006c00610062000500100073006e006f0077002e006c006100620007000800ec85dcdebeb8dc0106000400020000000800300030000000000000000000000000300000888e94c4d4eb5bfac31d9c4785d1c5e8e61b723672248f3d1b402f08d7d3072b0a0010000000000000000000000000000000000009001c0063006900660073002f00310030002e0030002e0030002e00320033000000000000000000"
        ),
        bytes.fromhex("000000000000000000000000000000000000000000000000"),
        0xE2888215,
        "NetNTLMv2",
        False,
    ),
    # Win11 -> Vista: NetNTLMv2, LM=Z(24) (v10.0.26100)
    (
        "Win11",
        bytes.fromhex("229ce94d7c94d554"),
        "Administrator",
        "SNOW",
        bytes.fromhex(
            "61a9557d50f7774619c7c278a9e6adf4010100000000000089b903e1beb8dc01addc3f0de63f73be000000000200080053004e004f00570001001a00560049005300540041002d004300480049004e004f004f004b000400100073006e006f0077002e006c006100620003002c00560049005300540041002d004300480049004e004f004f004b002e0073006e006f0077002e006c00610062000500100073006e006f0077002e006c00610062000700080089b903e1beb8dc0106000400020000000800500050000000000000000000000000300000e64f3b69ccf5909a04ef4b0d7503866d1a5cb18523eed9c532b2230ee76e532378a2c3c0c910d24d5350608f1dcaef0c394d94bca7110f14beaf81d15e72b5aa0a0010000000000000000000000000000000000009001c0063006900660073002f00310030002e0030002e0030002e00320033000000000000000000"
        ),
        bytes.fromhex("000000000000000000000000000000000000000000000000"),
        0xE2888215,
        "NetNTLMv2",
        False,
    ),
    # Srv03 -> XP SP3: NetNTLMv1-ESS (v5.2.3790) — TCP-flow-matched challenge
    (
        "Srv03",
        bytes.fromhex("38ec222f9dedff96"),
        "Administrator",
        "SRV03-NANSEN",
        bytes.fromhex("77d748f877eaaec1d5ed3027dba3f6dedbb19be38b324e35"),
        bytes.fromhex("58d925bb41e4813d00000000000000000000000000000000"),
        0xA2888205,
        "NetNTLMv1-ESS",
        False,
    ),
    # Srv08 -> XP SP3: NetNTLMv2 + LMv2 companion (v6.0.6003, no MsvAvTimestamp)
    (
        "Srv08",
        bytes.fromhex("f41e901fdebbdce1"),
        "Administrator",
        "SNOW",
        bytes.fromhex(
            "a872b37228899a6892dcf5036bfa7fb601010000000000006e4fc0eabeb8dc011b22e725551ce6ec0000000002001c00580050005300500033002d004d0041004c0041004d0055005400450001001c00580050005300500033002d004d0041004c0041004d0055005400450004001c00580050005300500033002d004d0041004c0041004d0055005400450003001c00580050005300500033002d004d0041004c0041004d005500540045000800300030000000000000000000000000300000d4d1ea6edbdbbb295591e2698fbab6a893f1628697028b2899fb26fbe8c47e080000000000000000"
        ),
        bytes.fromhex("7e799cc7b43a9fb8a86909473b2fcb491b22e725551ce6ec"),
        0xE2888215,
        "NetNTLMv2",
        True,
    ),
    # Srv08R2 -> XP SP3: NetNTLMv2, LM=Z(24) (v6.1.7601)
    (
        "Srv08R2",
        bytes.fromhex("03d8fbabb0dc3caa"),
        "Administrator",
        "SNOW",
        bytes.fromhex(
            "e4d7c06e6053caa970aa0ca82a97c4c2010100000000000020550cefbeb8dc017cbad975831bf34a0000000002001c00580050005300500033002d004d0041004c0041004d0055005400450001001c00580050005300500033002d004d0041004c0041004d0055005400450004001c00580050005300500033002d004d0041004c0041004d0055005400450003001c00580050005300500033002d004d0041004c0041004d005500540045000800300030000000000000000000000000300000a268615d40b4745abec040f241160d8e06a562fe2e6f23e80c604896347fe3b30a0010000000000000000000000000000000000009001c0063006900660073002f00310030002e0030002e0030002e00320031000000000000000000"
        ),
        bytes.fromhex("000000000000000000000000000000000000000000000000"),
        0xE2888215,
        "NetNTLMv2",
        False,
    ),
    # Srv12R2 -> XP SP3: NetNTLMv2, LM=Z(24) (v6.3.9600)
    (
        "Srv12R2",
        bytes.fromhex("d9e5e0584bbdad35"),
        "Administrator",
        "SNOW",
        bytes.fromhex(
            "934b0a667635fd8a09f8a0b5673734dc01010000000000000c1af3f3beb8dc011811a35d0e03573e0000000002001c00580050005300500033002d004d0041004c0041004d0055005400450001001c00580050005300500033002d004d0041004c0041004d0055005400450004001c00580050005300500033002d004d0041004c0041004d0055005400450003001c00580050005300500033002d004d0041004c0041004d00550054004500080030003000000000000000000000000030000075848049ebb073633b4e53079befd656f9518fd5ec3f6840779cbefc610f379b0a0010000000000000000000000000000000000009001c0063006900660073002f00310030002e0030002e0030002e00320031000000000000000000"
        ),
        bytes.fromhex("000000000000000000000000000000000000000000000000"),
        0xE2888215,
        "NetNTLMv2",
        False,
    ),
    # Srv16 -> XP SP3: NetNTLMv2, LM=Z(24) (v10.0.14393) — TCP-flow-matched
    (
        "Srv16",
        bytes.fromhex("77936e2ec48d1eb5"),
        "Administrator",
        "SNOW",
        bytes.fromhex(
            "00c41cf5d13b68584e42a2c184f0e90b0101000000000000c81438f8beb8dc010c95f9788fee9a1c0000000002001c00580050005300500033002d004d0041004c0041004d0055005400450001001c00580050005300500033002d004d0041004c0041004d0055005400450004001c00580050005300500033002d004d0041004c0041004d0055005400450003001c00580050005300500033002d004d0041004c0041004d00550054004500080030003000000000000000000000000030000040109496c79f7768b78aac13f80e314482c6e7a5ead5b181f6e52ac461814f370a0010000000000000000000000000000000000009001c0063006900660073002f00310030002e0030002e0030002e00320031000000000000000000"
        ),
        bytes.fromhex("000000000000000000000000000000000000000000000000"),
        0xE2888215,
        "NetNTLMv2",
        False,
    ),
    # Srv19 -> Vista: NetNTLMv2, LM=Z(24) (v10.0.17763) — TCP-flow-matched
    (
        "Srv19",
        bytes.fromhex("0e3f0e0f5c3add3d"),
        "Administrator",
        "SNOW",
        bytes.fromhex(
            "e624a210da3efcbd1a38ce3705c261a701010000000000008c6e32fbbeb8dc011c08947292b52ef7000000000200080053004e004f00570001001a00560049005300540041002d004300480049004e004f004f004b000400100073006e006f0077002e006c006100620003002c00560049005300540041002d004300480049004e004f004f004b002e0073006e006f0077002e006c00610062000500100073006e006f0077002e006c0061006200070008008c6e32fbbeb8dc0106000400020000000800300030000000000000000000000000300000a469e855ddef824e12dc015600ed019ecf98aa2cd021dee4e67cf7c5fd683e580a0010000000000000000000000000000000000009001c0063006900660073002f00310030002e0030002e0030002e00320033000000000000000000"
        ),
        bytes.fromhex("000000000000000000000000000000000000000000000000"),
        0xE2888215,
        "NetNTLMv2",
        False,
    ),
    # Srv22 -> Vista: NetNTLMv2, LM=Z(24) (v10.0.20348) — TCP-flow-matched
    (
        "Srv22",
        bytes.fromhex("975db6c485693f24"),
        "Administrator",
        "SNOW",
        bytes.fromhex(
            "5e6c1aa4ea3d72a7506135c00cbfe8ac0101000000000000008709ffbeb8dc0165e9a57c109dc110000000000200080053004e004f00570001001a00560049005300540041002d004300480049004e004f004f004b000400100073006e006f0077002e006c006100620003002c00560049005300540041002d004300480049004e004f004f004b002e0073006e006f0077002e006c00610062000500100073006e006f0077002e006c006100620007000800008709ffbeb8dc010600040002000000080030003000000000000000000000000030000012f26e54704b1c7dc3ff05a2db7b3427f75132b3958ad45e5dbf2c2d0b21cd2e0a0010000000000000000000000000000000000009001c0063006900660073002f00310030002e0030002e0030002e00320033000000000000000000"
        ),
        bytes.fromhex("000000000000000000000000000000000000000000000000"),
        0xE2888215,
        "NetNTLMv2",
        False,
    ),
]

# Anonymous probes from pcap — XP SP3, XP SP0, Srv03, Win7 send these before real auth
# Tuple: (id, flags, lm_response)
PCAP_ANONYMOUS_PROBES = [
    ("XPSP3_anon", 0xA2888A05, b"\x00"),
    ("XPSP0_anon", 0xE0888A15, b"\x00"),
    ("Srv03_anon", 0xA2888A05, b"\x00"),
    ("Win7_anon", 0xE2888A15, b"\x00"),
]

# NEGOTIATE flags from each unique Windows version (for flag echoing validation)
PCAP_NEGOTIATE_FLAGS = {
    "XPSP3": 0xA2088207,
    "XPSP0": 0xE008B297,
    "Vista": 0xE2088297,
    "Win7": 0xE2088297,
    "Win81": 0xE2088297,
    "Win10": 0xE2088297,
    "Win11": 0xE2088297,
    "Srv03": 0xA2088207,
    "Srv08": 0xE2088297,
    "Srv08R2": 0xE2088297,
    "Srv12R2": 0xE2088297,
    "Srv16": 0xE2088297,
    "Srv19": 0xE2088297,
    "Srv22": 0xE2088297,
}


class TestPcapHashClassification:
    """Verify _classify_hash_type against real Windows packet captures.

    Each vector is a real NTLMSSP AUTHENTICATE from smb_filtered.pcapng
    (14 Windows machines, XP SP0 through Server 2022).
    """

    @pytest.mark.parametrize(
        "vec",
        PCAP_VECTORS,
        ids=[v[0] for v in PCAP_VECTORS],
    )
    def test_classify(self, vec):
        _id, _ch, _u, _d, nt_resp, lm_resp, flags, expected_type, _ = vec
        result = _classify_hash_type(nt_resp, lm_resp, flags)
        assert result == expected_type, f"{_id}: expected {expected_type}, got {result}"


class TestPcapHashcatFormat:
    """Verify NTLM_to_hashcat produces valid hashcat lines from real pcap data."""

    @pytest.mark.parametrize(
        "vec",
        PCAP_VECTORS,
        ids=[v[0] for v in PCAP_VECTORS],
    )
    def test_hashcat_output(self, vec):
        _id, challenge, user, domain, nt_resp, lm_resp, flags, expected_type, _lmv2 = vec
        result = NTLM_to_hashcat(challenge, user, domain, lm_resp, nt_resp, flags)
        assert len(result) >= 1, f"{_id}: expected at least 1 hash, got 0"

        label, line = result[0]
        parts = line.split(":")
        assert len(parts) == 6, (
            f"{_id}: expected 6 colon-separated fields, got {len(parts)}"
        )
        assert parts[0] == user, f"{_id}: user mismatch"
        assert parts[1] == "", f"{_id}: field 1 should be empty (:: separator)"
        assert parts[2] == domain, f"{_id}: domain mismatch"

        if expected_type == "NetNTLMv2":
            assert label == NTLM_V2
            # ServerChallenge = 16 hex chars
            assert len(parts[3]) == 16
            assert parts[3] == challenge.hex()
            # NTProofStr = 32 hex chars (16 bytes)
            assert len(parts[4]) == 32
            # Blob = rest of nt_response after NTProofStr
            assert parts[5] == nt_resp[16:].hex()
        elif expected_type == "NetNTLMv1-ESS":
            assert label == NTLM_V1_ESS
            # LM field = 48 hex (ClientChallenge(8) + Z(16))
            assert len(parts[3]) == 48
            # NT field = 48 hex (24 bytes)
            assert len(parts[4]) == 48
            assert parts[4] == nt_resp.hex()
            # ServerChallenge raw
            assert parts[5] == challenge.hex()

    @pytest.mark.parametrize(
        "vec",
        [v for v in PCAP_VECTORS if v[8]],  # has_lmv2 == True
        ids=[v[0] for v in PCAP_VECTORS if v[8]],
    )
    def test_lmv2_companion(self, vec):
        """Vista and Srv08 produce LMv2 companion hashes (no MsvAvTimestamp)."""
        _id, challenge, user, domain, nt_resp, lm_resp, flags, _, _ = vec
        result = NTLM_to_hashcat(challenge, user, domain, lm_resp, nt_resp, flags)
        assert len(result) == 2, (
            f"{_id}: expected 2 hashes (primary + LMv2), got {len(result)}"
        )
        assert result[1][0] == NTLM_V2_LM

        lm_parts = result[1][1].split(":")
        # LMProof = first 16 bytes of LM response
        assert lm_parts[4] == lm_resp[:16].hex()
        # ClientChallenge = last 8 bytes of LM response
        assert lm_parts[5] == lm_resp[16:24].hex()

    @pytest.mark.parametrize(
        "vec",
        [v for v in PCAP_VECTORS if v[7] == "NetNTLMv2" and not v[8]],
        ids=[v[0] for v in PCAP_VECTORS if v[7] == "NetNTLMv2" and not v[8]],
    )
    def test_lmv2_suppressed_when_null(self, vec):
        """Win7+ sends LM=Z(24) due to MsvAvTimestamp — LMv2 must be suppressed."""
        _id, challenge, user, domain, nt_resp, lm_resp, flags, _, _ = vec
        assert lm_resp == b"\x00" * 24, f"{_id}: expected Z(24) LM response"
        result = NTLM_to_hashcat(challenge, user, domain, lm_resp, nt_resp, flags)
        assert len(result) == 1, (
            f"{_id}: expected 1 hash (LMv2 suppressed), got {len(result)}"
        )


class TestPcapEssDetection:
    """Verify ESS detection on real v1-ESS vectors from pcap.

    XP SP3, XP SP0, and Srv03 produce NetNTLMv1-ESS: LM response is
    ClientChallenge(8 bytes) + Z(16 bytes).
    """

    @pytest.mark.parametrize(
        "vec",
        [v for v in PCAP_VECTORS if v[7] == "NetNTLMv1-ESS"],
        ids=[v[0] for v in PCAP_VECTORS if v[7] == "NetNTLMv1-ESS"],
    )
    def test_ess_lm_structure(self, vec):
        _id, _, _, _, nt_resp, lm_resp, _flags, _, _ = vec
        assert len(nt_resp) == 24, f"{_id}: NT response should be 24 bytes"
        assert len(lm_resp) == 24, f"{_id}: LM response should be 24 bytes"
        # Last 16 bytes must be zero (ESS signature)
        assert lm_resp[8:24] == b"\x00" * 16, f"{_id}: LM[8:24] should be Z(16)"
        # First 8 bytes are client challenge (non-zero)
        assert lm_resp[:8] != b"\x00" * 8, f"{_id}: ClientChallenge should be non-zero"


class TestPcapNtlmv2BlobParsing:
    """Verify NTLMv2 blob parsing on real v2 vectors from pcap."""

    @pytest.mark.parametrize(
        "vec",
        [v for v in PCAP_VECTORS if v[7] == "NetNTLMv2"],
        ids=[v[0] for v in PCAP_VECTORS if v[7] == "NetNTLMv2"],
    )
    def test_blob_structure(self, vec):
        """NTLMv2 response = NTProofStr(16) + ClientBlob."""
        _id, _, _, _, nt_resp, _, _, _, _ = vec
        assert len(nt_resp) > 24, f"{_id}: NTLMv2 response must be > 24 bytes"

        # NTProofStr is first 16 bytes
        nt_proof = nt_resp[:16]
        blob = nt_resp[16:]
        assert len(nt_proof) == 16

        # Blob starts with RespType=1, HiRespType=1
        assert blob[0] == 0x01, f"{_id}: RespType should be 0x01"
        assert blob[1] == 0x01, f"{_id}: HiRespType should be 0x01"

    @pytest.mark.parametrize(
        "vec",
        [v for v in PCAP_VECTORS if v[7] == "NetNTLMv2"],
        ids=[v[0] for v in PCAP_VECTORS if v[7] == "NetNTLMv2"],
    )
    def test_log_blob_no_crash(self, vec, mock_logger):
        """_log_ntlmv2_blob should parse real blobs without crashing."""
        _id, _, _, _, nt_resp, lm_resp, flags, _, _ = vec
        token = _build_ntlm_authenticate(
            flags=flags,
            nt_response=nt_resp,
            lm_response=lm_resp,
        )
        # Should not raise
        _log_ntlmv2_blob(token, mock_logger)


class TestPcapFullAuthPipeline:
    """End-to-end: run real pcap vectors through NTLM_handle_authenticate_message."""

    @pytest.mark.parametrize(
        "vec",
        PCAP_VECTORS,
        ids=[v[0] for v in PCAP_VECTORS],
    )
    def test_authenticate_captures(self, vec, mock_logger, mock_session):
        _id, challenge, user, domain, nt_resp, lm_resp, flags, _ht, has_lmv2 = vec
        token = _build_ntlm_authenticate(
            flags=flags,
            user_name=user.encode("utf-16-le"),
            domain_name=domain.encode("utf-16-le"),
            nt_response=nt_resp,
            lm_response=lm_resp,
        )
        result = NTLM_handle_authenticate_message(
            token,
            challenge=challenge,
            client=("10.0.0.99", 12345),
            session=mock_session,
            logger=mock_logger,
        )
        assert result is True, f"{_id}: should capture credentials"

        # Verify db.add_auth was called
        assert mock_session.db.add_auth.called

        if has_lmv2:
            # Vista/Srv08: should have 2 calls (primary + LMv2)
            assert mock_session.db.add_auth.call_count == 2, (
                f"{_id}: expected 2 db.add_auth calls for LMv2 companion"
            )
        else:
            assert mock_session.db.add_auth.call_count == 1, (
                f"{_id}: expected 1 db.add_auth call"
            )


class TestPcapAnonymousProbes:
    """Verify anonymous detection on real anonymous probes from pcap.

    XP SP3, XP SP0, Srv03, and Win7 send anonymous AUTHENTICATE messages
    (empty user, empty NT, LM=0x00) before the real auth exchange.
    All have the NTLMSSP_NEGOTIATE_ANONYMOUS flag (0x00000800) set.
    """

    @pytest.mark.parametrize(
        "probe",
        PCAP_ANONYMOUS_PROBES,
        ids=[p[0] for p in PCAP_ANONYMOUS_PROBES],
    )
    def test_anonymous_flag_set(self, probe):
        """Real anonymous probes have the ANONYMOUS flag (0x800)."""
        _id, flags, _lm = probe
        assert flags & 0x00000800, f"{_id}: ANONYMOUS flag should be set"

    @pytest.mark.parametrize(
        "probe",
        PCAP_ANONYMOUS_PROBES,
        ids=[p[0] for p in PCAP_ANONYMOUS_PROBES],
    )
    def test_is_anonymous_detects_probe(self, probe):
        """_is_anonymous_authenticate correctly identifies real pcap probes."""
        _id, flags, lm = probe
        token = _build_ntlm_authenticate(
            flags=flags,
            user_name=b"",
            nt_response=b"",
            lm_response=lm,
        )
        assert _is_anonymous_authenticate(token) is True, (
            f"{_id}: should be detected as anonymous"
        )

    @pytest.mark.parametrize(
        "probe",
        PCAP_ANONYMOUS_PROBES,
        ids=[p[0] for p in PCAP_ANONYMOUS_PROBES],
    )
    def test_hashcat_returns_empty(self, probe):
        """Anonymous probes produce no hashcat output."""
        _id, flags, lm = probe
        result = NTLM_to_hashcat(
            b"\x00" * 8,  # challenge doesn't matter
            "",
            "",
            lm,
            b"",  # empty NT
            flags,
        )
        assert result == [], f"{_id}: anonymous should produce no hashes"


class TestPcapNegotiateFlags:
    """Verify NTLM_build_challenge_message echoes real Windows negotiate flags correctly.

    Tests every unique negotiate flag combination from the pcap (14 Windows versions).
    Key behaviors validated:
    - UNICODE/OEM echoed
    - ESS echoed (all modern Windows request it)
    - LM_KEY stripped when ESS present (mutual exclusivity)
    - NTLM, ALWAYS_SIGN, REQUEST_TARGET always set by server
    - TARGET_INFO always set by server (NTLMv2 support)
    """

    @pytest.mark.parametrize(
        ("client_id", "neg_flags"),
        list(PCAP_NEGOTIATE_FLAGS.items()),
        ids=list(PCAP_NEGOTIATE_FLAGS.keys()),
    )
    def test_challenge_mandatory_flags(self, client_id, neg_flags):
        """Server response always has NTLM + ALWAYS_SIGN + REQUEST_TARGET."""
        token = _build_ntlm_negotiate(neg_flags)
        msg = NTLM_build_challenge_message(token, challenge=CHALLENGE)
        resp_flags = msg["flags"]
        assert resp_flags & ntlm.NTLMSSP_NEGOTIATE_NTLM
        assert resp_flags & ntlm.NTLMSSP_NEGOTIATE_ALWAYS_SIGN
        assert resp_flags & ntlm.NTLMSSP_REQUEST_TARGET

    @pytest.mark.parametrize(
        ("client_id", "neg_flags"),
        list(PCAP_NEGOTIATE_FLAGS.items()),
        ids=list(PCAP_NEGOTIATE_FLAGS.keys()),
    )
    def test_challenge_echoes_unicode(self, client_id, neg_flags):
        """Server echoes UNICODE flag from client."""
        token = _build_ntlm_negotiate(neg_flags)
        msg = NTLM_build_challenge_message(token, challenge=CHALLENGE)
        client_unicode = bool(neg_flags & ntlm.NTLMSSP_NEGOTIATE_UNICODE)
        server_unicode = bool(msg["flags"] & ntlm.NTLMSSP_NEGOTIATE_UNICODE)
        assert client_unicode == server_unicode, f"{client_id}: UNICODE echo mismatch"

    @pytest.mark.parametrize(
        ("client_id", "neg_flags"),
        list(PCAP_NEGOTIATE_FLAGS.items()),
        ids=list(PCAP_NEGOTIATE_FLAGS.keys()),
    )
    def test_challenge_ess_lm_key_exclusivity(self, client_id, neg_flags):
        """When client sends both ESS and LM_KEY, server keeps only ESS."""
        token = _build_ntlm_negotiate(neg_flags)
        msg = NTLM_build_challenge_message(token, challenge=CHALLENGE)
        resp_flags = msg["flags"]
        has_ess = bool(resp_flags & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY)
        has_lm_key = bool(resp_flags & ntlm.NTLMSSP_NEGOTIATE_LM_KEY)
        if has_ess:
            assert not has_lm_key, f"{client_id}: ESS and LM_KEY cannot both be set"

    @pytest.mark.parametrize(
        ("client_id", "neg_flags"),
        list(PCAP_NEGOTIATE_FLAGS.items()),
        ids=list(PCAP_NEGOTIATE_FLAGS.keys()),
    )
    def test_challenge_has_target_info(self, client_id, neg_flags):
        """Server always includes TargetInfo (NTLMv2 AV_PAIRs) for pcap clients."""
        token = _build_ntlm_negotiate(neg_flags)
        msg = NTLM_build_challenge_message(token, challenge=CHALLENGE)
        assert msg["flags"] & ntlm.NTLMSSP_NEGOTIATE_TARGET_INFO
        assert msg["TargetInfoFields_len"] > 0
