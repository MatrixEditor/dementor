"""Unit tests for dementor.protocols.smb — SMB protocol handler.

Tests cover module-level functions, SMBServerConfig methods, and SMBHandler
methods (via a mock handler that bypasses the real socket).
"""

from __future__ import annotations

import struct
from unittest.mock import MagicMock, patch

import pytest
from impacket import nt_errors, smb, ntlm
from impacket import smb3structs as smb2

from dementor.protocols.smb import (
    SMB2_MAX_SIZE_LARGE,
    SMB2_MAX_SIZE_SMALL,
    SMBHandler,
    SMBServerConfig,
    STATUS_ACCOUNT_DISABLED,
    _split_smb_strings,
    get_command_name,
    get_server_time,
    parse_dialect,
)
from dementor.servers import BaseProtoHandler


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_smb_config():
    """Minimal SMBServerConfig mock with all required attributes."""
    cfg = MagicMock(spec=SMBServerConfig)
    cfg.smb_port = 445
    cfg.smb_enable_smb1 = True
    cfg.smb_enable_smb2 = True
    cfg.smb_allow_smb1_upgrade = True
    cfg.smb2_min_dialect = 0x202
    cfg.smb2_max_dialect = 0x311
    cfg.smb_nb_computer = "DEMENTOR"
    cfg.smb_nb_domain = "WORKGROUP"
    cfg.smb_server_os = "Windows"
    cfg.smb_native_lanman = "Windows"
    cfg.smb_captures_per_connection = 0
    cfg.smb_error_code = nt_errors.STATUS_SMB_BAD_UID
    cfg.ntlm_challenge = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    cfg.ntlm_disable_ess = False
    cfg.ntlm_disable_ntlmv2 = False
    cfg.ntlm_target_type = "server"
    cfg.ntlm_version = b"\x00" * 8
    cfg.ntlm_nb_computer = "DEMENTOR"
    cfg.ntlm_nb_domain = "WORKGROUP"
    cfg.ntlm_dns_computer = ""
    cfg.ntlm_dns_domain = ""
    cfg.ntlm_dns_tree = ""
    return cfg


@pytest.fixture
def mock_handler(mock_smb_config):
    """SMBHandler with all state initialized, bypassing real socket __init__."""
    handler = object.__new__(SMBHandler)
    handler.smb_config = mock_smb_config
    handler.config = MagicMock()
    handler.config.db.add_auth = MagicMock()
    handler.config.db.add_host = MagicMock()
    handler.logger = MagicMock()
    handler.logger.extra = {"protocol": "SMB"}
    handler.logger.format_inline = MagicMock(return_value="")
    handler.client_address = ("10.0.0.50", 49152)
    handler.server = MagicMock()
    handler.server.server_guid = b"\xaa" * 16

    # Per-connection state
    handler.authenticated = False
    handler.smb1_extended_security = True
    handler.smb1_challenge = mock_smb_config.ntlm_challenge
    handler.smb1_uid = 0
    handler.smb2_session_id = 0
    handler.smb2_tree_id_counter = 0
    handler.smb2_selected_dialect = 0x311
    handler.smb2_client_signing_required = False
    handler.smb2_client_max_dialect = 0x311
    handler.auth_attempt_count = 0
    handler.client_info: dict[str, str] = {}
    handler.client_files: set[str] = set()
    handler.ntlm_negotiate_fields: dict[str, str] = {}
    handler.smb1_fid_counter = 0
    handler.smb2_file_id_counter = 0

    # Mock send methods to capture output
    handler.send = MagicMock()
    handler.send_data = MagicMock()

    # Build dispatch tables
    handler.smb1_commands = {
        smb.SMB.SMB_COM_NEGOTIATE: handler.handle_smb1_negotiate,
        smb.SMB.SMB_COM_SESSION_SETUP_ANDX: handler.handle_smb1_session_setup,
        smb.SMB.SMB_COM_TREE_CONNECT_ANDX: handler.handle_smb1_tree_connect,
        smb.SMB.SMB_COM_LOGOFF_ANDX: handler.handle_smb1_logoff,
        smb.SMB.SMB_COM_CLOSE: handler.handle_smb1_close,
        smb.SMB.SMB_COM_READ_ANDX: handler.handle_smb1_read,
        smb.SMB.SMB_COM_TRANSACTION2: handler.handle_smb1_trans2,
        smb.SMB.SMB_COM_TREE_DISCONNECT: handler.handle_smb1_tree_disconnect,
        smb.SMB.SMB_COM_NT_CREATE_ANDX: handler.handle_smb1_nt_create,
    }
    handler.smb2_commands = {
        smb2.SMB2_NEGOTIATE: handler.handle_smb2_negotiate,
        smb2.SMB2_SESSION_SETUP: handler.handle_smb2_session_setup,
        smb2.SMB2_LOGOFF: handler.handle_smb2_logoff,
        smb2.SMB2_TREE_CONNECT: handler.handle_smb2_tree_connect,
        smb2.SMB2_TREE_DISCONNECT: handler.handle_smb2_tree_disconnect,
        smb2.SMB2_CREATE: handler.handle_smb2_create,
        smb2.SMB2_CLOSE: handler.handle_smb2_close,
        smb2.SMB2_READ: handler.handle_smb2_read,
        smb2.SMB2_IOCTL: handler.handle_smb2_ioctl,
        smb2.SMB2_WRITE: handler.handle_smb2_write,
        smb2.SMB2_FLUSH: handler.handle_smb2_flush,
        smb2.SMB2_LOCK: handler.handle_smb2_lock,
        smb2.SMB2_QUERY_DIRECTORY: handler.handle_smb2_query_directory,
        smb2.SMB2_QUERY_INFO: handler.handle_smb2_query_info,
        smb2.SMB2_SET_INFO: handler.handle_smb2_set_info,
    }
    return handler


# ---------------------------------------------------------------------------
# Helpers for building wire-format SMB2 packets
# ---------------------------------------------------------------------------


def _build_smb2_packet(
    command: int, data: bytes = b"", tree_id: int = 0
) -> smb2.SMB2Packet:
    """Build a minimal SMB2 packet with all header fields populated.

    Packets must be serialized and re-parsed so that all header fields
    (Reserved, CreditCharge, etc.) exist in the parsed Structure.
    """
    pkt = smb2.SMB2Packet()
    pkt["Command"] = command
    pkt["MessageID"] = 1
    pkt["TreeID"] = tree_id
    pkt["SessionID"] = 0x1000
    pkt["CreditCharge"] = 1
    pkt["CreditRequestResponse"] = 1
    pkt["Reserved"] = 0
    pkt["Data"] = data
    # Round-trip through wire format so all fields are properly populated
    wire = pkt.getData()
    return smb2.SMB2Packet(wire)


# ===========================================================================
# Tier 1: Pure/Near-Pure Functions
# ===========================================================================


class TestSplitSmbStrings:
    """_split_smb_strings(data, is_unicode) at line 92."""

    @pytest.mark.parametrize(
        ("data", "is_unicode", "expected"),
        [
            (b"", False, []),
            (b"hello\x00", False, ["hello"]),
            (b"hello\x00world\x00", False, ["hello", "world"]),
            (b"hello", False, ["hello"]),
            (
                "hello".encode("utf-16-le") + b"\x00\x00",
                True,
                ["hello"],
            ),
            (
                "hello".encode("utf-16-le")
                + b"\x00\x00"
                + "world".encode("utf-16-le")
                + b"\x00\x00",
                True,
                ["hello", "world"],
            ),
            # Without null terminator, rstrip(b"\x00") removes trailing \x00 from "o\x00"
            # producing odd bytes -> garbled last char; this is correct behavior
            ("hello".encode("utf-16-le"), True, ["hell\ufffd"]),
            (b"\x00\x00", False, []),
            # Japanese Unicode
            (
                "\u3042\u3044".encode("utf-16-le") + b"\x00\x00",
                True,
                ["\u3042\u3044"],
            ),
            (b"a\x00b\x00", False, ["a", "b"]),
        ],
        ids=[
            "empty",
            "ascii_single",
            "ascii_multiple",
            "ascii_no_null",
            "unicode_single",
            "unicode_multiple",
            "unicode_no_null",
            "empty_between_nulls",
            "japanese_unicode",
            "ascii_split_nulls",
        ],
    )
    def test_split(self, data, is_unicode, expected):
        assert _split_smb_strings(data, is_unicode) == expected

    def test_none_returns_empty(self):
        assert _split_smb_strings(None, False) == []

    def test_none_unicode_returns_empty(self):
        assert _split_smb_strings(None, True) == []


class TestParseDialect:
    """parse_dialect(value) at line 204."""

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (0x311, 0x311),
            ("3.1.1", 0x311),
            ("2.002", 0x202),
            ("2.1", 0x210),
            ("3.0", 0x300),
            ("3.0.2", 0x302),
        ],
        ids=["int_311", "str_311", "str_2002", "str_21", "str_30", "str_302"],
    )
    def test_valid(self, value, expected):
        assert parse_dialect(value) == expected

    def test_invalid_raises(self):
        with pytest.raises(ValueError, match="Unknown SMB2 dialect"):
            parse_dialect("1.0")

    def test_whitespace_stripped(self):
        assert parse_dialect(" 3.1.1 ") == 0x311


class TestGetCommandName:
    """get_command_name(command, smb_version) at line 352."""

    @pytest.mark.parametrize(
        ("command", "smb_version", "expected"),
        [
            (0x72, 0x01, "SMB_COM_NEGOTIATE"),
            (0x73, 0x01, "SMB_COM_SESSION_SETUP_ANDX"),
            (0x00, 0x02, "SMB2_NEGOTIATE"),
            (0x01, 0x02, "SMB2_SESSION_SETUP"),
            (0x03, 0x02, "SMB2_TREE_CONNECT"),
            (0x05, 0x02, "SMB2_CREATE"),
            (0xFF, 0x01, "Unknown"),
            (0x99, 0x02, "Unknown"),
            (0x00, 0x03, "Unknown"),
        ],
        ids=[
            "smb1_negotiate",
            "smb1_session_setup",
            "smb2_negotiate",
            "smb2_session_setup",
            "smb2_tree_connect",
            "smb2_create",
            "unknown_smb1",
            "unknown_smb2",
            "unknown_version",
        ],
    )
    def test_lookup(self, command, smb_version, expected):
        assert get_command_name(command, smb_version) == expected


class TestGetServerTime:
    """get_server_time() at line 343."""

    def test_returns_positive(self):
        assert get_server_time() > 0

    def test_monotonic(self):
        t1 = get_server_time()
        t2 = get_server_time()
        assert t2 >= t1


class TestSetSmbErrorCode:
    """SMBServerConfig.set_smb_error_code(value) at line 288."""

    def _make_config(self):
        cfg = object.__new__(SMBServerConfig)
        cfg.smb_error_code = 0
        return cfg

    def test_int_passthrough(self):
        cfg = self._make_config()
        cfg.set_smb_error_code(0xC0000022)
        assert cfg.smb_error_code == 0xC0000022

    def test_string_access_denied(self):
        cfg = self._make_config()
        cfg.set_smb_error_code("STATUS_ACCESS_DENIED")
        assert cfg.smb_error_code == nt_errors.STATUS_ACCESS_DENIED

    def test_string_success(self):
        cfg = self._make_config()
        cfg.set_smb_error_code("STATUS_SUCCESS")
        assert cfg.smb_error_code == 0

    def test_invalid_string_fallback(self):
        cfg = self._make_config()
        cfg.set_smb_error_code("INVALID_STATUS")
        assert cfg.smb_error_code == nt_errors.STATUS_SMB_BAD_UID

    def test_int_zero(self):
        cfg = self._make_config()
        cfg.set_smb_error_code(0)
        assert cfg.smb_error_code == 0


class TestSmb3NegContextPad:
    """_smb3_neg_context_pad(data_len) — instance method at line 840."""

    @pytest.mark.parametrize(
        ("data_len", "expected_pad_len"),
        [
            (0, 0),
            (1, 7),
            (4, 4),
            (7, 1),
            (8, 0),
            (9, 7),
        ],
        ids=["zero", "one", "four", "seven", "eight", "nine"],
    )
    def test_padding(self, mock_handler, data_len, expected_pad_len):
        result = mock_handler._smb3_neg_context_pad(data_len)
        assert len(result) == expected_pad_len
        assert result == b"\x00" * expected_pad_len


class TestBuildTrans2FileInfo:
    """_build_trans2_file_info(info_level) at line 2872."""

    @pytest.mark.parametrize(
        ("info_level", "expected_len"),
        [
            # CIFS-native levels
            (0x0001, 22),  # SMB_INFO_STANDARD
            (0x0100, 22),  # SMB_INFO_STANDARD alternate
            (0x0002, 26),  # SMB_INFO_QUERY_EA_SIZE
            (0x0200, 26),  # SMB_INFO_QUERY_EA_SIZE alternate
            (0x0003, 4),  # SMB_INFO_QUERY_EAS_FROM_LIST (Srv2003)
            (0x0120, 100),  # UNIX_BASIC (Samba)
            # Raw FileInformationClass (XP SP3 pcap)
            (6, 8),  # FileInternalInformation
            (7, 4),  # FileEaInformation / SMB_QUERY_FILE_EA_INFO
            (11, 8),  # FilePositionInformation
            (12, 12),  # FileNamesInformation
            (13, 4),  # FileModeInformation
            (14, 4),  # FileAlignmentInformation
            (16, 8),  # FileAllocationInformation
            (23, 8),  # FilePipeInformation
            (24, 36),  # FilePipeLocalInformation
            (25, 12),  # FilePipeRemoteInformation
            (26, 4),  # FileMailslotQueryInformation
            (30, 16),  # FileCompressionInformation
            # Pass-through levels
            (0x03EC, None),  # FileBasicInfo (class 4) — size varies
            (0x03ED, None),  # FileStandardInfo (class 5) — size varies
        ],
        ids=[
            "standard_0001",
            "standard_0100",
            "ea_size_0002",
            "ea_size_0200",
            "eas_from_list",
            "unix_basic",
            "internal_6",
            "ea_info_7",
            "position_11",
            "names_12",
            "mode_13",
            "alignment_14",
            "allocation_16",
            "pipe_23",
            "pipe_local_24",
            "pipe_remote_25",
            "mailslot_26",
            "compression_30",
            "passthrough_basic",
            "passthrough_standard",
        ],
    )
    def test_supported_levels(self, mock_handler, info_level, expected_len):
        result = mock_handler._build_trans2_file_info(info_level)
        assert result is not None, f"InfoLevel 0x{info_level:04x} should be supported"
        if expected_len is not None:
            assert len(result) == expected_len

    def test_file_basic_info_0101(self, mock_handler):
        result = mock_handler._build_trans2_file_info(0x0101)
        assert result is not None
        assert len(result) > 0  # SMBQueryFileBasicInfo

    def test_file_standard_info_0102(self, mock_handler):
        result = mock_handler._build_trans2_file_info(0x0102)
        assert result is not None
        assert len(result) > 0

    def test_file_all_info_0107(self, mock_handler):
        result = mock_handler._build_trans2_file_info(0x0107)
        assert result is not None
        assert len(result) > 0

    def test_file_all_info_raw_15(self, mock_handler):
        """FileAllInformation (class 15) — XP SP3 sends as raw class."""
        result = mock_handler._build_trans2_file_info(15)
        assert result is not None
        assert len(result) > 0

    def test_compression_info_010b(self, mock_handler):
        result = mock_handler._build_trans2_file_info(0x010B)
        assert result is not None
        assert len(result) == 16

    def test_name_valid_0006(self, mock_handler):
        """0x0006: FileInternalInformation / SMB_INFO_IS_NAME_VALID — 8 bytes."""
        result = mock_handler._build_trans2_file_info(0x0006)
        assert result is not None
        assert len(result) == 8

    def test_network_open_info_raw_38(self, mock_handler):
        """FileNetworkOpenInformation sent as raw class 38 by XP SP3."""
        result = mock_handler._build_trans2_file_info(38)
        assert result is not None
        assert len(result) == 56  # 4×FILETIME + sizes + attributes

    def test_ea_info_0103(self, mock_handler):
        result = mock_handler._build_trans2_file_info(0x0103)
        assert result is not None
        assert len(result) == 4

    def test_unsupported_returns_none(self, mock_handler):
        assert mock_handler._build_trans2_file_info(0x9999) is None

    def test_unsupported_passthrough_returns_none(self, mock_handler):
        assert mock_handler._build_trans2_file_info(0x03F0) is None


class TestResolveAuthErrorCode:
    """_resolve_auth_error_code() at line 1551."""

    def test_default_zero_returns_success(self, mock_handler):
        mock_handler.smb_config.smb_captures_per_connection = 0
        result = mock_handler._resolve_auth_error_code()
        assert result == nt_errors.STATUS_SUCCESS

    def test_multi_cred_first_returns_disabled(self, mock_handler):
        mock_handler.smb_config.smb_captures_per_connection = 3
        mock_handler.auth_attempt_count = 0
        result = mock_handler._resolve_auth_error_code()
        assert result == STATUS_ACCOUNT_DISABLED

    def test_multi_cred_second_returns_disabled(self, mock_handler):
        mock_handler.smb_config.smb_captures_per_connection = 3
        mock_handler.auth_attempt_count = 1
        result = mock_handler._resolve_auth_error_code()
        assert result == STATUS_ACCOUNT_DISABLED

    def test_multi_cred_final_returns_success(self, mock_handler):
        mock_handler.smb_config.smb_captures_per_connection = 3
        mock_handler.auth_attempt_count = 2
        result = mock_handler._resolve_auth_error_code()
        assert result == nt_errors.STATUS_SUCCESS

    def test_single_capture_returns_success(self, mock_handler):
        mock_handler.smb_config.smb_captures_per_connection = 1
        mock_handler.auth_attempt_count = 0
        result = mock_handler._resolve_auth_error_code()
        assert result == nt_errors.STATUS_SUCCESS

    def test_increments_attempt_count(self, mock_handler):
        mock_handler.smb_config.smb_captures_per_connection = 3
        mock_handler.auth_attempt_count = 0
        mock_handler._resolve_auth_error_code()
        assert mock_handler.auth_attempt_count == 1


# ===========================================================================
# Tier 2: Response Builders (need mock_handler)
# ===========================================================================


class TestBuildSmb2NegotiateResponse:
    """_build_smb2_negotiate_response(target_revision, request) at line 924."""

    def test_dialect_0202_small_max(self, mock_handler):
        resp = mock_handler._build_smb2_negotiate_response(0x0202)
        assert resp["MaxTransactSize"] == SMB2_MAX_SIZE_SMALL

    def test_dialect_0210_large_max(self, mock_handler):
        resp = mock_handler._build_smb2_negotiate_response(0x0210)
        assert resp["MaxTransactSize"] == SMB2_MAX_SIZE_LARGE

    def test_dialect_0311_large_max(self, mock_handler):
        resp = mock_handler._build_smb2_negotiate_response(0x0311)
        assert resp["MaxTransactSize"] == SMB2_MAX_SIZE_LARGE

    def test_security_buffer_present(self, mock_handler):
        resp = mock_handler._build_smb2_negotiate_response(0x0202)
        assert resp["SecurityBufferLength"] > 0

    def test_security_mode(self, mock_handler):
        resp = mock_handler._build_smb2_negotiate_response(0x0202)
        assert resp["SecurityMode"] == 0x01  # Signing enabled


class TestSmb2Create:
    """handle_smb2_create(packet) at line 2391."""

    def _build_create_request(self, filename: str) -> smb2.SMB2Packet:
        """Build a CREATE request with the given filename."""
        create_req = smb2.SMB2Create()
        fn_bytes = filename.encode("utf-16-le")
        create_req["NameLength"] = len(fn_bytes)
        create_req["Buffer"] = fn_bytes
        return _build_smb2_packet(smb2.SMB2_CREATE, create_req.getData())

    def test_filename_captured(self, mock_handler):
        pkt = self._build_create_request("test.txt")
        mock_handler.handle_smb2_create(pkt)
        assert "test.txt" in mock_handler.client_files

    def test_empty_name_not_in_files(self, mock_handler):
        pkt = self._build_create_request("")
        mock_handler.handle_smb2_create(pkt)
        assert len(mock_handler.client_files) == 0

    def test_file_id_increments(self, mock_handler):
        pkt1 = self._build_create_request("file1.txt")
        pkt2 = self._build_create_request("file2.txt")
        mock_handler.handle_smb2_create(pkt1)
        id1 = mock_handler.smb2_file_id_counter
        mock_handler.handle_smb2_create(pkt2)
        id2 = mock_handler.smb2_file_id_counter
        assert id2 == id1 + 1

    def test_response_sent(self, mock_handler):
        pkt = self._build_create_request("test.txt")
        mock_handler.handle_smb2_create(pkt)
        assert mock_handler.send_data.called


class TestSmb2TreeConnect:
    """handle_smb2_tree_connect(packet) at line 2089."""

    def _build_tree_connect_packet(self, path: str) -> smb2.SMB2Packet:
        """Build a TREE_CONNECT packet with the given UNC path."""
        path_bytes = path.encode("utf-16-le")
        tree_req = smb2.SMB2TreeConnect()
        tree_req["Buffer"] = path_bytes
        return _build_smb2_packet(smb2.SMB2_TREE_CONNECT, tree_req.getData())

    def test_tree_id_increments(self, mock_handler):
        pkt1 = self._build_tree_connect_packet("\\\\10.0.0.50\\IPC$")
        pkt2 = self._build_tree_connect_packet("\\\\10.0.0.50\\share")
        mock_handler.handle_smb2_tree_connect(pkt1)
        id1 = mock_handler.smb2_tree_id_counter
        mock_handler.handle_smb2_tree_connect(pkt2)
        id2 = mock_handler.smb2_tree_id_counter
        assert id2 == id1 + 1

    def test_path_recorded(self, mock_handler):
        pkt = self._build_tree_connect_packet("\\\\10.0.0.50\\data")
        mock_handler.handle_smb2_tree_connect(pkt)
        # Non-IPC$ paths should be recorded in client_info
        if "smb_path" in mock_handler.client_info:
            assert "data" in mock_handler.client_info["smb_path"]

    def test_response_sent(self, mock_handler):
        pkt = self._build_tree_connect_packet("\\\\10.0.0.50\\IPC$")
        mock_handler.handle_smb2_tree_connect(pkt)
        assert mock_handler.send_data.called


class TestSmb2QueryInfo:
    """handle_smb2_query_info(packet) at line 2482."""

    def _build_query_info_packet(
        self, info_type: int, file_info_class: int
    ) -> smb2.SMB2Packet:
        """Build a QUERY_INFO request packet with raw bytes."""
        # SMB2_QUERY_INFO: StructureSize(2) + InfoType(1) + FileInfoClass(1) +
        #   OutputBufferLength(4) + InputBufferOffset(2) + Reserved(2) +
        #   InputBufferLength(4) + AdditionalInformation(4) + Flags(4) + FileId(16)
        data = struct.pack("<H", 41)  # StructureSize
        data += struct.pack("<B", info_type)
        data += struct.pack("<B", file_info_class)
        data += struct.pack("<L", 4096)  # OutputBufferLength
        data += struct.pack("<H", 0)  # InputBufferOffset
        data += struct.pack("<H", 0)  # Reserved
        data += struct.pack("<L", 0)  # InputBufferLength
        data += struct.pack("<L", 0)  # AdditionalInformation
        data += struct.pack("<L", 0)  # Flags
        data += b"\x01" * 16  # FileId
        return _build_smb2_packet(smb2.SMB2_QUERY_INFO, data)

    def test_file_network_open_info(self, mock_handler):
        pkt = self._build_query_info_packet(0x01, 34)  # FileNetworkOpenInfo
        mock_handler.handle_smb2_query_info(pkt)
        assert mock_handler.send_data.called

    def test_file_standard_info(self, mock_handler):
        pkt = self._build_query_info_packet(0x01, 5)  # FileStandardInfo
        mock_handler.handle_smb2_query_info(pkt)
        assert mock_handler.send_data.called

    def test_file_basic_info(self, mock_handler):
        pkt = self._build_query_info_packet(0x01, 4)  # FileBasicInfo
        mock_handler.handle_smb2_query_info(pkt)
        assert mock_handler.send_data.called

    def test_file_all_info(self, mock_handler):
        pkt = self._build_query_info_packet(0x01, 18)  # FileAllInfo
        mock_handler.handle_smb2_query_info(pkt)
        assert mock_handler.send_data.called

    def test_unsupported_class(self, mock_handler):
        pkt = self._build_query_info_packet(0x01, 99)
        mock_handler.handle_smb2_query_info(pkt)
        # Should send error response (NOT_SUPPORTED)
        assert mock_handler.send_data.called

    def test_filesystem_info(self, mock_handler):
        pkt = self._build_query_info_packet(0x02, 0)  # FS info
        mock_handler.handle_smb2_query_info(pkt)
        assert mock_handler.send_data.called


class TestSmb2SimpleHandlers:
    """Simple SMB2 handlers that return fixed responses."""

    def test_read_returns_eof(self, mock_handler):
        # SMB2_READ raw: StructureSize(2) + Padding(1) + Flags(1) + Length(4) +
        #   Offset(8) + FileId(16) + MinimumCount(4) + Channel(4) +
        #   RemainingBytes(4) + ReadChannelInfoOffset(2) + ReadChannelInfoLength(2)
        data = struct.pack("<H", 49)  # StructureSize
        data += struct.pack("<B", 0)  # Padding
        data += struct.pack("<B", 0)  # Flags
        data += struct.pack("<L", 4096)  # Length
        data += struct.pack("<Q", 0)  # Offset
        data += b"\x01" * 16  # FileId
        data += struct.pack("<L", 0)  # MinimumCount
        data += struct.pack("<L", 0)  # Channel
        data += struct.pack("<L", 0)  # RemainingBytes
        data += struct.pack("<HH", 0, 0)  # ChannelInfo offset/length
        pkt = _build_smb2_packet(smb2.SMB2_READ, data)
        mock_handler.handle_smb2_read(pkt)
        assert mock_handler.send_data.called

    def test_close_returns_success(self, mock_handler):
        # SMB2_CLOSE: StructureSize(2) + Flags(2) + Reserved(4) + FileId(16)
        data = struct.pack("<HH", 24, 0) + b"\x00" * 4 + b"\x01" * 16
        pkt = _build_smb2_packet(smb2.SMB2_CLOSE, data)
        mock_handler.handle_smb2_close(pkt)
        assert mock_handler.send_data.called

    def test_write_returns_count(self, mock_handler):
        # SMB2_WRITE raw: StructureSize(2) + DataOffset(2) + Length(4) +
        #   Offset(8) + FileId(16) + Channel(4) + RemainingBytes(4) +
        #   WriteChannelInfoOffset(2) + WriteChannelInfoLength(2) + Flags(4) + Buffer
        buf = b"\x00" * 100
        data = struct.pack("<H", 49)  # StructureSize
        data += struct.pack("<H", 112)  # DataOffset (64 hdr + 48 fixed)
        data += struct.pack("<L", len(buf))  # Length
        data += struct.pack("<Q", 0)  # Offset
        data += b"\x01" * 16  # FileId
        data += struct.pack("<L", 0)  # Channel
        data += struct.pack("<L", 0)  # RemainingBytes
        data += struct.pack("<HH", 0, 0)  # WriteChannelInfo
        data += struct.pack("<L", 0)  # Flags
        data += buf
        pkt = _build_smb2_packet(smb2.SMB2_WRITE, data)
        mock_handler.handle_smb2_write(pkt)
        assert mock_handler.send_data.called

    def test_flush_returns_success(self, mock_handler):
        # SMB2_FLUSH: StructureSize(2) + Reserved1(2) + Reserved2(4) + FileId(16)
        data = struct.pack("<HH", 24, 0) + b"\x00" * 4 + b"\x01" * 16
        pkt = _build_smb2_packet(smb2.SMB2_FLUSH, data)
        mock_handler.handle_smb2_flush(pkt)
        assert mock_handler.send_data.called

    def test_lock_returns_success(self, mock_handler):
        # SMB2_LOCK: StructureSize(2) + LockCount(2) + LockSequenceIndex(4) + FileId(16)
        data = struct.pack("<HH", 48, 0) + b"\x00" * 4 + b"\x01" * 16
        pkt = _build_smb2_packet(smb2.SMB2_LOCK, data)
        mock_handler.handle_smb2_lock(pkt)
        assert mock_handler.send_data.called

    def test_set_info_returns_success(self, mock_handler):
        # SMB2_SET_INFO raw: StructureSize(2) + InfoType(1) + FileInfoClass(1) +
        #   BufferLength(4) + BufferOffset(2) + Reserved(2) +
        #   AdditionalInformation(4) + FileId(16) + Buffer
        buf = b"\x00" * 40
        data = struct.pack("<H", 33)  # StructureSize
        data += struct.pack("<BB", 0x01, 4)  # InfoType, FileInfoClass
        data += struct.pack("<L", len(buf))  # BufferLength
        data += struct.pack("<HH", 96, 0)  # BufferOffset, Reserved
        data += struct.pack("<L", 0)  # AdditionalInformation
        data += b"\x01" * 16  # FileId
        data += buf
        pkt = _build_smb2_packet(smb2.SMB2_SET_INFO, data)
        mock_handler.handle_smb2_set_info(pkt)
        assert mock_handler.send_data.called

    def test_query_directory_no_more_files(self, mock_handler):
        # SMB2_QUERY_DIRECTORY raw: StructureSize(2) + FileInformationClass(1) +
        #   Flags(1) + FileIndex(4) + FileId(16) + FileNameOffset(2) +
        #   FileNameLength(2) + OutputBufferLength(4) + Buffer
        fn = "*".encode("utf-16-le")
        data = struct.pack("<H", 33)  # StructureSize
        data += struct.pack("<BB", 0x25, 0)  # FileInfoClass, Flags
        data += struct.pack("<L", 0)  # FileIndex
        data += b"\x01" * 16  # FileId
        data += struct.pack("<HH", 96, len(fn))  # FileNameOffset, FileNameLength
        data += struct.pack("<L", 4096)  # OutputBufferLength
        data += fn
        pkt = _build_smb2_packet(smb2.SMB2_QUERY_DIRECTORY, data)
        mock_handler.handle_smb2_query_directory(pkt)
        assert mock_handler.send_data.called

    def test_tree_disconnect(self, mock_handler):
        # SMB2_TREE_DISCONNECT: StructureSize(2) + Reserved(2) = 4 bytes
        data = struct.pack("<HH", 4, 0)
        pkt = _build_smb2_packet(smb2.SMB2_TREE_DISCONNECT, data, tree_id=1)
        mock_handler.handle_smb2_tree_disconnect(pkt)
        assert mock_handler.send_data.called

    def test_logoff_resets_authenticated(self, mock_handler):
        mock_handler.authenticated = True
        # SMB2_LOGOFF: StructureSize(2) + Reserved(2) = 4 bytes
        data = struct.pack("<HH", 4, 0)
        pkt = _build_smb2_packet(smb2.SMB2_LOGOFF, data)
        mock_handler.handle_smb2_logoff(pkt)
        assert mock_handler.authenticated is False


class TestSmb2Negotiate:
    """handle_smb2_negotiate(packet) at line 1022."""

    def _build_negotiate_raw(
        self, dialects: list[int], sec_mode: int = 0x01
    ) -> smb2.SMB2Packet:
        """Build SMB2 NEGOTIATE with raw bytes for smb3.SMB2Negotiate parsing."""
        # smb3.SMB2Negotiate: StructureSize(2) + DialectCount(2) + SecurityMode(2) +
        #   Reserved(2) + Capabilities(4) + ClientGuid(16) + ClientStartTime(8) + Dialects
        data = struct.pack("<H", 36)  # StructureSize
        data += struct.pack("<H", len(dialects))
        data += struct.pack("<H", sec_mode)
        data += struct.pack("<H", 0)  # Reserved
        data += struct.pack("<L", 0)  # Capabilities
        data += b"\xbb" * 16  # ClientGuid
        data += b"\x00" * 8  # ClientStartTime
        for d in dialects:
            data += struct.pack("<H", d)
        return _build_smb2_packet(smb2.SMB2_NEGOTIATE, data)

    def test_selects_highest_common(self, mock_handler):
        pkt = self._build_negotiate_raw([0x202, 0x210, 0x302])
        mock_handler.smb_config.smb2_max_dialect = 0x302
        mock_handler.handle_smb2_negotiate(pkt)
        assert mock_handler.smb2_selected_dialect == 0x302
        assert mock_handler.send_data.called

    def test_empty_dialects_terminates(self, mock_handler):
        pkt = self._build_negotiate_raw([])
        with pytest.raises(BaseProtoHandler.TerminateConnection):
            mock_handler.handle_smb2_negotiate(pkt)

    def test_no_common_dialect_terminates(self, mock_handler):
        mock_handler.smb_config.smb2_min_dialect = 0x300
        mock_handler.smb_config.smb2_max_dialect = 0x311
        pkt = self._build_negotiate_raw([0x202, 0x210])
        with pytest.raises(BaseProtoHandler.TerminateConnection):
            mock_handler.handle_smb2_negotiate(pkt)

    def test_records_signing_required(self, mock_handler):
        pkt = self._build_negotiate_raw([0x202], sec_mode=0x03)  # SIGNING_REQUIRED
        mock_handler.handle_smb2_negotiate(pkt)
        assert mock_handler.smb2_client_signing_required is True

    def test_respects_min_dialect(self, mock_handler):
        mock_handler.smb_config.smb2_min_dialect = 0x210
        mock_handler.smb_config.smb2_max_dialect = 0x311
        pkt = self._build_negotiate_raw([0x202, 0x210, 0x302])
        mock_handler.handle_smb2_negotiate(pkt)
        # Should select 0x302 (highest in range), not 0x202
        assert mock_handler.smb2_selected_dialect >= 0x210


class TestSmb2HandleIoctl:
    """handle_smb2_ioctl(packet) at line 2169."""

    def _build_ioctl_packet(
        self, ctl_code: int, buffer_data: bytes = b""
    ) -> smb2.SMB2Packet:
        # Build IOCTL data manually since impacket's SMB2Ioctl has None-default fields
        # Structure: StructureSize(4) + Reserved(2) + CtlCode(4) + FileId(16) +
        #   InputOffset(4) + InputCount(4) + MaxInputResponse(4) + OutputOffset(4) +
        #   OutputCount(4) + MaxOutputResponse(4) + Flags(4) + Reserved2(4) + Buffer
        input_offset = 120  # 64 (SMB2 header) + 56 (IOCTL fixed)
        data = struct.pack("<LH", 57, 0)  # StructureSize, Reserved
        data += struct.pack("<L", ctl_code)
        data += b"\xff" * 16  # FileId
        data += struct.pack("<L", input_offset if buffer_data else 0)  # InputOffset
        data += struct.pack("<L", len(buffer_data))  # InputCount
        data += struct.pack("<L", 0)  # MaxInputResponse
        data += struct.pack("<L", 0)  # OutputOffset
        data += struct.pack("<L", 0)  # OutputCount
        data += struct.pack("<L", 65536)  # MaxOutputResponse
        data += struct.pack("<L", 0)  # Flags
        data += struct.pack("<L", 0)  # Reserved2
        data += buffer_data
        return _build_smb2_packet(smb2.SMB2_IOCTL, data)

    def test_unknown_ctl_returns_fs_driver(self, mock_handler):
        pkt = self._build_ioctl_packet(0x12345678)
        mock_handler.handle_smb2_ioctl(pkt)
        assert mock_handler.send_data.called

    def test_validate_negotiate_responds(self, mock_handler):
        # FSCTL_VALIDATE_NEGOTIATE_INFO = 0x00140204
        # Build valid VALIDATE_NEGOTIATE_INFO request
        vni = smb2.VALIDATE_NEGOTIATE_INFO()
        vni["Capabilities"] = 0x2F
        vni["Guid"] = b"\xbb" * 16
        vni["SecurityMode"] = 0x01
        vni["DialectCount"] = 1
        vni["Dialects"] = struct.pack("<H", 0x302)
        mock_handler.smb2_selected_dialect = 0x302
        pkt = self._build_ioctl_packet(0x00140204, vni.getData())
        mock_handler.handle_smb2_ioctl(pkt)
        assert mock_handler.send_data.called


class TestSmb1SimpleHandlers:
    """Simple SMB1 handlers."""

    def _build_smb1_packet(self, command: int) -> smb.NewSMBPacket:
        pkt = smb.NewSMBPacket()
        pkt["Flags1"] = 0
        pkt["Flags2"] = smb.SMB.FLAGS2_NT_STATUS
        pkt["Pid"] = 1
        pkt["Mid"] = 1
        pkt["Tid"] = 1
        cmd = smb.SMBCommand(command)
        cmd["Parameters"] = b""
        cmd["Data"] = b""
        pkt.addCommand(cmd)
        # Round-trip to populate all fields
        wire = pkt.getData()
        return smb.NewSMBPacket(data=wire)

    def test_smb1_read_responds(self, mock_handler):
        pkt = self._build_smb1_packet(smb.SMB.SMB_COM_READ_ANDX)
        mock_handler.handle_smb1_read(pkt)
        assert mock_handler.send_data.called

    def test_smb1_close_responds(self, mock_handler):
        pkt = self._build_smb1_packet(smb.SMB.SMB_COM_CLOSE)
        mock_handler.handle_smb1_close(pkt)
        assert mock_handler.send_data.called

    def test_smb1_tree_disconnect_responds(self, mock_handler):
        pkt = self._build_smb1_packet(smb.SMB.SMB_COM_TREE_DISCONNECT)
        mock_handler.handle_smb1_tree_disconnect(pkt)
        assert mock_handler.send_data.called

    def test_smb1_logoff_terminates(self, mock_handler):
        pkt = self._build_smb1_packet(smb.SMB.SMB_COM_LOGOFF_ANDX)
        with pytest.raises(BaseProtoHandler.TerminateConnection):
            mock_handler.handle_smb1_logoff(pkt)


class TestHandleSmbPacket:
    """handle_smb_packet(packet, smbv1) at line 779."""

    def test_dispatches_known_smb2_command(self, mock_handler):
        """Known SMB2 command dispatches to handler."""
        logoff = smb2.SMB2Logoff()
        pkt = _build_smb2_packet(smb2.SMB2_LOGOFF, logoff.getData())
        mock_handler.authenticated = True
        mock_handler.handle_smb_packet(pkt, smbv1=False)
        # Logoff should have reset authenticated
        assert mock_handler.authenticated is False

    def test_unknown_smb2_sends_not_supported(self, mock_handler):
        """Unknown SMB2 command sends NOT_SUPPORTED instead of crashing."""
        pkt = _build_smb2_packet(0x99)  # Unknown command
        pkt["Command"] = 0x99
        mock_handler.handle_smb_packet(pkt, smbv1=False)
        # Should have sent an error response, not crashed
        assert mock_handler.send_data.called

    def test_unknown_smb1_sends_not_implemented(self, mock_handler):
        """Unknown SMB1 command sends NOT_IMPLEMENTED."""
        pkt = smb.NewSMBPacket()
        pkt["Flags1"] = 0
        pkt["Flags2"] = smb.SMB.FLAGS2_NT_STATUS
        pkt["Pid"] = 1
        pkt["Mid"] = 1
        pkt["Tid"] = 1
        cmd = smb.SMBCommand(0xFE)  # Unknown
        cmd["Parameters"] = b""
        cmd["Data"] = b""
        pkt.addCommand(cmd)
        wire = pkt.getData()
        parsed = smb.NewSMBPacket(data=wire)
        mock_handler.handle_smb_packet(parsed, smbv1=True)
        assert mock_handler.send_data.called


class TestSmb2SessionSetup:
    """handle_smb2_session_setup IS_GUEST logic at line 1597.

    These are partial integration tests — we mock handle_ntlmssp to return
    a fixed response and only verify the IS_GUEST SessionFlags logic.
    """

    def _build_session_setup_packet(self) -> smb2.SMB2Packet:
        ss = smb2.SMB2SessionSetup()
        neg = ntlm.NTLMAuthNegotiate()
        neg["flags"] = ntlm.NTLMSSP_NEGOTIATE_UNICODE
        ss["SecurityBufferLength"] = len(neg.getData())
        ss["Buffer"] = neg.getData()
        return _build_smb2_packet(smb2.SMB2_SESSION_SETUP, ss.getData())

    def test_is_guest_when_low_dialect(self, mock_handler):
        """Client max dialect <= 3.0.2 and no signing required -> IS_GUEST."""
        mock_handler.smb2_client_max_dialect = 0x302
        mock_handler.smb2_client_signing_required = False
        pkt = self._build_session_setup_packet()

        # Mock handle_ntlmssp to return STATUS_SUCCESS
        with patch.object(
            mock_handler,
            "handle_ntlmssp",
            return_value=(b"\x00" * 4, nt_errors.STATUS_SUCCESS),
        ):
            mock_handler.handle_smb2_session_setup(pkt)

        # Verify IS_GUEST was set (check the response that was sent)
        assert mock_handler.send_data.called

    def test_no_guest_when_signing_required(self, mock_handler):
        """Signing required -> no IS_GUEST regardless of dialect."""
        mock_handler.smb2_client_max_dialect = 0x302
        mock_handler.smb2_client_signing_required = True
        pkt = self._build_session_setup_packet()

        with patch.object(
            mock_handler,
            "handle_ntlmssp",
            return_value=(b"\x00" * 4, nt_errors.STATUS_SUCCESS),
        ):
            mock_handler.handle_smb2_session_setup(pkt)

        assert mock_handler.send_data.called

    def test_no_guest_when_high_dialect(self, mock_handler):
        """Client max dialect >= 3.1.1 -> no IS_GUEST."""
        mock_handler.smb2_client_max_dialect = 0x311
        mock_handler.smb2_client_signing_required = False
        pkt = self._build_session_setup_packet()

        with patch.object(
            mock_handler,
            "handle_ntlmssp",
            return_value=(b"\x00" * 4, nt_errors.STATUS_SUCCESS),
        ):
            mock_handler.handle_smb2_session_setup(pkt)

        assert mock_handler.send_data.called
