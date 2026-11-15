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
# !!! WARNING: a lot of code below !!!
# pyright: basic
import struct as _stdlib_struct
import uuid
import secrets
import typing

from typing_extensions import override

from scapy.fields import NetBIOSNameField
from rich.markup import escape
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
from dementor.config.util import is_true, HostFallbackValue
from dementor.loader import BaseProtocolModule, DEFAULT_ATTR
from dementor.log.logger import ProtocolLogger, dm_logger
from dementor.protocols.ntlm import (
    ntlm_build_challenge_message,
    NTLM_TRANSPORT_CLEARTEXT,
    NTLM_TRANSPORT_RAW,
    ntlm_handle_negotiate_message,
    ntlm_timestamp,
    ntlm_handle_authenticate_message,
    ntlm_handle_legacy_raw_auth,
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


def _split_smb_strings(data: bytes, is_unicode: bool) -> list[str]:
    if not data:
        return []

    if not is_unicode:
        return [s.decode("ascii", errors="replace") for s in data.split(b"\x00") if s]

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

SMB2_INTEGRITY_SHA512 = uint16.to_bytes(0x0001, order=LittleEndian)

SMB2_DIALECT_STRINGS: dict[str, int] = {
    "2.002": smb2.SMB2_DIALECT_002,
    "2.1": smb2.SMB2_DIALECT_21,
    "3.0": smb2.SMB2_DIALECT_30,
    "3.0.2": smb2.SMB2_DIALECT_302,
    "3.1.1": smb2.SMB2_DIALECT_311,
}

SMB2_MAX_SIZE_SMALL: int = 65_536  # SMB 2.0.2
SMB2_MAX_SIZE_LARGE: int = 8_388_608  # SMB 2.1+

SMB2_SERVER_CAPABILITIES: int = 0x2F

# Matching Windows 7+:
#   UNICODE(0x04) | LARGE_FILES(0x08) | NT_SMBS(0x10) | RPC_REMOTE_APIS(0x20) |
#   STATUS32(0x40) | LEVEL_II_OPLOCKS(0x80) | LOCK_AND_READ(0x100) |
#   NT_FIND(0x200) | INFOLEVEL_PASSTHRU(0x2000) | LARGE_READX(0x4000) |
#   LARGE_WRITEX(0x8000) | LWIO(0x10000)
SMB1_CAPABILITIES_BASE: int = 0x0001E3FC

SMB1_MAX_MPX_COUNT: int = 50
SMB1_MAX_BUFFER_SIZE: int = 16644

STATUS_ACCOUNT_DISABLED: int = 0xC0000072

SMB2_SIGNING_CAPABILITIES_ID: int = 0x0008

_PARSE_ERRORS = (_stdlib_struct.error, KeyError, IndexError, TypeError, ValueError)


# (missing in impacket struct definitions)
@struct(order=LittleEndian)
class SMB2SigningCapabilities(struct_factory.mixin):  # type: ignore[unsupported-base]
    SigningAlgorithmCount: uint16_t
    SigningAlgorithms: f[list[int], uint16[this.SigningAlgorithmCount]]


def parse_dialect(value: str | int) -> int:
    """Convert a dialect string (e.g. "3.1.1") to its hex constant."""
    if isinstance(value, int):
        return value
    key = str(value).strip()
    if key not in SMB2_DIALECT_STRINGS:
        raise ValueError(
            f"Unknown SMB2 dialect {key!r}; valid: {', '.join(SMB2_DIALECT_STRINGS)}"
        )
    return SMB2_DIALECT_STRINGS[key]


class SMBServerConfig(TomlConfig):
    _section_ = "SMB"
    _fields_ = [
        A("smb_port", "Port"),
        A("smb_enable_smb1", "EnableSMB1", True, factory=is_true),
        A("smb_enable_smb2", "EnableSMB2", True, factory=is_true),
        A("smb_allow_smb1_upgrade", "AllowSMB1Upgrade", True, factory=is_true),
        A("smb2_min_dialect", "SMB2MinDialect", "2.002", factory=parse_dialect),
        A("smb2_max_dialect", "SMB2MaxDialect", "3.1.1", factory=parse_dialect),
        A(
            "smb_nb_computer",
            "NTLM.NetBIOSComputer",
            None,
            section_local=False,
            factory=HostFallbackValue("NetBIOSComputer", "DEMENTOR"),
        ),
        A(
            "smb_nb_domain",
            "NTLM.NetBIOSDomain",
            None,
            section_local=False,
            factory=HostFallbackValue("NetBIOSDomain", "WORKGROUP"),
        ),
        A("smb_server_os", "ServerOS", "Windows"),
        A("smb_native_lanman", "NativeLanMan", "Windows"),
        A("smb_captures_per_connection", "CapturesPerConnection", 0, factory=int),
        A("smb_error_code", "ErrorCode", default_val=None),
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
        smb_error_code: int | None

    def set_smb_error_code(self, value: str | int | None) -> None:
        match value:
            case int():
                self.smb_error_code = value
            case str():
                try:
                    self.smb_error_code = getattr(nt_errors, str(value))
                except AttributeError:
                    dm_logger.error(
                        f"Invalid SMB error code: {value} - using default: STATUS_SMB_BAD_UID"
                    )
                    self.smb_error_code = nt_errors.STATUS_SMB_BAD_UID
            case _:
                self.smb_error_code = None


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


def get_server_time() -> int:
    return ntlm_timestamp()


def get_command_name(command: int, smb_version: int) -> str:
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

    return "Unknown"


class SMBHandler(BaseProtoHandler):
    STATE_NEGOTIATE = 0
    STATE_AUTH = 1

    def __init__(
        self,
        config: SessionConfig,
        server_config: SMBServerConfig,
        request: typing.Any,
        client_address: tuple[str, int],
        server: typing.Any,
    ) -> None:
        self.authenticated = False
        self.smb_config = server_config

        self.smb1_extended_security: bool = True
        self.smb1_challenge: bytes = config.ntlm_challenge
        self.smb1_uid: int = 0
        self.smb2_session_id: int = 0
        self.smb2_tree_id_counter: int = 0
        self.smb2_selected_dialect: int = 0
        self.smb2_client_signing_required: bool = False
        self.smb2_client_max_dialect: int = 0
        self.auth_attempt_count: int = 0
        self.client_info: dict[str, str] = {}
        self.client_files: set[str] = set()
        self.ntlm_negotiate_fields: dict[str, str] = {}
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
        return ProtocolLogger(
            extra={
                "protocol": "SMB",
                "protocol_color": "light_goldenrod1",
                "host": self.client_host,
                "port": self.smb_config.smb_port,
            }
        )

    def setup(self) -> None:
        self.logger.debug(f"Incoming connection from {self.client_host}")

    def finish(self) -> None:
        self._emit_smb_client_info()
        self.logger.debug(f"Connection to {self.client_host} closed")

    def _emit_smb_client_info(self) -> None:
        keys = [
            ("smb_os", "OS"),
            ("smb_lanman", "LAN Manager"),
            ("smb_calling_name", "Calling Name"),
            ("smb_called_name", "Called Name"),
            ("smb_account", "Account"),
            ("smb_domain", "Domain"),
            ("smb_path", "Path"),
            ("smb_dialect", "Dialect"),
        ]
        parts = [
            f"[b]{label}[/]: {escape(self.client_info[k])}"
            for k, label in keys
            if self.client_info.get(k)
        ]
        if self.client_files:
            filenames: str = escape(", ".join(sorted(self.client_files)))
            parts.append(f"files:{filenames}")
        if parts:
            conn_info = " [b]|[/] ".join(parts)
            self.logger.display(f"Client connection: {conn_info} closed")

    def send_data(self, payload: bytes, ty: int | None = None) -> None:
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
        resp = smb.NewSMBPacket()
        resp["Flags1"] = smb.SMB.FLAGS1_REPLY

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
        tree_id: int | None = None,
    ) -> None:
        resp = smb2.SMB2Packet()
        resp["Flags"] = smb2.SMB2_FLAGS_SERVER_TO_REDIR
        resp["Status"] = status or nt_errors.STATUS_SUCCESS

        if packet is None:
            packet = {
                "Command": command or 0,
                "CreditCharge": 0,
                "Reserved": 0,
                "MessageID": 0,
                "TreeID": 0,
            }
        resp["Command"] = packet["Command"]
        resp["CreditCharge"] = packet["CreditCharge"]
        resp["Reserved"] = packet["Reserved"]
        resp["SessionID"] = self.smb2_session_id
        resp["MessageID"] = packet["MessageID"]
        resp["TreeID"] = tree_id if tree_id is not None else packet["TreeID"]
        resp["CreditRequestResponse"] = 32
        resp["Data"] = command_data
        self.send_data(resp.getData())

    def _smb2_error_response(self, packet: smb2.SMB2Packet, status: int) -> None:
        resp = smb2.SMB2Error()
        self.send_smb2_command(resp.getData(), packet, status=status)

    def handle_data(self, data: bytes | None, transport: typing.Any) -> None:
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
                    self.logger.debug("Failed to parse NetBIOS session request names")
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

    def _smb3_neg_context_pad(self, data_len: int) -> bytes:
        return b"\x00" * ((8 - (data_len % 8)) % 8)

    def _smb3_build_neg_context_list(
        self,
        context_objects: list[tuple[int, bytes]],
    ) -> bytes:
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
        except _PARSE_ERRORS as e:
            self.logger.debug(f"Warning: invalid negotiate context list: {e}")
        return target_cipher, target_sign

    def _build_smb2_negotiate_response(
        self,
        target_revision: int,
        request: smb2.SMB2Negotiate | None = None,
    ) -> smb2.SMB2Negotiate_Response:
        command = smb2.SMB2Negotiate_Response()
        command["SecurityMode"] = 0x01
        command["DialectRevision"] = target_revision
        command["ServerGuid"] = self.server.server_guid  # type: ignore[union-attr]
        command["Capabilities"] = SMB2_SERVER_CAPABILITIES
        max_size = (
            SMB2_MAX_SIZE_SMALL
            if target_revision == smb2.SMB2_DIALECT_002
            else SMB2_MAX_SIZE_LARGE
        )
        command["MaxTransactSize"] = max_size
        command["MaxReadSize"] = max_size
        command["MaxWriteSize"] = max_size
        command["SystemTime"] = get_server_time()
        command["ServerStartTime"] = 0
        command["SecurityBufferOffset"] = 0x80

        blob = build_neg_token_init([SPNEGO_NTLMSSP_MECH])
        command["Buffer"] = blob.getData()
        command["SecurityBufferLength"] = len(command["Buffer"])

        if target_revision == smb2.SMB2_DIALECT_311:
            int_caps = smb3.SMB2PreAuthIntegrityCapabilities()
            int_caps["HashAlgorithmCount"] = 1
            int_caps["SaltLength"] = 32
            int_caps["HashAlgorithms"] = SMB2_INTEGRITY_SHA512
            int_caps["Salt"] = secrets.token_bytes(32)

            target_cipher = smb3.SMB2_ENCRYPTION_AES128_GCM
            target_sign = 0x001  #  AES-CMAC signing algorithm
            if request:
                target_cipher, target_sign = self._smb3_get_target_capabilities(request)

            enc_caps = smb3.SMB2EncryptionCapabilities()
            enc_caps["CipherCount"] = 1
            enc_caps["Ciphers"] = uint16.to_bytes(target_cipher, order=LittleEndian)

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
        req = smb3.SMB2Negotiate(data=packet["Data"])
        dialect_count: int = req["DialectCount"]
        req_raw_dialects: list[int] = req["Dialects"]
        dialect_count = min(dialect_count, len(req_raw_dialects))

        req_dialects: list[int] = req_raw_dialects[:dialect_count]
        if len(req_dialects) == 0:
            self.logger.debug("SMB2_NEGOTIATE: no dialects offered", is_client=True)
            self.logger.fail("SMB Negotiation: Client failed to provide any dialects.")
            raise BaseProtoHandler.TerminateConnection

        str_req_dialects = ", ".join([SMB2_DIALECTS.get(d, hex(d)) for d in req_dialects])

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
            resp = smb2.SMB2Error()
            self.send_smb2_command(
                resp.getData(),
                status=nt_errors.STATUS_NOT_SUPPORTED,
                command=smb2.SMB2_NEGOTIATE,
            )
            raise BaseProtoHandler.TerminateConnection

        command = self._build_smb2_negotiate_response(dialect, req)
        self.smb2_selected_dialect = dialect
        try:
            self.smb2_client_signing_required = bool(req["SecurityMode"] & 0x0002)
        except _PARSE_ERRORS:
            self.smb2_client_signing_required = False
        client_negotiable = [d for d in req_dialects if d in SMB2_NEGOTIABLE_DIALECTS]
        self.smb2_client_max_dialect = max(client_negotiable) if client_negotiable else 0
        dialect_name = SMB2_DIALECTS.get(dialect, hex(dialect))
        self.client_info["smb_dialect"] = dialect_name
        self.logger.debug(
            f"SMB2_NEGOTIATE: selected dialect {dialect_name}", is_server=True
        )

        if dialect == smb2.SMB2_DIALECT_311:
            self.logger.debug(
                "SMB 3.1.1: hash capture OK, but path/filename capture "
                "unavailable (client requires signed responses)",
                is_server=True,
            )

        self.send_smb2_command(command.getData())

    def _fill_smb1_negotiate_params(
        self, params: typing.Any, nt_lm_index: int, server_time: int
    ) -> None:
        """Set negotiate parameter fields shared by both extended and non-extended paths."""
        params["DialectIndex"] = nt_lm_index
        params["SecurityMode"] = (
            smb.SMB.SECURITY_AUTH_ENCRYPTED | smb.SMB.SECURITY_SHARE_USER
        )
        params["MaxMpxCount"] = SMB1_MAX_MPX_COUNT
        params["MaxNumberVcs"] = 1
        params["MaxBufferSize"] = SMB1_MAX_BUFFER_SIZE
        params["MaxRawSize"] = 65536
        params["SessionKey"] = 0
        params["LowDateTime"] = server_time & 0xFFFFFFFF
        params["HighDateTime"] = (server_time >> 32) & 0xFFFFFFFF
        params["ServerTimeZone"] = 0

    def handle_smb1_negotiate(self, packet: smb.NewSMBPacket) -> None:
        resp = smb.NewSMBPacket()
        resp["Flags1"] = smb.SMB.FLAGS1_REPLY
        resp["Pid"] = packet["Pid"]
        resp["Tid"] = packet["Tid"]
        resp["Mid"] = packet["Mid"]

        req = smb.SMBCommand(packet["Data"][0])
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
        smb2_upgrade_target: str | None = None
        if cfg.smb_allow_smb1_upgrade and cfg.smb_enable_smb2:
            smb2_entries: dict[str, int] = {
                dialect: index
                for index, dialect in enumerate(dialects)
                if dialect in SMB2_DIALECT_REV
            }
            if smb2_entries:
                if "SMB 2.???" in smb2_entries:
                    smb2_upgrade_target = "SMB 2.???"
                else:
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

        server_time = get_server_time()
        use_extended = bool(packet["Flags2"] & smb.SMB.FLAGS2_EXTENDED_SECURITY)

        if use_extended:
            self.smb1_extended_security = True

            resp["Flags2"] = (
                smb.SMB.FLAGS2_EXTENDED_SECURITY
                | smb.SMB.FLAGS2_NT_STATUS
                | smb.SMB.FLAGS2_UNICODE
                | smb.SMB.FLAGS2_LONG_NAMES
            )

            _dialects_data = smb.SMBExtended_Security_Data()
            _dialects_data["ServerGUID"] = self.server.server_guid  # type: ignore[union-attr]
            blob = build_neg_token_init([SPNEGO_NTLMSSP_MECH])
            _dialects_data["SecurityBlob"] = blob.getData()

            _dialects_parameters = smb.SMBExtended_Security_Parameters()
            _dialects_parameters["Capabilities"] = (
                smb.SMB.CAP_EXTENDED_SECURITY | SMB1_CAPABILITIES_BASE
            )
            _dialects_parameters["ChallengeLength"] = 0
            dialect_label = "NT LM 0.12"
        else:
            self.smb1_extended_security = False
            self.smb1_challenge = self.config.ntlm_challenge

            resp["Flags2"] = (
                smb.SMB.FLAGS2_NT_STATUS
                | smb.SMB.FLAGS2_UNICODE
                | smb.SMB.FLAGS2_LONG_NAMES
            )

            _dialects_parameters = smb.SMBNTLMDialect_Parameters()
            _dialects_data = smb.SMBNTLMDialect_Data()

            _dialects_parameters["ChallengeLength"] = 8
            _dialects_data["Challenge"] = self.config.ntlm_challenge
            _dialects_parameters["Capabilities"] = SMB1_CAPABILITIES_BASE

            _dialects_data["Payload"] = smbserver.encodeSMBString(
                resp["Flags2"], cfg.smb_nb_domain
            ) + smbserver.encodeSMBString(resp["Flags2"], cfg.smb_nb_computer)
            dialect_label = "NT LM 0.12 (non-extended)"

        self._fill_smb1_negotiate_params(_dialects_parameters, nt_lm_index, server_time)

        command = smb.SMBCommand(smb.SMB.SMB_COM_NEGOTIATE)
        command["Data"] = _dialects_data
        command["Parameters"] = _dialects_parameters

        self.logger.debug(
            "SMB_COM_NEGOTIATE: selected dialect %s", dialect_label, is_server=True
        )
        self.client_info["smb_dialect"] = dialect_label
        resp.addCommand(command)
        self.send_data(resp.getData())

    def handle_ntlmssp(
        self,
        token: bytes,
        command_name: str = "SMB2_SESSION_SETUP",
    ) -> tuple[bytes, int]:
        is_gssapi = not token.startswith(b"NTLMSSP")

        if self.smb2_session_id == 0:
            self.smb2_session_id = secrets.randbelow(0xFFFFFFFFFFFFFFFE) + 1
        if self.smb1_uid == 0:
            self.smb1_uid = secrets.randbelow(0xFFFE) + 1

        match token[0]:
            case 0x60:  # ASN.1 APPLICATION[0]
                self.logger.debug(f"<{command_name}> GSSAPI negTokenInit", is_client=True)
                try:
                    neg_token = spnego.SPNEGO_NegTokenInit(data=token)
                except _PARSE_ERRORS as e:
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

            case 0xA1:  # ASN.1 CONTEXT[1]
                self.logger.debug(f"<{command_name}> GSSAPI negTokenArg", is_client=True)
                try:
                    neg_token = spnego.SPNEGO_NegTokenResp(data=token)
                except _PARSE_ERRORS as e:
                    self.logger.debug(f"Invalid GSSAPI token: {e}")
                    raise BaseProtoHandler.TerminateConnection from None
                token = neg_token["ResponseToken"]

        if len(token) <= 8:
            self.logger.fail(f"<{command_name}> Invalid NTLM token length: {len(token)}")
            raise BaseProtoHandler.TerminateConnection

        match token[8]:
            case 0x01:  # NEGOTIATE_MESSAGE
                negotiate = ntlm.NTLMAuthNegotiate()
                negotiate.fromString(token)
                if not is_gssapi:
                    self.logger.debug(
                        f"<{command_name}> NTLMSSP_NEGOTIATE_MESSAGE", is_client=True
                    )

                self.ntlm_negotiate_fields = ntlm_handle_negotiate_message(
                    negotiate, self.logger
                )

                challenge = ntlm_build_challenge_message(
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

                error_code = nt_errors.STATUS_MORE_PROCESSING_REQUIRED

            case 0x02:  # CHALLENGE_MESSAGE
                if not is_gssapi:
                    self.logger.debug(
                        f"<{command_name}> NTLMSSP_CHALLENGE_MESSAGE", is_client=True
                    )
                self.logger.debug("NTLM challenge message not supported!")
                raise BaseProtoHandler.TerminateConnection

            case 0x03:  # AUTHENTICATE_MESSAGE
                authenticate = ntlm.NTLMAuthChallengeResponse()
                authenticate.fromString(token)
                if not is_gssapi:
                    self.logger.debug(
                        f"<{command_name}> NTLMSSP_AUTHENTICATE_MESSAGE", is_client=True
                    )

                captured = ntlm_handle_authenticate_message(
                    authenticate,
                    challenge=self.config.ntlm_challenge,
                    client=self.client_address,
                    session=self.config,
                    logger=self.logger,
                    negotiate_fields=self.ntlm_negotiate_fields,
                )

                if not captured:
                    error_code = nt_errors.STATUS_ACCESS_DENIED
                    resp = build_neg_token_resp(NEG_STATE_REJECT)
                else:
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
        self.auth_attempt_count += 1
        max_captures = self.smb_config.smb_captures_per_connection
        error_code: int = nt_errors.STATUS_SUCCESS

        if max_captures > 0 and self.auth_attempt_count < max_captures:
            self.logger.debug(
                "ErrorCode=0x%08x (STATUS_ACCOUNT_DISABLED, capture %d/%d)",
                STATUS_ACCOUNT_DISABLED,
                self.auth_attempt_count,
                max_captures,
                is_server=True,
            )
            error_code = STATUS_ACCOUNT_DISABLED

        if self.smb_config.smb_error_code is not None:
            # Allow custom override via config
            error_code = self.smb_config.smb_error_code

        if error_code == nt_errors.STATUS_SUCCESS:
            self.logger.debug(
                "ErrorCode=0x%08x (STATUS_SUCCESS, awaiting tree connect)",
                0,
                is_server=True,
            )
        return error_code

    def handle_smb2_session_setup(self, packet: smb2.SMB2Packet) -> None:
        req = smb2.SMB2SessionSetup(data=packet["Data"])

        try:
            prev_session: int = req["PreviousSessionId"]
            prev_str = f"0x{prev_session:016x}" if prev_session else "(empty)"
            self.logger.debug(
                f"SMB2_SESSION_SETUP: PreviousSessionId={prev_str}",
                is_client=True,
            )
        except _PARSE_ERRORS:
            self.logger.debug("Failed to extract PreviousSessionId", exc_info=True)

        command = smb2.SMB2SessionSetup_Response()

        resp_token, error_code = self.handle_ntlmssp(
            req["Buffer"], command_name="SMB2_SESSION_SETUP"
        )
        command["SecurityBufferLength"] = len(resp_token)
        command["SecurityBufferOffset"] = 0x48
        command["Buffer"] = resp_token

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
        self.logger.debug("SMB2_LOGOFF", is_client=True)

        response = smb2.SMB2Logoff_Response()
        self.authenticated = False
        self.send_smb2_command(
            response.getData(),
            packet,
            status=nt_errors.STATUS_SUCCESS,
        )

    def handle_smb1_session_setup(self, packet: smb.NewSMBPacket) -> None:
        command = smb.SMBCommand(packet["Data"][0])
        if command["WordCount"] == 12:
            parameters = smb.SMBSessionSetupAndX_Extended_Response_Parameters()
            data = smb.SMBSessionSetupAndX_Extended_Response_Data(flags=packet["Flags2"])

            setup_params = smb.SMBSessionSetupAndX_Extended_Parameters(
                command["Parameters"]
            )
            setup_data = smb.SMBSessionSetupAndX_Extended_Data()
            setup_data["SecurityBlobLength"] = setup_params["SecurityBlobLength"]
            setup_data.fromString(command["Data"])

            try:
                is_unicode = bool(packet["Flags2"] & smb.SMB.FLAGS2_UNICODE)
                blob_len: int = setup_params["SecurityBlobLength"]
                raw_after_blob = command["Data"][blob_len:]
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
        cfg = self.smb_config
        setup_params = smb.SMBSessionSetupAndX_Parameters(command["Parameters"])

        oem_len: int = setup_params["AnsiPwdLength"]
        uni_len: int = setup_params["UnicodePwdLength"]
        is_unicode = bool(packet["Flags2"] & smb.SMB.FLAGS2_UNICODE)
        raw_data: bytes = command["Data"]
        oem_pwd: bytes = raw_data[:oem_len] if oem_len else b""
        uni_pwd: bytes = raw_data[oem_len : oem_len + uni_len] if uni_len else b""

        if oem_len == 0 and uni_len == 0:
            transport: str | None = None
        elif uni_len == 0 and oem_len <= 1 and oem_pwd in (b"", b"\x00"):
            transport = None
        elif (
            (uni_len == 0 and oem_len not in (0, 24) and oem_len <= 256)
            or (oem_len == 0 and uni_len not in (0, 24) and uni_len <= 512)
        ):
            self.logger.debug(
                "SMB_COM_SESSION_SETUP_ANDX: plaintext password detected "
                "despite challenge (unusual client behavior)",
                is_client=True,
            )
            transport = NTLM_TRANSPORT_CLEARTEXT
        else:
            transport = NTLM_TRANSPORT_RAW

        string_data = raw_data[oem_len + uni_len :]
        needs_pad = is_unicode and (oem_len + uni_len) % 2 == 0
        if needs_pad and len(string_data) > 0:
            string_data = string_data[1:]
        strings = _split_smb_strings(string_data, is_unicode)

        if transport is None:
            account = ""
            domain = ""
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
            if packet["Flags2"] & smb.SMB.FLAGS2_UNICODE and uni_pwd:
                pwd_data = uni_pwd
                if (oem_len % 2 == 0) and len(pwd_data) > 0:
                    pwd_data = pwd_data[1:]
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
                ntlm_handle_legacy_raw_auth(
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
            ntlm_handle_legacy_raw_auth(
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

        if self.smb1_uid == 0:
            self.smb1_uid = secrets.randbelow(0xFFFE) + 1

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

        error_code = self._resolve_auth_error_code()
        self.send_smb1_command(
            smb.SMB.SMB_COM_SESSION_SETUP_ANDX,
            resp_data,
            resp_params,
            packet,
            error_code=error_code,
        )

    def handle_smb1_logoff(self, packet: smb.NewSMBPacket) -> None:
        self.logger.debug("SMB_COM_LOGOFF_ANDX", is_client=True)

        parameters = smb.SMBLogOffAndX()
        self.send_smb1_command(
            smb.SMB.SMB_COM_LOGOFF_ANDX,
            b"",
            parameters,
            packet,
        )
        raise BaseProtoHandler.TerminateConnection

    def _extract_smb2_tree_path(self, packet: smb2.SMB2Packet) -> str:
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

    def handle_smb2_tree_connect(self, packet: smb2.SMB2Packet) -> None:
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

        # Extract share name from UNC path (\\server\share -> share)
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
            if path:
                self.client_info["smb_path"] = path
            resp["ShareType"] = 0x01  # SMB2_SHARE_TYPE_DISK
            resp["ShareFlags"] = 0x00000000
            self.logger.debug(
                "SMB2_TREE_CONNECT share accepted (TreeId=%d, path=%s)",
                self.smb2_tree_id_counter,
                path,
                is_server=True,
            )

        self.send_smb2_command(resp.getData(), packet, tree_id=self.smb2_tree_id_counter)

    def handle_smb2_tree_disconnect(self, packet: smb2.SMB2Packet) -> None:
        self.logger.debug(
            "SMB2_TREE_DISCONNECT TreeId=%d", packet["TreeID"], is_client=True
        )
        resp = smb2.SMB2TreeDisconnect_Response()
        self.send_smb2_command(resp.getData(), packet)

    def handle_smb2_ioctl(self, packet: smb2.SMB2Packet) -> None:
        try:
            req = smb2.SMB2Ioctl(packet["Data"])
            ctl_code = req["CtlCode"]
            self.logger.debug("SMB2_IOCTL CtlCode=0x%08x", ctl_code, is_client=True)
        except _PARSE_ERRORS:
            self.logger.debug("SMB2_IOCTL (malformed)", is_client=True)
            self._smb2_error_response(packet, nt_errors.STATUS_INVALID_PARAMETER)
            return

        if ctl_code == smb2.FSCTL_VALIDATE_NEGOTIATE_INFO:
            self._handle_validate_negotiate(packet, req)
        else:
            self._smb2_error_response(packet, nt_errors.STATUS_FS_DRIVER_REQUIRED)

    def _handle_validate_negotiate(
        self, packet: smb2.SMB2Packet, req: smb2.SMB2Ioctl
    ) -> None:
        try:
            vni = smb2.VALIDATE_NEGOTIATE_INFO(req["Buffer"])
            self.logger.debug(
                "FSCTL_VALIDATE_NEGOTIATE_INFO: Capabilities=0x%08x SecurityMode=0x%04x",
                vni["Capabilities"],
                vni["SecurityMode"],
                is_client=True,
            )

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

        except _PARSE_ERRORS:
            self.logger.debug("FSCTL_VALIDATE_NEGOTIATE_INFO failed", exc_info=True)
            self._smb2_error_response(packet, nt_errors.STATUS_ACCESS_DENIED)

    def handle_smb1_tree_connect(self, packet: smb.NewSMBPacket) -> None:
        path = ""
        try:
            cmd = smb.SMBCommand(packet["Data"][0])
            params = smb.SMBTreeConnectAndX_Parameters(cmd["Parameters"])
            pwd_len: int = params["PasswordLength"]
            raw_data: bytes = cmd["Data"]
            is_unicode = bool(packet["Flags2"] & smb.SMB.FLAGS2_UNICODE)

            offset = pwd_len
            if is_unicode and (43 + pwd_len) % 2 == 1:
                offset += 1  # skip alignment pad byte

            if is_unicode:
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
            self.logger.debug("SMB1 TREE_CONNECT IPC$ accepted", is_server=True)
            resp_data["Service"] = b"IPC\x00"
        else:
            if path:
                self.client_info["smb_path"] = path
            resp_data["Service"] = b"A:\x00"
            self.logger.debug(
                "SMB1 TREE_CONNECT share accepted (path=%s)", path, is_server=True
            )
        resp_data["NativeFileSystem"] = smbserver.encodeSMBString(packet["Flags2"], "")
        self.send_smb1_command(
            smb.SMB.SMB_COM_TREE_CONNECT_ANDX,
            resp_data,
            resp_params,
            packet,
        )

    def handle_smb1_tree_disconnect(self, packet: smb.NewSMBPacket) -> None:
        self.logger.debug("SMB_COM_TREE_DISCONNECT Tid=%d", packet["Tid"], is_client=True)
        self.send_smb1_command(
            smb.SMB.SMB_COM_TREE_DISCONNECT,
            b"",
            b"",
            packet,
        )

    def handle_smb2_create(self, packet: smb2.SMB2Packet) -> None:
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
        except _PARSE_ERRORS:
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
        except _PARSE_ERRORS:
            self.logger.debug("SMB2_QUERY_DIRECTORY (malformed)", is_client=True)
        self._smb2_error_response(packet, nt_errors.STATUS_NO_MORE_FILES)

    def handle_smb2_query_info(self, packet: smb2.SMB2Packet) -> None:
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
        except _PARSE_ERRORS:
            self.logger.debug("SMB2_QUERY_INFO (malformed)", is_client=True)
            self._smb2_error_response(packet, nt_errors.STATUS_INVALID_PARAMETER)
            return

        if info_type == 0x02:
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
            info = smb2.FILE_STANDARD_INFORMATION()
            info["AllocationSize"] = 0
            info["EndOfFile"] = 0
            info["NumberOfLinks"] = 1
            info["DeletePending"] = 0
            info["Directory"] = 0
            output_data = info.getData()

        elif file_info_class == smb2.SMB2_FILE_BASIC_INFO:
            info = smb2.FILE_BASIC_INFORMATION()
            info["CreationTime"] = now
            info["LastAccessTime"] = now
            info["LastWriteTime"] = now
            info["ChangeTime"] = now
            info["FileAttributes"] = smb2.FILE_ATTRIBUTE_ARCHIVE
            output_data = info.getData()

        elif file_info_class == smb2.SMB2_FILE_ALL_INFO:
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
        except _PARSE_ERRORS:
            self.logger.debug("SMB2_READ (malformed)", is_client=True)
        self._smb2_error_response(packet, nt_errors.STATUS_END_OF_FILE)

    def handle_smb2_close(self, packet: smb2.SMB2Packet) -> None:
        self.logger.debug("SMB2_CLOSE", is_client=True)
        resp = smb2.SMB2Close_Response()
        self.send_smb2_command(resp.getData(), packet)

    def handle_smb2_write(self, packet: smb2.SMB2Packet) -> None:
        count = 0
        try:
            req = smb2.SMB2Write(packet["Data"])
            count = req["Length"]
            self.logger.debug(
                "SMB2_WRITE Length=%d Offset=%d", count, req["Offset"], is_client=True
            )
        except _PARSE_ERRORS:
            self.logger.debug("SMB2_WRITE (malformed)", is_client=True)
        resp = smb2.SMB2Write_Response()
        resp["Count"] = count
        self.send_smb2_command(resp.getData(), packet)

    def handle_smb2_flush(self, packet: smb2.SMB2Packet) -> None:
        self.logger.debug("SMB2_FLUSH", is_client=True)
        resp = smb2.SMB2Flush_Response()
        self.send_smb2_command(resp.getData(), packet)

    def handle_smb2_lock(self, packet: smb2.SMB2Packet) -> None:
        self.logger.debug("SMB2_LOCK", is_client=True)
        resp = smb2.SMB2Lock_Response()
        self.send_smb2_command(resp.getData(), packet)

    def handle_smb2_set_info(self, packet: smb2.SMB2Packet) -> None:
        try:
            req = smb2.SMB2SetInfo(packet["Data"])
            self.logger.debug(
                "SMB2_SET_INFO InfoType=0x%02x Class=%d",
                req["InfoType"],
                req["FileInfoClass"],
                is_client=True,
            )
        except _PARSE_ERRORS:
            self.logger.debug("SMB2_SET_INFO (malformed)", is_client=True)
        resp = smb2.SMB2SetInfo_Response()
        self.send_smb2_command(resp.getData(), packet)

    def handle_smb1_nt_create(self, packet: smb.NewSMBPacket) -> None:
        name = ""
        try:
            cmd = smb.SMBCommand(packet["Data"][0])
            params = smb.SMBNtCreateAndX_Parameters(cmd["Parameters"])
            file_name_length: int = params["FileNameLength"]
            raw_data: bytes = cmd["Data"]
            is_unicode = bool(packet["Flags2"] & smb.SMB.FLAGS2_UNICODE)

            if is_unicode:
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
        except _PARSE_ERRORS:
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
        # Absolute offsets from SMB header start
        # 32(hdr) + 1(WC) + 20(Words) + 2(BC) = 55
        pad1 = b"\x00"  # align to even offset (55 -> 56)
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
        now = get_server_time()

        PASS_THROUGH_BASE = 0x03E8

        native = info_level
        if info_level >= PASS_THROUGH_BASE:
            native = info_level - PASS_THROUGH_BASE

        # SMB_INFO_STANDARD (0x0001/0x0100)
        if info_level in {0x0001, 0x0100}:
            return b"\x00" * 22

        # SMB_INFO_QUERY_EA_SIZE (0x0002/0x0200)
        if info_level in {0x0002, 0x0200}:
            return b"\x00" * 26  # 22 (standard) + 4 (EaSize)

        # SMB_INFO_QUERY_EAS_FROM_LIST (0x0003)
        if info_level == 0x0003:
            return b"\x00" * 4

        if info_level == 0x0006:
            return b"\x00" * 8

        # SMB_QUERY_FILE_EA_INFO (0x0103)
        if native == 7 or info_level == 0x0103:
            return b"\x00" * 4

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
            tail = b"\x00" * (4 + 4 + 8 + 4 + 4 + 4)
            return basic.getData() + std.getData() + b"\x00" * 8 + tail

        if native == 30 or info_level == 0x010B:
            return b"\x00" * 16

        if native == 4 or info_level == smb.SMB_QUERY_FILE_BASIC_INFO:
            file_info = smb.SMBQueryFileBasicInfo()
            file_info["CreationTime"] = now
            file_info["LastAccessTime"] = now
            file_info["LastWriteTime"] = now
            file_info["LastChangeTime"] = now
            file_info["ExtFileAttributes"] = smb2.FILE_ATTRIBUTE_ARCHIVE
            return file_info.getData()

        if native == 5 or info_level == smb.SMB_QUERY_FILE_STANDARD_INFO:
            file_info = smb.SMBQueryFileStandardInfo()
            file_info["AllocationSize"] = 0
            file_info["EndOfFile"] = 0
            file_info["NumberOfLinks"] = 1
            file_info["DeletePending"] = 0
            file_info["Directory"] = 0
            return file_info.getData()

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

        # Zero-filled responses grouped by size:
        #
        #   8 bytes: FileInternalInformation (6)
        #            FilePositionInformation (11)
        #            FileAllocationInformation (16)
        #            FilePipeInformation (23)
        if native in {6, 11, 16, 23}:
            return b"\x00" * 8

        #  12 bytes: FileNamesInformation (12)
        #            FilePipeRemoteInformation (25)
        if native in {12, 25}:
            return b"\x00" * 12

        #   4 bytes: FileModeInformation (13)
        #            FileAlignmentInformation (14)
        #            FileMailslotQueryInformation (26)
        if native in {13, 14, 26}:
            return b"\x00" * 4

        #  36 bytes: FilePipeLocalInformation (24)
        if native == 24:
            return b"\x00" * 36

        if info_level == 0x0120:
            return b"\x00" * 100

        return None

    def handle_smb1_trans2(self, packet: smb.NewSMBPacket) -> None:
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
        except _PARSE_ERRORS:
            self.logger.debug("SMB_COM_TRANSACTION2 (malformed)", is_client=True)

        if subcommand == smb.SMB.TRANS2_QUERY_PATH_INFORMATION:
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
            # Request parameters: FID(2) + InformationLevel(2)
            info_level = 0
            try:
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
        try:
            cmd = smb.SMBCommand(packet["Data"][0])
            params = smb.SMBReadAndX_Parameters(cmd["Parameters"])
            self.logger.debug(
                "SMB_COM_READ_ANDX Fid=%d Offset=%d",
                params["Fid"],
                params["Offset"],
                is_client=True,
            )
        except _PARSE_ERRORS:
            self.logger.debug("SMB_COM_READ_ANDX (malformed)", is_client=True)
        self.send_smb1_command(
            smb.SMB.SMB_COM_READ_ANDX,
            b"",
            b"",
            packet,
            error_code=nt_errors.STATUS_END_OF_FILE,
        )

    def handle_smb1_close(self, packet: smb.NewSMBPacket) -> None:
        try:
            cmd = smb.SMBCommand(packet["Data"][0])
            params = smb.SMBClose_Parameters(cmd["Parameters"])
            self.logger.debug("SMB_COM_CLOSE Fid=%d", params["FID"], is_client=True)
        except _PARSE_ERRORS:
            self.logger.debug("SMB_COM_CLOSE (malformed)", is_client=True)
        self.send_smb1_command(
            smb.SMB.SMB_COM_CLOSE,
            b"",
            b"",
            packet,
        )


class SMBServer(ThreadingTCPServer):
    default_handler_class = SMBHandler
    default_port = 445

    def __init__(
        self,
        config: SessionConfig,
        server_config: SMBServerConfig,
        server_address: tuple[str, int] | None = None,
        RequestHandlerClass: type | None = None,
    ) -> None:
        self.server_config = server_config
        # Stable ServerGuid per server instance
        self.server_guid: bytes = secrets.token_bytes(16)
        super().__init__(config, server_address, RequestHandlerClass)

    def finish_request(
        self, request: typing.Any, client_address: tuple[str, int]
    ) -> None:
        self.RequestHandlerClass(
            self.config, self.server_config, request, client_address, self
        )
