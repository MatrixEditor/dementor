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
import uuid
import calendar
import time
import secrets

from impacket.smbserver import TypesMech, MechTypes
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

from dementor.config.toml import TomlConfig, Attribute as A
from dementor.config.session import SessionConfig
from dementor.config.util import get_value
from dementor.logger import ProtocolLogger, dm_logger
from dementor.protocols.ntlm import (
    NTLM_AUTH_CreateChallenge,
    NTLM_report_auth,
    ATTR_NTLM_CHALLENGE,
    ATTR_NTLM_ESS,
    NTLM_split_fqdn,
)
from dementor.protocols.spnego import (
    negTokenInit_step,
    negTokenInit,
    SPNEGO_NTLMSSP_MECH,
)
from dementor.servers import BaseProtoHandler, ThreadingTCPServer, ServerThread


SMB2_DIALECTS = {
    smb2.SMB2_DIALECT_002: "SMB 2.002",
    smb2.SMB2_DIALECT_21: "SMB 2.1",
    smb2.SMB2_DIALECT_30: "SMB 3.0",
    smb2.SMB2_DIALECT_302: "SMB 3.0.2",
    smb2.SMB2_DIALECT_311: "SMB 3.1.1",
    # used in SMB1 requests
    0x0000: "SMB 2.???",
}

SMB2_DIALECT_REV = {v: k for k, v in SMB2_DIALECTS.items()}


class SMBServerConfig(TomlConfig):
    _section_ = "SMB"
    _fields_ = [
        A("smb_port", "Port"),
        A("smb_server_os", "ServerOS", "Windows"),
        A("smb_fqdn", "FQDN", "DEMENTOR", section_local=False),
        A("smb_error_code", "ErrorCode", nt_errors.STATUS_SMB_BAD_UID),
        # proposed: protocol transition from smb1 to smb2
        A("smb2_support", "SMB2Support", True),
        ATTR_NTLM_CHALLENGE,
        ATTR_NTLM_ESS,
    ]

    def set_smb_error_code(self, value: str | int):
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


def apply_config(session):
    session.smb_config = list(
        map(SMBServerConfig, get_value("SMB", "Server", default=[]))
    )


def create_server_threads(session):
    servers = []
    if session.smb_enabled:
        for server_config in session.smb_config:
            servers.append(
                ServerThread(
                    session,
                    SMBServer,
                    server_config,
                    server_address=(session.bind_address, server_config.smb_port),
                )
            )
    return servers


def SMB_get_server_time():
    value = calendar.timegm(time.gmtime())
    value *= 10000000
    return value + 116444736000000000


# --- SMB2/3 ---
def smb2_negotiate(handler, target_revision: int):
    command = smb2.SMB2Negotiate_Response()
    command["SecuityMode"] = 0x01  # signing enabled, but not enforced
    command["DialectRevision"] = target_revision
    command["ServerGuid"] = secrets.token_bytes(16)
    command["Capabilities"] = 0x00
    command["MaxTransactSize"] = 65536
    command["MaxReadSize"] = 65536
    command["MaxWriteSize"] = 65536
    command["SystemTime"] = SMB_get_server_time()
    command["ServerStartTime"] = SMB_get_server_time()
    command["SecurityBufferOffset"] = 0x80

    blob = negTokenInit([SPNEGO_NTLMSSP_MECH])
    command["Buffer"] = blob.getData()
    command["SecurityBufferLength"] = len(command["Buffer"])
    return command


def smb2_negotiate_protocol(handler, packet: smb2.SMB2Packet) -> None:
    req = smb3.SMB2Negotiate(data=packet["Data"])
    # Let's take the first dialect the clients wan't us to use
    req_dialects = req["Dialects"][: req["DialectCount"]]
    str_req_dialects = ", ".join([SMB2_DIALECTS.get(d, hex(d)) for d in req_dialects])
    guid = uuid.UUID(bytes_le=req["ClientGuid"])
    handler.log_client(
        f"requested dialects: {str_req_dialects} (client: {guid})", "SMB2_NEGOTIATE"
    )

    # REVISIT
    dialect = None
    for candidate in req_dialects:
        if candidate < 0x300:  # SMBv3 not supported
            dialect = candidate

    if dialect is None:
        handler.logger.fail(
            f"Client requested unsupported dialects: {str_req_dialects}"
        )
        raise BaseProtoHandler.TerminateConnection

    command = smb2_negotiate(handler, dialect)
    handler.log_server(f"selected dialect: {SMB2_DIALECTS[dialect]}", "SMB2_NEGOTIATE")
    handler.send_smb2_command(command.getData())


def smb2_session_setup(handler, packet: smb2.SMB2Packet) -> None:
    req = smb2.SMB2SessionSetup(data=packet["Data"])
    command = smb2.SMB2SessionSetup_Response()

    resp_token, error_code = handler.authenticate(req["Buffer"])
    command["SecurityBufferLength"] = len(resp_token)
    command["SecurityBufferOffset"] = 0x48
    command["Buffer"] = resp_token

    return handler.send_smb2_command(
        command.getData(),
        packet,
        status=error_code,
    )


# --- SMB1 ---
def smb1_negotiate_protocol(handler, packet: smb.NewSMBPacket) -> None:
    resp = smb.NewSMBPacket()
    resp["Flags1"] = smb.SMB.FLAGS1_REPLY
    resp["Pid"] = packet["Pid"]
    resp["Tid"] = packet["Tid"]
    resp["Mid"] = packet["Mid"]

    req = smb.SMBCommand(packet["Data"][0])
    dialects = [
        dialect.rstrip(b"\x00").decode(errors="replace")
        for dialect in req["Data"].split(b"\x02")[1:]
    ]
    handler.log_client(f"dialects: {', '.join(dialects)}", "SMB_COM_NEGOTIATE")
    # always select the first one present if SMB2 is not present
    index = 0
    for i, dialect in enumerate(dialects):
        if dialect in SMB2_DIALECT_REV and handler.smb_config.smb2_support:
            index = i
            break

    target_dialect = dialects[index]
    if target_dialect in SMB2_DIALECT_REV:
        # Requested dialect is SMB2 -> respond with SMB2
        command = smb2_negotiate(handler, SMB2_DIALECT_REV[target_dialect])
        handler.log_server("Switching protocol to SMBv2", "SMB_COM_NEGOTIATE")
        return handler.send_smb2_command(command.getData(), command=smb2.SMB2_NEGOTIATE)

    if packet["Flags2"] & smb.SMB.FLAGS2_EXTENDED_SECURITY:
        resp["Flags2"] = smb.SMB.FLAGS2_EXTENDED_SECURITY | smb.SMB.FLAGS2_NT_STATUS
        _dialects_data = smb.SMBExtended_Security_Data()
        _dialects_data["ServerGUID"] = secrets.token_bytes(16)
        blob = negTokenInit([SPNEGO_NTLMSSP_MECH])
        _dialects_data["SecurityBlob"] = blob.getData()

        _dialects_parameters = smb.SMBExtended_Security_Parameters()
        _dialects_parameters["Capabilities"] = (
            smb.SMB.CAP_EXTENDED_SECURITY
            | smb.SMB.CAP_USE_NT_ERRORS
            | smb.SMB.CAP_NT_SMBS
            | smb.SMB.CAP_UNICODE
        )
        _dialects_parameters["ChallengeLength"] = 0
    else:
        handler.logger.fail(
            "Client requested SMB1 or lower dialect without extended security, "
            "which is not supported."
        )
        raise BaseProtoHandler.TerminateConnection

    _dialects_parameters["DialectIndex"] = index
    _dialects_parameters["SecurityMode"] = (
        smb.SMB.SECURITY_AUTH_ENCRYPTED | smb.SMB.SECURITY_SHARE_USER
    )
    _dialects_parameters["MaxMpxCount"] = 1
    _dialects_parameters["MaxNumberVcs"] = 1
    _dialects_parameters["MaxBufferSize"] = 64000
    _dialects_parameters["MaxRawSize"] = 65536
    _dialects_parameters["SessionKey"] = 0
    _dialects_parameters["LowDateTime"] = 0
    _dialects_parameters["HighDateTime"] = 0
    _dialects_parameters["ServerTimeZone"] = 0

    command = smb.SMBCommand(smb.SMB.SMB_COM_NEGOTIATE)
    command["Data"] = _dialects_data
    command["Parameters"] = _dialects_parameters

    handler.log_server(f"selected dialect: {target_dialect}", "SMB_COM_NEGOTIATE")
    resp.addCommand(command)
    handler.send_data(resp.getData())


def smb1_session_setup(handler, packet: smb.NewSMBPacket) -> None:
    command = smb.SMBCommand(packet["Data"][0])
    handler.log_client(f"session setup: {command.fields}", "SMB_COM_SESSION_SETUP_ANDX")
    # handler.send_data(packet.getData())

    # From [MS-SMB]
    # When extended security is being used (see section 3.2.4.2.4), the
    # request MUST take the following form
    # [..]
    # WordCount (1 byte): The value of this field MUST be 0x0C.
    if command["WordCount"] == 12:
        parameters = smb.SMBSessionSetupAndX_Extended_Response_Parameters()
        data = smb.SMBSessionSetupAndX_Extended_Response_Data(flags=packet["Flags2"])

        setup_params = smb.SMBSessionSetupAndX_Extended_Parameters(
            command["Parameters"]
        )
        setup_data = smb.SMBSessionSetupAndX_Extended_Data()
        setup_data["SecurityBlobLength"] = setup_params["SecurityBlobLength"]
        setup_data.fromString(command["Data"])

        resp_token, error_code = handler.authenticate(setup_data["SecurityBlob"])
        data["SecurityBlob"] = resp_token
        data["SecurityBlobLength"] = len(resp_token)
        parameters["SecurityBlobLength"] = len(resp_token)
        data["NativeOS"] = smbserver.encodeSMBString(
            packet["Flags2"],
            handler.smb_config.smb_server_os,
        )
        data["NativeLanMan"] = smbserver.encodeSMBString(
            packet["Flags2"],
            handler.smb_config.smb_server_os,
        )
        handler.send_smb1_command(
            smb.SMB.SMB_COM_SESSION_SETUP_ANDX,
            data,
            parameters,
            packet,
            error_code=error_code,
        )


# --- Handler ---
class SMBHandler(BaseProtoHandler):
    STATE_NEGOTIATE = 0
    STATE_AUTH = 1

    def __init__(
        self, config: SessionConfig, server_config, request, client_address, server
    ) -> None:
        # initialize session data
        self.authenticated = False
        self.smb_config = server_config
        self.smb1_commands = {
            smb.SMB.SMB_COM_NEGOTIATE: smb1_negotiate_protocol,
            smb.SMB.SMB_COM_SESSION_SETUP_ANDX: smb1_session_setup,
        }
        self.smb2_commands = {
            smb2.SMB2_NEGOTIATE: smb2_negotiate_protocol,
            smb2.SMB2_SESSION_SETUP: smb2_session_setup,
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

    def send_data(self, payload: bytes, ty=None) -> None:
        packet = nmb.NetBIOSSessionPacket()
        packet.set_type(ty or nmb.NETBIOS_SESSION_MESSAGE)
        packet.set_trailer(payload)
        self.send(packet.rawData())

    def send_smb1_command(self, command, data, parameters, packet, error_code=None):
        resp = smb.NewSMBPacket()
        resp["Flags1"] = smb.SMB.FLAGS1_REPLY
        resp["Flags2"] = (
            smb.SMB.FLAGS2_EXTENDED_SECURITY
            | smb.SMB.FLAGS2_NT_STATUS
            | smb.SMB.FLAGS2_LONG_NAMES
            | packet["Flags2"] & smb.SMB.FLAGS2_UNICODE
        )
        resp["Pid"] = packet["Pid"]
        resp["Tid"] = packet["Tid"]
        resp["Mid"] = packet["Mid"]
        if error_code:
            resp["ErrorCode"] = error_code >> 16
            resp["_reserved"] = error_code >> 8 & 0xFF
            resp["ErrorClass"] = error_code & 0xFF

        command = smb.SMBCommand(command)
        command["Data"] = data
        command["Parameters"] = parameters
        resp.addCommand(command)

        self.send_data(resp.getData())

    def send_smb2_command(
        self, command_data: bytes, packet=None, command=None, status=None
    ) -> None:
        resp = smb2.SMB2Packet()
        resp["Flags"] = smb2.SMB2_FLAGS_SERVER_TO_REDIR  # (response)
        resp["Status"] = status or nt_errors.STATUS_SUCCESS

        if packet is None:
            packet = {
                "Command": command or 0,
                "CreditCharge": 0,
                "Reserved": 0,
                "MessageID": 0,
                "TreeID": 0xFFFF,
            }
        resp["CreditRequestResponse"] = 1
        resp["Command"] = packet["Command"]
        resp["CreditCharge"] = packet["CreditCharge"]
        resp["Reserved"] = packet["Reserved"]
        resp["SessionID"] = 0
        resp["MessageID"] = packet["MessageID"]
        resp["TreeID"] = packet["TreeID"]
        resp["CreditRequestResponse"] = 1
        resp["Data"] = command_data
        self.send_data(resp.getData())

    def setup(self) -> None:
        self.logger.debug(f"Incoming connection from {self.client_host}")

    def finish(self) -> None:
        self.logger.debug(f"Connection to {self.client_host} closed")

    def handle_data(self, data, transport) -> None:
        # transport.settimeout(2)
        while True:
            data = self.recv(8192)
            if not data:
                break

            # 1. Step: decode NetBIOS packet
            packet = nmb.NetBIOSSessionPacket(data)
            if packet.get_type() == nmb.NETBIOS_SESSION_KEEP_ALIVE:
                # discard keep alive packets
                self.logger.debug("<NETBIOS_SESSION_KEEP_ALIVE>", is_client=True)
                continue

            if packet.get_type() == nmb.NETBIOS_SESSION_REQUEST:
                # NOTE: we can split the packet trailer and get the caller and remote name
                # using the 0x20 space separator:
                # 0000   81 00 00 44 20 43 4b 46 44 45 4e 45 43 46 44 45   ...D CKFDENECFDE
                # 0010   46 46 43 46 47 45 46 46 43 43 41 43 41 43 41 43   FFCFGEFFCCACACAC
                # 0020   41 43 41 43 41 00 20 45 4d 45 50 45 44 45 42 45   ACACA. EMEPEDEBE
                # 0030   4d 45 4e 45 42 45 44 45 49 45 4a 45 4f 45 46 43   MENEBEDEIEJEOEFC
                # 0040   41 43 41 43 41 41 41 00                           ACACAAA.
                try:
                    _, remote, caller = packet.get_trailer().split(b" ")
                    field = NetBIOSNameField("caller", b"<invalid>")
                    called_name = field.m2i(None, b"\x20" + remote[:-2]).decode(
                        errors="replace"
                    )
                    calling_name = field.m2i(None, b"\x20" + caller[:-2]).decode(
                        errors="replace"
                    )
                    self.logger.debug(
                        f"<NETBIOS_SESSION_REQUEST> {calling_name} -> {called_name}",
                        is_client=True,
                    )
                except ValueError:
                    pass  # silently ignore
                # accept all session requests
                self.send_data(b"\x00", nmb.NETBIOS_SESSION_POSITIVE_RESPONSE)
                continue

            # 2. Step: decode SMB packet
            # The protocol identifier for SMBv1 is 0xFF 0x53 0x4C 0x49 0x53 0x4E 0x00:
            raw_smb_data = packet.get_trailer()
            smbv1 = False
            match raw_smb_data[0]:
                case 0xFF:  # SMB1
                    packet = smb.NewSMBPacket(data=raw_smb_data)
                    smbv1 = True
                case 0xFE:  # SMB2/SMB3
                    packet = smb2.SMB2Packet(data=raw_smb_data)
                case _:
                    self.logger.error(f"Unknown SMB packet type: {raw_smb_data[0]}")
                    break

            # 3. Step: handle SMB packet
            self.handle_smb_packet(packet, smbv1)

    def handle_smb_packet(self, packet, smbv1=False):
        command = packet["Command"]
        title = f"SMBv{1 if smbv1 else 2} command {command:#x}"
        handler_map = self.smb1_commands if smbv1 else self.smb2_commands
        handler = handler_map.get(command)
        if handler:
            try:
                handler(self, packet)
            except BaseProtoHandler.TerminateConnection:
                raise
            except Exception as e:
                self.logger.exception(f"Error in {title}: {e}")
        else:
            self.logger.error(f"{title} not implemented")
            raise BaseProtoHandler.TerminateConnection

    def log_client(self, msg, command=None):
        self.log(msg, command, is_client=True)

    def log_server(self, msg, command=None):
        self.log(msg, command, is_server=True)

    def log(self, msg, command=None, is_server=False, is_client=False):
        if command:
            msg = f"<{command}> {msg}"
        self.logger.debug(msg, is_server=is_server, is_client=is_client)

    def authenticate(self, token: bytes) -> tuple:
        # Performs NTLM negotiation with the client
        is_gssapi = not token.startswith(b"NTLMSSP")
        command_name = "SMB2_SESSION_SETUP"

        # Raw NTLM token can be used directly
        match token[0]:
            case 0x60:  # GSSAPI negTokenInit
                self.log_client("GSSAPI negTokenInit", command_name)
                # Still in NEGOTIATE state, which means we expect a simple
                # negTokenInit structure
                try:
                    neg_token = spnego.SPNEGO_NegTokenInit(data=token)
                except Exception as e:
                    self.logger.debug(f"Invalid GSSAPI token: {e}")
                    raise BaseProtoHandler.TerminateConnection

                # There should be exactly one mechanism
                mech_type = neg_token["MechTypes"][0]
                if mech_type != TypesMech[SPNEGO_NTLMSSP_MECH]:
                    # reject this request by providing the NTLM mechanism
                    name = MechTypes.get(mech_type, "<unknown>")
                    self.logger.warning(
                        f"<{command_name}> Unsupported mechanism: {name} ({mech_type.hex()})"
                    )

                    resp = negTokenInit_step(
                        0x02,  # reject
                        supported_mech=SPNEGO_NTLMSSP_MECH,
                    )
                    return resp.getData(), nt_errors.STATUS_MORE_PROCESSING_REQUIRED

                # great, we have the NTLM token
                token = neg_token["MechToken"]

            case 0xA1:  # GSSAPI negTokenResp
                # we expect a negTokenArg storing the NTLM auth token
                self.log_client("GSSAPI negTokenArg", command_name)
                try:
                    neg_token = spnego.SPNEGO_NegTokenResp(data=token)
                except Exception as e:
                    self.logger.debug(f"Invalid GSSAPI token: {e}")
                    raise BaseProtoHandler.TerminateConnection

                token = neg_token["ResponseToken"]

        # NTLM authentication below
        if len(token) < 8:
            self.logger.error(
                f"<{command_name}> Invalid NTLM token length: {len(token)}"
            )
            raise BaseProtoHandler.TerminateConnection

        error_code = self.smb_config.smb_error_code
        match token[8]:
            case 0x01:  # NEGOTIATE
                negotiate = ntlm.NTLMAuthNegotiate()
                negotiate.fromString(token)
                if not is_gssapi:
                    self.log_client("NTLMSSP_NEGOTIATE_MESSAGE", command_name)

                challenge = NTLM_AUTH_CreateChallenge(
                    negotiate,
                    *NTLM_split_fqdn(self.smb_config.smb_fqdn),
                    challenge=self.smb_config.ntlm_challenge,
                    disable_ess=not self.smb_config.ntlm_ess,
                )
                self.log_server("NTLMSSP_CHALLENGE_MESSAGE", command_name)
                if is_gssapi:
                    resp = negTokenInit_step(
                        0x01,  # accept-incomplete
                        challenge.getData(),
                        supported_mech=SPNEGO_NTLMSSP_MECH,
                    )
                else:
                    resp = challenge

                # important: we have to adjust the state here
                error_code = nt_errors.STATUS_MORE_PROCESSING_REQUIRED

            case 0x02:  # CHALLENGE
                # shouldn't happen
                if not is_gssapi:
                    self.log_client("NTLMSSP_CHALLENGE_MESSAGE", command_name)
                self.logger.warning("NTLM challenge message not supported!")
                raise BaseProtoHandler.TerminateConnection

            case 0x03:  # AUTHENTICATE
                authenticate = ntlm.NTLMAuthChallengeResponse()
                authenticate.fromString(token)
                if not is_gssapi:
                    self.log_client("NTLMSSP_AUTHENTICATE_MESSAGE", command_name)

                NTLM_report_auth(
                    authenticate,
                    challenge=self.smb_config.ntlm_challenge,
                    client=self.client_address,
                    session=self.config,
                    logger=self.logger,
                )
                resp = negTokenInit_step(0x02)

            case message_type:
                self.log_client(f"NTLMSSP: unknown {message_type:02x}", command_name)
                raise BaseProtoHandler.TerminateConnection

        return resp.getData(), error_code


class SMBServer(ThreadingTCPServer):
    default_handler_class = SMBHandler
    default_port = 445

    def __init__(
        self,
        config: SessionConfig,
        server_config,
        server_address=None,
        RequestHandlerClass: type | None = None,
    ) -> None:
        self.server_config = server_config
        super().__init__(config, server_address, RequestHandlerClass)

    def finish_request(self, request, client_address) -> None:
        return self.RequestHandlerClass(
            self.config, self.server_config, request, client_address, self
        )
