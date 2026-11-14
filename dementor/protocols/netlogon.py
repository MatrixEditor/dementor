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
import enum

from scapy.layers import smb
from scapy.fields import (
    FlagsField,
    LEShortEnumField,
    StrNullField,
    StrNullFieldUtf16,
    XLEShortField,
    ConditionalField,
    ByteField,
)


LOGON_PRIMARY_QUERY = 0x07
LOGON_SAM_LOGON_REQUEST = 0x12
LOGON_SAM_LOGON_RESPONSE = 0x13
LOGON_SAM_PAUSE_RESPONSE = 0x14
LOGON_SAM_USER_UNKNOWN = 0x15
LOGON_SAM_LOGON_RESPONSE_EX = 0x17
LOGON_PRIMARY_RESPONSE = 0x17
LOGON_SAM_USER_UNKNOWN_EX = 0x19


NETLOGON_NT_VERSION_1 = 0x00000001
NETLOGON_NT_VERSION_5 = 0x00000002
NETLOGON_NT_VERSION_5EX = 0x00000004
NETLOGON_NT_VERSION_5EX_WITH_IP = 0x00000008
NETLOGON_NT_VERSION_WITH_CLOSEST_SITE = 0x00000010
NETLOGON_NT_VERSION_AVOID_NT4EMUL = 0x01000000
NETLOGON_NT_VERSION_PDC = 0x10000000
NETLOGON_NT_VERSION_IP = 0x20000000
NETLOGON_NT_VERSION_LOCAL = 0x40000000
NETLOGON_NT_VERSION_GC = 0x80000000


DS_PDC_FLAG = 0x00000001
DS_GC_FLAG = 0x00000004
DS_LDAP_FLAG = 0x00000008
DS_DS_FLAG = 0x00000010
DS_KDC_FLAG = 0x00000020
DS_TIMESERV_FLAG = 0x00000040
DS_CLOSEST_FLAG = 0x00000080
DS_WRITABLE_FLAG = 0x00000100
DS_GOOD_TIMESERV_FLAG = 0x00000200
DS_NDNC_FLAG = 0x00000400
DS_SELECT_SECRET_DOMAIN_6_FLAG = 0x00000800
DS_FULL_SECRET_DOMAIN_6_FLAG = 0x00001000
DS_WS2008_FLAG = 0x00002000
DS_WS2012_FLAG = 0x00004000
DS_WS2012R2_FLAG = 0x00008000
DS_WS2016_FLAG = 0x00010000
DS_DNS_CONTROLLER_FLAG = 0x20000000
DS_DNS_DOMAIN_FLAG = 0x40000000
DS_DNS_FOREST_FLAG = 0x80000000


class NETLOGON_PRIMARY_RESPONSE(smb.NETLOGON):
    fields_desc = [
        # Opcode (2 bytes, little-endian)
        LEShortEnumField("OpCode", LOGON_PRIMARY_RESPONSE, smb._NETLOGON_opcodes),
        # PrimaryDCName (variable, null-terminated ASCII)
        StrNullField("PrimaryDCName", ""),
        # UnicodePrimaryDCName (variable, null-terminated UTF-16LE, even-aligned)
        StrNullFieldUtf16("UnicodePrimaryDCName", ""),
        ConditionalField(
            ByteField("UnicodePrimaryDCNamePad", default=0x00),
            lambda pkt: len(pkt.PrimaryDCName) % 2 != 0,
        ),
        # UnicodeDomainName (variable, null-terminated UTF-16LE)
        StrNullFieldUtf16("UnicodeDomainName", ""),
        # NtVersion (4 bytes, little-endian)
        FlagsField("NtVersion", NETLOGON_NT_VERSION_1, -32, smb._NV_VERSION),
        # LmNtToken (2 bytes, little-endian)
        XLEShortField("LmNtToken", 0xFFFF),
        # Lm20Token (2 bytes, little-endian)
        XLEShortField("Lm20Token", 0xFFFF),
    ]


class ResponseFamily(enum.Enum):
    SAM_LOGON_EX = enum.auto()
    SAM_LOGON = enum.auto()
    PRIMARY = enum.auto()
    SAM_LOGON_NT40 = enum.auto()


def select_response_type(nt_version: int) -> ResponseFamily:
    if nt_version & (NETLOGON_NT_VERSION_5EX | NETLOGON_NT_VERSION_5EX_WITH_IP):
        return ResponseFamily.SAM_LOGON_EX

    if nt_version & NETLOGON_NT_VERSION_5:
        return ResponseFamily.SAM_LOGON

    if nt_version & NETLOGON_NT_VERSION_PDC:
        return ResponseFamily.PRIMARY

    # Default to NT40 response
    return ResponseFamily.SAM_LOGON_NT40


def build_primary_response(
    domain_name: str,
    dc_name: str,
    nt_version: int = NETLOGON_NT_VERSION_1,
) -> NETLOGON_PRIMARY_RESPONSE:
    return NETLOGON_PRIMARY_RESPONSE(
        OpCode=LOGON_PRIMARY_RESPONSE,
        PrimaryDCName=dc_name,
        UnicodePrimaryDCName=dc_name,
        UnicodeDomainName=domain_name,
        NtVersion=nt_version,
        LmNtToken=0xFFFF,
        Lm20Token=0xFFFF,
    )


def build_sam_logon_response_nt40(
    dc_name: str,
    user_name: str,
    domain_name: str,
    opcode: int = LOGON_SAM_LOGON_RESPONSE,
) -> smb.NETLOGON_SAM_LOGON_RESPONSE_NT40:
    return smb.NETLOGON_SAM_LOGON_RESPONSE_NT40(
        OpCode=opcode,
        UnicodeLogonServer=dc_name,
        UnicodeUserName=user_name,
        UnicodeDomainName=domain_name,
        NtVersion=NETLOGON_NT_VERSION_1,
        LmNtToken=0xFFFF,
        Lm20Token=0xFFFF,
    )


def build_sam_logon_response(
    dc_name: str,
    user_name: str,
    domain_name: str,
    domain_guid: bytes,
    dns_forest_name: str,
    dns_domain_name: str,
    dns_host_name: str,
    dc_ip_address: str,
    is_pdc: bool = False,
    opcode: int = LOGON_SAM_LOGON_RESPONSE,
) -> smb.NETLOGON_SAM_LOGON_RESPONSE:
    flags = DS_DS_FLAG  # Always set for AD DCs
    if is_pdc:
        flags |= DS_PDC_FLAG

    return smb.NETLOGON_SAM_LOGON_RESPONSE(
        OpCode=opcode,
        UnicodeLogonServer=dc_name,
        UnicodeUserName=user_name,
        UnicodeDomainName=domain_name,
        DomainGuid=domain_guid,
        # SiteGuid is always NULL GUID
        DnsForestName=dns_forest_name,
        DnsDomainName=dns_domain_name,
        DnsHostName=dns_host_name,
        DcIpAddress=dc_ip_address,
        Flags=flags,
        NtVersion=NETLOGON_NT_VERSION_1 | NETLOGON_NT_VERSION_5,
        LmNtToken=0xFFFF,
        Lm20Token=0xFFFF,
    )


def build_sam_logon_response_ex(
    dc_name: str,
    user_name: str,
    domain_name: str,
    domain_guid: bytes,
    dns_forest_name: str,
    dns_domain_name: str,
    dns_host_name: str,
    dc_site_name: str = "Default-First-Site-Name",
    client_site_name: str = "Default-First-Site-Name",
    dc_ip_address: str | None = None,
    next_closest_site_name: str | None = None,
    flags: int = 0,
    dc_functional_level: int = 7,  # WIN2008R2
    opcode: int = LOGON_SAM_LOGON_RESPONSE_EX,
) -> smb.NETLOGON_SAM_LOGON_RESPONSE_EX:
    flags = flags | DS_DS_FLAG  # Always set for AD DCs

    # Add functional level flags
    if dc_functional_level >= 3:  # WIN2008
        flags |= DS_WS2008_FLAG
    if dc_functional_level >= 5:  # WIN2012
        flags |= DS_WS2012_FLAG
    if dc_functional_level >= 6:  # WIN2012R2
        flags |= DS_WS2012R2_FLAG
    if dc_functional_level >= 7:  # WIN2016
        flags |= DS_WS2016_FLAG

    nt_version = NETLOGON_NT_VERSION_1 | NETLOGON_NT_VERSION_5EX

    if dc_ip_address:
        nt_version |= NETLOGON_NT_VERSION_5EX_WITH_IP
    if next_closest_site_name:
        nt_version |= NETLOGON_NT_VERSION_WITH_CLOSEST_SITE

    response = smb.NETLOGON_SAM_LOGON_RESPONSE_EX(
        OpCode=opcode,
        Flags=flags,
        DomainGuid=domain_guid,
        DnsForestName=dns_forest_name,
        DnsDomainName=dns_domain_name,
        DnsHostName=dns_host_name,
        NetbiosDomainName=domain_name,
        NetbiosComputerName=dc_name,
        UserName=user_name,
        DcSiteName=dc_site_name,
        ClientSiteName=client_site_name,
        NtVersion=nt_version,
        LmNtToken=0xFFFF,
        Lm20Token=0xFFFF,
    )

    if dc_ip_address:
        response.DcSockAddr = smb.DcSockAddr(sin_addr=dc_ip_address)

    if next_closest_site_name:
        response.NextClosestSiteName = next_closest_site_name

    return response


def build_response(
    request: smb.NETLOGON_SAM_LOGON_REQUEST | smb.NETLOGON_LOGON_QUERY,
    dc_name: str,
    domain_name: str,
    domain_guid: bytes,
    dns_forest_name: str,
    dns_domain_name: str,
    dns_host_name: str,
    dc_ip_address: str | None = None,
    flags: int = 0,
) -> (
    smb.NETLOGON_SAM_LOGON_RESPONSE_EX
    | smb.NETLOGON_SAM_LOGON_RESPONSE
    | smb.NETLOGON_SAM_LOGON_RESPONSE_NT40
    | NETLOGON_PRIMARY_RESPONSE
):
    nt_version: int = int(request.NtVersion)
    user_name = getattr(request, "UnicodeUserName", "")
    response_type = select_response_type(nt_version)

    if response_type == ResponseFamily.SAM_LOGON_EX:
        return build_sam_logon_response_ex(
            dc_name=dc_name,
            user_name=user_name,
            domain_name=domain_name,
            domain_guid=domain_guid,
            dns_forest_name=dns_forest_name,
            dns_domain_name=dns_domain_name,
            dns_host_name=dns_host_name,
            dc_ip_address=dc_ip_address,
            flags=flags,
        )

    if response_type == ResponseFamily.SAM_LOGON:
        if dc_ip_address:
            return build_sam_logon_response(
                dc_name=dc_name,
                user_name=user_name,
                domain_name=domain_name,
                domain_guid=domain_guid,
                dns_forest_name=dns_forest_name,
                dns_domain_name=dns_domain_name,
                dns_host_name=dns_host_name,
                dc_ip_address=dc_ip_address,
            )

        return build_sam_logon_response_nt40(
            dc_name=dc_name,
            user_name=user_name,
            domain_name=domain_name,
        )

    if response_type == ResponseFamily.PRIMARY:
        return build_primary_response(
            domain_name=domain_name,
            dc_name=dc_name,
        )

    return build_sam_logon_response_nt40(
        dc_name=dc_name,
        user_name=user_name,
        domain_name=domain_name,
    )
