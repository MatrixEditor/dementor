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
r"""NETLOGON mailslot ping protocol implementation per [MS-ADTS].

This module implements the NETLOGON mailslot ping protocol as specified in
[MS-ADTS] § 6.3 (Publishing and Locating a Domain Controller). The protocol
is used by Windows clients to discover and verify domain controllers.

NETLOGON mailslot pings are sent to the ``\\MAILSLOT\\NET\\NETLOGON`` mailslot
and use various message structures depending on the client's capabilities
and requirements.

For more information, see:
- [MS-ADTS] Active Directory Technical Specification
- [MS-NRPC] Netlogon Remote Protocol
"""

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


# ===========================================================================
# Constants per [MS-ADTS] § 6.3.1.3 - Operation Code
# ===========================================================================
LOGON_PRIMARY_QUERY = 0x07  # Query for PDC (opcode 7)
LOGON_SAM_LOGON_REQUEST = 0x12  # SAM logon request (opcode 18)
LOGON_SAM_LOGON_RESPONSE = 0x13  # SAM logon response (opcode 19)
LOGON_SAM_PAUSE_RESPONSE = 0x14  # SAM pause response (opcode 20)
LOGON_SAM_USER_UNKNOWN = 0x15  # SAM user unknown (opcode 21)
LOGON_SAM_LOGON_RESPONSE_EX = 0x17  # SAM logon response extended (opcode 23)
LOGON_PRIMARY_RESPONSE = 0x17  # Primary response (opcode 23)
LOGON_SAM_USER_UNKNOWN_EX = 0x19  # SAM user unknown extended (opcode 25)


# ===========================================================================
# NETLOGON_NT_VERSION Options Bits per [MS-ADTS] § 6.3.1.1
# ===========================================================================
# These flags indicate the client's capabilities and the type of response
# expected. Multiple flags can be combined using bitwise OR.

NETLOGON_NT_VERSION_1 = 0x00000001
"""Version 1 support.

Indicates basic NETLOGON protocol support. This flag is always set in
responses per [MS-ADTS] § 6.3.5.
"""

NETLOGON_NT_VERSION_5 = 0x00000002
"""Version 5 support.

Indicates support for NETLOGON_SAM_LOGON_RESPONSE structure.
If set, server uses NETLOGON_SAM_LOGON_RESPONSE for response.
"""

NETLOGON_NT_VERSION_5EX = 0x00000004
"""Extended version 5 support.

Indicates support for NETLOGON_SAM_LOGON_RESPONSE_EX structure.
If set, server uses NETLOGON_SAM_LOGON_RESPONSE_EX for response.
"""

NETLOGON_NT_VERSION_5EX_WITH_IP = 0x00000008
"""Extended version 5 with IP address.

Indicates support for NETLOGON_SAM_LOGON_RESPONSE_EX with DcSockAddr field.
If set, server includes IP address in response.
"""

NETLOGON_NT_VERSION_WITH_CLOSEST_SITE = 0x00000010
"""Support for closest site information.

Indicates support for NextClosestSiteName field in response.
If set and DC functional level >= WIN2008, server includes closest site.
"""

NETLOGON_NT_VERSION_AVOID_NT4EMUL = 0x01000000
"""Avoid NT4 emulation.

If set, server does not use NT4-compatible response format even if
dc.nt4EmulatorEnabled is TRUE.
"""

NETLOGON_NT_VERSION_PDC = 0x10000000
"""PDC query.

Indicates client is specifically looking for a Primary Domain Controller.
If set, server uses NETLOGON_PRIMARY_RESPONSE structure.
"""

NETLOGON_NT_VERSION_IP = 0x20000000
"""IP address support.

Indicates client supports IP address in response.
"""

NETLOGON_NT_VERSION_LOCAL = 0x40000000
"""Local query.

Indicates query is from local machine. Server may respond even if
Netlogon RPC server is not initialized.
"""

NETLOGON_NT_VERSION_GC = 0x80000000
"""Global Catalog query.

Indicates client is looking for a Global Catalog server.
"""


# ===========================================================================
# DS_FLAG Options Bits per [MS-ADTS] § 6.3.1.2
# ===========================================================================
# These flags describe the capabilities and roles of the responding DC.

DS_PDC_FLAG = 0x00000001
"""PDC of the domain.

Indicates the DC is the Primary Domain Controller for the domain.
"""

DS_GC_FLAG = 0x00000004
"""Global Catalog server.

Indicates the DC is a Global Catalog server.
"""

DS_LDAP_FLAG = 0x00000008
"""LDAP server.

Indicates the DC supports LDAP.
"""

DS_DS_FLAG = 0x00000010
"""Directory Service.

Indicates the DC is a directory service (always set for AD DCs).
"""

DS_KDC_FLAG = 0x00000020
"""Kerberos KDC.

Indicates the DC is a Kerberos Key Distribution Center.
"""

DS_TIMESERV_FLAG = 0x00000040
"""Time server.

Indicates the DC is a Windows Time Service server.
"""

DS_CLOSEST_FLAG = 0x00000080
"""Closest DC.

Indicates the DC is in the same site as the client.
"""

DS_WRITABLE_FLAG = 0x00000100
"""Writable DC.

Indicates the DC is writable (not a Read-Only DC).
"""

DS_GOOD_TIMESERV_FLAG = 0x00000200
"""Good time server.

Indicates the DC has a reliable time source.
"""

DS_NDNC_FLAG = 0x00000400
"""Non-domain NC.

Indicates the DC hosts a non-domain naming context.
"""

DS_SELECT_SECRET_DOMAIN_6_FLAG = 0x00000800
"""Select secret domain 6.

Indicates the DC is a Windows Server 2008 or later DC.
"""

DS_FULL_SECRET_DOMAIN_6_FLAG = 0x00001000
"""Full secret domain 6.

Indicates the DC has full secrets for the domain.
"""

DS_WS2008_FLAG = 0x00002000
"""Windows Server 2008.

Indicates the DC is running Windows Server 2008 or later.
"""

DS_WS2012_FLAG = 0x00004000
"""Windows Server 2012.

Indicates the DC is running Windows Server 2012 or later.
"""

DS_WS2012R2_FLAG = 0x00008000
"""Windows Server 2012 R2.

Indicates the DC is running Windows Server 2012 R2 or later.
"""

DS_WS2016_FLAG = 0x00010000
"""Windows Server 2016.

Indicates the DC is running Windows Server 2016 or later.
"""

DS_DNS_CONTROLLER_FLAG = 0x20000000
"""DNS controller.

Indicates the DC is a DNS server.
"""

DS_DNS_DOMAIN_FLAG = 0x40000000
"""DNS domain.

Indicates the domain name is a DNS name.
"""

DS_DNS_FOREST_FLAG = 0x80000000
"""DNS forest.

Indicates the forest name is a DNS name.
"""


# ===========================================================================
# Scapy Packet Classes
# ===========================================================================
# Scapy does not define NETLOGON_PRIMARY_RESPONSE, so we define it here
# following Scapy's conventions for NETLOGON packet structures.


class NETLOGON_PRIMARY_RESPONSE(smb.NETLOGON):
    """
    NETLOGON_PRIMARY_RESPONSE structure per [MS-ADTS] § 6.3.1.5.

    This structure is sent by a PDC in response to a LOGON_PRIMARY_QUERY
    request. It contains the NetBIOS names of the PDC and domain.

    Wire Format
    -----------
    Per [MS-ADTS] § 6.3.1.5:
    - Opcode (2 bytes): LOGON_PRIMARY_RESPONSE (0x17)
    - PrimaryDCName (variable): Null-terminated ASCII NetBIOS name
    - UnicodePrimaryDCName (variable): Null-terminated UTF-16LE (even-aligned)
    - UnicodeDomainName (variable): Null-terminated UTF-16LE
    - NtVersion (4 bytes): NETLOGON_NT_VERSION_1
    - LmNtToken (2 bytes): 0xFFFF
    - Lm20Token (2 bytes): 0xFFFF

    Note: All multibyte quantities are represented in little-endian byte order.
    """

    fields_desc = [
        # Opcode (2 bytes, little-endian)
        # Per [MS-ADTS] § 6.3.1.5, set to LOGON_PRIMARY_RESPONSE (0x17)
        LEShortEnumField("OpCode", LOGON_PRIMARY_RESPONSE, smb._NETLOGON_opcodes),
        # PrimaryDCName (variable, null-terminated ASCII)
        # Per [MS-ADTS] § 6.3.1.5, ASCII NetBIOS name of the server
        StrNullField("PrimaryDCName", ""),
        # UnicodePrimaryDCName (variable, null-terminated UTF-16LE, even-aligned)
        # Per [MS-ADTS] § 6.3.1.5, Unicode NetBIOS name of the server
        StrNullFieldUtf16("UnicodePrimaryDCName", ""),
        ConditionalField(
            ByteField("UnicodePrimaryDCNamePad", default=0x00),
            # +2 because of unicode encoding
            lambda pkt: (len(pkt.MailslotName) + 2) % 2 != 0,
        ),
        # UnicodeDomainName (variable, null-terminated UTF-16LE)
        # Per [MS-ADTS] § 6.3.1.5, Unicode NetBIOS name of the domain
        StrNullFieldUtf16("UnicodeDomainName", ""),
        # NtVersion (4 bytes, little-endian)
        # Per [MS-ADTS] § 6.3.5, set to NETLOGON_NT_VERSION_1
        FlagsField("NtVersion", NETLOGON_NT_VERSION_1, -32, smb._NV_VERSION),
        # LmNtToken (2 bytes, little-endian)
        # Per [MS-ADTS] § 6.3.1.5, must be 0xFFFF
        XLEShortField("LmNtToken", 0xFFFF),
        # Lm20Token (2 bytes, little-endian)
        # Per [MS-ADTS] § 6.3.1.5, must be 0xFFFF
        XLEShortField("Lm20Token", 0xFFFF),
    ]


# ===========================================================================
# Response Type Selection per [MS-ADTS] § 6.3.5
# ===========================================================================
def select_response_type(nt_version: int) -> int:
    """
    Select appropriate NETLOGON response type based on NtVersion flags.

    Per [MS-ADTS] § 6.3.5, the server selects the response structure based
    on the NtVersion field in the client's request:

    1. If dc.nt4EmulatorEnabled is TRUE and AVOID_NT4EMUL is not set,
       use NETLOGON_SAM_LOGON_RESPONSE_NT40
    2. Else if V5EX or V5EX_WITH_IP is set,
       use NETLOGON_SAM_LOGON_RESPONSE_EX
    3. Else if V5 is set,
       use NETLOGON_SAM_LOGON_RESPONSE
    4. Else if PDC is set,
       use NETLOGON_PRIMARY_RESPONSE
    5. Else,
       use NETLOGON_SAM_LOGON_RESPONSE_NT40

    :param nt_version: NtVersion field from client request
    :type nt_version: int
    :return: Opcode for response structure
    :rtype: int
    """
    # Check for extended V5 support
    if nt_version & (NETLOGON_NT_VERSION_5EX | NETLOGON_NT_VERSION_5EX_WITH_IP):
        return LOGON_SAM_LOGON_RESPONSE_EX

    # Check for V5 support
    if nt_version & NETLOGON_NT_VERSION_5:
        return LOGON_SAM_LOGON_RESPONSE

    # Check for PDC query
    if nt_version & NETLOGON_NT_VERSION_PDC:
        return LOGON_PRIMARY_RESPONSE

    # Default to NT40 response
    return LOGON_SAM_LOGON_RESPONSE  # NT40 response (opcode 19)


# ===========================================================================
# NETLOGON_PRIMARY_RESPONSE per [MS-ADTS] § 6.3.1.5
# ===========================================================================
def build_primary_response(
    domain_name: str,
    dc_name: str,
    nt_version: int = NETLOGON_NT_VERSION_1,
) -> NETLOGON_PRIMARY_RESPONSE:
    """
    Build NETLOGON_PRIMARY_RESPONSE per [MS-ADTS] § 6.3.1.5.

    This response is sent by a PDC in response to a LOGON_PRIMARY_QUERY
    request. It contains the NetBIOS names of the PDC and domain.

    Per [MS-ADTS] § 6.3.5, the response fields are set as follows:
    - OperationCode: LOGON_PRIMARY_RESPONSE (0x17)
    - PrimaryDCName: ASCII NetBIOS name of the server
    - UnicodePrimaryDCName: Unicode NetBIOS name of the server (even-aligned)
    - UnicodeDomainName: Unicode NetBIOS name of the domain
    - NtVersion: NETLOGON_NT_VERSION_1
    - LmNtToken: 0xFFFF
    - Lm20Token: 0xFFFF

    :param domain_name: NetBIOS domain name (e.g., "CONTOSO")
    :type domain_name: str
    :param dc_name: NetBIOS DC name (e.g., "DC01")
    :type dc_name: str
    :param nt_version: NtVersion field, defaults to NETLOGON_NT_VERSION_1
    :type nt_version: int
    :return: NETLOGON_PRIMARY_RESPONSE structure
    :rtype: NETLOGON_PRIMARY_RESPONSE
    """
    return NETLOGON_PRIMARY_RESPONSE(
        OpCode=LOGON_PRIMARY_RESPONSE,
        PrimaryDCName=dc_name,
        UnicodePrimaryDCName=dc_name,
        UnicodeDomainName=domain_name,
        NtVersion=nt_version,
        LmNtToken=0xFFFF,
        Lm20Token=0xFFFF,
    )


# ===========================================================================
# NETLOGON_SAM_LOGON_RESPONSE_NT40 per [MS-ADTS] § 6.3.1.7
# ===========================================================================
def build_sam_logon_response_nt40(
    dc_name: str,
    user_name: str,
    domain_name: str,
    opcode: int = LOGON_SAM_LOGON_RESPONSE,
) -> smb.NETLOGON_SAM_LOGON_RESPONSE_NT40:
    """
    Build NETLOGON_SAM_LOGON_RESPONSE_NT40 per [MS-ADTS] § 6.3.1.7.

    This is the NT4-compatible response format used for backward compatibility
    with older clients or when NT4 emulation is enabled.

    Per [MS-ADTS] § 6.3.5, the response fields are set as follows:
    - OperationCode: LOGON_SAM_LOGON_RESPONSE (0x13) or
                     LOGON_SAM_PAUSE_RESPONSE (0x14) or
                     LOGON_SAM_USER_UNKNOWN (0x15)
    - UnicodeLogonServer: Unicode NetBIOS name of the server
    - UnicodeUserName: Unicode user name from request
    - UnicodeDomainName: Unicode NetBIOS name of the domain
    - NtVersion: NETLOGON_NT_VERSION_1
    - LmNtToken: 0xFFFF
    - Lm20Token: 0xFFFF

    :param dc_name: NetBIOS DC name (e.g., "DC01")
    :type dc_name: str
    :param user_name: User name from request
    :type user_name: str
    :param domain_name: NetBIOS domain name (e.g., "CONTOSO")
    :type domain_name: str
    :param opcode: Operation code, defaults to LOGON_SAM_LOGON_RESPONSE
    :type opcode: int
    :return: NETLOGON_SAM_LOGON_RESPONSE_NT40 structure
    :rtype: smb.NETLOGON_SAM_LOGON_RESPONSE_NT40
    """
    return smb.NETLOGON_SAM_LOGON_RESPONSE_NT40(
        OpCode=opcode,
        UnicodeLogonServer=dc_name,
        UnicodeUserName=user_name,
        UnicodeDomainName=domain_name,
        NtVersion=NETLOGON_NT_VERSION_1,
        LmNtToken=0xFFFF,
        Lm20Token=0xFFFF,
    )


# ===========================================================================
# NETLOGON_SAM_LOGON_RESPONSE per [MS-ADTS] § 6.3.1.8
# ===========================================================================


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
    r"""
    Build NETLOGON_SAM_LOGON_RESPONSE per [MS-ADTS] § 6.3.1.8.

    This is the Version 5 response format that includes DNS names and
    domain GUID information.

    Per [MS-ADTS] § 6.3.5, the response fields are set as follows:
    - OperationCode: LOGON_SAM_LOGON_RESPONSE (0x13) or
                     LOGON_SAM_PAUSE_RESPONSE (0x14) or
                     LOGON_SAM_USER_UNKNOWN (0x15)
    - UnicodeLogonServer: Unicode NetBIOS name of the server
    - UnicodeUserName: Unicode user name from request
    - UnicodeDomainName: Unicode NetBIOS name of the domain
    - DomainGuid: GUID of the domain
    - SiteGuid: Always NULL GUID
    - DnsForestName: DNS name of the forest
    - DnsDomainName: DNS name of the domain
    - DnsHostName: DNS name of the server
    - DcIpAddress: IP address of the server
    - Flags: DS_FLAG bits (DS_PDC_FLAG if PDC, DS_DS_FLAG always set)
    - NtVersion: NETLOGON_NT_VERSION_1 | NETLOGON_NT_VERSION_5
    - LmNtToken: 0xFFFF
    - Lm20Token: 0xFFFF

    :param dc_name: NetBIOS DC name (e.g., "DC01")
    :type dc_name: str
    :param user_name: User name from request
    :type user_name: str
    :param domain_name: NetBIOS domain name (e.g., "CONTOSO")
    :type domain_name: str
    :param domain_guid: Domain GUID (16 bytes)
    :type domain_guid: bytes
    :param dns_forest_name: DNS forest name (e.g., "contoso.com")
    :type dns_forest_name: str
    :param dns_domain_name: DNS domain name (e.g., "contoso.com")
    :type dns_domain_name: str
    :param dns_host_name: DNS host name (e.g., "dc01.contoso.com")
    :type dns_host_name: str
    :param dc_ip_address: IP address of DC
    :type dc_ip_address: str
    :param is_pdc: Whether DC is PDC, defaults to False
    :type is_pdc: bool
    :param opcode: Operation code, defaults to LOGON_SAM_LOGON_RESPONSE
    :type opcode: int
    :return: NETLOGON_SAM_LOGON_RESPONSE structure
    :rtype: smb.NETLOGON_SAM_LOGON_RESPONSE
    """
    # Build Flags field per [MS-ADTS] § 6.3.5
    flags = DS_DS_FLAG  # Always set for AD DCs
    if is_pdc:
        flags |= DS_PDC_FLAG

    return smb.NETLOGON_SAM_LOGON_RESPONSE(
        OpCode=opcode,
        UnicodeLogonServer=dc_name,
        UnicodeUserName=user_name,
        UnicodeDomainName=domain_name,
        DomainGuid=domain_guid,
        # SiteGuid is always NULL GUID per [MS-ADTS] § 6.3.5
        DnsForestName=dns_forest_name,
        DnsDomainName=dns_domain_name,
        DnsHostName=dns_host_name,
        DcIpAddress=dc_ip_address,
        Flags=flags,
        NtVersion=NETLOGON_NT_VERSION_1 | NETLOGON_NT_VERSION_5,
        LmNtToken=0xFFFF,
        Lm20Token=0xFFFF,
    )


# ===========================================================================
# NETLOGON_SAM_LOGON_RESPONSE_EX per [MS-ADTS] § 6.3.1.9
# ===========================================================================
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
    r"""
    Build NETLOGON_SAM_LOGON_RESPONSE_EX per [MS-ADTS] § 6.3.1.9.

    This is the extended Version 5 response format that includes additional
    information such as site names, IP address, and extended flags.

    Per [MS-ADTS] § 6.3.5, the response fields are set as follows:
    - OperationCode: LOGON_SAM_LOGON_RESPONSE_EX (0x17) or
                     LOGON_SAM_USER_UNKNOWN_EX (0x19)
    - Sbz: Always 0x0
    - Flags: DS_FLAG bits indicating DC capabilities
    - DnsForestName: DNS name of the forest
    - DnsDomainName: DNS name of the domain
    - DnsHostName: DNS name of the server
    - NetbiosDomainName: NetBIOS name of the domain
    - NetbiosComputerName: NetBIOS name of the server
    - UserName: User name from request
    - DcSiteName: Site name of the server
    - ClientSiteName: Site name of the client
    - DcSockAddrSize: Size of IP address (if V5EX_WITH_IP set)
    - DcSockAddr: IP address of server (if V5EX_WITH_IP set)
    - NextClosestSiteName: Next closest site (if WITH_CLOSEST_SITE set)
    - NtVersion: NETLOGON_NT_VERSION_1 | NETLOGON_NT_VERSION_5EX [| ...]
    - LmNtToken: 0xFFFF
    - Lm20Token: 0xFFFF

    :param dc_name: NetBIOS DC name (e.g., "DC01")
    :type dc_name: str
    :param user_name: User name from request
    :type user_name: str
    :param domain_name: NetBIOS domain name (e.g., "CONTOSO")
    :type domain_name: str
    :param dns_forest_name: DNS forest name (e.g., "contoso.com")
    :type dns_forest_name: str
    :param dns_domain_name: DNS domain name (e.g., "contoso.com")
    :type dns_domain_name: str
    :param dns_host_name: DNS host name (e.g., "dc01.contoso.com")
    :type dns_host_name: str
    :param dc_site_name: Site name of DC, defaults to "Default-First-Site-Name"
    :type dc_site_name: str
    :param client_site_name: Site name of client, defaults to "Default-First-Site-Name"
    :type client_site_name: str
    :param dc_ip_address: IP address of DC, defaults to None
    :type dc_ip_address: str | None
    :param next_closest_site_name: Next closest site, defaults to None
    :type next_closest_site_name: str | None
    :param dc_functional_level: DC functional level, defaults to 7 (WIN2008R2)
    :type dc_functional_level: int
    :param opcode: Operation code, defaults to LOGON_SAM_LOGON_RESPONSE_EX
    :type opcode: int
    :return: NETLOGON_SAM_LOGON_RESPONSE_EX structure
    :rtype: smb.NETLOGON_SAM_LOGON_RESPONSE_EX
    """
    # Build Flags field per [MS-ADTS] § 6.3.5
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

    # Build NtVersion field per [MS-ADTS] § 6.3.5
    nt_version = NETLOGON_NT_VERSION_1 | NETLOGON_NT_VERSION_5EX

    if dc_ip_address:
        nt_version |= NETLOGON_NT_VERSION_5EX_WITH_IP
    if next_closest_site_name:
        nt_version |= NETLOGON_NT_VERSION_WITH_CLOSEST_SITE

    # Build response
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

    # Add optional fields if present
    if dc_ip_address:
        response.DcSockAddr = smb.DcSockAddr(sin_addr=dc_ip_address)

    if next_closest_site_name:
        response.NextClosestSiteName = next_closest_site_name

    return response


# ===========================================================================
# High-Level API
# ===========================================================================


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
    r"""
    Build appropriate NETLOGON response based on request NtVersion.

    This is a high-level convenience function that automatically selects
    the correct response structure based on the client's NtVersion field
    per [MS-ADTS] § 6.3.5.

    :param request: NETLOGON request from client
    :type request: smb.NETLOGON_SAM_LOGON_REQUEST | smb.NETLOGON_LOGON_QUERY
    :param dc_name: NetBIOS DC name
    :type dc_name: str
    :param domain_name: NetBIOS domain name
    :type domain_name: str
    :param domain_guid: Domain GUID (16 bytes)
    :type domain_guid: bytes
    :param dns_forest_name: DNS forest name
    :type dns_forest_name: str
    :param dns_domain_name: DNS domain name
    :type dns_domain_name: str
    :param dns_host_name: DNS host name
    :type dns_host_name: str
    :param dc_ip_address: IP address of DC, defaults to None
    :type dc_ip_address: str | None
    :param is_pdc: Whether DC is PDC, defaults to False
    :type is_pdc: bool
    :param nt4_emulator_enabled: Whether NT4 emulation is enabled, defaults to False
    :type nt4_emulator_enabled: bool
    :return: Appropriate NETLOGON response structure
    :rtype: smb.NETLOGON_SAM_LOGON_RESPONSE_EX | smb.NETLOGON_SAM_LOGON_RESPONSE | smb.NETLOGON_SAM_LOGON_RESPONSE_NT40 | NETLOGON_PRIMARY_RESPONSE
    """
    # REVISIT: scapy is parsing MailslotName wrong
    # Extract NtVersion from request
    nt_version: int = int(request.NtVersion)

    # Extract user name if present
    user_name = getattr(request, "UnicodeUserName", "")

    # Select response type
    response_type: int = select_response_type(nt_version)

    # Build appropriate response
    if response_type == LOGON_SAM_LOGON_RESPONSE_EX:
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

    if response_type == LOGON_SAM_LOGON_RESPONSE:
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

    if response_type == LOGON_PRIMARY_RESPONSE:
        return build_primary_response(
            domain_name=domain_name,
            dc_name=dc_name,
        )

    return build_sam_logon_response_nt40(
        dc_name=dc_name,
        user_name=user_name,
        domain_name=domain_name,
    )
