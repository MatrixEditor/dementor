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
"""Remote Mailslot Protocol implementation per [MS-MAIL].

This module implements the Remote Mailslot Protocol as specified in
[MS-MAIL] (Remote Mailslot Protocol). Mailslots provide a one-way
interprocess communication mechanism for connectionless, unreliable
message delivery over SMB.

The protocol is used extensively in Windows networking for service
discovery, domain controller location, and browser service announcements.
"""

from impacket.smb import SMB
from scapy.layers import netbios, smb


# ===========================================================================
# Constants
# ===========================================================================
# Mailslot operation codes per [MS-MAIL] § 2.2.1
MAILSLOT_WRITE = 0x0001  # Write to mailslot

# Mailslot class values per [MS-MAIL] § 2.2.1
MAILSLOT_CLASS_UNRELIABLE = 0x0002  # Unreliable (connectionless)

# Common mailslot names per [MS-MAIL] § 1.3
MAILSLOT_NETLOGON = "\\MAILSLOT\\NET\\NETLOGON"
MAILSLOT_BROWSE = "\\MAILSLOT\\BROWSE"
MAILSLOT_LANMAN = "\\MAILSLOT\\LANMAN"

# NBT datagram types per [RFC1002] § 4.4.1
NBT_DIRECT_UNIQUE = 0x10  # Direct unique datagram
NBT_DIRECT_GROUP = 0x11  # Direct group datagram
NBT_BROADCAST = 0x12  # Broadcast datagram

# NBT datagram flags per [RFC1002] § 4.4.1
# SNT (Source Node Type) field values:
NBT_SNT_B_NODE = 0x00  # B-node (broadcast)
NBT_SNT_P_NODE = 0x01  # P-node (point-to-point)
NBT_SNT_M_NODE = 0x02  # M-node (mixed)
NBT_SNT_H_NODE = 0x03  # H-node (hybrid)

# Flag bits:
NBT_FLAG_FIRST = 0x02  # First packet
NBT_FLAG_MORE = 0x01  # More fragments follow


# ===========================================================================
# Mailslot Message Construction
# ===========================================================================
def build_mailslot_write(
    mailslot_name: str,
    data: bytes,
    mailslot_class: int = MAILSLOT_CLASS_UNRELIABLE,
    priority: int = 0,
) -> smb.SMBMailslot_Write:
    r"""
    Build an SMB mailslot write transaction per [MS-MAIL] § 2.2.1.

    Constructs an SMB_COM_TRANSACTION request with mailslot-specific
    setup words and parameters. The transaction writes data to a named
    mailslot on the target system.

    Per [MS-MAIL] § 2.2.1, the SMB_COM_TRANSACTION request contains:
    - Setup words: [MailSlotOpcode, Priority, Class]
    - Name: Mailslot name (null-terminated ASCII)
    - Data: Message payload

    Product Behavior Notes (per [MS-MAIL] § 2.2.1):
    - <3> Windows sets SMB_Header.Flags to 0x00
    - <4> Windows sets SMB_Header.Flags2 to 0x00
    - <5> Windows sets SMB_Header.PIDLow to 0x0000

    :param mailslot_name: Name of the mailslot (e.g., "\\\\MAILSLOT\\\\NET\\\\NETLOGON")
    :type mailslot_name: str
    :param data: Message payload to write to the mailslot
    :type data: bytes
    :param mailslot_class: Mailslot class (1=reliable, 2=unreliable), defaults to 2
    :type mailslot_class: int
    :param priority: Message priority (0-9), defaults to 0
    :type priority: int
    :return: SMB mailslot write transaction
    :rtype: smb.SMBMailslot_Write

    Example:
    >>> from dementor.protocols import mailslot
    >>> msg = mailslot.build_mailslot_write(
    ...     mailslot.MAILSLOT_NETLOGON,
    ...     b"\\x07\\x00...",  # NETLOGON message
    ... )
    >>> bytes(msg)
    b'\\x11\\x00...'

    """
    # Setup words per [MS-MAIL] § 2.2.1:
    # - Setup[0]: MailSlotOpcode (0x0001 = Write)
    # - Setup[1]: Priority (0-9)
    # - Setup[2]: Class (1=reliable, 2=unreliable)
    setup_words = [MAILSLOT_WRITE, priority, mailslot_class]

    # Mailslot name must be null-terminated ASCII per [MS-MAIL] § 2.2.1
    mailslot_name_bytes = mailslot_name.encode("ascii") + b"\x00"

    # Build the SMB_COM_TRANSACTION mailslot write
    # Per [MS-MAIL] § 2.2.1, the Buffer field contains:
    # - ("Parameter", b"") - Empty parameter block
    # - ("Data", data) - Message payload
    return smb.SMBMailslot_Write(
        SetupCount=3,
        Setup=setup_words,
        Name=mailslot_name_bytes,
        Buffer=[
            ("Parameter", b""),
            ("Data", data),
        ],
    )


def build_smb_header(
    command: int = SMB.SMB_COM_TRANSACTION,
    flags: int = 0x00,
    flags2: int = 0x00,
    tid: int = 0x0000,
    pid_low: int = 0xFEFF,
    uid: int = 0x0000,
    mid: int = 0x0000,
) -> smb.SMB_Header:
    """
    Build an SMB header for mailslot transactions per [MS-MAIL] § 2.2.1.

    Per [MS-MAIL] § 2.2.1 product behavior notes:
    - <3> Windows sets Flags to 0x00
    - <4> Windows sets Flags2 to 0x00
    - <5> Windows sets PIDLow to 0xFEFF

    :param command: SMB command code, defaults to 0x25 (SMB_COM_TRANSACTION)
    :type command: int
    :param flags: SMB flags, defaults to 0x00
    :type flags: int
    :param flags2: SMB flags2, defaults to 0x00
    :type flags2: int
    :param tid: Tree ID, defaults to 0x0000
    :type tid: int
    :param pid_low: Process ID (low word), defaults to 0xFEFF
    :type pid_low: int
    :param uid: User ID, defaults to 0x0000
    :type uid: int
    :param mid: Multiplex ID, defaults to 0x0000
    :type mid: int
    :return: SMB header
    :rtype: smb.SMB_Header
    """
    return smb.SMB_Header(
        Command=command,
        Flags=flags,
        Flags2=flags2,
        TID=tid,
        PIDLow=pid_low,
        UID=uid,
        MID=mid,
    )


# ===========================================================================
# NBT Datagram Construction
# ===========================================================================
def build_nbt_datagram(
    source_name: str,
    destination_name: str,
    source_ip: str,
    smb_packet: smb.SMB_Header | smb.SMBMailslot_Write,
    datagram_type: int = NBT_DIRECT_GROUP,
    source_port: int = 138,
    node_type: int = NBT_SNT_H_NODE,
    first_packet: bool = True,
    more_fragments: bool = False,
) -> netbios.NBTDatagram:
    """
    Build an NBT datagram for mailslot message delivery per [RFC1002] § 4.4.1.

    NetBIOS over TCP/UDP (NBT) datagrams provide the transport layer for
    mailslot messages. The datagram encapsulates the SMB mailslot write
    transaction and delivers it to the target NetBIOS name.

    Per [RFC1002] § 4.4.1, the NBT datagram header contains:
    - MSG_TYPE: Datagram type (DIRECT_UNIQUE, DIRECT_GROUP, BROADCAST)
    - FLAGS: Source node type and fragmentation flags
    - DGM_ID: Datagram identifier
    - SOURCE_IP: IP address of sender
    - SOURCE_PORT: UDP port of sender (typically 138)
    - SOURCE_NAME: NetBIOS name of sender (16 bytes, encoded)
    - DESTINATION_NAME: NetBIOS name of recipient (16 bytes, encoded)

    Per [MS-MAIL] § 3.1.4.1 product behavior note <13>:
    - Windows uses DIRECT_GROUP (0x11) for mailslot broadcasts
    - Source node type is typically H-node (0x03)
    - First packet flag (F) is set to 1
    - More fragments flag (M) is set to 0 for single-packet messages

    :param source_name: NetBIOS name of sender (max 15 chars)
    :type source_name: str
    :param destination_name: NetBIOS name of recipient (max 15 chars)
    :type destination_name: str
    :param source_ip: IP address of sender
    :type source_ip: str
    :param smb_packet: SMB packet to encapsulate
    :type smb_packet: smb.SMB_Header | smb.SMBMailslot_Write
    :param datagram_type: NBT datagram type, defaults to NBT_DIRECT_GROUP (0x11)
    :type datagram_type: int
    :param source_port: UDP source port, defaults to 138
    :type source_port: int
    :param node_type: Source node type (B/P/M/H-node), defaults to H-node (0x03)
    :type node_type: int
    :param first_packet: First packet flag, defaults to True
    :type first_packet: bool
    :param more_fragments: More fragments flag, defaults to False
    :type more_fragments: bool
    :return: NBT datagram
    :rtype: netbios.NBTDatagram
    """
    # Encode NetBIOS names per [RFC1001] § 14.1
    # NetBIOS names are 16 bytes: 15 chars + 1 byte suffix
    # Pad with spaces to 15 chars, append null byte (0x00) for workstation
    source_nb_name = (source_name.upper()[:15].ljust(15) + "\x00").encode("ascii")
    dest_nb_name = (destination_name.upper()[:15].ljust(15) + "\x00").encode("ascii")

    # Build FLAGS field per [RFC1002] § 4.4.1
    # Bits 0-1: SNT (Source Node Type)
    # Bit 2: F (First packet)
    # Bit 3: M (More fragments)
    flags = (node_type & 0x03) << 2
    if first_packet:
        flags |= NBT_FLAG_FIRST
    if more_fragments:
        flags |= NBT_FLAG_MORE

    # Build NBT datagram per [RFC1002] § 4.4.1
    datagram = netbios.NBTDatagram(
        Type=datagram_type,
        Flags=flags,
        SourceIP=source_ip,
        SourcePort=source_port,
        SourceName=source_nb_name,
        DestinationName=dest_nb_name,
    )

    # Attach SMB packet as payload
    return datagram / smb_packet


# ===========================================================================
# High-Level API
# ===========================================================================
def mailslot_write(
    mailslot_name: str,
    data: bytes,
    source_name: str,
    destination_name: str,
    source_ip: str,
    mailslot_class: int = MAILSLOT_CLASS_UNRELIABLE,
    priority: int = 0,
) -> bytes:
    r"""
    Build a complete mailslot message ready for transmission.

    This is a high-level convenience function that combines all the steps
    required to build a mailslot message:
    1. Build SMB mailslot write transaction per [MS-MAIL] § 2.2.1
    2. Build SMB header per [MS-MAIL] § 2.2.1
    3. Build NBT datagram per [RFC1002] § 4.4.1

    The resulting packet can be sent via UDP to port 138 on the target system.

    :param mailslot_name: Name of the mailslot (e.g., "\\\\MAILSLOT\\\\NET\\\\NETLOGON")
    :type mailslot_name: str
    :param data: Message payload
    :type data: bytes
    :param source_name: NetBIOS name of sender (max 15 chars)
    :type source_name: str
    :param destination_name: NetBIOS name of recipient (max 15 chars)
    :type destination_name: str
    :param source_ip: IP address of sender
    :type source_ip: str
    :param mailslot_class: Mailslot class (1=reliable, 2=unreliable), defaults to 2
    :type mailslot_class: int
    :param priority: Message priority (0-9), defaults to 0
    :type priority: int
    :return: Complete mailslot message as bytes
    :rtype: bytes
    """
    # Build SMB mailslot write transaction
    transaction = build_mailslot_write(
        mailslot_name=mailslot_name,
        data=data,
        mailslot_class=mailslot_class,
        priority=priority,
    )

    # Build SMB header
    smb_header = build_smb_header()

    # Combine SMB header and transaction
    smb_packet = smb_header / transaction

    # Build NBT datagram
    datagram = build_nbt_datagram(
        source_name=source_name,
        destination_name=destination_name,
        source_ip=source_ip,
        smb_packet=smb_packet,
    )

    # Return as bytes
    return bytes(datagram)
