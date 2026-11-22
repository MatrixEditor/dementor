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
from impacket.smb import SMB
from scapy.layers import netbios, smb


# Constants
MAILSLOT_WRITE = 0x0001  # Write to mailslot
MAILSLOT_CLASS_UNRELIABLE = 0x0002  # Unreliable (connectionless)
MAILSLOT_NETLOGON = "\\MAILSLOT\\NET\\NETLOGON"
MAILSLOT_BROWSE = "\\MAILSLOT\\BROWSE"
MAILSLOT_LANMAN = "\\MAILSLOT\\LANMAN"

NBT_DIRECT_UNIQUE = 0x10  # Direct unique datagram
NBT_DIRECT_GROUP = 0x11  # Direct group datagram
NBT_BROADCAST = 0x12  # Broadcast datagram
NBT_SNT_B_NODE = 0x00  # B-node (broadcast)
NBT_SNT_P_NODE = 0x01  # P-node (point-to-point)
NBT_SNT_M_NODE = 0x02  # M-node (mixed)
NBT_SNT_H_NODE = 0x03  # H-node (hybrid)

NBT_FLAG_FIRST = 0x02  # First packet
NBT_FLAG_MORE = 0x01  # More fragments follow


def build_mailslot_write(
    mailslot_name: str,
    data: bytes,
    mailslot_class: int = MAILSLOT_CLASS_UNRELIABLE,
    priority: int = 0,
) -> smb.SMBMailslot_Write:
    # - Setup[0]: MailSlotOpcode (0x0001 = Write)
    # - Setup[1]: Priority (0-9)
    # - Setup[2]: Class (1=reliable, 2=unreliable)
    setup_words = [MAILSLOT_WRITE, priority, mailslot_class]

    mailslot_name_bytes = mailslot_name.encode("ascii") + b"\x00"
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
    return smb.SMB_Header(
        Command=command,
        Flags=flags,
        Flags2=flags2,
        TID=tid,
        PIDLow=pid_low,
        UID=uid,
        MID=mid,
    )


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
    # NetBIOS names are 16 bytes: 15 chars + 1 byte suffix
    # Pad with spaces to 15 chars, append null byte (0x00) for workstation
    source_nb_name = (source_name.upper()[:15].ljust(15) + "\x00").encode("ascii")
    dest_nb_name = (destination_name.upper()[:15].ljust(15) + "\x00").encode("ascii")

    # Bits 0-1: SNT (Source Node Type)
    # Bit 2: F (First packet)
    # Bit 3: M (More fragments)
    flags = (node_type & 0x03) << 2
    if first_packet:
        flags |= NBT_FLAG_FIRST
    if more_fragments:
        flags |= NBT_FLAG_MORE

    datagram = netbios.NBTDatagram(
        Type=datagram_type,
        Flags=flags,
        SourceIP=source_ip,
        SourcePort=source_port,
        SourceName=source_nb_name,
        DestinationName=dest_nb_name,
    )
    return datagram / smb_packet


def mailslot_write(
    mailslot_name: str,
    data: bytes,
    source_name: str,
    destination_name: str,
    source_ip: str,
    mailslot_class: int = MAILSLOT_CLASS_UNRELIABLE,
    priority: int = 0,
) -> bytes:
    transaction = build_mailslot_write(
        mailslot_name=mailslot_name,
        data=data,
        mailslot_class=mailslot_class,
        priority=priority,
    )

    smb_header = build_smb_header()
    smb_packet = smb_header / transaction
    datagram = build_nbt_datagram(
        source_name=source_name,
        destination_name=destination_name,
        source_ip=source_ip,
        smb_packet=smb_packet,
    )
    return bytes(datagram)
