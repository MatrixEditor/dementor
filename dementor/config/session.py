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
import asyncio
import typing

from typing import Any
from pathlib import Path

from dementor.config.toml import TomlConfig, Attribute
from dementor.config.util import is_true
from dementor.paths import DEMENTOR_PATH
from dementor import config

if typing.TYPE_CHECKING:
    from dementor.protocols import (
        kerberos,
        mdns,
        netbios,
        llmnr,
        ldap,
        smb,
        smtp,
        ftp,
        http,
        imap,
        ipp,
        mssql,
        mysql,
        pop3,
        quic,
        ssdp,
        upnp,
        x11,
    )
    from dementor.protocols.msrpc import rpc
    from dementor.db.model import DementorDB
    from dementor.db.connector import DatabaseConfig


class SessionConfig(TomlConfig):
    _section_ = "Dementor"
    _fields_ = [
        Attribute("extra_modules", "ExtraModules", list),
        Attribute("workspace_path", "Workspace", DEMENTOR_PATH),
    ] + [
        # TODO: place this somewhere else
        Attribute(f"{name.lower()}_enabled", name, True, factory=is_true)
        for name in (
            "LLMNR",
            "NBTNS",
            "NBTDS",
            "SMTP",
            "SMB",
            "FTP",
            "KDC",
            "LDAP",
            "QUIC",
            "mDNS",
            "HTTP",
            "RPC",
            "WinRM",
            "MSSQL",
            "SSRP",
            "IMAP",
            "POP3",
            "MySQL",
            "X11",
            "IPP",
            "SSDP",
            "UPnP",
        )
    ]

    # TODO: move into .pyi
    if typing.TYPE_CHECKING:
        workspace_path: str
        extra_modules: list[str]
        ipv6: str | None
        ipv4: str | None
        interface: str | None
        protocols: dict[str, Any]

        db: DementorDB
        db_config: DatabaseConfig
        krb5_config: kerberos.KerberosConfig
        mdns_config: mdns.MDNSConfig
        llmnr_config: llmnr.LLMNRConfig
        netbiosns_config: netbios.NBTNSConfig
        ldap_config: list[ldap.LDAPServerConfig]
        smtp_servers: list[smtp.SMTPServerConfig]
        smb_config: list[smb.SMBServerConfig]
        ftp_config: list[ftp.FTPServerConfig]
        proxy_config: http.ProxyAutoConfig
        http_config: list[http.HTTPServerConfig]
        winrm_config: list[http.HTTPServerConfig]
        imap_config: list[imap.IMAPServerConfig]
        ipp_config: ipp.IPPConfig
        rpc_config: rpc.RPCConfig
        mssql_config: mssql.MSSQLConfig
        ssrp_config: mssql.SSRPConfig
        mysql_config: mysql.MySQLConfig
        pop3_config: list[pop3.POP3ServerConfig]
        quic_config: quic.QuicServerConfig
        ssdp_config: ssdp.SSDPConfig
        upnp_config: upnp.UPNPConfig
        x11_config: x11.X11Config

        ntlm_challange: bytes
        ntlm_ess: bool
        analysis: bool
        loop: asyncio.AbstractEventLoop

        llmnr_enabled: bool
        nbtns_enabled: bool
        nbtds_enabled: bool
        smtp_enabled: bool
        smb_enabled: bool
        ftp_enabled: bool
        kdc_enabled: bool
        ldap_enabled: bool
        quic_enabled: bool
        mdns_enabled: bool
        http_enabled: bool
        rpc_enabled: bool
        winrm_enabled: bool
        mssql_enabled: bool
        ssrp_enabled: bool
        imap_enabled: bool
        pop3_enabled: bool
        mysql_enabled: bool
        x11_enabled: bool
        ipp_enabled: bool
        ssdp_enabled: bool
        upnp_enabled: bool

    def __init__(self) -> None:
        super().__init__(config._get_global_config().get("Dementor", {}))
        # global options that are not loaded from configuration
        self.ipv6 = None
        self.ipv4 = None
        self.interface = None
        self.analysis = False
        self.loop = asyncio.get_event_loop()
        self.protocols = {}

        # SMTP configuration
        self.smtp_servers = []

        # NTLM configuration
        self.ntlm_challange = b"1337LEET"
        self.ntlm_ess = True

    def is_bound_to_all(self) -> bool:
        # REVISIT: this should raise an exception
        return self.interface == "ALL"

    @property
    def bind_address(self) -> str:
        return "::" if self.ipv6 else str(self.ipv4)

    @property
    def ipv6_support(self) -> bool:
        return bool(self.ipv6) and not getattr(self, "ipv4_only", False)

    def resolve_path(self, path: str | Path) -> Path:
        raw_path = str(path)
        if raw_path[0] == "/":
            return Path(raw_path)
        elif raw_path.startswith("./") or raw_path.startswith("../"):
            return Path(raw_path).resolve()

        return (Path(self.workspace_path) / raw_path).resolve()
