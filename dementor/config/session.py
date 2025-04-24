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
import asyncio

from typing import Any, List

from dementor.config.toml import TomlConfig, Attribute
from dementor.config.util import is_true
from dementor.paths import DEMENTOR_PATH
from dementor import config


class SessionConfig(TomlConfig):
    _section_ = "Dementor"
    _fields_ = [
        # TODO: place this somewhere else
        Attribute("llmnr_enabled", "LLMNR", True, factory=is_true),
        Attribute("nbtns_enabled", "NBTNS", True, factory=is_true),
        Attribute("nbtds_enabled", "NBTDS", True, factory=is_true),
        Attribute("smtp_enabled", "SMTP", True, factory=is_true),
        Attribute("smb_enabled", "SMB", True, factory=is_true),
        Attribute("ftp_enabled", "FTP", True, factory=is_true),
        Attribute("kdc_enabled", "KDC", True, factory=is_true),
        Attribute("ldap_enabled", "LDAP", True, factory=is_true),
        Attribute("quic_enabled", "QUIC", True, factory=is_true),
        Attribute("mdns_enabled", "mDNS", True, factory=is_true),
        Attribute("http_enabled", "HTTP", True, factory=is_true),
        Attribute("msrpc_enabled", "RPC", True, factory=is_true),
        Attribute("winrm_enabled", "WinRM", True, factory=is_true),
        Attribute("mssql_enabled", "MSSQL", True, factory=is_true),
        Attribute("ssrp_enabled", "SSRP", True, factory=is_true),
        Attribute("imap_enabled", "IMAP", True, factory=is_true),
        Attribute("extra_modules", "ExtraModules", list),
        Attribute("workspace_path", "Workspace", DEMENTOR_PATH),
    ]

    # TODO: move into .pyi
    db: Any
    db_config: Any
    krb5_config: Any
    mdns_config: Any
    llmnr_config: Any
    quic_config: Any
    netbiosns_config: Any
    ldap_config: List[Any]

    def __init__(self) -> None:
        super().__init__(config.dm_config.get("Dementor", {}))
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

        # SMB configuration
        self.smb_server_config = []

    def is_bound_to_all(self) -> bool:
        # REVISIT: this should raise an exception
        return self.interface == "ALL"

    @property
    def bind_address(self) -> str:
        return "::" if self.ipv6 else str(self.ipv4)

    @property
    def ipv6_support(self) -> bool:
        return bool(self.ipv6) and not getattr(self, "ipv4_only", False)
