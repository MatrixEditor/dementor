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
import tomllib
import os
import asyncio

from typing import Any, List, Optional

from dementor.paths import ASSETS_PATH, CONFIG_PATH, DEMENTOR_PATH
from dementor.database import DementorDB


_LOCAL = object()


class TomlConfig:
    _section_: str | None
    _fields_: list[tuple]

    def __init__(self, config: dict) -> None:
        for field in self._fields_:
            attr_name, name, default_val = field
            self._set_field(config, attr_name, name, default_val)

    def __getitem__(self, key: str) -> Any:
        if hasattr(self, key):
            return getattr(self, key)

        for attrname, qname, _ in getattr(self, "_fields_", []):
            if "." in qname:
                _, qname = qname.rsplit(".", 1)

            if key == qname:
                return getattr(self, attrname)

        raise KeyError(f"Could not find config with key {key!r}")

    @staticmethod
    def build_config(cls_ty, section: str | None = None) -> Any:
        return cls_ty(get_value(section or cls_ty._section_, key=None, default={}))

    def _set_field(
        self, config: dict, field_name: str, qname: str, default_val=None
    ) -> None:
        # Behaviour:
        #   1. resolve default value:
        #       - If default_val is _LOCAL, there will be no default value
        #       - If self._section_ is present, it will be used to fetch the
        #         defualt value. The name may contain "."
        #   2. Retrieve value from target section
        #   3. Apply value by either
        #       - Calling a function with 'set_<attr_name>', or
        #       - using setattr directly

        section = getattr(self, "_section_", None)
        if "." in qname:
            # REVISIT: section will be overwritten here
            # get section path and target property name
            alt_section, qname = qname.rsplit(".", 1)
        else:
            alt_section = None

        if default_val is not _LOCAL:
            # PRIOROTY list:
            #   1. _section_
            #   2. alternative section in qname
            #   3. variable in dm_config.Globals
            sections = (
                get_value(section or "", key=None, default={}),
                get_value(alt_section or "", key=None, default={}),
                get_value("Globals", key=None, default={}),
            )
            for section_config in sections:
                if qname in section_config:
                    default_val = section_config[qname]
                    break

        value = config.get(qname, default_val)
        if value is _LOCAL:
            raise Exception(
                f"Expected '{qname}' in config or section({section}) for {self.__class__.__name__}!"
            )

        if value is default_val and isinstance(value, type):
            # use factory instead of return value
            value = value()

        func = getattr(self, f"set_{field_name}", None)
        if func:
            func(value)
        else:
            setattr(self, field_name, value)


class SessionConfig(TomlConfig):
    _section_ = "Dementor"
    _fields_ = [
        ("workspace_path", "Workspace", DEMENTOR_PATH),
        ("llmnr_enabled", "LLMNR", True),
        ("netbiosns_enabled", "NBTNS", True),
        ("netbiosds_enabled", "NBTDS", True),
        ("smtp_enabled", "SMTP", True),
        ("smb_enabled", "SMB", True),
        ("ftp_enabled", "FTP", True),
        ("kdc_enabled", "KDC", True),
        ("ldap_enabled", "LDAP", True),
        ("quic_enabled", "QUIC", True),
        ("db_duplicate_creds", "DB.DuplicateCreds", True),
        ("extra_modules", "ExtraModules", list),
    ]

    db: DementorDB
    krb5_config: Any
    mdns_config: Any
    llmnr_config: Any
    quic_config: Any
    netbiosns_config: Any
    ldap_config: List[Any]

    def __init__(self) -> None:
        super().__init__(dm_config.get("Dementor", {}))
        # global options that are not loaded from configuration
        self.ipv6: Optional[str] = None
        self.ipv4: Optional[str] = None
        self.interface = None
        self.analysis = False
        self.loop = asyncio.get_event_loop()

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


def _read(path: str):
    with open(path, "rb") as f:
        return tomllib.load(f)


dm_default_config = _read(os.path.join(ASSETS_PATH, "Dementor.conf"))

if os.path.exists(CONFIG_PATH):
    dm_config = _read(CONFIG_PATH)
else:
    dm_config = {}

if not dm_config or "Dementor" not in dm_config:
    # TODO: do first run
    dm_config = dm_default_config


def get_bool(section: str, key: str, default=False) -> bool:
    value = str(get_value(section, key=key, default=str(default)))
    return is_true(value)


def get_value(section: str, key: str | None, default=None) -> Any:
    sections = section.split(".")
    if len(sections) == 1:
        target = dm_config.get(sections[0], {})
    else:
        target = dm_config
        for section in sections:
            target = target[section]

    if key is None:
        return target

    return target.get(key, default)


def is_true(value) -> bool:
    return str(value).lower() in ("true", "1", "yes", "on")


def init_from_file(path: str):
    global dm_config

    if os.path.exists(path):
        dm_config = _read(path)
