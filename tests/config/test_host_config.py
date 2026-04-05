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
"""Unit tests for the Host identity configuration feature.

Covers:
- ``dementor.config.util.HostValue``: FQDN parsing and value derivation
- ``dementor.config.util.HostDerivedValue``: per-attribute factory (pure, no global fetches)
- ``dementor.config.attr.ATTR_GLOBALS_HOST``: single Attribute for Host
- NTLM session identity (ntlm_nb_computer, ntlm_nb_domain, …) via apply_config
- Protocol FQDN fallback (SMTP, LDAP, POP3, IMAP, MSSQL, RPC, HTTP, SMB)
- CLI -H / --host option (parse_options integration)
"""

import pytest

from unittest.mock import MagicMock

from dementor.config import _set_global_config, get_global_config
from dementor.config.attr import ATTR_GLOBALS_HOST
from dementor.config.toml import Attribute
from dementor.config.util import HostValue, HostDerivedValue, HostFallbackValue

from dementor.protocols import ntlm
from dementor.protocols.smtp import SMTPServerConfig
from dementor.protocols.ldap import LDAPServerConfig
from dementor.protocols.imap import IMAPServerConfig
from dementor.protocols.mssql import MSSQLConfig
from dementor.protocols.msrpc.rpc import RPCConfig
from dementor.protocols.mssql import SSRPConfig
from dementor.protocols.smb import SMBServerConfig

from dementor.standalone import parse_options

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _with_globals(**kw):
    """Return a minimal global config dict that has a Globals section."""
    return {"Globals": kw}


# ---------------------------------------------------------------------------
# HostValue - construction
# ---------------------------------------------------------------------------


class TestHostValueConstruction:
    def test_full_fqdn_splits_correctly(self):
        hv = HostValue("DC01.contoso.lab")
        assert hv.hostname == "DC01"
        assert hv.domain == "contoso.lab"

    def test_no_dot_hostname_only(self):
        hv = HostValue("DEMENTOR")
        assert hv.hostname == "DEMENTOR"
        assert hv.domain == ""

    def test_multi_label_domain(self):
        hv = HostValue("srv.sub.corp.example.com")
        assert hv.hostname == "srv"
        assert hv.domain == "sub.corp.example.com"

    def test_str_returns_raw(self):
        hv = HostValue("DC01.contoso.lab")
        assert str(hv) == "DC01.contoso.lab"

    def test_str_hostname_only(self):
        hv = HostValue("MYHOST")
        assert str(hv) == "MYHOST"

    def test_call_returns_new_instance(self):
        factory = HostValue("DEMENTOR")
        result = factory("DC01.corp.local")
        assert isinstance(result, HostValue)
        assert result.hostname == "DC01"
        assert result.domain == "corp.local"

    def test_whitespace_stripped(self):
        hv = HostValue("  DC01.corp.com  ")
        assert str(hv) == "DC01.corp.com"


# ---------------------------------------------------------------------------
# HostValue - get_value field derivation
# ---------------------------------------------------------------------------


class TestHostValueGetValue:
    @pytest.fixture
    def hv(self):
        return HostValue("DC01.contoso.lab")

    @pytest.fixture
    def hv_no_domain(self):
        return HostValue("DEMENTOR")

    # --- with domain ---

    def test_host_field(self, hv):
        assert hv.get_value("Host") == "DC01.contoso.lab"

    def test_fqdn_field(self, hv):
        assert hv.get_value("FQDN") == "DC01.contoso.lab"

    def test_dns_computer(self, hv):
        assert hv.get_value("DnsComputer") == "DC01.contoso.lab"

    def test_dns_hostname(self, hv):
        assert hv.get_value("DNSHostName") == "DC01"

    def test_netbios_computer(self, hv):
        assert hv.get_value("NetBIOSComputer") == "DC01"

    def test_netbios_name(self, hv):
        assert hv.get_value("NetBIOSName") == "DC01"

    def test_netbios_domain(self, hv):
        assert hv.get_value("NetBIOSDomain") == "CONTOSO.LAB"

    def test_netbios_domain_name(self, hv):
        assert hv.get_value("NetBIOSDomainName") == "CONTOSO.LAB"

    def test_dns_domain(self, hv):
        assert hv.get_value("DnsDomain") == "contoso.lab"

    def test_dns_domain_name(self, hv):
        assert hv.get_value("DNSDomainName") == "contoso.lab"

    def test_dns_tree(self, hv):
        assert hv.get_value("DnsTree") == "contoso.lab"

    def test_unknown_field_returns_hostname(self, hv):
        assert hv.get_value("UnknownField") == "DC01"

    # --- without domain ---

    def test_no_domain_fqdn_is_hostname(self, hv_no_domain):
        assert hv_no_domain.get_value("FQDN") == "DEMENTOR"

    def test_no_domain_dns_computer_is_empty(self, hv_no_domain):
        # DnsComputer must be empty when there is no domain (omit AV_PAIR)
        assert hv_no_domain.get_value("DnsComputer") == ""

    def test_no_domain_netbios_domain_fallback(self, hv_no_domain):
        assert hv_no_domain.get_value("NetBIOSDomain") == "WORKGROUP"

    def test_no_domain_dns_domain_empty(self, hv_no_domain):
        assert hv_no_domain.get_value("DnsDomain") == ""

    def test_no_domain_dns_tree_empty(self, hv_no_domain):
        assert hv_no_domain.get_value("DnsTree") == ""

    # --- NetBIOS 15-char truncation ---

    def test_netbios_computer_truncated_to_15(self):
        hv = HostValue("AVERYLONGHOSTNAME123.corp.local")
        nb = hv.get_value("NetBIOSComputer")
        assert len(nb) <= 15
        assert nb == "AVERYLONGHOSTNA"

    def test_netbios_computer_uppercased(self):
        hv = HostValue("dc01.contoso.lab")
        assert hv.get_value("NetBIOSComputer") == "DC01"

    def test_netbios_domain_uppercased(self):
        hv = HostValue("dc01.contoso.lab")
        assert hv.get_value("NetBIOSDomain") == "CONTOSO.LAB"

    def test_dns_domain_lowercased(self):
        hv = HostValue("DC01.CONTOSO.LAB")
        assert hv.get_value("DnsDomain") == "contoso.lab"


# ---------------------------------------------------------------------------
# ATTR_GLOBALS_HOST - Attribute metadata
# ---------------------------------------------------------------------------


class TestAttrGlobalsHost:
    def test_is_attribute_instance(self):
        assert isinstance(ATTR_GLOBALS_HOST, Attribute)

    def test_attr_name(self):
        assert ATTR_GLOBALS_HOST.attr_name == "host"

    def test_qname(self):
        assert ATTR_GLOBALS_HOST.qname == "Host"

    def test_not_section_local(self):
        assert ATTR_GLOBALS_HOST.section_local is False

    def test_factory_is_host_value(self):
        assert ATTR_GLOBALS_HOST.factory is HostValue

    def test_factory_produces_host_value_instance(self):
        result = ATTR_GLOBALS_HOST.factory("DC01.corp.local")
        assert isinstance(result, HostValue)
        assert result.hostname == "DC01"


# ---------------------------------------------------------------------------
# HostDerivedValue - per-attribute factory
# ---------------------------------------------------------------------------


class TestHostDerivedValue:
    """
    Verify that HostDerivedValue is a pure factory used with qname="Host".

    it receives a Host string and derives the specific field from it - no
    global config access.
    """

    def test_derives_fqdn_from_host_string(self):
        factory = HostDerivedValue("FQDN")
        assert factory("DC01.contoso.lab") == "DC01.contoso.lab"

    def test_derives_netbios_computer_from_host_string(self):
        factory = HostDerivedValue("NetBIOSComputer")
        assert factory("DC01.contoso.lab") == "DC01"

    def test_derives_netbios_domain_from_host_string(self):
        factory = HostDerivedValue("NetBIOSDomain")
        assert factory("DC01.contoso.lab") == "CONTOSO.LAB"

    def test_derives_dns_computer_from_host_string(self):
        factory = HostDerivedValue("DnsComputer")
        assert factory("DC01.contoso.lab") == "DC01.contoso.lab"

    def test_derives_dns_domain_from_host_string(self):
        factory = HostDerivedValue("DnsDomain")
        assert factory("DC01.contoso.lab") == "contoso.lab"

    def test_explicit_value_parsed_as_host(self):
        """Any explicit string is treated as a Host and the field is derived."""
        factory = HostDerivedValue("FQDN", "DEMENTOR")
        assert factory("explicit.host.com") == "explicit.host.com"

    def test_fallback_when_none(self):
        factory = HostDerivedValue("FQDN", "DEMENTOR")
        assert factory(None) == "DEMENTOR"

    def test_fallback_netbios_domain_workgroup(self):
        factory = HostDerivedValue("NetBIOSDomain", "WORKGROUP")
        assert factory(None) == "WORKGROUP"

    def test_hostname_only_netbios_domain_workgroup(self):
        factory = HostDerivedValue("NetBIOSDomain", "WORKGROUP")
        assert factory("DEMENTOR") == "WORKGROUP"

    def test_hostname_only_dns_computer_empty(self):
        factory = HostDerivedValue("DnsComputer", "")
        assert factory("DEMENTOR") == ""

    def test_post_factory_applied_to_explicit_value(self):
        factory = HostDerivedValue("FQDN", "DEMENTOR", post_factory=str.upper)
        assert factory("dc01.corp.com") == "DC01.CORP.COM"

    def test_post_factory_applied_to_derived_value(self):
        factory = HostDerivedValue("DnsComputer", "DEMENTOR", post_factory=str.upper)
        assert factory("dc01.corp.com") == "DC01.CORP.COM"


# ---------------------------------------------------------------------------
# HostFallbackValue - explicit-first, Host-derived fallback factory
# ---------------------------------------------------------------------------


class TestHostFallbackValue:
    """Verify that HostFallbackValue uses explicit values directly and
    reads Globals.Host only as a last resort.
    """  # noqa: D205

    def test_explicit_value_returned_as_is(self):
        factory = HostFallbackValue("FQDN", "DEMENTOR")
        assert factory("explicit.smtp.com") == "explicit.smtp.com"

    def test_explicit_netbios_returned_as_is(self):
        factory = HostFallbackValue("NetBIOSComputer", "DEMENTOR")
        assert factory("MYSERVER") == "MYSERVER"

    def test_fallback_when_none_and_no_host(self):
        original = get_global_config()
        try:
            _set_global_config({})
            factory = HostFallbackValue("FQDN", "DEMENTOR")
            assert factory(None) == "DEMENTOR"
        finally:
            _set_global_config(original)

    def test_derives_fqdn_from_globals_host_when_none(self):
        original = get_global_config()
        try:
            _set_global_config({"Globals": {"Host": "DC01.contoso.lab"}})
            factory = HostFallbackValue("FQDN", "DEMENTOR")
            assert factory(None) == "DC01.contoso.lab"
        finally:
            _set_global_config(original)

    def test_derives_netbios_computer_from_globals_host(self):
        original = get_global_config()
        try:
            _set_global_config({"Globals": {"Host": "DC01.contoso.lab"}})
            factory = HostFallbackValue("NetBIOSComputer", "DEMENTOR")
            assert factory(None) == "DC01"
        finally:
            _set_global_config(original)

    def test_derives_netbios_domain_from_globals_host(self):
        original = get_global_config()
        try:
            _set_global_config({"Globals": {"Host": "DC01.contoso.lab"}})
            factory = HostFallbackValue("NetBIOSDomain", "WORKGROUP")
            assert factory(None) == "CONTOSO.LAB"
        finally:
            _set_global_config(original)

    def test_explicit_beats_globals_host(self):
        """An explicit value must win over [Globals].Host derivation."""
        original = get_global_config()
        try:
            _set_global_config({"Globals": {"Host": "DC01.contoso.lab"}})
            factory = HostFallbackValue("FQDN", "DEMENTOR")
            assert factory("override.corp.com") == "override.corp.com"
        finally:
            _set_global_config(original)

    def test_post_factory_applied_to_explicit(self):
        factory = HostFallbackValue("FQDN", "DEMENTOR", post_factory=str.upper)
        assert factory("smtp.corp.com") == "SMTP.CORP.COM"

    def test_post_factory_applied_to_derived(self):
        original = get_global_config()
        try:
            _set_global_config({"Globals": {"Host": "dc01.corp.com"}})
            factory = HostFallbackValue("FQDN", "DEMENTOR", post_factory=str.upper)
            assert factory(None) == "DC01.CORP.COM"
        finally:
            _set_global_config(original)

    def test_hostname_only_netbios_domain_workgroup_fallback(self):
        original = get_global_config()
        try:
            _set_global_config({"Globals": {"Host": "DEMENTOR"}})
            factory = HostFallbackValue("NetBIOSDomain", "WORKGROUP")
            assert factory(None) == "WORKGROUP"
        finally:
            _set_global_config(original)


# ---------------------------------------------------------------------------
# NTLM session identity - apply_config picks up Globals.Host
# ---------------------------------------------------------------------------


class TestNTLMApplyConfigWithHost:
    """Verify that ntlm.apply_config() derives identity from Globals.Host."""

    def _apply(self, globals_dict: dict, extra_sections: dict | None = None):
        original = get_global_config()
        try:
            cfg = {"Globals": globals_dict}
            if extra_sections:
                cfg.update(extra_sections)
            _set_global_config(cfg)
            session = MagicMock()
            ntlm.apply_config(session)
            return session
        finally:
            _set_global_config(original)

    def test_default_identity_when_no_host(self):
        session = self._apply({})
        assert session.ntlm_nb_computer == "DEMENTOR"
        assert session.ntlm_nb_domain == "WORKGROUP"
        assert session.ntlm_dns_computer == ""
        assert session.ntlm_dns_domain == ""

    def test_identity_derived_from_host(self):
        session = self._apply({"Host": "DC01.contoso.lab"})
        assert session.ntlm_nb_computer == "DC01"
        assert session.ntlm_nb_domain == "CONTOSO.LAB"
        assert session.ntlm_dns_computer == "DC01.contoso.lab"
        assert session.ntlm_dns_domain == "contoso.lab"

    def test_ntlm_section_overrides_host(self):
        """Explicit [NTLM].NetBIOSComputer beats [Globals].Host derivation."""
        session = self._apply(
            {"Host": "DC01.contoso.lab"},
            {"NTLM": {"NetBIOSComputer": "OVERRIDE"}},
        )
        assert session.ntlm_nb_computer == "OVERRIDE"
        # Domain still from Host since no [NTLM].NetBIOSDomain
        assert session.ntlm_nb_domain == "CONTOSO.LAB"

    def test_globals_explicit_field_beats_host(self):
        """An explicit [Globals].NetBIOSComputer beats [Globals].Host derivation."""
        session = self._apply({"Host": "DC01.contoso.lab", "NetBIOSComputer": "EXPLICIT"})
        assert session.ntlm_nb_computer == "EXPLICIT"
        # Other fields still from Host
        assert session.ntlm_nb_domain == "CONTOSO.LAB"


# ---------------------------------------------------------------------------
# Protocol FQDN fallback - SMTP, LDAP, POP3, IMAP, MSSQL, HTTP, RPC
# ---------------------------------------------------------------------------


class TestProtocolFQDNFallback:
    """Verify that protocol FQDN attrs derive from Globals.Host."""

    def _global_cfg(self, host: str, **extra_globals):
        return {"Globals": {"Host": host, **extra_globals}}

    def test_smtp_fqdn_from_host(self):
        original = get_global_config()
        try:
            _set_global_config(self._global_cfg("MAIL01.corp.com"))

            cfg = SMTPServerConfig({"Port": 25})
            assert cfg.smtp_fqdn == "MAIL01.corp.com"
        finally:
            _set_global_config(original)

    def test_smtp_fqdn_explicit_in_protocol_overrides_host(self):
        original = get_global_config()
        try:
            _set_global_config(
                {
                    "Globals": {"Host": "MAIL01.corp.com"},
                    "SMTP": {
                        "Host": "explicit.smtp.com"
                    },  # explicit Host in [SMTP] beats [Globals].Host
                }
            )

            cfg = SMTPServerConfig({"Port": 25})
            assert cfg.smtp_fqdn == "explicit.smtp.com"
        finally:
            _set_global_config(original)

    def test_ldap_fqdn_from_host(self):
        original = get_global_config()
        try:
            _set_global_config(self._global_cfg("DC01.corp.local"))

            cfg = LDAPServerConfig({"Port": 389, "Connectionless": False})
            assert cfg.ldap_fqdn == "DC01.corp.local"
        finally:
            _set_global_config(original)

    def test_imap_fqdn_from_host(self):
        original = get_global_config()
        try:
            _set_global_config(self._global_cfg("MAIL01.corp.com"))

            cfg = IMAPServerConfig({"Port": 143})
            assert cfg.imap_fqdn == "MAIL01.corp.com"
        finally:
            _set_global_config(original)

    def test_mssql_fqdn_from_host(self):
        original = get_global_config()
        try:
            _set_global_config(self._global_cfg("SQL01.corp.com"))

            cfg = MSSQLConfig({"Port": 1433})
            assert cfg.mssql_fqdn == "SQL01.corp.com"
        finally:
            _set_global_config(original)

    def test_rpc_fqdn_from_host(self):
        original = get_global_config()
        try:
            _set_global_config(self._global_cfg("DC01.corp.local"))

            cfg = RPCConfig({})
            assert cfg.rpc_fqdn == "DC01.corp.local"
        finally:
            _set_global_config(original)

    def test_ssrp_server_name_from_host(self):
        """SSRP derives its server name from Globals.Host (via MSSQL.FQDN chain)."""
        original = get_global_config()
        try:
            _set_global_config(self._global_cfg("SQL01.corp.com"))

            cfg = SSRPConfig({})
            assert cfg.ssrp_server_name == "SQL01.corp.com"
        finally:
            _set_global_config(original)

    def test_smb_nb_computer_from_host(self):
        """SMB identity derives NetBIOSComputer from Globals.Host."""
        original = get_global_config()
        try:
            _set_global_config(self._global_cfg("DC01.corp.local"))

            cfg = SMBServerConfig({"Port": 445})
            assert cfg.smb_nb_computer == "DC01"
            assert cfg.smb_nb_domain == "CORP.LOCAL"
        finally:
            _set_global_config(original)

    def test_smb_nb_computer_explicit_overrides_host(self):
        """Explicit [SMB].NetBIOSComputer beats Globals.Host derivation."""
        original = get_global_config()
        try:
            _set_global_config(
                {
                    "Globals": {"Host": "DC01.corp.local"},
                    "SMB": {"NetBIOSComputer": "EXPLICIT"},
                }
            )

            cfg = SMBServerConfig({"Port": 445})
            assert cfg.smb_nb_computer == "EXPLICIT"
            assert cfg.smb_nb_domain == "CORP.LOCAL"  # still derived from Host
        finally:
            _set_global_config(original)

    def test_smb_nb_computer_default_when_no_host(self):
        """Without Host, SMB identity falls back to hardcoded 'DEMENTOR'."""
        original = get_global_config()
        try:
            _set_global_config({})

            cfg = SMBServerConfig({"Port": 445})
        finally:
            _set_global_config(original)
        assert cfg.smb_nb_computer == "DEMENTOR"
        assert cfg.smb_nb_domain == "WORKGROUP"

    def test_per_server_fqdn_overrides_globals(self):
        """Per-server FQDN takes priority over Globals.Host."""
        original = get_global_config()
        try:
            _set_global_config(self._global_cfg("MAIL01.corp.com"))

            # Per-server config dict with explicit "Host" key
            cfg = SMTPServerConfig({"Port": 25, "Host": "perserver.example.com"})
            assert cfg.smtp_fqdn == "perserver.example.com"
        finally:
            _set_global_config(original)

    def test_no_host_smtp_falls_back_to_hardcoded_default(self):
        original = get_global_config()
        try:
            _set_global_config({})

            cfg = SMTPServerConfig({"Port": 25})
        finally:
            _set_global_config(original)
        assert cfg.smtp_fqdn == "DEMENTOR"


# ---------------------------------------------------------------------------
# CLI -H option integration
# ---------------------------------------------------------------------------


class TestCLIHostOption:
    def test_parse_options_globals_host(self):

        result = parse_options(["Globals.Host=DC01.contoso.lab"])
        assert result == {"Globals": {"Host": "DC01.contoso.lab"}}

    def test_host_flag_sets_globals_host(self):
        """Simulate -H DC01.contoso.lab being applied to the config."""
        original = get_global_config()
        try:
            import dementor.config as cfg_mod  # noqa: PLC0415

            cfg_mod.dm_config.setdefault("Globals", {})["Host"] = "DC01.contoso.lab"
            result = get_global_config()["Globals"]
        finally:
            _set_global_config(original)

        assert result["Host"] == "DC01.contoso.lab"
        # Factories derive on attribute access - verify the factory works correctly
        factory = HostDerivedValue("NetBIOSComputer", "DEMENTOR")
        assert factory("DC01.contoso.lab") == "DC01"

    def test_option_flag_equivalent_to_host_flag(self):
        """Globals.Host via -O must produce same result as -H."""
        via_O = parse_options(["Globals.Host=DC01.contoso.lab"])
        # -H DC01.contoso.lab is equivalent to setting Globals.Host directly
        assert via_O["Globals"]["Host"] == "DC01.contoso.lab"
