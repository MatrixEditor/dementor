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
"""Unit tests for the dementor configuration backbone.

Covers:
- ``dementor.config.toml``: ``TomlConfig``, ``Attribute``, ``_set_field``, ``build_config``
- ``dementor.config.util``: ``get_value``, ``is_true``
- ``dementor.config``: ``get_global_config``, ``_set_global_config``
"""
import pytest

from unittest.mock import patch

from dementor.config.toml import TomlConfig, Attribute, _LOCAL
from dementor.config.util import get_value, is_true
from dementor.config import get_global_config, _set_global_config


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class SimpleConfig(TomlConfig):
    _section_ = "Simple"
    _fields_ = [
        Attribute("host", "host", default_val="localhost"),
        Attribute("port", "port", default_val=8080, factory=int),
    ]


class RequiredFieldConfig(TomlConfig):
    _section_ = "Req"
    _fields_ = [
        Attribute("required_val", "value"),  # no default_val -> _LOCAL sentinel
    ]


class FactoryConfig(TomlConfig):
    _section_ = "Factory"
    _fields_ = [
        Attribute("count", "count", default_val="5", factory=int),
        Attribute(
            "flag",
            "flag",
            default_val="yes",
            factory=lambda v: str(v).lower() in ("true", "1", "yes"),
        ),
    ]


class GlobalFallbackConfig(TomlConfig):
    _section_ = "Proto"
    _fields_ = [
        # section_local=False means also look in Globals
        Attribute("timeout", "timeout", default_val=30, section_local=False),
    ]


# ---------------------------------------------------------------------------
# TomlConfig - basic instantiation
# ---------------------------------------------------------------------------


class TestTomlConfigBasic:
    def test_default_values_used_when_config_empty(self):
        cfg = SimpleConfig({})
        assert cfg.host == "localhost"
        assert cfg.port == 8080

    def test_none_config_treated_as_empty_dict(self):
        cfg = SimpleConfig(None)
        assert cfg.host == "localhost"
        assert cfg.port == 8080

    def test_config_values_override_defaults(self):
        cfg = SimpleConfig({"host": "example.com", "port": "9090"})
        assert cfg.host == "example.com"
        assert cfg.port == 9090  # factory=int applied

    def test_partial_override(self):
        cfg = SimpleConfig({"host": "myhost"})
        assert cfg.host == "myhost"
        assert cfg.port == 8080  # default preserved

    def test_factory_applied_to_value(self):
        cfg = SimpleConfig({"port": "1234"})
        assert cfg.port == 1234
        assert isinstance(cfg.port, int)

    def test_factory_applied_to_default(self):
        cfg = FactoryConfig({})
        assert cfg.count == 5
        assert isinstance(cfg.count, int)
        assert cfg.flag is True

    def test_factory_processes_supplied_value(self):
        cfg = FactoryConfig({"count": "99", "flag": "false"})
        assert cfg.count == 99
        assert cfg.flag is False


# ---------------------------------------------------------------------------
# Attribute - sentinel behaviour
# ---------------------------------------------------------------------------


class TestAttributeSentinel:
    def test_required_field_raises_when_missing(self):
        with pytest.raises(ValueError, match="value"):
            RequiredFieldConfig({})

    def test_required_field_succeeds_when_supplied(self):
        cfg = RequiredFieldConfig({"value": "hello"})
        assert cfg.required_val == "hello"

    def test_local_sentinel_is_not_none(self):
        # _LOCAL must be a distinct object from None so that None can be a valid default
        assert _LOCAL is not None

    def test_none_default_distinct_from_local(self):
        class NullableConfig(TomlConfig):
            _section_ = "N"
            _fields_ = [Attribute("val", "val", default_val=None)]

        cfg = NullableConfig({})
        assert cfg.val is None


# ---------------------------------------------------------------------------
# _set_field - type coercion and setter dispatch
# ---------------------------------------------------------------------------


class TestSetField:
    def test_custom_setter_called_when_present(self):
        class SetterConfig(TomlConfig):
            _section_ = "S"
            _fields_ = [Attribute("value", "value", default_val=0, factory=int)]

            def set_value(self, val: int) -> None:
                self.value = val * 2  # double on set

        cfg = SetterConfig({"value": "7"})
        assert cfg.value == 14

    def test_setattr_used_when_no_setter(self):
        cfg = SimpleConfig({"host": "direct"})
        assert cfg.host == "direct"

    def test_dotted_qname_reads_nested_config(self):
        class DottedConfig(TomlConfig):
            _section_ = "Outer"
            _fields_ = [
                Attribute("inner_val", "Inner.key", default_val="default"),
            ]

        cfg = DottedConfig({"Inner": {"key": "nested_value"}})
        assert cfg.inner_val == "nested_value"


# ---------------------------------------------------------------------------
# TomlConfig.__getitem__
# ---------------------------------------------------------------------------


class TestGetItem:
    def test_getitem_by_attr_name(self):
        cfg = SimpleConfig({"host": "h1"})
        assert cfg["host"] == "h1"

    def test_getitem_by_qname(self):
        cfg = SimpleConfig({"port": "7777"})
        assert cfg["port"] == 7777

    def test_getitem_missing_raises_key_error(self):
        cfg = SimpleConfig({})
        with pytest.raises(KeyError):
            _ = cfg["nonexistent"]


# ---------------------------------------------------------------------------
# TomlConfig.build_config - reads from global config
# ---------------------------------------------------------------------------


class TestBuildConfig:
    def test_build_config_uses_global_config(self):
        with patch(
            "dementor.config.util.get_global_config",
            return_value={"Simple": {"host": "fromglobal"}},
        ):
            cfg = TomlConfig.build_config(SimpleConfig)
        assert cfg.host == "fromglobal"

    def test_build_config_empty_section_uses_defaults(self):
        with patch("dementor.config.util.get_global_config", return_value={}):
            cfg = TomlConfig.build_config(SimpleConfig)
        assert cfg.host == "localhost"

    def test_build_config_section_override(self):
        with patch(
            "dementor.config.util.get_global_config",
            return_value={"Alt": {"host": "althost"}},
        ):
            cfg = TomlConfig.build_config(SimpleConfig, section="Alt")
        assert cfg.host == "althost"

    def test_build_config_raises_when_section_none(self):
        class NoSection(TomlConfig):
            _section_ = ""
            _fields_ = []

        with pytest.raises(ValueError, match="section cannot be None"):
            TomlConfig.build_config(NoSection)


# ---------------------------------------------------------------------------
# TomlConfig.as_dict / __repr__
# ---------------------------------------------------------------------------


class TestAsDict:
    def test_as_dict_returns_all_fields(self):
        cfg = SimpleConfig({"host": "myhost", "port": "9000"})
        d = cfg.as_dict()
        assert d == {"host": "myhost", "port": 9000}

    def test_repr_contains_field_values(self):
        cfg = SimpleConfig({"host": "repr_test"})
        assert "repr_test" in repr(cfg)


# ---------------------------------------------------------------------------
# get_value - utility function
# ---------------------------------------------------------------------------


class TestGetValue:
    def test_returns_default_when_key_missing(self):
        with patch("dementor.config.util.get_global_config", return_value={}):
            result = get_value("NoSuchSection", "key", default="fallback")
        assert result == "fallback"

    def test_returns_value_from_section(self):
        with patch(
            "dementor.config.util.get_global_config",
            return_value={"NTLM": {"Challenge": "aabbccdd"}},
        ):
            result = get_value("NTLM", "Challenge", default=None)
        assert result == "aabbccdd"

    def test_returns_none_default_when_not_specified(self):
        with patch("dementor.config.util.get_global_config", return_value={}):
            result = get_value("Missing", "key")
        assert result is None

    def test_returns_whole_section_when_key_none(self):
        section_data = {"Port": 443, "SSL": True}
        with patch(
            "dementor.config.util.get_global_config", return_value={"LDAP": section_data}
        ):
            result = get_value("LDAP", key=None, default={})
        assert result == section_data

    def test_dotted_section_path(self):
        config = {"HTTP": {"server": {"Port": 80}}}
        with patch("dementor.config.util.get_global_config", return_value=config):
            result = get_value("HTTP.server", "Port", default=0)
        assert result == 80

    def test_missing_nested_path_returns_default(self):
        with patch("dementor.config.util.get_global_config", return_value={}):
            result = get_value("A.B.C", "key", default=42)
        assert result == 42


# ---------------------------------------------------------------------------
# is_true - bool coercion
# ---------------------------------------------------------------------------


class TestIsTrue:
    @pytest.mark.parametrize(
        "truthy", ["true", "True", "TRUE", "1", "on", "ON", "yes", "YES"]
    )
    def test_truthy_values(self, truthy):
        assert is_true(truthy) is True

    @pytest.mark.parametrize(
        "falsy", ["false", "False", "0", "off", "no", "", "random", "2"]
    )
    def test_falsy_values(self, falsy):
        assert is_true(falsy) is False

    def test_non_string_input(self):
        # is_true coerces via str() so non-string inputs should work
        assert is_true(1) is True
        assert is_true(0) is False


# ---------------------------------------------------------------------------
# get_global_config / _set_global_config
# ---------------------------------------------------------------------------


class TestGlobalConfig:
    def test_set_and_get_global_config(self):
        original = get_global_config()
        try:
            _set_global_config({"test_key": "test_val"})
            assert get_global_config()["test_key"] == "test_val"
        finally:
            _set_global_config(original)

    def test_global_config_returns_dict(self):
        result = get_global_config()
        assert isinstance(result, dict)

    def test_global_config_isolation(self):
        original = get_global_config()
        _set_global_config({"isolated": True})
        assert get_global_config().get("isolated") is True
        _set_global_config(original)
        assert "isolated" not in get_global_config()


# ---------------------------------------------------------------------------
# GlobalFallbackConfig - section_local=False reads Globals
# ---------------------------------------------------------------------------


class TestGlobalFallback:
    def test_global_fallback_used_when_section_missing(self):
        config = {"Globals": {"timeout": 60}}
        with patch("dementor.config.util.get_global_config", return_value=config):
            cfg = TomlConfig.build_config(GlobalFallbackConfig)
        assert cfg.timeout == 60

    def test_section_value_overrides_global(self):
        config = {"Proto": {"timeout": 10}, "Globals": {"timeout": 60}}
        with patch("dementor.config.util.get_global_config", return_value=config):
            cfg = TomlConfig.build_config(GlobalFallbackConfig)
        assert cfg.timeout == 10
