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
"""Tests for dementor/log/logger.py - ProtocolLogger and LoggingConfig."""

import pytest

from unittest.mock import patch

from dementor.log.logger import ProtocolLogger, LoggingConfig

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def logger():
    """Return a fresh ProtocolLogger with no extra context."""
    return ProtocolLogger()


@pytest.fixture
def logger_with_context():
    """Return a ProtocolLogger pre-configured with protocol context."""
    return ProtocolLogger(
        extra={
            "protocol": "SMB",
            "protocol_color": "cyan",
            "host": "192.168.1.1",
            "port": "445",
        }
    )


# ---------------------------------------------------------------------------
# ProtocolLogger init tests
# ---------------------------------------------------------------------------


class TestProtocolLoggerInit:
    def test_init_no_extra(self):
        lg = ProtocolLogger()
        assert lg.extra == {}

    def test_init_with_extra(self):
        extra = {"protocol": "HTTP", "host": "10.0.0.1"}
        lg = ProtocolLogger(extra=extra)
        assert lg.extra["protocol"] == "HTTP"
        assert lg.extra["host"] == "10.0.0.1"

    def test_init_none_extra_uses_empty_dict(self):
        lg = ProtocolLogger(extra=None)
        assert lg.extra == {}

    def test_logger_name(self, logger):
        assert logger.logger.name == "dementor"


# ---------------------------------------------------------------------------
# Accessor tests
# ---------------------------------------------------------------------------


class TestProtocolLoggerAccessors:
    def test_get_protocol_name_default_empty(self, logger):
        assert logger.get_protocol_name() == ""

    def test_get_protocol_name_from_context(self, logger_with_context):
        assert logger_with_context.get_protocol_name() == "SMB"

    def test_get_protocol_color_default_white(self, logger):
        assert logger.get_protocol_color() == "white"

    def test_get_protocol_color_from_context(self, logger_with_context):
        assert logger_with_context.get_protocol_color() == "cyan"

    def test_get_host_default_empty(self, logger):
        assert logger.get_host() == ""

    def test_get_host_from_context(self, logger_with_context):
        assert logger_with_context.get_host() == "192.168.1.1"

    def test_get_port_default_empty(self, logger):
        assert logger.get_port() == ""

    def test_get_port_from_context(self, logger_with_context):
        assert logger_with_context.get_port() == "445"

    def test_get_extra_from_per_call_extra(self, logger):
        per_call = {"protocol": "SMTP"}
        result = logger._get_extra("protocol", per_call, "default")
        assert result == "SMTP"
        # per_call should have had the key popped
        assert "protocol" not in per_call

    def test_get_extra_falls_back_to_default(self, logger):
        result = logger._get_extra("nonexistent_key", None, "fallback")
        assert result == "fallback"

    def test_get_extra_per_call_overrides_context(self, logger_with_context):
        per_call = {"protocol": "FTP"}
        result = logger_with_context._get_extra("protocol", per_call)
        assert result == "FTP"


# ---------------------------------------------------------------------------
# Format tests
# ---------------------------------------------------------------------------


class TestProtocolLoggerFormat:
    def test_format_returns_tuple(self, logger):
        msg, kwargs = logger.format("test message")
        assert isinstance(msg, str)
        assert isinstance(kwargs, dict)

    def test_format_with_context(self, logger_with_context):
        msg, _ = logger_with_context.format("hello")
        assert isinstance(msg, str)
        assert "hello" in msg

    def test_format_inline_returns_tuple(self, logger):
        result = logger.format_inline("test", {})
        assert isinstance(result, tuple)
        msg, _ = result
        assert isinstance(msg, str)

    def test_format_inline_with_context(self, logger_with_context):
        result = logger_with_context.format_inline("inline message", {})
        msg, _ = result
        assert isinstance(msg, str)
        assert "inline message" in msg


# ---------------------------------------------------------------------------
# Log method tests
# ---------------------------------------------------------------------------


class TestProtocolLoggerLogMethods:
    def test_log_method_exists(self, logger):
        assert callable(logger.log)

    def test_debug_method_exists(self, logger):
        assert callable(logger.debug)

    def test_info_method_exists(self, logger):
        assert callable(logger.info)

    def test_warning_method_exists(self, logger):
        assert callable(logger.warning)

    def test_success_method_exists(self, logger):
        assert callable(logger.success)

    def test_display_method_exists(self, logger):
        assert callable(logger.display)

    def test_highlight_method_exists(self, logger):
        assert callable(logger.highlight)

    def test_fail_method_exists(self, logger):
        assert callable(logger.fail)

    def test_log_does_not_raise_with_basic_message(self, logger):
        with patch.object(logger.logger, "log"):
            logger.debug("test message")

    def test_log_accepts_is_client_kwarg(self, logger):
        with patch.object(logger.logger, "log"):
            logger.debug("test", is_client=True)

    def test_log_accepts_is_server_kwarg(self, logger):
        with patch.object(logger.logger, "log"):
            logger.info("test", is_server=True)


# ---------------------------------------------------------------------------
# log_config lazy load test
# ---------------------------------------------------------------------------


class TestProtocolLoggerLogConfig:
    def test_log_config_returns_logging_config(self, logger):
        cfg = logger.log_config
        assert isinstance(cfg, LoggingConfig)

    def test_log_config_is_cached(self, logger):
        cfg1 = logger.log_config
        cfg2 = logger.log_config
        assert cfg1 is cfg2


# ---------------------------------------------------------------------------
# add_logfile test
# ---------------------------------------------------------------------------


class TestProtocolLoggerAddLogfile:
    def test_add_logfile_method_exists(self, logger):
        assert callable(logger.add_logfile)

    def test_add_logfile_adds_rotating_handler(self, logger, tmp_path):
        log_path = str(tmp_path / "test.log")
        logger.add_logfile(log_path)
        handler_types = [type(h).__name__ for h in logger.logger.handlers]
        assert "RotatingFileHandler" in handler_types
        # Cleanup
        for h in logger.logger.handlers[:]:
            if hasattr(h, "baseFilename"):
                h.close()
                logger.logger.removeHandler(h)
