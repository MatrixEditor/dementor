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
# pyright: reportUninitializedInstanceVariable=false, reportUnusedCallResult=false
# pyright: reportAny=false, reportExplicitAny=false
import argparse
import inspect
import logging
import pathlib
import datetime
import sys
import typing

from typing import Any, ClassVar
from logging.handlers import RotatingFileHandler
from typing_extensions import override

from rich.logging import RichHandler
from rich.markup import render

from dementor.config import util
from dementor.config.session import SessionConfig
from dementor.config.toml import TomlConfig, Attribute as A
from dementor.log import dm_print, dm_console

# -------------------------------------------------------------------------
# Global constants
# -------------------------------------------------------------------------
LOG_DEFAULT_TIMEFMT = "%H:%M:%S"


# -------------------------------------------------------------------------
# Configuration wrapper
# -------------------------------------------------------------------------
class LoggingConfig(TomlConfig):
    """
    Configuration holder for the ``[Log]`` section of the ``dementor`` TOML file.

    :ivar log_debug_loggers: Names of loggers that can be switched on when
                            ``--debug`` is used.
    :type log_debug_loggers: list[str]
    :ivar log_dir: Directory where rotating log files are created.
    :type log_dir: str
    :ivar log_enable: Master switch - when ``False`` no file handlers are added.
    :type log_enable: bool
    :ivar log_timestamps: If ``True`` prepend a timestamp to every formatted
                          message.
    :type log_timestamps: bool
    :ivar log_timestamp_fmt: ``datetime.strftime`` format used for the timestamp
                             prefix.
    :type log_timestamp_fmt: str
    """

    _section_: ClassVar[str] = "Log"
    _fields_: ClassVar[list[A]] = [
        A("log_debug_loggers", "DebugLoggers", list),
        A("log_dir", "LogDir", "logs"),
        A("log_enable", "Enabled", True),
        A("log_timestamps", "Timestamps", False),
        A("log_timestamp_fmt", "TimestampFmt", LOG_DEFAULT_TIMEFMT),
    ]

    if typing.TYPE_CHECKING:  # pragma: no cover
        log_debug_loggers: list[str]
        log_dir: str
        log_enable: bool
        log_timestamps: bool
        log_timestamp_fmt: str


def init() -> None:
    """
    Initialise the global logging configuration.

    Called once at application startup.
    """
    debug_parser = argparse.ArgumentParser(add_help=False)
    debug_parser.add_argument("--debug", action="store_true")
    debug_parser.add_argument("--verbose", action="store_true")
    argv, _ = debug_parser.parse_known_args()

    config = TomlConfig.build_config(LoggingConfig)
    loggers = {name: logging.getLogger(name) for name in config.log_debug_loggers}
    for debug_logger in loggers.values():
        debug_logger.disabled = True

    handler = RichHandler(
        console=dm_console,
        rich_tracebacks=False,
        tracebacks_show_locals=False,
        highlighter=None,
        markup=False,
        keywords=[],
        omit_repeated_times=False,
    )
    # Explicitly disable any highlighter - the ProtocolLogger performs its
    # own colour handling.
    handler.highlighter = None  # pyright: ignore[reportAttributeAccessIssue]

    logging.basicConfig(
        format="(%(name)s) %(message)s",
        datefmt="[%X]",
        handlers=[handler],
        encoding="utf-8",
    )

    root_logger = logging.getLogger("root")
    if argv.verbose:
        dm_logger.logger.setLevel(logging.DEBUG)
        root_logger.setLevel(logging.DEBUG)
    elif argv.debug:
        dm_logger.logger.setLevel(logging.DEBUG)
        root_logger.setLevel(logging.DEBUG)
        for debug_logger in loggers.values():
            debug_logger.disabled = False
    else:
        dm_logger.logger.setLevel(logging.INFO)
        root_logger.setLevel(logging.INFO)


# -------------------------------------------------------------------------
# Protocol-aware logger
# -------------------------------------------------------------------------
class ProtocolLogger(logging.LoggerAdapter[Any]):
    """Custom logger adapter for protocol-specific context-aware logging.

    Enhances standard logs with protocol name, host, port, and color-coded prefixes.
    Supports both console output (via `dm_print`) and file logging (via `RotatingFileHandler`).

    :ivar _log_config: Cached `LoggingConfig` instance.
    :vartype _log_config: LoggingConfig
    """

    def __init__(self, extra: dict[str, Any] | None = None) -> None:
        """
        Initialise the adapter.

        :param extra: Dictionary of contextual values that will be merged with
                      per-call ``extra`` mappings.  Typical keys are
                      ``protocol``, ``protocol_color``, ``host`` and ``port``.
        :type extra: dict | None
        """
        super().__init__(logging.getLogger("dementor"), extra or {})
        self._log_config: LoggingConfig | None = None

    # -----------------------------------------------------------------
    # Helper properties
    # -----------------------------------------------------------------
    @property
    def log_config(self) -> LoggingConfig:
        """Lazily load and cache the :class:`LoggingConfig`."""
        if not self._log_config:
            self._log_config = TomlConfig.build_config(LoggingConfig)
        return self._log_config

    def _get_extra(
        self,
        name: str,
        extra: dict[str, Any] | None = None,
        default: Any = None,
    ) -> Any:
        """
        Fetch ``name`` from *extra* or from the adapter's default mapping.

        :param name: Key to look up.
        :type name: str
        :param extra: Per-call extra mapping (may be ``None``).
        :type extra: dict | None
        :param default: Fallback value if the key is missing.
        :type default: Any
        :return: Resolved value.
        :rtype: Any
        """
        value = (self.extra or {}).get(name, default)
        return extra.pop(name, value) if extra else value

    # -----------------------------------------------------------------
    # Accessors used by the formatting helpers
    # -----------------------------------------------------------------
    def get_protocol_name(self, extra: dict[str, Any] | None = None) -> str:
        """
        Return the protocol name (or an empty string).

        :param extra: Optional per-call extra mapping.
        :type extra: dict | None
        :return: Protocol name.
        :rtype: str
        """
        return str(self._get_extra("protocol", extra, ""))

    def get_protocol_color(self, extra: dict[str, Any] | None = None) -> str:
        """
        Return the colour used for the protocol prefix - defaults to ``white``.

        :param extra: Optional per-call extra mapping.
        :type extra: dict | None
        :return: Colour name.
        :rtype: str
        """
        return str(self._get_extra("protocol_color", extra, "white"))

    def get_host(self, extra: dict[str, Any] | None = None) -> str:
        """
        Return the host string (or empty).

        :param extra: Optional per-call extra mapping.
        :type extra: dict | None
        :return: Host.
        :rtype: str
        """
        return str(self._get_extra("host", extra, ""))

    def get_port(self, extra: dict[str, Any] | None = None) -> str:
        """
        Return the port string (or empty).

        :param extra: Optional per-call extra mapping.
        :type extra: dict | None
        :return: Port.
        :rtype: str
        """
        return str(self._get_extra("port", extra, ""))

    # -----------------------------------------------------------------
    # Message formatting ----------------------------------------------
    # -----------------------------------------------------------------
    def format(self, msg: str, **kwargs: Any) -> tuple[str, dict[str, Any]]:
        """Format message with timestamp, protocol, host, and port prefixes.

        Uses `log_timestamps` and `log_timestamp_fmt` from config.

        :param msg: Log message.
        :type msg: str
        :param args: Unused positional args.
        :param kwargs: Contextual metadata (e.g., `host`, `protocol`).
        :return: Formatted message and modified kwargs.
        :rtype: tuple[str, dict[str, Any]]
        """
        ts_prefix = ""
        if self.log_config.log_timestamps:
            # [ is escaped because later the string is passed through rich.
            ts_prefix = r"\["
            now = datetime.datetime.now(tz=datetime.UTC)
            try:
                ts_prefix = (
                    f"{ts_prefix}{now.strftime(self.log_config.log_timestamp_fmt)}] "
                )
            except Exception:  # pragma: no cover - fallback to default format
                ts_prefix = f"{ts_prefix}{now.strftime(LOG_DEFAULT_TIMEFMT)}] "

        if self.extra is None:
            # No context - simply prepend the timestamp (if any) and return.
            return f"{ts_prefix}{msg}", kwargs

        # Build the rich-style prefix: ``[bold colour]PROTOCOL[/] host port``.
        proto = self.get_protocol_name(kwargs)
        host = self.get_host(kwargs) or "<no-host>"
        port = self.get_port(kwargs) or "<no-port>"
        colour = self.get_protocol_color(kwargs)

        formatted = f"{ts_prefix}[bold {colour}]{proto:<10}[/] {host:<25} {port:<6} {msg}"
        return formatted, kwargs

    def format_inline(
        self, msg: str, kwargs: dict[str, Any]
    ) -> tuple[str, dict[str, Any]]:
        """Produce a compact inline representation for convenience methods.

        The format resembles ``(PROTO) (host:port) <direction> message``.

        :param msg: The original log message.
        :type msg: str
        :param kwargs: Mapping that may contain ``protocol``, ``host``,
                       ``port``, ``is_server`` and ``is_client`` flags.
        :type kwargs: dict[str, Any]
        :return: Rendered line and the (potentially mutated) ``kwargs``.
        :rtype: tuple[str, dict[str, Any]]
        """
        proto = self.get_protocol_name(kwargs)
        host = self.get_host(kwargs)
        port = self.get_port(kwargs) or "-"
        is_server = kwargs.pop("is_server", False)
        is_client = kwargs.pop("is_client", False)

        line = msg
        if is_client:
            line = f"C: {line}"
        elif is_server:
            line = f"S: {line}"
        if host:
            line = f"({host}:{port}) {line}"
        if proto:
            line = f"({proto}) {line}"
        return line, kwargs

    @override
    def log(
        self,
        level: int,
        msg: str,
        *args: Any,
        exc_info: Any | None = None,
        stack_info: bool = False,
        **kwargs: Any,
    ) -> None:
        """
        Emit a log record.

        The method first formats the message for *inline* output, then:

        * If the logger is disabled for the supplied ``level`` we still write
          the entry to the file handler(s) via :meth:`_emit_log_entry`.
        * Otherwise the standard ``LoggerAdapter.log`` implementation is used.

        :param level: Logging level (e.g. ``logging.INFO``).
        :type level: int
        :param msg: Log message.
        :type msg: str
        :param args: Positional arguments forwarded to the underlying ``Logger``.
        :type args: tuple
        :param exc_info: Exception info, passed unchanged to ``Logger.log``.
        :type exc_info: Any | None
        :param stack_info: ``True`` to include stack information.
        :type stack_info: bool
        :param kwargs: Additional keyword arguments (e.g. ``protocol``,
                       ``host``) that influence formatting.
        :type kwargs: dict
        """
        msg, kwargs = self.format_inline(msg, kwargs)

        if not self.isEnabledFor(level):
            # Message filtered for console - still persist it.
            return self._emit_log_entry(msg, level, *args, **kwargs)

        return super().log(
            level,
            msg,
            *args,
            exc_info=exc_info,
            stack_info=stack_info,
            stacklevel=2,
            **kwargs,
        )

    # -----------------------------------------------------------------
    # Convenience helpers
    # -----------------------------------------------------------------
    def success(
        self, msg: str, color: str | None = None, *args: Any, **kwargs: Any
    ) -> None:
        """
        Log a successful operation (green ``[+]`` prefix).

        :param msg: Message to display.
        :type msg: str
        :param color: Override the colour used for the ``[+]`` marker.
        :type color: str | None
        :param _args: Positional arguments forwarded to :func:`dm_print`.
        :type _args: typing.Any
        :param _kwargs: Keyword arguments forwarded to :func:`dm_print`.
        :type _kwargs: dict
        :example:
            >>> logger = ProtocolLogger()
            >>> logger.success("Handshake completed")
        """
        colour = color or "green"
        prefix = f"[bold {colour}]" + r"\[+]" + f"[/bold {colour}]"
        msg, kwargs = self.format(f"{prefix} {msg}", **kwargs)
        dm_print(msg, *args, **kwargs)
        self._emit_log_entry(msg, logging.INFO, *args)

    def display(self, msg: str, *args: Any, **kwargs: Any) -> None:
        """
        Log a generic informational message (blue ``[*]`` prefix).

        :param msg: Message to display.
        :type msg: str
        :param _args: Positional arguments forwarded to :func:`dm_print`.
        :type _args: typing.Any
        :param _kwargs: Keyword arguments forwarded to :func:`dm_print`.
        :type _kwargs: dict
        :example:
            >>> logger.display("Waiting for data...")
        """
        prefix = r"[bold blue]\[*][/bold blue]"
        msg, kwargs = self.format(f"{prefix} {msg}", **kwargs)
        dm_print(msg, *args, **kwargs)
        self._emit_log_entry(msg, logging.INFO, *args)

    def highlight(self, msg: str, *args: Any, **kwargs: Any) -> None:
        """
        Render a highlighted line (yellow, bold).

        :param msg: Message to highlight.
        :type msg: str
        :param _args: Positional arguments forwarded to :func:`dm_print`.
        :type _args: typing.Any
        :param _kwargs: Keyword arguments forwarded to :func:`dm_print`.
        :type _kwargs: dict
        """
        msg, kwargs = self.format(f"[bold yellow]{msg}[/yellow bold]", **kwargs)
        dm_print(msg, *args, **kwargs)
        self._emit_log_entry(msg, logging.INFO, *args)

    def fail(self, msg: str, color: str | None = None, *args: Any, **kwargs: Any) -> None:
        """
        Log an error condition (red ``[-]`` prefix).

        :param msg: Error description.
        :type msg: str
        :param color: Override the colour of the ``[-]`` marker.
        :type color: str | None
        :param _args: Positional arguments forwarded to :func:`dm_print`.
        :type _args: typing.Any
        :param _kwargs: Keyword arguments forwarded to :func:`dm_print`.
        :type _kwargs: dict
        """
        colour = color or "red"
        prefix = f"[bold {colour}]" + r"\[-]" + f"[/bold {colour}]"
        msg, kwargs = self.format(f"{prefix} {msg}", **kwargs)
        dm_print(msg, *args, **kwargs)
        self._emit_log_entry(msg, logging.ERROR, *args)

    def _emit_log_entry(self, text: str, level: int = logging.INFO, *args: Any) -> None:
        """Emit log entry to file handler only.

        Strips Rich markup and writes raw text to all file handlers.

        :param text: Formatted message (rich markup may be present).
        :type text: str
        :param level: Logging level - defaults to ``logging.INFO``.
        :type level: int
        :param _args: Positional arguments (kept for compatibility).
        :type _args: typing.Any
        """
        caller = inspect.currentframe().f_back.f_back.f_back
        plain = render(text).plain
        if self.logger.handlers and caller:
            for handler in self.logger.handlers:
                handler.handle(
                    logging.LogRecord(
                        "dementor",
                        level,
                        pathname=caller.f_code.co_filename,
                        lineno=caller.f_lineno,
                        msg=plain,
                        args=args,
                        exc_info=None,
                    )
                )

    # -----------------------------------------------------------------
    # Rotating file support
    # -----------------------------------------------------------------
    def add_logfile(self, log_file_path: str) -> None:
        """Add a rotating file handler for persistent logging.

        Creates log directory if needed. Appends startup metadata to existing files.

        :param log_file_path: Path to log file.
        :type log_file_path: str
        """
        formatter = logging.Formatter(
            "%(asctime)s | %(filename)s:%(lineno)s - %(levelname)s (%(name)s): %(message)s",
            datefmt="[%X]",
        )

        outfile = pathlib.Path(log_file_path)
        file_exists = outfile.exists()

        if not file_exists:
            outfile.parent.mkdir(parents=True, exist_ok=True)
            # Create an empty file atomically
            open(str(outfile), "x").close()

        handler = RotatingFileHandler(
            outfile,
            maxBytes=100_000,
            encoding="utf-8",
        )

        # Write a small header the first time the file is created.
        with handler._open() as fp:  # pylint: disable=protected-access
            now = datetime.datetime.now(tz=datetime.UTC).strftime("%d-%m-%Y %H:%M:%S")
            args = " ".join(sys.argv[1:])
            header = f"[{now}]> LOG_START\n[{now}]> ARGS: {args}\n"
            fp.write(header if not file_exists else f"\n{header}")

        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.info(f"Created log file handler for {log_file_path}")

    @staticmethod
    def init_logfile(session: SessionConfig) -> None:
        """Initialize log file based on global config and session path resolution.

        Called during application startup if logging is enabled.

        :param session: Session configuration containing log directory.
        :type session: SessionConfig
        """
        config = TomlConfig.build_config(LoggingConfig)
        if not config.log_enable:
            return

        log_dir: pathlib.Path = session.resolve_path(config.log_dir or "logs")
        log_dir.mkdir(parents=True, exist_ok=True)

        log_name = f"dm_log-{util.now()}.log"
        dm_logger.add_logfile(str(log_dir / log_name))


# -------------------------------------------------------------------------
# Global logger instance used throughout the package
# -------------------------------------------------------------------------
dm_logger = ProtocolLogger()
"""Global instance of `ProtocolLogger` for application-wide logging.

Used by modules without explicit context (e.g., core startup, utilities).
Context should be added via `extra` or overridden in subclasses.
"""
