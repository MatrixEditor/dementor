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
from typing import Any


import argparse
import inspect
import logging
import pathlib
import datetime
import sys
import typing

from abc import abstractmethod
from logging.handlers import RotatingFileHandler

from rich.logging import RichHandler
from rich.markup import render

from dementor.config import util
from dementor.config.session import SessionConfig
from dementor.config.toml import TomlConfig, Attribute as A
from dementor.log import dm_print, dm_console


class LoggingConfig(TomlConfig):
    _section_ = "Log"
    _fields_ = [
        A("log_debug_loggers", "DebugLoggers", list),
        A("log_dir", "LogDir", "logs"),
        A("log_enable", "Enabled", True),
        A("log_capture_hosts", "CaptureHostsTo", None),
    ]

    if typing.TYPE_CHECKING:
        log_debug_loggers: list[str]
        log_dir: str
        log_enable: bool
        log_capture_hosts: list[str]


def init():
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
        # show_path=False,
    )
    # should be disabled
    handler.highlighter = None
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


class ProtocolLogger(logging.LoggerAdapter):
    def __init__(self, extra=None) -> None:
        super().__init__(logging.getLogger("dementor"), extra or {})

    def _get_extra(self, name: str, extra=None, default=None):
        value = (self.extra or {}).get(name, default)
        return extra.pop(name, value) if extra else value

    def get_protocol_name(self, extra=None) -> str:
        return str(self._get_extra("protocol", extra, ""))

    def get_protocol_color(self, extra=None) -> str:
        return str(self._get_extra("protocol_color", extra, "white"))

    def get_host(self, extra=None) -> str:
        return str(self._get_extra("host", extra, ""))

    def get_port(self, extra=None) -> str:
        return str(self._get_extra("port", extra, ""))

    def format(
        self, msg: str, *args: typing.Any, **kwargs: typing.Any
    ) -> tuple[str, dict[str, Any]]:
        if self.extra is None:
            return f"{msg}", kwargs

        mod = self.get_protocol_name(kwargs)
        host = self.get_host(kwargs) or "<no-host>"
        port = self.get_port(kwargs) or "<no-port>"
        color = self.get_protocol_color(kwargs)
        return (
            f"[bold {color}]{mod:<10}[/] {host:<25} {port:<6} {msg}",
            kwargs,
        )

    def format_inline(
        self, msg: str, kwargs: dict[str, Any]
    ) -> tuple[str, dict[str, Any]]:
        mod = self.get_protocol_name(kwargs)
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

        if mod:
            line = f"({mod}) {line}"
        return line, kwargs

    def log(
        self,
        level: int,
        msg: str,
        *args,
        exc_info: Any | None = None,
        stack_info: bool = False,
        **kwargs,
    ) -> None:
        msg, kwargs = self.format_inline(msg, kwargs)
        if not self.isEnabledFor(level):
            # always emit log entries to the file handler
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

    def success(self, msg: str, color: str | None = None, *args, **kwargs):
        color = color or "green"
        prefix = r"[bold %s]\[+][/bold %s]" % (color, color)
        msg, kwargs = self.format(f"{prefix} {msg}", **kwargs)
        dm_print(msg, *args, **kwargs)
        self._emit_log_entry(msg, *args, **kwargs)

    def display(self, msg: str, *args, **kwargs):
        prefix = r"[bold %s]\[*][/bold %s]" % ("blue", "blue")
        msg, kwargs = self.format(f"{prefix} {msg}", **kwargs)
        dm_print(msg, *args, **kwargs)
        self._emit_log_entry(msg, *args, **kwargs)

    def highlight(self, msg: str, *args, **kwargs):
        msg, kwargs = self.format(f"[bold yellow]{msg}[/yellow bold]", **kwargs)
        dm_print(msg, *args, **kwargs)
        self._emit_log_entry(msg, *args, **kwargs)

    def fail(self, msg: str, color=None, *args, **kwargs):
        color = color or "red"
        prefix = r"[bold %s]\[-][/bold %s]" % (color, color)
        msg, kwargs = self.format(f"{prefix} {msg}", **kwargs)
        dm_print(msg, *args, **kwargs)
        self._emit_log_entry(msg, *args, **kwargs)

    def _emit_log_entry(
        self, text: str, level: int = logging.INFO, *args, **kwargs
    ) -> None:
        caller = inspect.currentframe().f_back.f_back.f_back
        text = render(text).plain
        if len(self.logger.handlers) > 0:  # file handler
            for handler in self.logger.handlers:
                handler.handle(
                    logging.LogRecord(
                        "dementor",
                        level,
                        pathname=caller.f_code.co_filename,
                        lineno=caller.f_lineno,
                        msg=text,
                        args=args,
                        # kwargs=kwargs,
                        exc_info=None,
                    )
                )

    def add_logfile(self, log_file_path: str) -> None:
        formatter = logging.Formatter(
            "%(asctime)s | %(filename)s:%(lineno)s - %(levelname)s (%(name)s): %(message)s",
            datefmt="[%X]",
        )
        outfile = pathlib.Path(log_file_path)
        file_exists = outfile.exists()
        if not file_exists:
            if not outfile.parent.exists():
                outfile.parent.mkdir(parents=True, exist_ok=True)
            open(str(outfile), "x").close()

        handler = RotatingFileHandler(
            outfile,
            maxBytes=100000,
            encoding="utf-8",
        )
        with handler._open() as fp:
            time = datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S")
            args = " ".join(sys.argv[1:])
            line = f"[{time}]> LOG_START\n[{time}]> ARGS: {args}\n"
            if not file_exists:
                fp.write(line)
            else:
                fp.write(f"\n{line}")

        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.info(f"Created log file handler for {log_file_path}")

    @staticmethod
    def init_logfile(session: SessionConfig) -> None:
        config = TomlConfig.build_config(LoggingConfig)
        if not config.log_enable:
            return

        log_dir: pathlib.Path = session.resolve_path(config.log_dir or "logs")
        log_dir.mkdir(parents=True, exist_ok=True)
        log_name = f"dm_log-{util.now()}.log"
        dm_logger.add_logfile(str(log_dir / log_name))


class ProtocolLoggerMixin:
    def __init__(self) -> None:
        self.logger: ProtocolLogger = self.proto_logger()

    @abstractmethod
    def proto_logger(self) -> ProtocolLogger:
        pass


dm_logger = ProtocolLogger()
