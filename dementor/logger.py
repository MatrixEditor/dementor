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
import argparse
import inspect
import logging
import threading
import pathlib
import datetime
import sys

from abc import abstractmethod
from logging.handlers import RotatingFileHandler

from rich.console import Console
from rich.logging import RichHandler
from rich.markup import render

from dementor.config.toml import TomlConfig, Attribute as A

dm_console = Console(
    soft_wrap=True,
    tab_size=4,
    highlight=False,
    highlighter=None,
)

dm_console_lock = threading.Lock()


class LoggingConfig(TomlConfig):
    _section_ = "Log"
    _fields_ = [
        A("log_debug_loggers", "DebugLoggers", list),
        A("log_dir", "LogDir", "logs"),
        A("log_enable", "Enabled", True),
    ]


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


def dm_print(msg, *args, **kwargs) -> None:
    # If someone has a better idea I'll be open for it. This is just
    # a here to synchronize the logging output
    if kwargs.pop("locked", False):
        dm_console.print(msg, *args, **kwargs)
        return

    with dm_console_lock:
        dm_console.print(msg, *args, **kwargs)


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

    def format(self, msg, *args, **kwargs):
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

    def format_inline(self, msg, kwargs):
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

    def log(self, level, msg, *args, exc_info=None, stack_info=False, **kwargs) -> None:
        msg, kwargs = self.format_inline(msg, kwargs)
        return super().log(
            level,
            msg,
            *args,
            exc_info=exc_info,
            stack_info=stack_info,
            stacklevel=2,
            **kwargs,
        )

    def success(self, msg, color=None, *args, **kwargs):
        color = color or "green"
        prefix = r"[bold %s]\[+][/bold %s]" % (color, color)
        msg, kwargs = self.format(f"{prefix} {msg}", **kwargs)
        dm_print(msg, *args, **kwargs)
        self._emit_log_entry(msg, *args, **kwargs)

    def display(self, msg, *args, **kwargs):
        prefix = r"[bold %s]\[*][/bold %s]" % ("blue", "blue")
        msg, kwargs = self.format(f"{prefix} {msg}", **kwargs)
        dm_print(msg, *args, **kwargs)
        self._emit_log_entry(msg, *args, **kwargs)

    def highlight(self, msg, *args, **kwargs):
        msg, kwargs = self.format(f"[bold yellow]{msg}[/yellow bold]", **kwargs)
        dm_print(msg, *args, **kwargs)
        self._emit_log_entry(msg, *args, **kwargs)

    def fail(self, msg, color=None, *args, **kwargs):
        color = color or "red"
        prefix = r"[bold %s]\[-][/bold %s]" % (color, color)
        msg, kwargs = self.format(f"{prefix} {msg}", **kwargs)
        dm_print(msg, *args, **kwargs)
        self._emit_log_entry(msg, *args, **kwargs)

    def _emit_log_entry(self, text, *args, **kwargs) -> None:
        caller = inspect.currentframe().f_back.f_back.f_back
        text = render(text).plain
        if len(self.logger.handlers) > 0:  # file handler
            for handler in self.logger.handlers:
                handler.handle(
                    logging.LogRecord(
                        "dementor",
                        logging.INFO,
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
            open(str(outfile), "x")

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
        self.logger.debug(f"Created log file handler for {log_file_path}")

    @staticmethod
    def init_logfile(session) -> None:
        config = TomlConfig.build_config(LoggingConfig)
        if not config.log_enable:
            return

        workspace = pathlib.Path(session.workspace_path)
        workspace /= config.log_dir or "logs"
        workspace.mkdir(parents=True, exist_ok=True)
        log_name = f"log_{datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S')}.log"
        dm_logger.add_logfile(str(workspace / log_name))


class ProtocolLoggerMixin:
    def __init__(self) -> None:
        self.logger = self.proto_logger()

    @abstractmethod
    def proto_logger(self) -> ProtocolLogger:
        pass


dm_logger = ProtocolLogger()
