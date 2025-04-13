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
import logging
import threading

from abc import abstractmethod

from rich.console import Console
from rich.logging import RichHandler

dm_console = Console(
    soft_wrap=True,
    tab_size=4,
    highlight=False,
    highlighter=None,
)

dm_console_lock = threading.Lock()


def init():
    from dementor.config import get_value

    debug_parser = argparse.ArgumentParser(add_help=False)
    debug_parser.add_argument("--debug", action="store_true")
    debug_parser.add_argument("--verbose", action="store_true")
    argv, _ = debug_parser.parse_known_args()

    loggers = {
        name: logging.getLogger(name) for name in get_value("Log", "DebugLoggers", [])
    }

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

    def format(self, msg, *args, **kwargs):
        if self.extra is None:
            return f"{msg}", kwargs

        module_name = self.extra.get("protocol", self.extra.get("module_name", None))
        host = self.extra.get("host", kwargs.pop("host", "<no-host>"))
        port = self.extra.get("port", kwargs.pop("port", "<no-port>"))
        module_color = self.extra.get(
            "protocol_color", self.extra.get("module_color", "cyan")
        )
        return (
            f"[bold {module_color}]{module_name:<10}[/] {host:<25} {port:<6} {msg}",
            kwargs,
        )

    def success(self, msg, color=None, *args, **kwargs):
        color = color or "green"
        prefix = r"[bold %s]\[+][/bold %s]" % (color, color)
        msg, kwargs = self.format(f"{prefix} [white]{msg}[/white]", **kwargs)
        dm_print(msg, *args, **kwargs)

    def display(self, msg, *args, **kwargs):
        prefix = r"[bold %s]\[*][/bold %s]" % ("blue", "blue")
        msg, kwargs = self.format(f"{prefix} [white]{msg}[/white]", **kwargs)
        dm_print(msg, *args, **kwargs)

    def highlight(self, msg, *args, **kwargs):
        msg, kwargs = self.format(f"[bold yellow]{msg}[/yellow bold]", **kwargs)
        dm_print(msg, *args, **kwargs)

    def fail(self, msg, color=None, *args, **kwargs):
        color = color or "red"
        prefix = r"[bold %s]\[-][/bold %s]" % (color, color)
        msg, kwargs = self.format(f"{prefix} {msg}", **kwargs)
        dm_print(msg, *args, **kwargs)


class ProtocolLoggerMixin:
    def __init__(self) -> None:
        self.logger = self.proto_logger()

    @abstractmethod
    def proto_logger(self) -> ProtocolLogger:
        pass


dm_logger = ProtocolLogger()
