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
import textwrap
import argparse

from typing import TYPE_CHECKING
from typing_extensions import override

from dementor.tui.action import ReplAction, command, REPL_COMMANDS

if TYPE_CHECKING:
    from rich.console import Console

@command
class ExitCommand(ReplAction):
    """Terminates the current session."""

    names: list[str] = ["exit", "quit", "bye"]

    @override
    def execute(self, argv: argparse.Namespace) -> None:
        raise StopIteration


@command
class HelpCommand(ReplAction):
    """Displays the help menu.

    Use 'help <command>' do get detailed information about a supported command.
    """

    names: list[str] = ["help", "?"]

    @override
    def execute(self, argv: argparse.Namespace) -> None:
        if len(argv.args_raw) == 0:
            self.print_help_menu()
        else:
            self.print_help(argv.args_raw[0])

    def print_help_menu(self) -> None:
        console: Console = self.repl.console
        console.print("\n[b]Supported Commands:[/]")
        for action_cls in set(REPL_COMMANDS.values()):
            doc_info = (action_cls.__doc__ or "<missing doc>").splitlines()[0]
            name = "/".join(action_cls.names)
            text = f"{name}[white]"
            console.print(text.ljust(50, "."), doc_info)

    def print_help(self, name: str) -> None:
        console: Console = self.repl.console
        if name not in REPL_COMMANDS:
            console.print(f"[b red]No help available for unknown command: {name}[/]")
            return

        action_cls = REPL_COMMANDS[name]
        if action_cls.__doc__:
            console.print(textwrap.dedent(action_cls.__doc__), "\n")

        parser = action_cls(self.repl).get_parser()
        if parser:
            parser.print_help()
        # else:
        #     console.print(f"[b yellow]No usage available for command: {name}[/]")
