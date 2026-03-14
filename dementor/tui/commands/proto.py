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
from rich.prompt import Prompt
from dementor.loader import ProtocolManager
from dementor.config.toml import TomlConfig
from rich.console import Console
from dementor.config.session import SessionConfig
from typing_extensions import override
import argparse


from dementor.tui.action import command, ReplAction


ON = r"[bold green]\[ON][/bold green]"
OFF = r"[bold red]\[OFF][/bold red]"

@command
class ServiceCommand(ReplAction):
    """Configure protocol servers."""

    names: list[str] = ["proto"]

    def get_service_parser(self) -> argparse.ArgumentParser:
        names = [name.lower() for name in self.repl.session.manager.threads]
        parser = argparse.ArgumentParser(
            prog="proto <name>", description=f"Available protocols: {names}"
        )
        subs = parser.add_subparsers(required=True)

        mod = subs.add_parser("off")
        mod.add_argument("-y", "--yes", action="store_true")
        mod.set_defaults(fn=self.service_stop)

        mod = subs.add_parser("on")
        mod.set_defaults(fn=self.service_start)

        mod = subs.add_parser("status")
        mod.set_defaults(fn=self.service_status)
        return parser

    @override
    def execute(self, argv: argparse.Namespace) -> None:
        if not argv.args_raw:
            return self.repl.console.print("[b red]Service name must be specified[/]")

        name, *args = argv.args_raw
        match name.lower():
            case "status":
                self.service_status_all()
                return None

        parser = self.get_service_parser()
        argv = parser.parse_args(args)
        argv.fn(name, argv)

    def service_stop(self, name: str, argv: argparse.Namespace) -> None:
        manager: ProtocolManager = self.repl.session.manager
        if not manager.is_running(name):
            self.repl.console.print(f"[b yellow]No servers running for {name}![/]")
            return

        if (
            argv.yes
            or Prompt.ask(
                f"Do you want to stop the {name.upper()} service?",
                choices=["y", "n"],
            ).lower()
            == "y"
        ):
            status = Console().status(
                f"[bold red]Shutting down...[/bold red] ([dim]{name}[/])",
                spinner="aesthetic",
                spinner_style="red",
            )
            is_debug = self.repl.session.debug
            if not is_debug:
                status.start()

            manager.stop(name)
            if not is_debug:
                status.stop()

    def service_status(self, name: str, argv: argparse.Namespace | None = None) -> None:
        console: Console = self.repl.console
        tasks = self.repl.session.manager.threads.get(name.lower())
        active_tasks = [t for t in tasks or [] if t.is_alive()]
        console.print(
            f"[b]{name.upper()} [/][white]".ljust(50, "."),
            ON if active_tasks else OFF,
            end="",
        )
        if len(active_tasks) > 1:
            console.print(f" ({len(active_tasks)})")
        else:
            console.print()


    def service_start(self, name: str, argv: argparse.Namespace) -> None:
        pass

    def service_status_all(self) -> None:
        for name in sorted(self.repl.session.manager.protocols):
            self.service_status(name)
