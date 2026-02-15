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
# pyright: basic
import argparse
import shlex
import textwrap

from abc import ABC
from threading import Thread
from rich import markup
from rich.prompt import Prompt
from rich.table import Table
from sqlalchemy import sql
from typing_extensions import TypeVar, override
from rich.console import Console

from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout

from dementor.config.session import SessionConfig
from dementor import __version__
from dementor.config.toml import TomlConfig
from dementor.db.model import Credential, HostInfo
from dementor.loader import ProtocolLoader, ProtocolModule
from dementor.servers import stop_server_thread

_AT = TypeVar("_AT", bound="ReplAction")

REPL_COMMANDS: dict[str, type["ReplAction"]] = {}

ON = r"[bold green]\[ON][/bold green]"
OFF = r"[bold red]\[OFF][/bold red]"


class ReplAction(ABC):
    names: list[str]

    def __init__(self, repl: "Repl") -> None:
        super().__init__()
        self.repl: "Repl" = repl

    def get_parser(self) -> argparse.ArgumentParser | None:
        return None

    def execute(self, argv: argparse.Namespace) -> None:
        pass


def command(cls: type[_AT]) -> type[_AT]:
    names: list[str] | None = getattr(cls, "names", None)
    if not names:
        REPL_COMMANDS[cls.__name__] = cls
    else:
        for alias in names:
            REPL_COMMANDS[alias] = cls
    return cls


class Repl:
    def __init__(
        self,
        session: SessionConfig,
        tasks: dict[str, list[Thread]],
        protocols: dict[str, ProtocolModule],
    ) -> None:
        self.session: SessionConfig = session
        self.tasks: dict[str, list[Thread]] = tasks
        self.console: Console = Console()
        self.protocols: dict[str, ProtocolModule] = protocols
        self.prompt_session: PromptSession[str] = PromptSession()

    def get_prompt(self):
        return [["bold", "dm "], ["", f"({__version__})"], ["", "> "]]

    def run(self) -> None:
        with patch_stdout(raw=True):
            while True:
                try:
                    line = self.prompt_session.prompt(self.get_prompt()).strip()
                    if not line:
                        continue

                    command, *args = shlex.split(line)
                    action_cls = REPL_COMMANDS.get(command)
                    if not action_cls:
                        self.console.print(f"[yellow]Unknown command: {command}[/]")
                        continue

                    action = action_cls(self)
                    parser = action.get_parser()
                    if parser:
                        action.execute(parser.parse_args(args))
                    else:
                        argv = argparse.Namespace(args_raw=args)
                        action.execute(argv)
                except KeyboardInterrupt:
                    pass
                except StopIteration:
                    break
                except SystemExit:
                    pass


@command
class ExitAction(ReplAction):
    """Terminates the current session."""

    names: list[str] = ["exit", "quit", "bye"]

    @override
    def execute(self, argv: argparse.Namespace) -> None:
        raise StopIteration


@command
class HelpAction(ReplAction):
    """Displays the help menu

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
        else:
            console.print(f"[b yellow]No usage available for command: {name}[/]")


@command
class DBAction(ReplAction):
    """Query the database"""

    names: list[str] = ["db"]

    @override
    def get_parser(self) -> argparse.ArgumentParser | None:
        parser = argparse.ArgumentParser(prog="db")
        subs = parser.add_subparsers(required=True)

        mod_get = subs.add_parser("creds")
        mod_get.add_argument("--raw", action="store_true")
        mod_get.add_argument("--credtype", type=str)
        mod_get.set_defaults(fn=self.credentials)

        return parser

    @override
    def execute(self, argv: argparse.Namespace) -> None:
        func = getattr(argv, "fn", None)
        if func:
            func(argv)

    def credentials(self, argv: argparse.Namespace) -> None:
        session: SessionConfig = self.repl.session
        console: Console = self.repl.console

        table = Table()
        table.add_column("When")
        table.add_column("Type")
        table.add_column("Host")
        table.add_column("Username")
        table.add_column("Password/Hash")
        query = sql.select(Credential)
        if argv.credtype:
            query = query.where(Credential.credtype == argv.credtype)

        results = session.db.session.scalars(query).all()
        if len(results) == 0:
            console.print("[b yellow]No credentials captured yet![/]")
            return

        for credential in results:
            name = credential.username
            if credential.domain:
                name = f"{credential.domain}/{name}"

            host_query = sql.select(HostInfo).where(HostInfo.id == credential.host)
            host = session.db.session.scalar(host_query)
            password = str(credential.password or "<EMPTY>")
            host_info = credential.hostname or (
                host.ip or host.hostname if host else ""
            )
            table.add_row(
                markup.escape(credential.timestamp),
                markup.escape(f"{credential.protocol}/{credential.credtype}"),
                markup.escape(host_info),
                markup.escape(name),
                markup.escape(password),
            )
            if argv.raw:
                console.print(
                    f"({credential.timestamp}): {credential.protocol}/{credential.credtype}"
                )
                console.print(f"  Host: {markup.escape(host_info)}")
                console.print(f"  Username: [bold yellow]{markup.escape(name)}[/]")
                console.print(
                    f"  Password/Hash: [bold yellow]{markup.escape(password)}[/]\n"
                )

        if not argv.raw:
            console.print(table)


@command
class ServiceAction(ReplAction):
    """Configure protocol servers"""

    names: list[str] = ["service"]

    def get_service_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(prog=f"service <name>")
        subs = parser.add_subparsers(required=True)

        mod_config = subs.add_parser("config")
        mod_config_subs = mod_config.add_subparsers(required=True)

        mod = mod_config_subs.add_parser("get")
        mod.add_argument("variable", nargs="?")
        mod.set_defaults(fn=self.service_get_attr)

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
                return

        parser = self.get_service_parser()
        argv = parser.parse_args(args)
        argv.fn(name, argv)

    def service_get_attr(self, name: str, argv: argparse.Namespace) -> None:
        session: SessionConfig = self.repl.session
        console: Console = self.repl.console

        config: TomlConfig | list[TomlConfig] | None = getattr(
            session, f"{name.lower()}_config", None
        )
        if config is None:
            return console.print(f"[b red]Unknown service: {name}[/]")

        if not isinstance(config, list):
            console.print("\n" + r"\[[b]" + name.upper() + "[/]]")
            self._print_config(argv.variable, config)
        else:
            if argv.variable and "." not in argv.variable:
                console.print("[bold yellow]Missing server index in variable path![/]")
                return

            if argv.variable:
                num, variable = str(argv.variable).split(".", maxsplit=1)
                try:
                    num = int(num)
                except ValueError:
                    console.print("[b red]First path element must be a valid number[/]")
                    return
            else:
                num, variable = -1, ""
            for i, server_config in enumerate(config):
                if num in (i, -1):
                    console.print("\n" + r"\[[b white]" + f"{i}.{name.upper()}" + "[/]]")
                    self._print_config(variable, server_config)

    def _print_config(self, variable: str | None, config: TomlConfig) -> None:
        for attribute in config._fields_:
            name = attribute.qname
            value = getattr(config, attribute.attr_name, None)
            if not variable or variable.lower() in (
                attribute.qname.lower(),
                attribute.attr_name.lower(),
            ):
                self.repl.console.print(f"{name} = {value!r}")

    def service_stop(self, name: str, argv: argparse.Namespace) -> None:
        tasks = self.repl.tasks
        if name.lower() not in tasks:
            self.repl.console.print(f"[b yellow]No servers running for {name}![/]")
            return

        servers = tasks[name]
        if (
            argv.yes
            or Prompt.ask(
                f"Do you want to stop the {name.upper()} service?",
                choices=["y", "n"],
            ).lower()
            == "y"
        ):
            for server_thread in servers:
                stop_server_thread(server_thread)
                del server_thread
            servers.clear()

    def service_status(self, name: str, argv: argparse.Namespace | None = None) -> None:
        console: Console = self.repl.console
        tasks = self.repl.tasks.get(name)
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
        tasks = self.repl.tasks.get(name)
        active_tasks = [t for t in tasks or [] if t.is_alive()]
        if active_tasks:
            self.repl.console.print(f"[b yellow]Servers already running for {name}![/]")
            return

        status_attr = f"{name.lower()}_enabled"
        if getattr(self.repl.session, status_attr, False) is False:
            setattr(self.repl.session, status_attr, True)

        loader = ProtocolLoader()
        threads = loader.create_servers(self.repl.protocols[name], self.repl.session)
        self.repl.console.print(f"Starting {name.upper()} servers ({len(threads)})")
        self.repl.tasks[name] = threads

        for thread in threads:
            thread.daemon = True
            thread.start()

    def service_status_all(self) -> None:
        for name in self.repl.session.protocols:
            protocol = self.repl.protocols[name]
            if hasattr(protocol, "create_server_threads"):
                self.service_status(name)

