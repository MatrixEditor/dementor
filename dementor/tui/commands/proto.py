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
# pyright: reportAny=false, reportExplicitAny=false, reportUnusedCallResult=false
import argparse
import rich.markup
import shlex

from typing import TYPE_CHECKING, Any
from typing_extensions import override

from rich.tree import Tree
from rich.panel import Panel
from rich.columns import Columns
from rich.prompt import Prompt
from prompt_toolkit.document import Document

from dementor.config.util import is_true, BytesValue
from dementor.config.toml import TomlConfig, Attribute
from dementor.loader import ProtocolManager, BaseProtocolModule
from dementor.tui.action import command, ReplAction

if TYPE_CHECKING:
    from rich.console import Console

ON = r"[bold green]\[ON][/bold green]"
OFF = r"[bold red]\[OFF][/bold red]"


@command
class ServiceCommand(ReplAction):
    """Command implementation for managing protocol services.

    This class is registered under the name proto and provides the
    sub-commands on/start, off/stop and status.  The
    status command can be invoked with a specific protocol name to show a
    detailed view or without a name to list all services.
    """

    names: list[str] = ["proto"]

    def get_proto_parser(self) -> argparse.ArgumentParser:
        """Create an :class:`argparse.ArgumentParser` for the proto command.

        The parser description contains a comma-separated list of currently
        available protocol names.  Sub-commands are attached a fn attribute
        that points to the concrete method handling the action; this attribute
        is later used by :meth:`execute`.

        :return: Configured argument parser.
        :rtype: argparse.ArgumentParser
        """
        # Available protocol names (lower-case) for the help text
        names = [name.lower() for name in self.repl.session.manager.threads]
        parser = argparse.ArgumentParser(
            prog="proto <name>",
            description="Available protocols: \n - " + ", ".join(names),
            formatter_class=argparse.RawTextHelpFormatter,
        )
        subs = parser.add_subparsers(required=True, title="sub-commands")

        off_parser = subs.add_parser(
            "off",
            aliases=["stop"],
            help="Terminate the specified protocol service.",
        )
        off_parser.add_argument(
            "-y",
            "--yes",
            action="store_true",
            help="Skip confirmation prompt and stop immediately.",
        )
        off_parser.set_defaults(fn=self.service_stop)

        on_parser = subs.add_parser(
            "on",
            aliases=["start"],
            help="Start the specified protocol service.",
        )
        on_parser.set_defaults(fn=self.service_start)

        status_parser = subs.add_parser(
            "status",
            help="Display the current status of the given protocol service.",
        )
        status_parser.set_defaults(fn=self.service_status)

        # config sub-command for runtime server configuration
        config_parser = subs.add_parser(
            "config",
            help="Inspect or modify runtime configuration of protocol server threads.",
        )
        config_parser.add_argument(
            "key",
            metavar="KEY[+][=VALUE]",
            type=str,
            nargs="?",
            help="Configuration key (optionally prefixed with thread index, e.g., '0.smtp_port').",
        )
        config_parser.set_defaults(fn=self.service_config)

        # reload sub-command
        reload_parser = subs.add_parser(
            "reload",
            help="Reload the specified protocol service (stop, reload module, recreate threads, start).",
        )
        reload_parser.set_defaults(fn=self.service_reload)
        return parser

    @override
    def execute(self, argv: argparse.Namespace) -> None:
        """Entry point invoked by the REPL for the proto command.

        argv.args_raw holds the arguments following the proto keyword.
        When no protocol name is supplied an error message is shown.  Supplying
        status without additional arguments triggers a full service list.

        :param argv: Parsed arguments from the REPL.
        :type argv: argparse.Namespace
        """
        args_raw: list[str] = list(argv.args_raw)
        if not args_raw:
            self.repl.console.print("[bold red]Service name must be specified[/]")
            self.get_proto_parser().print_usage()
            return

        name, *args = args_raw
        # proto status (no further args) lists all services
        if name.lower() == "status" and not args:
            self.service_status_all()
            return

        parser = self.get_proto_parser()
        parsed = parser.parse_args(args)
        # fn was attached by get_service_parser
        if name.lower() not in self.repl.session.manager.protocols:
            self.repl.console.print(f"[bold yellow]Unknown service name: {name!r}[/]")
        else:
            parsed.fn(name, parsed)

    def service_stop(self, name: str, argv: argparse.Namespace) -> None:
        """Stop a running protocol service.

        Prompts the user for confirmation unless the --yes flag is set.

        :param name: Protocol name (case-insensitive).
        :type name: str
        :param argv: Parsed arguments; argv.yes bypasses the prompt.
        :type argv: argparse.Namespace
        """
        manager: ProtocolManager = self.repl.session.manager
        if not manager.is_running(name):
            self.repl.console.print(f"[bold yellow]No servers running for {name}![/]")
            return

        confirmed = (
            argv.yes
            or Prompt.ask(
                f"Do you want to stop the {name.upper()} service?",
                choices=["y", "n"],
            ).lower()
            == "y"
        )
        if not confirmed:
            return

        # Initialise spinner for shutdown
        status = self.repl.console.status(
            f"[bold red]Shutting down...[/bold red] ([dim]{name}[/])",
            spinner="aesthetic",
            spinner_style="red",
        )
        if not self.repl.session.debug:
            status.start()

        manager.stop(name)
        status.stop()

    def service_status(
        self, name: str, argv: argparse.Namespace | None = None, details: bool = True
    ) -> None:
        """Print the status of a single protocol service.

        When details is True a tree view with address/port information
        for each thread is rendered; otherwise a compact ON/OFF line is
        printed.

        :param name: Protocol name.
        :type name: str
        :param argv: Unused placeholder for compatibility with the parser.
        :type argv: argparse.Namespace | None
        :param details: Whether to show a detailed tree view.
        :type details: bool
        """
        console: Console = self.repl.console
        manager: ProtocolManager = self.repl.session.manager
        protocol = manager.protocols[name.lower()]
        tasks = self.repl.session.manager.threads[name.lower()]
        active_tasks = [t for t in tasks or [] if t.is_running()]

        label = f"{name.upper()} [white]".ljust(50, ".")
        if not details:
            console.print(label, ON if active_tasks else OFF, end="")
            if len(active_tasks) > 1:
                console.print(f" ({len(active_tasks)})")
            else:
                console.print()
        else:
            label = f"[bold]{name.upper()}[/]"
            if protocol.poisoner:
                label = f"{label} ([bold blue]Poisoner[/])"

            tree = Tree(label)
            for thread in tasks or []:
                active = thread.is_running()
                if not active:
                    label = "<stopped> [white]".ljust(50, ".")
                else:
                    addr, port = thread.get_address(), thread.get_port()
                    label = f"{addr}:{port} [white]".ljust(50, ".")
                _ = tree.add(f"{label} {ON if active else OFF}")

            console.print(tree)

    def service_reload(self, name: str, argv: argparse.Namespace) -> None:
        """Reload a protocol service.

        Stops the service if running, reloads the protocol module via the loader,
        recreates threads and starts the service again.
        """
        manager: ProtocolManager = self.repl.session.manager
        status = self.repl.console.status(
            f"[bold red]Reloading...[/bold red] ([dim]{name}[/])",
            spinner="aesthetic",
            spinner_style="red",
        )
        is_debug: bool = self.repl.session.debug

        if not is_debug:
            status.start()

        try:
            # Stop if running
            if manager.is_running(name):
                status.update(f"[bold red]Stopping services...[/] ([dim]{name}[/])")
                manager.stop(name)
            # Reload protocol module
            # Resolve protocol path and reload using loader
            protocol_path = manager.session.protocols.get(name.lower())
            if protocol_path:
                status.update(f"[bold red]Reloading module...[/] ([dim]{name}[/])")
                # Load fresh module and replace in manager.loader
                new_module = manager.loader.load_protocol(protocol_path)
                # Recreate protocol instance
                # Find protocol class name via __proto__ list
                proto_names = getattr(new_module, "__proto__", [])
                for proto_name in proto_names:
                    proto_ty = getattr(new_module, proto_name, None)
                    if isinstance(proto_ty, type) and issubclass(
                        proto_ty, BaseProtocolModule
                    ):
                        if proto_ty.name.lower() != name.lower():
                            continue

                        # instantiate new protocol
                        proto_instance = proto_ty()
                        # apply config and replace in manager
                        proto_instance.apply_config(manager.session)
                        manager.protocols[proto_instance.name.lower()] = proto_instance
                        break

            status.update(f"[bold red]Starting services...[/] ([dim]{name}[/])")
            # Recreate threads and start
            manager.create_threads(name)
            manager.start(name)
        finally:
            status.stop()

    def service_start(self, name: str, argv: argparse.Namespace) -> None:
        """Start a protocol service if it is not already running.

        A spinner is shown while the service threads are created and started.

        :param name: Protocol name.
        :type name: str
        :param argv: Parsed arguments (currently unused).
        :type argv: argparse.Namespace
        """
        manager: ProtocolManager = self.repl.session.manager
        if manager.is_running(name):
            self.repl.console.print(
                f"[bold yellow]Servers already running for {name}![/]"
            )
            return

        # Initialise spinner for start
        status = self.repl.console.status(
            f"[bold red]Starting...[/bold red] ([dim]{name}[/])",
            spinner="aesthetic",
            spinner_style="red",
        )
        if not self.repl.session.debug:
            status.start()
        try:
            manager.create_threads(name)
            manager.start(name)
        finally:
            status.stop()

    def _list_fields(self, cfg: TomlConfig) -> None:
        """List configurable fields of a TomlConfig instance."""
        fields = [f"[b]{attr.qname}[/]: {attr.attr_name}" for attr in cfg._fields_]
        console = self.repl.console
        console.print(
            Panel(
                Columns(
                    fields,
                    equal=True,
                    padding=(0, 4),
                    expand=False,
                ),
                title="Configurable Fields",
            )
        )

    def service_config(self, name: str, argv: argparse.Namespace) -> None:
        """Inspect or modify runtime server configuration for a protocol.

        Only fields defined in the protocol's ``_fields_`` are editable.
        """
        manager: ProtocolManager = self.repl.session.manager
        console = self.repl.console
        threads = manager.threads.get(name.lower(), [])
        if not threads:
            console.print(f"[bold red]No running servers for {name}![/]")
            return
        # Determine which thread's config to use (default first thread)
        cfg = threads[0].server_config
        key_path: str = argv.key or ""
        # Support optional thread index prefix (e.g., "0.smtp_port") or wildcard '*' to apply to all threads.
        apply_all = False
        if key_path and "." in key_path:
            prefix, rest = key_path.split(".", 1)
            if prefix == "*":
                apply_all = True
                key_path = rest
            elif prefix.isdigit():
                idx = int(prefix)
                if 0 <= idx < len(threads):
                    cfg = threads[idx].server_config
                    key_path = rest
                else:
                    console.print(f"[b red]Server index {idx} out of range for {name}[/]")
                    return
        # If no key specified, list available fields
        if not key_path:
            console.print(f"[b]Active servers[/]: {len(threads)}")
            self._list_fields(cfg)
            return
        # Disallow nested keys - only top-level fields are allowed
        if "." in key_path:
            console.print(
                "[b red]Nested keys are not supported. Use a top-level field name.[/]"
            )
            return
        # Parse key/value
        if "=" in key_path:
            key, raw_value = key_path.split("=", 1)
        else:
            key, raw_value = key_path, None

        cfg_targets = (
            [cfg] if not apply_all else [thread.server_config for thread in threads]
        )
        # Resolve field (case-insensitive) from _fields_
        for i, cfg in enumerate(cfg_targets):
            cfg_fields: list[Attribute] = cfg._fields_
            target_key: str = key.lower()
            field: Attribute | None = next(
                filter(
                    lambda f: (
                        f.qname.lower() == target_key or f.attr_name.lower() == target_key
                    ),
                    cfg_fields,
                ),
                None,
            )
            if field is None:
                console.print(f"[b red]Invalid configuration field: {key}[/]")
                return

            if raw_value is not None:
                # Perform type-aware conversion based on existing value
                # Determine new value based on type of current field in first thread (or cfg)
                def convert(val: Any) -> Any:
                    match val:
                        case bool():
                            return is_true(raw_value)
                        case int():
                            return int(raw_value)
                        case float():
                            return float(raw_value)
                        case bytes():
                            return BytesValue(len(val))(raw_value)
                        case _:
                            return raw_value

                current_val = getattr(cfg, field.attr_name)
                new_val = convert(current_val)
                setattr(cfg, field.attr_name, new_val)
                console.print(f"[b green]Set {i}.{field.qname} = {new_val}[/]")
            else:
                # Display current value (for single config; if apply_all, show first)
                target_cfg = threads[0].server_config if apply_all else cfg
                value = getattr(target_cfg, field.attr_name)
                console.print(
                    Panel(
                        rich.markup.escape(repr(value)),
                        title=field.qname,
                        expand=False,
                    )
                )

    def service_status_all(self) -> None:
        """Display the status of **all** configured protocol services.

        Services are listed alphabetically, with poisoner protocols highlighted
        separately.

        """
        console: Console = self.repl.console
        manager: ProtocolManager = self.repl.session.manager

        poisoners: list[str] = [
            name
            for name, _ in filter(
                lambda pair: pair[1].poisoner, manager.protocols.items()
            )
        ]

        console.print("[b]Poisoners:[/]")
        for name in sorted(poisoners):
            self.service_status(name, details=False)

        console.print("\n[b]Services:[/]")
        for name in sorted(set(manager.protocols) - set(poisoners)):
            self.service_status(name, details=False)

    @override
    def get_completions(self, word: str, document: Document) -> list[str]:
        """Provide completions for protocol name, sub-commands and flags.

        * Token 0 - the command name ``proto`` (already supplied by the REPL).
        * Token 1 - the protocol service name.
        * Token 2 - the sub-command (on/off/status/config/reload).
        * Tokens 3+ - flags/options specific to the chosen sub-command.
        """
        # Split the current line, handling simple quoting.
        try:
            tokens = shlex.split(document.text_before_cursor)
        except Exception:
            tokens = document.text_before_cursor.split()

        # Available protocol names (lower-case).
        services = [name.lower() for name in self.repl.session.manager.threads]
        services.append("status")
        subcommands = ["on", "off", "status", "config", "reload", "start", "stop"]

        # No service name yet - suggest protocol names.
        if len(tokens) <= 1 or (len(tokens) == 2 and word):
            return [s for s in services if s.startswith(word.lower())]

        # Service name provided, suggest sub-commands.
        if len(tokens) == 2 or (len(tokens) == 3 and word):
            return [sc for sc in subcommands if sc.startswith(word)]

        # Sub-command identified - suggest its flags (if any).
        sub = tokens[2]
        flags: dict[str, list[str]] = {
            "off": ["-y", "--yes"],
            "stop": ["-y", "--yes"],
        }
        # Unknown sub-command - fall back to sub-command suggestions.
        if sub not in subcommands:
            return [sc for sc in subcommands if sc.startswith(word)]

        possible = flags.get(sub, [])
        return [f for f in possible if f.startswith(word) and f not in tokens]
