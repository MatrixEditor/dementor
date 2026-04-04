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
import json
import argparse
import sqlalchemy
import shlex

from pathlib import Path
from rich import markup
from rich.table import Table

from typing import TYPE_CHECKING
from prompt_toolkit.document import Document
from typing_extensions import override

from dementor.db import _CLEARTEXT
from dementor.tui.action import command, ReplAction
from dementor.db.model import Credential, HostInfo, HostExtra

if TYPE_CHECKING:
    from dementor.config.session import SessionConfig
    from rich.console import Console


@command
class DBCommand(ReplAction):
    """Query the database for captured credentials and host information.

    This command provides subcommands to interact with the database,
    including listing credentials and displaying host information.
    """

    names: list[str] = ["db"]

    @override
    def get_parser(self) -> argparse.ArgumentParser | None:
        """Create and return the argument parser for database commands."""
        parser = argparse.ArgumentParser(
            prog="db", description="Query the database for various information."
        )
        subs = parser.add_subparsers(required=True)

        mod_get = subs.add_parser("creds", help="List captured credentials.")
        mod_get.add_argument(
            "--raw",
            action="store_true",
            help="Display credentials in raw format instead of table.",
        )
        mod_get.add_argument(
            "--credtype",
            type=str,
            help="Filter by credential type (e.g., Cleartext, ntlm).",
        )
        mod_get.add_argument(
            "index",
            type=int,
            nargs="?",
            help="Display only the credential at this index.",
        )
        mod_get.set_defaults(fn=self.credentials)

        hosts_parser = subs.add_parser("hosts", help="List discovered hosts.")
        hosts_parser.add_argument(
            "--raw",
            action="store_true",
            help="Display hosts in raw format instead of table.",
        )
        hosts_parser.add_argument(
            "index", type=int, nargs="?", help="Display only the host at this index."
        )
        hosts_parser.set_defaults(fn=self.hosts)

        clean_parser = subs.add_parser(
            "clean", help="Remove all entries from the database."
        )
        clean_parser.add_argument(
            "--yes", action="store_true", help="Confirm deletion of all entries."
        )
        clean_parser.set_defaults(fn=self.clean)

        export_parser = subs.add_parser(
            "export", help="Export captured credentials as hashcat-compatible lines."
        )
        export_parser.add_argument(
            "outfile",
            type=Path,
            nargs="?",
            help="Path to the output file where hashcat lines will be written.",
        )
        export_parser.add_argument(
            "--credtype",
            type=str,
            help="Filter by credential type (e.g., Cleartext, NetNTLMv2).",
        )
        export_parser.set_defaults(fn=self.export)
        return parser

    @override
    def execute(self, argv: argparse.Namespace) -> None:
        """Execute the selected subcommand."""
        func = getattr(argv, "fn", None)
        if func:
            func(argv)

    def credentials(self, argv: argparse.Namespace) -> None:
        """Display captured credentials from the database."""
        session: SessionConfig = self.repl.session
        console: Console = self.repl.console

        table = Table()
        table.add_column("Idx")
        table.add_column("Capture Time")
        table.add_column("Type")
        table.add_column("Host")
        table.add_column("Username")
        table.add_column("Password/Hash")
        query = sqlalchemy.select(Credential)
        if argv.credtype:
            query = query.where(Credential.credtype == argv.credtype)

        results = session.db.session.scalars(query).all()
        if len(results) == 0:
            console.print("[b yellow]No credentials captured yet![/]")
            return

        for credential in results:
            if argv.index is not None and credential.id != argv.index:
                continue

            name = credential.username
            if credential.domain:
                name = f"{credential.domain}/{name}"

            host_query = sqlalchemy.select(HostInfo).where(HostInfo.id == credential.host)
            host = session.db.session.scalar(host_query)
            password = str(credential.password or "<EMPTY>")
            host_info = credential.hostname or (host.ip or host.hostname if host else "")
            table.add_row(
                str(credential.id),
                markup.escape(credential.timestamp),
                markup.escape(f"{credential.protocol}/{credential.credtype}"),
                markup.escape(host_info),
                markup.escape(name),
                markup.escape(password),
            )
            if argv.raw:
                console.print(
                    f"([dim grey]{markup.escape(credential.timestamp)}[/]): "
                    f"{credential.protocol}/{credential.credtype}",
                    highlight=False,
                )
                console.print(f"  Host: {markup.escape(host_info)}")
                console.print(f"  Username: [bold yellow]{markup.escape(name)}[/]")
                console.print(
                    f"  Password/Hash: [bold yellow]{markup.escape(password)}[/]\n"
                )

        if not argv.raw:
            console.print(table)

    def hosts(self, argv: argparse.Namespace) -> None:
        """Display discovered hosts from the database."""
        session: SessionConfig = self.repl.session
        console: Console = self.repl.console

        table = Table()
        table.add_column("Idx")
        table.add_column("IP")
        table.add_column("Hostname")
        table.add_column("Domain")
        table.add_column("Extras")
        query = sqlalchemy.select(HostInfo)

        results = session.db.session.scalars(query).all()
        if len(results) == 0:
            console.print("[b yellow]No hosts discovered yet![/]")
            return

        for host in results:
            if argv.index is not None and argv.index != host.id:
                continue

            extras = session.db.session.scalars(
                sqlalchemy.select(HostExtra).where(HostExtra.host == host.id)
            ).all()

            table_extras = []
            for extra in extras:
                document = json.loads(extra.value)
                table_extras.append(f"{extra.key}: {document!r}")

            table.add_row(
                str(host.id),
                markup.escape(host.ip),
                markup.escape(host.hostname or ""),
                markup.escape(host.domain or ""),
                "\n".join(table_extras),
            )
            if argv.raw:
                console.print(f"IP: {markup.escape(host.ip)}")
                if host.hostname:
                    console.print(f"  Hostname: {markup.escape(host.hostname)}")
                if host.domain:
                    console.print(f"  Domain: {markup.escape(host.domain)}")
                console.print()

        if not argv.raw:
            console.print(table)

    def clean(self, argv: argparse.Namespace) -> None:
        """Remove all database entries."""
        session: SessionConfig = self.repl.session
        console: Console = self.repl.console

        db_session = session.db.session
        if not argv.yes:
            console.print("[red]Use --yes to confirm database wipe.[/]")
            return

        try:
            # Create a metadata object
            metadata = sqlalchemy.MetaData()
            # Reflect the database schema
            metadata.reflect(bind=session.db.db_engine)
            # Iterate over all tables and delete all rows
            for table in reversed(metadata.sorted_tables):
                db_session.execute(table.delete())
            db_session.commit()

            console.print("[bold green]Database cleaned.[/]\n")
        except Exception as e:
            db_session.rollback()
            console.print(f"[bold red]Failed to clean database:[/] {e}")

    def export(self, argv: argparse.Namespace) -> None:
        """Export captured credentials in hashcat-compatible format."""
        session: SessionConfig = self.repl.session
        console: Console = self.repl.console

        query = sqlalchemy.select(Credential)
        if argv.credtype:
            query = query.where(Credential.credtype == argv.credtype.lower())

        results = session.db.session.scalars(query).all()
        if not results:
            console.print("[b yellow]No credentials available to export![/]")
            return

        lines: list[str] = []

        for cred in results:
            if not cred.password:
                continue

            username = cred.username or ""
            password = cred.password
            credtype = (cred.credtype or "").lower()

            line = (
                f"{username}:{password}" if credtype == _CLEARTEXT.lower() else password
            )
            lines.append(line)

        if not lines:
            console.print("[b yellow]No exportable credentials found![/]")
            return

        if not argv.outfile:
            console.print("\n".join(map(markup.escape, lines)), highlight=False)
        else:
            try:
                with argv.outfile.open("w", encoding="utf-8") as f:
                    f.write("\n".join(lines))

                console.print(
                    f"[bold green]Exported {len(lines)} credential(s) to[/] {markup.escape(str(argv.outfile))}"
                )
            except Exception as e:
                console.print(f"[bold red]Failed to export credentials:[/] {e}")

    @override
    def get_completions(self, word: str, document: Document) -> list[str]:
        """Provide completions for sub-commands and their options.

        The REPL already supplies the command name (``db``). This method
        suggests the four sub-commands and, once a sub-command is identified,
        offers the relevant ``--`` flags.
        """
        # Split the current line into tokens, handling simple quoting.
        try:
            tokens = shlex.split(document.text_before_cursor)
        except Exception:
            tokens = document.text_before_cursor.split()

        # No sub-command yet - suggest the four possible actions.
        subcommands = ["creds", "hosts", "clean", "export"]
        if len(tokens) <= 1:
            return [sc for sc in subcommands if sc.startswith(word)]

        # Determine which sub-command is being used.
        sub = tokens[1]
        # Map sub-command to its specific flag completions.
        flags: dict[str, list[str]] = {
            "creds": ["--raw", "--credtype"],
            "hosts": ["--raw"],
            "clean": ["--yes"],
            "export": ["--credtype"],
        }
        # If the sub-command is unknown, fall back to sub-command suggestions.
        if sub not in flags:
            return [sc for sc in subcommands if sc.startswith(word)]

        # Provide flag completions for the recognized sub-command.
        return [
            flag for flag in flags[sub] if flag.startswith(word) and flag not in tokens
        ]
