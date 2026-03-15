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
import logging

from typing import TYPE_CHECKING
from typing_extensions import override

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from dementor.tui.action import command, ReplAction
from dementor.config.toml import TomlConfig
from dementor.log.logger import LoggingConfig, dm_logger

if TYPE_CHECKING:
    from dementor.config.session import SessionConfig
    from rich.console import Console


@command
class EnvCommand(ReplAction):
    """Display the current environment configuration of the session."""

    names: list[str] = ["env"]

    @override
    def execute(self, argv: argparse.Namespace) -> None:
        # argv is unused; the command has no options.
        session: SessionConfig = self.repl.session
        console: Console = self.repl.console

        # -----------------------------------------------------------------
        # Network section
        # -----------------------------------------------------------------
        iface = session.interface or "<none>"
        ipv4 = session.ipv4 or "<none>"
        ipv6 = session.ipv6 or "<none>"
        bind_addr = session.bind_address
        ipv6_sup = "[b green]yes[/]" if session.ipv6_support else "[b red]no[/]"

        # -----------------------------------------------------------------
        # Database section - values are optional, provide placeholders.
        # -----------------------------------------------------------------
        db_dialect = session.db.db_engine.dialect.name
        db_path = session.db.db_path

        # -----------------------------------------------------------------
        # Logging configuration - built from the global TOML config.
        # -----------------------------------------------------------------
        log_cfg: LoggingConfig = TomlConfig.build_config(LoggingConfig)
        log_enable = log_cfg.log_enable
        log_dir = session.resolve_path(log_cfg.log_dir) if log_enable else "-"
        effective_level = logging.getLevelName(dm_logger.logger.getEffectiveLevel())

        # -----------------------------------------------------------------
        # General session information.
        # -----------------------------------------------------------------
        mode = "[b grey]Analysis[/]" if session.analysis else "[b red]Attack[/]"
        workspace = session.workspace_path
        proto_cnt = len(session.manager.protocols) if hasattr(session, "manager") else 0

        table = Table.grid(padding=(0, 2))
        table.add_column(justify="right", style="bold", no_wrap=True)
        table.add_column(style="dim")

        # Helper to insert a section header row (underlined key).
        def header(title: str, space: bool = False) -> None:
            if space:
                table.add_row("", "")
            table.add_row(f"[u]{title}[/]", "")

        # Network
        header("Network")
        table.add_row("Interface", iface)
        table.add_row("IPv4", ipv4)
        table.add_row("IPv6", ipv6)
        table.add_row("Bind address", bind_addr)
        table.add_row("IPv6 support", ipv6_sup)

        # Database
        header("Database", space=True)
        table.add_row("Path", str(db_path))
        table.add_row("Dialect", str(db_dialect))

        # Logging
        header("Logging", space=True)
        table.add_row("Enabled", "[b green]yes[/]" if log_enable else "[b red]no[/]")
        if log_enable:
            table.add_row("Log dir", str(log_dir))
        table.add_row("Effective level", str(effective_level))

        # General
        header("General", space=True)
        table.add_row("Mode", mode)
        table.add_row("Workspace", str(workspace))
        table.add_row("Protocols loaded", str(proto_cnt))

        panel = Panel(table, title=Text("Environment", style="bold"), expand=False)
        console.print(panel)
