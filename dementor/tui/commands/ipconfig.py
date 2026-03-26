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
from argparse import Namespace
from typing import TYPE_CHECKING
from typing_extensions import override

from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from dementor.tui.action import command, ReplAction

if TYPE_CHECKING:
    from dementor.config.session import SessionConfig
    from rich.console import Console


@command
class IPConfigCommand(ReplAction):
    """Display the current IP configuration of the session.

    Shows IPv4, IPv6 addresses, selected interface, bind address and whether IPv6
    support is enabled. No arguments are required.
    """

    names: list[str] = ["ip", "ipconfig"]

    @override
    def execute(self, argv: Namespace):
        """Print the IP configuration to the REPL console.

        ``argv`` is ignored because this command does not accept any options.
        """
        # Retrieve session and console
        session: SessionConfig = self.repl.session
        console: Console = self.repl.console

        # Gather information
        ipv4 = getattr(session, "ipv4", None)
        ipv6 = getattr(session, "ipv6", None)
        interface = getattr(session, "interface", None)
        bind_addr = session.bind_address
        ipv6_support = session.ipv6_support

        table = Table.grid(padding=(0, 2))
        table.add_column(justify="right", style="bold", no_wrap=True)
        table.add_column(style="dim")

        table.add_row("Interface", interface or "<none>")
        table.add_row("IPv4", ipv4 or "<none>")
        table.add_row("IPv6", ipv6 or "<none>")
        table.add_row("Bind address", bind_addr)
        table.add_row(
            "IPv6 support", "[b green]yes[/]" if ipv6_support else "[b red]no[/]"
        )

        panel = Panel(
            table,
            title=Text("IP Configuration", style="bold"),
            expand=False,
        )
        console.print(panel)
