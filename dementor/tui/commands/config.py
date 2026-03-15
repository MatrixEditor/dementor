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
import rich.markup
import argparse

from typing import TYPE_CHECKING, Any
from typing_extensions import override

from rich.tree import Tree
from rich.panel import Panel
from rich.columns import Columns

from dementor.tui.action import command, ReplAction
from dementor.config import get_global_config
from dementor.config.util import is_true


if TYPE_CHECKING:
    from rich.console import Console


@command
class ConfigCommand(ReplAction):
    """Interact with the runtime configuration of the current session.

    Provides commands to view, modify, and list configuration sections.
    """

    names: list[str] = ["config"]

    @override
    def get_parser(self) -> argparse.ArgumentParser | None:
        parser = argparse.ArgumentParser(
            prog="config",
            description="Inspect or modify global session configuration.",
            formatter_class=argparse.RawTextHelpFormatter,
        )
        parser.add_argument(
            "key",
            metavar="KEY[+][=VALUE]",
            type=str,
            nargs="?",
            help="Configuration key to query or modify. Append '+' to add to a list, use '=VALUE' to set.",
        )
        return parser

    @override
    def execute(self, argv: argparse.Namespace) -> None:
        config: dict[str, Any] = get_global_config()
        console: Console = self.repl.console

        if not argv.key:
            # List all top-level configuration sections
            self._list_sections(config, console)
            return

        if "=" in argv.key:
            key, raw_value = argv.key.split("=", 1)
        else:
            key, raw_value = argv.key, None

        # Determine if operation is append (key ends with '+')
        is_append = False
        if key.endswith("+"):
            is_append = True
            key = key[:-1]

        cleaned_key: str = str(key)
        # Resolve the target container and final key/index
        target, final = self._resolve_key_path(config, key)
        if target is None:
            console.print(f"[b red]Invalid configuration key: {cleaned_key}[/]")
            return

        # If a value is provided, perform set/append
        if raw_value is not None:
            if is_append:
                # Append to list at final location
                if isinstance(target, list):
                    target.append(raw_value)
                    console.print(f"[b green]Appended value to {cleaned_key}[/]")
                elif isinstance(target, dict) and isinstance(target.get(final), list):
                    target[final].append(raw_value)
                    console.print(f"[b green]Appended value to {cleaned_key}[/]")
                else:
                    console.print(
                        f"[b red]Target is not a list, cannot append: {cleaned_key}[/]"
                    )
            # Set operation (supports index assignment for lists)
            elif isinstance(target, list) and isinstance(final, int):
                if 0 <= final < len(target):
                    # Preserve type of existing element if possible
                    existing = target[final]
                    new_val = raw_value
                    if isinstance(existing, bool):
                        new_val = is_true(raw_value)
                    elif isinstance(existing, int):
                        new_val = int(raw_value)
                    elif isinstance(existing, float):
                        new_val = float(raw_value)
                    # For other types (e.g., str, bytes), keep raw string
                    target[final] = new_val
                    console.print(f"[b green]Set {cleaned_key} = {new_val}[/]")
                else:
                    console.print(f"[b red]Index out of range for {cleaned_key}[/]")
            elif isinstance(target, dict):
                # Prohibit setting whole sections (dict values)
                existing = target.get(final)
                if isinstance(existing, dict):
                    console.print(
                        f"[b red]Cannot set whole section '{cleaned_key}'. Use specific sub-keys.[/]"
                    )
                else:
                    # Cast to type of existing value if possible
                    new_val = raw_value
                    if isinstance(existing, bool):
                        new_val = is_true(raw_value)
                    elif isinstance(existing, int):
                        new_val = int(raw_value)
                    elif isinstance(existing, float):
                        new_val = float(raw_value)
                    target[final] = new_val
                    console.print(f"[b green]Set {cleaned_key} = {new_val}[/]")
            else:
                console.print(f"[b red]Cannot set value for {cleaned_key}[/]")
        else:
            # Display the current value
            value = None
            if isinstance(target, list) and isinstance(final, int):
                if 0 <= final < len(target):
                    value = target[final]
            elif isinstance(target, dict):
                value = target.get(final)
            self._display_value(key, value, console)

    # ---------------------------------------------------------------------
    # Helper methods
    # ---------------------------------------------------------------------
    def _list_sections(self, config: dict[str, Any], console: "Console") -> None:
        """Display a table of top-level configuration sections.

        :param config: The global configuration dictionary.
        :type config: dict[str, Any]
        :param console: Rich console used for output.
        :type console: Console
        """
        console.print(
            Panel(
                Columns(
                    list(config),
                    equal=True,
                    padding=(0, 4),
                    expand=False,
                ),
                title="Configuration Sections",
            )
        )

    def _resolve_key_path(
        self, config: dict[str, Any], key: str
    ) -> tuple[Any | None, str | int | None]:
        """Resolve a dotted/key-with-index path case-insensitively.

        :param config: Configuration dictionary to search.
        :type config: dict[str, Any]
        :param key: Dotted path or key with optional list index.
        :type key: str
        :return: Tuple ``(container, final)`` where ``container`` is the dict or
                 list holding the target value and ``final`` is the actual key
                 (preserving case) or list index. Returns ``(None, None)`` if
                 resolution fails.
        :rtype: tuple[Any | None, str | int | None]
        """
        # Default result when resolution fails
        result_container: Any | None = None
        result_key: str | int | None = None
        invalid = False

        if not key:
            # Empty key is considered invalid – keep defaults
            invalid = True
        else:
            # Helper for case-insensitive dict lookup returning the actual key
            def ci_lookup(d: dict[str, Any], lookup: str) -> str | None:
                for k in d:
                    if k.lower() == lookup.lower():
                        return k
                return None

            parts = key.split(".")
            current: Any = config
            for i, part in enumerate(parts):
                # Handle list-style syntax: name[idx] or [idx]
                if "[" in part and part.endswith("]"):
                    name, idx_str = part[:-1].split("[", 1)
                    if name:
                        if not isinstance(current, dict):
                            invalid = True
                            break
                        actual_name = ci_lookup(current, name)
                        if actual_name is None:
                            invalid = True
                            break
                        current = current[actual_name]
                    try:
                        idx = int(idx_str)
                    except ValueError:
                        invalid = True
                        break
                    if i == len(parts) - 1:
                        # Final element – return the list and index
                        result_container = current
                        result_key = idx
                        break
                    # Descend into the list element for further traversal
                    if not isinstance(current, list) or idx >= len(current):
                        invalid = True
                        break
                    current = current[idx]
                else:
                    # Plain dictionary key
                    if not isinstance(current, dict):
                        invalid = True
                        break
                    if i == len(parts) - 1:
                        actual_key = ci_lookup(current, part)
                        if actual_key is None:
                            invalid = True
                        else:
                            result_container = current
                            result_key = actual_key
                        break
                    # Intermediate segment – move deeper
                    actual_key = ci_lookup(current, part)
                    if actual_key is None:
                        invalid = True
                        break
                    current = current[actual_key]
        # If resolution failed, ensure both results are None
        if invalid:
            result_container, result_key = None, None
        return result_container, result_key

    def _display_value(self, key: str, value: Any, console: "Console") -> None:
        """Render a configuration value using Rich widgets.

        :param key: The configuration key (used for titles).
        :type key: str
        :param value: The value to display; may be a ``dict``, ``list`` or scalar.
        :type value: Any
        :param console: Rich console for output.
        :type console: Console
        """
        if value is None:
            console.print(f"[b yellow]No value found for '{key}'.[/]")
            return
        if isinstance(value, dict):
            tree = Tree(f"[bold]{key}[/]")
            for k, v in value.items():
                tree.add(f"[b]{k}[/]: {v!r}")
            console.print(tree)
        elif isinstance(value, list):
            panels = [
                Panel(str(item), title=f"[{i}]", expand=False)
                for i, item in enumerate(value)
            ]
            console.print(Columns(panels))
        else:
            console.print(Panel(rich.markup.escape(repr(value)), title=key, expand=False))
