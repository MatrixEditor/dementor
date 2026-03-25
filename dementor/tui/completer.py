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
import shlex

from typing_extensions import override
from collections.abc import Iterable
from typing import TYPE_CHECKING

from prompt_toolkit.document import Document
from prompt_toolkit.completion import Completer, Completion, CompleteEvent

from .action import REPL_COMMANDS
from dementor.log.logger import dm_logger

if TYPE_CHECKING:
    from dementor.tui.repl import Repl


class ReplCompleter(Completer):
    """A ``prompt_toolkit`` completer for the interactive REPL.

    The completer works in two stages:

    1. **Command completion** - when the cursor is at the first word of the
       line, it suggests all registered command names from
       :data:`dementor.tui.action.REPL_COMMANDS`.
    2. **Flag completion** - after a command has been entered, the completer
       inspects the command's ``argparse`` parser (if any) and offers the
       defined option strings (e.g. ``--interface``) as completions.

    The goal is to provide a runtime, introspection-based completion experience
    without requiring a static completion file.
    """

    def __init__(self, repl: "Repl") -> None:
        self.repl: Repl = repl

    # Helper -----------------------------------------------------------------
    def _iter_command_names(self) -> Iterable[str]:
        """Yield all command names/aliases registered in ``REPL_COMMANDS``."""
        yield from REPL_COMMANDS.keys()

    def _get_parser_for_command(self, command_name: str):
        """Return the ``argparse.ArgumentParser`` for *command_name* or ``None``.

        The function lazily creates an instance of the action class associated
        with *command_name* and calls its ``get_parser`` method.
        """
        action_cls = REPL_COMMANDS.get(command_name)
        if not action_cls:
            return None
        try:
            action_obj = action_cls(self.repl)
            return action_obj.get_parser()
        except Exception:
            # Guard against actions that require additional runtime state.
            return None

    # Completer interface ------------------------------------------------------
    @override
    def get_completions(self, document: Document, complete_event: CompleteEvent):
        """Yield :class:`prompt_toolkit.completion.Completion` objects.

        The logic mirrors the description in the class docstring.  It works on
        the raw text before the cursor and tries to be tolerant of incomplete
        quoting.
        """
        text_before = document.text_before_cursor.lstrip()
        # Determine the current word to replace.
        word = document.get_word_before_cursor(WORD=True)
        # Split the line into tokens - ``shlex`` is used for proper handling of
        # quoted arguments but we fall back to a simple split if parsing fails.
        try:
            tokens = shlex.split(text_before)
        except Exception:
            tokens = text_before.split()

        # No tokens yet -> suggest command names.
        if not tokens:
            for name in self._iter_command_names():
                if name.startswith(word):
                    yield Completion(name, start_position=-len(word))
            return

        # First token is the command.
        command = tokens[0]
        # After the command - collect completions from the command's hook.
        completions: set[str] = set()
        action_cls = REPL_COMMANDS.get(command)
        if action_cls:
            try:
                action_obj = action_cls(self.repl)
                custom = action_obj.get_completions(word, document)
                completions.update(custom)
            except Exception:
                dm_logger.debug("Failed to get custom completions for %s", command)
        else:
            for name in self._iter_command_names():
                if name.startswith(word):
                    yield Completion(name, start_position=-len(word))

        # Yield matching completions
        for opt in sorted(completions):
            if opt.startswith(word):
                yield Completion(opt, start_position=-len(word))
