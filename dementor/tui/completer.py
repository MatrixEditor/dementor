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
    2. **Argument completion** - after a command has been entered, the
       completer delegates to that command's own
       :meth:`~dementor.tui.action.ReplAction.get_completions` hook.
    """

    def __init__(self, repl: "Repl") -> None:
        self.repl: Repl = repl

    def _iter_command_names(self) -> Iterable[str]:
        """Yield all command names/aliases registered in ``REPL_COMMANDS``."""
        yield from REPL_COMMANDS.keys()

    # Completer interface ------------------------------------------------------
    @override
    def get_completions(
        self, document: Document, complete_event: CompleteEvent
    ) -> Iterable[Completion]:
        """Yield :class:`prompt_toolkit.completion.Completion` objects.

        The logic mirrors the description in the class docstring.  It works on
        the raw text before the cursor and tries to be tolerant of incomplete
        quoting.
        """
        text_before = document.text_before_cursor.lstrip()
        word = document.get_word_before_cursor(WORD=True)
        # shlex handles quoted arguments correctly; fall back to a plain
        # split if the line has unbalanced quotes (still being typed).
        try:
            tokens = shlex.split(text_before)
        except Exception:
            tokens = text_before.split()

        if not tokens:
            for name in self._iter_command_names():
                if name.startswith(word):
                    yield Completion(name, start_position=-len(word))
            return

        command = tokens[0]
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

        for opt in sorted(completions):
            if opt.startswith(word):
                yield Completion(opt, start_position=-len(word))
