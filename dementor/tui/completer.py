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
    def __init__(self, repl: "Repl") -> None:
        self.repl: Repl = repl

    def _iter_command_names(self) -> Iterable[str]:
        yield from REPL_COMMANDS.keys()

    @override
    def get_completions(
        self, document: Document, complete_event: CompleteEvent
    ) -> Iterable[Completion]:
        text_before = document.text_before_cursor.lstrip()
        word = document.get_word_before_cursor(WORD=True)
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
