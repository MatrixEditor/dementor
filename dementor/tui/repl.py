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
import argparse
import shlex
import textwrap

from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout
from rich.console import Console

from dementor.config.session import SessionConfig
from dementor.loader import ProtocolModule
from dementor.servers import ServerThread
from dementor.tui import action
from dementor import __version__


class Repl:
    def __init__(
        self,
        session: SessionConfig,
        tasks: list[ServerThread],
        protocols: dict[str, ProtocolModule],
    ) -> None:
        self.session: SessionConfig = session
        self.prompt_session: PromptSession[str] = PromptSession()
        self.tasks: list[ServerThread] = tasks
        self.protocols: dict[str, ProtocolModule] = protocols
        self.console: Console = Console()

    def get_prompt(self):
        return [["bold", "dm "], ["", f"({__version__})"], ["", "> "]]

    def run(self) -> None:
        with patch_stdout(raw=True):
            while True:
                try:
                    line = self.prompt_session.prompt(self.get_prompt()).strip()
                    if not line:
                        continue

                    self._handle_line(line)
                except KeyboardInterrupt:
                    pass
                except StopIteration:
                    break
                except SystemExit:
                    pass

    def _handle_line(self, line: str) -> None:
        line = line.strip()
        if not line:
            return

        command, *args = shlex.split(line)
        action_cls = action.REPL_COMMANDS.get(command)
        if not action_cls:
            self.console.print(f"[yellow]Unknown command: {command}[/]")
            return

        action_obj = action_cls(self)
        parser = action_obj.get_parser()
        if parser:
            action_obj.execute(parser.parse_args(args))
        else:
            argv = argparse.Namespace(args_raw=args)
            action_obj.execute(argv)
