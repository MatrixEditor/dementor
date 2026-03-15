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
import sqlalchemy
import argparse
import shlex

from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout
from rich.console import Console

from dementor.log.logger import dm_logger
from dementor.config.session import SessionConfig
from dementor.tui import action
from dementor import __version__
from dementor.db.model import Credential
from dementor.tui.completer import ReplCompleter


class Repl:
    """Main REPL class.

    The REPL (Read-Eval-Print Loop) provides an interactive command-line
    interface for Dementor. It is built on top of :mod:`prompt_toolkit` for
    advanced line editing, history and asynchronous input, and :mod:`rich` for
    coloured output. The loop displays a dynamic prompt that shows the
    application version, the currently selected network interface, the active
    database backend and the number of stored credentials. If debug mode is
    enabled a ``[Debug]`` flag is added.

    The REPL integrates tightly with :class:`~dementor.config.session.SessionConfig`:
    * ``session.db`` gives access to the SQLAlchemy engine and model objects.
    * ``session.loop`` is the asyncio event loop used to run the asynchronous
      ``arun`` coroutine.
    * ``session.interface`` and ``session.debug`` influence the prompt
      appearance.

    The class is deliberately lightweight - it only orchestrates input,
    builds the prompt and delegates all functional work to the action classes.
    This makes it easy to extend the CLI by adding new entries to
    ``action.REPL_COMMANDS`` without modifying the REPL core.

    :param session: The current session configuration providing access to the
                    database, event loop and other runtime options.
    :type session: SessionConfig
    """

    def __init__(
        self,
        session: SessionConfig,
    ) -> None:
        """Create a new REPL instance.

        :param session: The active session configuration.
        :type session: SessionConfig
        """
        self.session: SessionConfig = session
        self.prompt_session: PromptSession[str] = PromptSession(
            completer=ReplCompleter(self)
        )
        self.console: Console = Console()

    def get_prompt(self):
        """Build the prompt parts for the REPL.

        :return: A list of style/segment tuples understood by ``prompt_toolkit``.
        :rtype: list[tuple[str, str]]
        """
        parts: list[tuple[str, str]] = []

        parts.append(("bold", "dm"))
        parts.append(("", "("))
        parts.append(("bold fg:#888888", f"v{__version__}"))
        parts.append(("", ")"))
        if self.session.interface:
            parts.append(("bold", f"@{self.session.interface} "))

        db_mode = self.session.db.db_engine.dialect
        creds = self.session.db.session.scalars(sqlalchemy.select(Credential)).all()
        parts.append(("fg:#888888", "using "))
        parts.append(("bold fg:#00ff00", f"[{db_mode.name}/{len(creds)}] "))

        if self.session.debug:
            parts.append(("bold fg:#4444ff", "[Debug] "))

        parts.append(("", "# "))
        return parts

    def run(self) -> None:
        """Run the REPL synchronously.

        This method starts the asyncio event loop and executes :meth:`arun`.
        """
        self.session.loop.run_until_complete(self.arun())

    def get_placeholder(self) -> list[tuple[str, str]]:
        return [
            (
                "#888888 bg:default noreverse noitalic nounderline noblink",
                "Enter 'help' to see a list of available commands",
            )
        ]

    async def arun(self) -> None:
        """Main asynchronous REPL loop.

        It continuously reads user input, handles interruptions and routes
        commands to the appropriate action classes.
        """
        with patch_stdout(raw=True):
            while True:
                try:
                    line = await self.prompt_session.prompt_async(
                        self.get_prompt(),
                        placeholder=self.get_placeholder(),
                    )
                    line = line.strip()
                    if not line:
                        continue

                    self._handle_line(line)
                except KeyboardInterrupt:
                    pass
                except StopIteration:
                    break
                except SystemExit:
                    pass
                except Exception as e:
                    dm_logger.error(
                        f"Error while interpreting command: {e}",
                        exc_info=self.session.debug,
                    )

    def _handle_line(self, line: str) -> None:
        """Parse and dispatch a single line of user input.

        :param line: The raw command line entered by the user.
        :type line: str
        """
        line = line.strip()
        if not line:
            return

        command, *args = shlex.split(line)
        action_cls = action.REPL_COMMANDS.get(command)
        if not action_cls:
            self.console.print(f"[bold dim yellow]Unknown command: {command}[/]")
            return

        action_obj = action_cls(self)
        parser = action_obj.get_parser()
        if parser:
            action_obj.execute(parser.parse_args(args))
        else:
            argv = argparse.Namespace(args_raw=args)
            action_obj.execute(argv)
