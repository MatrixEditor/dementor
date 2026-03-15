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
# pyright: basic
"""Top-level utilities for defining REPL actions.

This module provides an abstract base class :class:`ReplAction` that all
interactive commands for the :class:`~dementor.tui.repl.Repl` must inherit from.
It also supplies the :func:`command` decorator used to register concrete
action classes in the global :data:`REPL_COMMANDS` registry.

The design mirrors the command-pattern used throughout the project and enables
dynamic discovery of available commands at runtime.

Typical usage::

    from dementor.tui.action import ReplAction, command


    @command
    class MyCommand(ReplAction):
        '''Implementation of a custom REPL command.'''

        def execute(self, argv): ...

The :func:`command` decorator can also be used with an explicit ``names``
attribute on the class to provide aliases.
"""

import argparse

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, TypeVar

from prompt_toolkit.document import Document

if TYPE_CHECKING:
    from dementor.tui.repl import Repl

_AT = TypeVar("_AT", bound="ReplAction")

# Registry mapping command names to their implementing :class:`ReplAction` subclasses.
REPL_COMMANDS: dict[str, type["ReplAction"]] = {}


class ReplAction(ABC):
    """Abstract base class for all REPL actions.

    Sub-classes represent a single command that can be invoked from the
    interactive REPL.  Each concrete action must implement :meth:`execute`
    and may optionally provide a custom :class:`argparse.ArgumentParser`
    via :meth:`get_parser`.
    """

    names: list[str]

    def __init__(self, repl: "Repl") -> None:
        super().__init__()
        self.repl: Repl = repl

    def get_parser(self) -> argparse.ArgumentParser | None:
        """Return an argument parser for the command.

        Sub-classes may override this method to expose command-line options
        that are parsed before :meth:`execute` is called.  The default
        implementation returns ``None`` which signals that the command does
        not accept any additional arguments.
        """
        return None

    @abstractmethod
    def execute(self, argv: argparse.Namespace) -> None:
        """Execute the command logic.

        Concrete subclasses must implement this method.  The *argv* argument
        contains the parsed result of the parser returned by
        :meth:`get_parser`.  If :meth:`get_parser` returns ``None`` the *argv*
        will be an empty :class:`argparse.Namespace`.
        """

    def get_completions(self, word: str, document: Document) -> list[str]:
        """Return a list of completion strings for the given *word*.

        Sub-classes may override this to provide custom completions.
        The default implementation returns an empty list.
        """
        return []


def command(cls: type[_AT]) -> type[_AT]:
    """Class decorator that registers a REPL action.

    The decorator inspects the ``names`` attribute of the class.  If the
    attribute is missing or empty, the class name is used as the command key.
    Otherwise each entry in ``names`` is treated as an alias.  All keys are
    stored in the global :data:`REPL_COMMANDS` dictionary which maps a command
    string to the implementing class.
    """
    names: list[str] | None = getattr(cls, "names", None)
    if not names:
        REPL_COMMANDS[cls.__name__] = cls
    else:
        for alias in names:
            REPL_COMMANDS[alias] = cls
    return cls
