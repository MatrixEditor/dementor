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
import argparse

from abc import ABC
from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:
    from dementor.tui.repl import Repl

_AT = TypeVar("_AT", bound="ReplAction")

REPL_COMMANDS: dict[str, type["ReplAction"]] = {}


class ReplAction(ABC):
    names: list[str]

    def __init__(self, repl: "Repl") -> None:
        super().__init__()
        self.repl: "Repl" = repl

    def get_parser(self) -> argparse.ArgumentParser | None:
        return None

    def execute(self, argv: argparse.Namespace) -> None:
        pass


def command(cls: type[_AT]) -> type[_AT]:
    names: list[str] | None = getattr(cls, "names", None)
    if not names:
        REPL_COMMANDS[cls.__name__] = cls
    else:
        for alias in names:
            REPL_COMMANDS[alias] = cls
    return cls
