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
# pyright: reportAny=false, reportExplicitAny=false
import threading

from typing import Any
from rich.console import Console

dm_console: Console = Console(
    soft_wrap=True,
    tab_size=4,
    highlight=False,
    highlighter=None,
)
"""Rich Console instance for thread-safe terminal output.

Used globally for formatted logging output. Disables automatic highlighting and word wrapping
to ensure consistent rendering across platforms and loggers.

Note: All output should go through `dm_print` to ensure thread safety.
"""

dm_console_lock: threading.Lock = threading.Lock()
"""Threading lock to serialize console output.

Prevents interleaved or corrupted log messages when multiple threads write to `dm_console`
simultaneously (e.g., during concurrent protocol execution).

All `dm_print` calls respect this lock unless explicitly marked `locked=True`.
"""


def dm_print(msg: str, *args: Any, **kwargs: Any) -> None:
    """Thread-safe wrapper for `dm_console.print()`.

    Ensures log messages are printed atomically. If `locked=True` is passed,
    bypasses the lock for internal use (e.g., when already holding the lock).

    :param msg: Message to print (supports Rich markup).
    :type msg: str
    :param args: Positional arguments passed to `Console.print()`.
    :param kwargs: Keyword arguments passed to `Console.print()`.
    :keyword locked: If `True`, skips acquiring `dm_console_lock` (internal use).
    :type locked: bool, optional

    Example:
    >>> dm_print("[bold green]Success![/]", locked=True)

    """
    if kwargs.pop("locked", False):
        dm_console.print(msg, *args, **kwargs)
    else:
        with dm_console_lock:
            dm_console.print(msg, *args, **kwargs)


__all__ = ["dm_console", "dm_console_lock", "dm_print"]
