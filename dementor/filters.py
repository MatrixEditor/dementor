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
import re
import sys
import glob
import pathlib
import fnmatch

from typing import Any

from dementor.config.toml import Attribute


class FilterObj:
    """Represents a filter pattern for matching strings (e.g., hostnames, IPs).

    Supports three pattern types:
    - Literal string match
    - Regular expression (prefixed with `re:`)
    - Glob pattern (prefixed with `g:`), translated to regex (Python 3.13+)
    """

    def __init__(self, target: str, extra: dict[str, Any] | None = None) -> None:
        self.target: str = target
        self.extra: dict[str, Any] = extra or {}
        # Determine the concrete matching strategy (regex, glob or plain)
        if self.target.startswith("re:"):
            self.pattern: re.Pattern[str] | None = re.compile(self.target[3:])
            self.target = self.target[3:]
        elif self.target.startswith("g:"):
            self.target = self.target[2:]
            # glob.translate is only available since 3.13
            if (sys.version_info.major, sys.version_info.minor) < (3, 13):
                self.pattern = re.compile(fnmatch.translate(self.target))
            else:
                self.pattern = re.compile(glob.translate(self.target))
        else:
            self.pattern = None

    def matches(self, source: str) -> bool:
        r"""Check if the source string matches this filter.

        Example:
        >>> f = FilterObj("re:.*\\.example\\.com")
        >>> f.matches("api.example.com")
        True
        >>> f = FilterObj("host1")
        >>> f.matches("host1")
        True

        """
        return (
            self.pattern.match(source) is not None
            if self.pattern
            else self.target == source
        )

    @staticmethod
    def from_file(source: str, extra: Any | None) -> list["FilterObj"]:
        filters = []
        path = pathlib.Path(source)
        if path.exists() and path.is_file():
            filters = [FilterObj(t, extra) for t in path.read_text("utf-8").splitlines()]
        return filters


def _optional_filter(
    value: list[str | dict[str, Any]] | None,
) -> "Filters | None":
    return None if value is None else Filters(value)


ATTR_BLACKLIST = Attribute(
    "ignored",
    "Ignore",
    default_val=None,
    section_local=False,
    factory=_optional_filter,
)
"""Attribute definition for blacklist filters.

Maps TOML key `Ignore` to `ignored` attribute. Accepts list of strings or files.
Used to exclude matching targets from processing.

Example TOML:
```toml
[Globals]
Ignore = ["re:.*\\.internal\\.", "g:*.test.*"]
```
"""


ATTR_WHITELIST = Attribute(
    "targets",
    "Targets",
    default_val=None,
    section_local=False,
    factory=_optional_filter,
)
"""Attribute definition for whitelist filters.

Maps TOML key `Targets` to `targets` attribute. Accepts list of strings or files.
Used to restrict processing to only matching targets.

Example TOML:
```toml
[Globals]
Targets = ["192.168.1.100"]
```
"""


def in_scope(value: str, config: Any) -> bool:
    """Determine if a value is allowed based on whitelist and blacklist filters.

    Evaluates filters in order:
    1. If `targets` exists and value is not in it -> `False`
    2. If `ignored` exists and value is in it -> `False`
    3. Otherwise -> `True`

    Example:
    >>> class C:
    ...     pass
    >>> cfg = C()
    >>> cfg.targets = Filters(["host1", "host2"])
    >>> in_scope("host1", cfg)
    True
    >>> in_scope("host3", cfg)
    False
    >>> cfg.ignored = Filters(["host1"])
    >>> in_scope("host1", cfg)
    False

    """
    if hasattr(config, "targets"):
        is_target = value in config.targets if config.targets else True
        if not is_target:
            return False
    if hasattr(config, "ignored"):
        is_ignored = value in config.ignored if config.ignored else False
        if is_ignored:
            return False
    return True


class Filters:
    def __init__(self, config: list[str | dict[str, Any]]) -> None:
        r"""Initialize filters from a configuration list.

        Each item can be:
        - A string: treated as literal or pattern (`re:...`, `g:...`)
        - A dict: with `Target` (pattern) or `File` (path to patterns)

        Example:
        >>> filters = Filters(
        ...     [
        ...         "re:.*\\.example\\.com",
        ...         {"File": "targets.txt"},
        ...         {"Target": "host1", "reason": "admin"},
        ...     ]
        ... )

        """
        self.filters: list[FilterObj] = []
        for filter_config in config:
            if isinstance(filter_config, str):
                # String means simple filter expression without extra config
                if not filter_config:
                    continue
                self.filters.append(FilterObj(filter_config))
            else:
                # must be a dictionary
                # 1. Direct target specification
                target = filter_config.get("Target")
                if target:
                    # target with optional extras
                    self.filters.append(FilterObj(target, filter_config))
                else:
                    # 2. source file with list of targets
                    source = filter_config.get("File")
                    if source is None:
                        # TODO: add logging here
                        # If "File" is missing we silently skip the entry.
                        continue
                    self.filters.extend(FilterObj.from_file(source, filter_config))

    def __contains__(self, host: str) -> bool:
        return self.has_match(host)

    def get_matched(self, host: str) -> list[FilterObj]:
        return list(filter(lambda x: x.matches(host), self.filters))

    def get_first_match(self, host: str) -> FilterObj | None:
        return next(iter(self.get_matched(host)), None)

    def has_match(self, host: str) -> bool:
        return len(self.get_matched(host)) > 0
