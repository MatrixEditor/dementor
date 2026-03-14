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
import warnings

from typing import Any

from dementor.config.toml import Attribute


class FilterObj:
    """Represents a filter pattern for matching strings (e.g., hostnames, IPs).

    Supports three pattern types:
    - Literal string match
    - Regular expression (prefixed with `re:`)
    - Glob pattern (prefixed with `g:`), translated to regex (Python 3.13+)

    :param target: Pattern string. May be literal, `re:...`, or `g:...`.
    :type target: str
    :param extra: Optional metadata associated with this filter.
    :type extra: Any, optional
    """

    def __init__(self, target: str, extra: dict[str, Any] | None = None) -> None:
        """Initialize a filter object with pattern and optional metadata.

        Automatically detects pattern type and compiles regex if applicable.

        :param target: Pattern string (literal, `re:regex`, or `g:glob`).
        :type target: str
        :param extra: Additional context or metadata (e.g., source file, rule ID).
        :type extra: Any, optional
        """
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
                warnings.warn(
                    "glob.translate is only available since 3.13, "
                    + "using basic-string instead",
                    stacklevel=2,
                )
                self.pattern = None
            else:
                self.pattern = re.compile(glob.translate(self.target))
        else:
            self.pattern = None

    def matches(self, source: str) -> bool:
        """Check if the source string matches this filter.

        :param source: String to test against the filter.
        :type source: str
        :return: `True` if match, `False` otherwise.
        :rtype: bool

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
    def from_string(target: str, extra: Any | None = None) -> "FilterObj":
        """Create a `FilterObj` from a string pattern.

        :param target: Pattern string.
        :type target: str
        :param extra: Optional metadata.
        :type extra: Any, optional
        :return: Filter object.
        :rtype: FilterObj
        """
        return FilterObj(target, extra)

    @staticmethod
    def from_file(source: str, extra: Any | None) -> list["FilterObj"]:
        """Load multiple filters from a text file (one per line).

        :param source: Path to file containing filter patterns.
        :type source: str
        :param extra: Metadata to attach to each filter.
        :type extra: Any, optional
        :return: List of `FilterObj` instances.
        :rtype: list[FilterObj]
        """
        filters = []
        path = pathlib.Path(source)
        if path.exists() and path.is_file():
            filters = [FilterObj(t, extra) for t in path.read_text("utf-8").splitlines()]
        return filters


def _optional_filter(
    value: list[str | dict[str, Any]] | None,
) -> "Filters | None":
    """Factory function to convert optional config list into `Filters` instance.

    Used with `Attribute` to auto-convert config values. Returns `None` if input is `None`.

    :param value: List of filter specs or `None`.
    :type value: list[str | dict[str, Any]] | None
    :return: `Filters` instance or `None`.
    :rtype: Filters | None
    """
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

    :param value: String to test (e.g., hostname, IP).
    :type value: str
    :param config: Object with optional `targets` and `ignored` attributes (`Filters`).
    :type config: Any
    :return: `True` if value is in scope, `False` otherwise.
    :rtype: bool

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
    """Collection of `FilterObj` instances for matching against multiple patterns.

    Supports loading filters from:
    - Direct string patterns
    - File paths containing patterns (one per line)
    - Config dictionaries with `Target` or `File` keys

    Implements `__contains__` for easy membership testing.

    :ivar filters: List of compiled `FilterObj` instances.
    :vartype filters: list[FilterObj]
    """

    def __init__(self, config: list[str | dict[str, Any]]) -> None:
        """Initialize filters from a configuration list.

        Each item can be:
        - A string: treated as literal or pattern (`re:...`, `g:...`)
        - A dict: with `Target` (pattern) or `File` (path to patterns)

        :param config: List of filter specifications.
        :type config: list[str | dict[str, Any]]

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
                self.filters.append(FilterObj.from_string(filter_config))
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
        """Check if a host matches any filter.

        :param host: String to test.
        :type host: str
        :return: `True` if any filter matches.
        :rtype: bool
        """
        return self.has_match(host)

    def get_matched(self, host: str) -> list[FilterObj]:
        """Return all filters that match the host.

        :param host: String to test.
        :type host: str
        :return: List of matching `FilterObj` instances.
        :rtype: list[FilterObj]
        """
        return list(filter(lambda x: x.matches(host), self.filters))

    def get_first_match(self, host: str) -> FilterObj | None:
        """Return the first matching filter, or `None` if none match.

        :param host: String to test.
        :type host: str
        :return: First matching filter or `None`.
        :rtype: FilterObj | None
        """
        return next(iter(self.get_matched(host)), None)

    def has_match(self, host: str) -> bool:
        """Check if at least one filter matches the host.

        :param host: String to test.
        :type host: str
        :return: `True` if any filter matches.
        :rtype: bool
        """
        return len(self.get_matched(host)) > 0
