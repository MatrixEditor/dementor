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
import re
import sys
import glob
import pathlib
import warnings

from typing import Any, List
from dementor.config.toml import Attribute


class FilterObj:
    def __init__(self, target: str, extra: Any | None = None) -> None:
        self.target = target
        self.extra = extra or {}

        # Patterns can be either regex directly or glob-style
        #  pre compute pattern
        if self.target.startswith("re:"):
            self.pattern = re.compile(self.target[3:])
            self.target = self.target[3:]

        elif self.target.startswith("g:"):
            self.target = self.target[2:]
            # glob.translate is only available since 3.13
            if (sys.version_info.major, sys.version_info.minor) < (3, 13):
                warnings.warn(
                    "glob.translate is only available since 3.13, "
                    "using basic-string instead"
                )
                self.pattern = None
            else:
                self.pattern = re.compile(glob.translate(self.target))

        else:
            self.pattern = None

    def matches(self, source: str) -> bool:
        return (
            self.pattern.match(source) is not None
            if self.pattern
            else self.target == source
        )

    @staticmethod
    def from_string(target: str, extra: Any | None = None):
        return FilterObj(target, extra)

    @staticmethod
    def from_file(source: str, extra: Any | None) -> list:
        filters = []
        path = pathlib.Path(source)
        if path.exists() and path.is_file():
            filters = [
                FilterObj(t, extra) for t in path.read_text("utf-8").splitlines()
            ]

        return filters


def _optional_filter(value):
    return None if value is None else Filters(value)


ATTR_BLACKLIST = Attribute(
    "ignored",
    "Ignore",
    default_val=None,
    section_local=False,
    factory=_optional_filter,
)

ATTR_WHITELIST = Attribute(
    "targets",
    "Target",
    default_val=None,
    section_local=False,
    factory=_optional_filter,
)

def in_scope(value: str, config: Any) -> bool:
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
    def __init__(self, config: List[str | dict]) -> None:
        self.filters = []
        for filter_config in config:
            if isinstance(filter_config, str):
                # String means simple filter expression without extra config
                if not filter_config:
                    continue

                self.filters.append(FilterObj.from_string(filter_config))
            else:
                # must be a dictionary
                # 1. Direct target specification
                target = filter_config.pop("Target", None)
                if target:
                    # target with optional extras
                    self.filters.append(FilterObj(target, filter_config))
                else:
                    # 2. source file with list of targets
                    source = filter_config.pop("File")
                    if source is None:
                        # silently continue
                        continue

                    self.filters.extend(FilterObj.from_file(source, filter_config))

    def __contains__(self, host: str) -> bool:
        return self.has_match(host)

    def get_machted(self, host: str) -> list:
        return list(filter(lambda x: x.matches(host), self.filters))

    def get_first_match(self, host: str) -> FilterObj | None:
        return next(iter(self.get_machted(host)), None)

    def has_match(self, host: str) -> bool:
        return len(self.get_machted(host)) > 0
