# Copyright (c) 2025 MatrixEditor
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
import pathlib

from typing import Any, List
from dementor.config import Attribute as A

class FilterObj:
    def __init__(self, target: str, extra: Any | None = None) -> None:
        self.target = target
        self.extra = extra or {}
        #  pre compute pattern
        if self.target.startswith("re:"):
            self.pattern = re.compile(self.target[3:])
            self.target = self.target[3:]
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


class BlacklistConfigMixin:
    _extra_fields_ = [
        A("ignored", "Ignore", None, section_local=False),
    ]

    def set_ignored(self, value):
        self.ignored = value if value is None else Filters(value)

    def is_ignored(self, host: str):
        return host in self.ignored if self.ignored else False


class WhitelistConfigMixin:
    _extra_fields_ = [
        # REVISIT: document why section_local is False here
        A("targets", "Target", None, section_local=False),
    ]

    def set_targets(self, value):
        self.targets = value if value is None else Filters(value)

    def is_target(self, host: str):
        # will always be a target if no list has been configured
        return host in self.targets if self.targets else True


def in_scope(value: str, config: Any) -> bool:
    if isinstance(config, WhitelistConfigMixin):
        if not config.is_target(value):
            return False

    if isinstance(config, BlacklistConfigMixin):
        if config.is_ignored(value):
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
