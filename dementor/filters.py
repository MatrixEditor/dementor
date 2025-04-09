import re
import pathlib
import fnmatch

from typing import Any, List


class FilterObj:
    def __init__(self, target: str, extra: Any | None = None) -> None:
        self.target = target
        self.extra = extra or {}
        #  pre compute pattern
        self.pattern = re.compile(fnmatch.translate(self.target))

    def matches(self, source: str) -> bool:
        return self.pattern.match(source) is not None

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
        ("ignored", "Ignore", None),
    ]

    def set_ignored(self, value):
        self.ignored = value if value is None else Filters(value)

    def is_ignored(self, host: str):
        return host in self.ignored if self.ignored else False


class WhitelistConfigMixin:
    _extra_fields_ = [
        ("targets", "Target", None),
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
