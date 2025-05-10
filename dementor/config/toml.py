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
from typing import NamedTuple, Callable, Any

from dementor.config.util import get_value

_LOCAL = object()


class Attribute(NamedTuple):
    attr_name: str
    qname: str
    default_val: Any | None = _LOCAL
    section_local: bool = True
    factory: Callable[[Any], Any] | None = None


class TomlConfig:
    _section_: str | None
    _fields_: list[Attribute]

    def __init__(self, config: dict | None = None) -> None:
        for field in self._fields_:
            self._set_field(
                config or {},
                field.attr_name,
                field.qname,
                field.default_val,
                field.section_local,
                field.factory,
            )

    def __getitem__(self, key: str) -> Any:
        if hasattr(self, key):
            return getattr(self, key)

        for attr in getattr(self, "_fields_", []):
            name = attr.qname
            if "." in name:
                _, name = name.rsplit(".", 1)

            if key == name:
                return getattr(self, attr.attr_name)

        raise KeyError(f"Could not find config with key {key!r}")

    @staticmethod
    def build_config(cls_ty, section: str | None = None) -> Any:
        return cls_ty(get_value(section or cls_ty._section_, key=None, default={}))

    def _set_field(
        self,
        config: dict,
        field_name: str,
        qname: str,
        default_val=None,
        section_local=False,
        factory=None,
    ) -> None:
        # Behaviour:
        #   1. resolve default value:
        #       - If default_val is _LOCAL, there will be no default value
        #       - If self._section_ is present, it will be used to fetch the
        #         defualt value. The name may contain "."
        #   2. Retrieve value from target section
        #   3. Apply value by either
        #       - Calling a function with 'set_<attr_name>', or
        #       - using setattr directly

        section = getattr(self, "_section_", None)
        if "." in qname:
            # REVISIT: section will be overwritten here
            # get section path and target property name
            alt_section, qname = qname.rsplit(".", 1)
        else:
            alt_section = None

        if default_val is not _LOCAL:
            # PRIOROTY list:
            #   1. _section_
            #   2. alternative section in qname
            #   3. variable in dm_config.Globals
            sections = [
                get_value(section or "", key=None, default={}),
                get_value(alt_section or "", key=None, default={}),
            ]
            if not section_local:
                sections.append(get_value("Globals", key=None, default={}))

            for section_config in sections:
                if qname in section_config:
                    default_val = section_config[qname]
                    break

        value = config.get(qname, default_val)
        if value is _LOCAL:
            raise Exception(
                f"Expected '{qname}' in config or section({section}) for {self.__class__.__name__}!"
            )

        if value is default_val and isinstance(value, type):
            # use factory instead of return value
            value = value()

        if factory:
            value = factory(value)

        func = getattr(self, f"set_{field_name}", None)
        if func:
            func(value)
        else:
            setattr(self, field_name, value)
