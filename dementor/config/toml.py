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
from typing import ClassVar, NamedTuple, Any, TypeVar
from collections.abc import Callable

from dementor.config.util import get_value

_T = TypeVar("_T", bound="TomlConfig")

# --------------------------------------------------------------------------- #
# Helper sentinel used to differentiate “no default supplied” from “None”.
# --------------------------------------------------------------------------- #
_LOCAL = object()


class Attribute(NamedTuple):
    """
    Metadata describing a single configuration attribute.

    The :class:`TomlConfig` base class uses a list of ``Attribute`` objects
    (``_fields_``) to know how to populate its instance attributes from a TOML
    configuration dictionary.

    :param attr_name: Name of the instance attribute that will receive the value.
    :type attr_name: str
    :param qname: Qualified name of the configuration key.  May contain a dot
        (``"."``) to indicate that the key lives in a *different* configuration
        section.
    :type qname: str
    :param default_val: Default value to fall back to when the key is missing.
        ``_LOCAL`` (a private sentinel) means “no default - the key is required”.
    :type default_val: Any | None, optional
    :param section_local: If ``True`` the key is looked for only in the section
        defined by the concrete subclass (``self._section_``).  If ``False`` the
        ``Globals`` section is also consulted.
    :type section_local: bool, optional
    :param factory: Optional callable that post-processes the raw value (e.g.
        converting a string to ``bytes``).
    :type factory: Callable[[Any], Any] | None, optional
    """

    attr_name: str
    qname: str
    default_val: Any | None = _LOCAL
    section_local: bool = True
    factory: Callable[[Any], Any] | None = None


class TomlConfig:
    """
    Base class for configuration objects that are built from a TOML-derived
    ``dict`` structure.

    Sub-classes must define two class attributes:

    * ``_section_`` - the name of the top-level configuration section that
      contains the values for this type.
    * ``_fields_`` - a list of :class:`Attribute` objects describing how each
      instance attribute is resolved.

    Example
    -------
    >>> class MyConfig(TomlConfig):
    ...     _section_ = "my"
    ...     _fields_ = [
    ...         Attribute("host", "host", default_val="localhost"),
    ...         Attribute("port", "port", default_val=8080, factory=int),
    ...     ]
    >>> cfg = MyConfig({"host": "example.com"})
    >>> cfg.host, cfg.port
    ('example.com', 8080)
    """

    # Sub-classes are expected to provide these attributes.
    _section_: ClassVar[str]
    _fields_: ClassVar[list[Attribute]]

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """
        Initialise the configuration object.

        :param config: Raw configuration dictionary that originates from the
            TOML file; may be ``None`` to indicate an empty configuration.
        :type config: dict[str, Any] | None, optional
        """
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
        """
        Dictionary-style access to configuration attributes.

        The lookup first tries the real attribute name, then falls back to the
        short name extracted from the qualified ``qname`` of each field.

        :param key: Attribute name to retrieve.
        :type key: str
        :raises KeyError: If *key* does not match any known attribute.
        :return: The stored value.
        :rtype: Any
        """
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
    def build_config(cls_ty: type[_T], section: str | None = None) -> _T:
        """
        Factory that builds a concrete ``TomlConfig`` subclass from the global
        configuration.

        :param cls_ty: Concrete subclass of :class:`TomlConfig` to instantiate.
        :type cls_ty: type[_T]
        :param section: Override the subclass' ``_section_`` attribute.  If not
            supplied the subclass' own ``_section_`` is used.
        :type section: str | None, optional
        :raises ValueError: If *section* resolves to ``None``.
        :return: An instantiated configuration object.
        :rtype: _T
        """
        section_name = section or cls_ty._section_
        if not section_name:
            raise ValueError("section cannot be None")

        return cls_ty(get_value(section_name, key=None, default={}))

    # --------------------------------------------------------------------- #
    # Internal helper - resolves a single field according to the rules
    # --------------------------------------------------------------------- #
    def _set_field(
        self,
        config: dict[str, Any],
        field_name: str,
        qname: str,
        default_val: Any | None = None,
        section_local: bool = False,
        factory: Callable[[Any], Any] | None = None,
    ) -> None:
        """
        Resolve and assign a single configuration attribute.

        The resolution algorithm follows three steps:

        1. **Default value** - if ``default_val`` is not the sentinel ``_LOCAL`` the
           method looks for a value in the configuration hierarchy:

           * first in the subclass' ``_section_``,
           * then in an *alternative* section encoded in ``qname`` (everything
             before the last ``"."``), and
           * finally in the ``Globals`` section when ``section_local`` is
             ``False``.

        2. **Actual value** - the value from the caller-provided *config* dict
           overrides the default.

        3. **Post-processing** - optionally run a ``factory`` on the value and
           finally store the value either via a custom ``set_<field_name>`` method
           or directly with ``setattr``.

        :param config: The user-supplied configuration dictionary.
        :type config: dict
        :param field_name: Instance attribute that will receive the value.
        :type field_name: str
        :param qname: Qualified configuration key (may contain a section prefix).
        :type qname: str
        :param default_val: Default value or ``_LOCAL`` sentinel.
        :type default_val: Any, optional
        :param section_local: When ``False`` also search the ``Globals`` section.
        :type section_local: bool, optional
        :param factory: Callable that transforms the raw value.
        :type factory: Callable[[Any], Any] | None, optional
        :raises Exception: If the key is required (``_LOCAL``) but missing.
        """
        section = getattr(self, "_section_", None)
        if "." in qname:
            alt_section, qname = qname.rsplit(".", 1)
        else:
            alt_section = None

        # --------------------------------------------------------------- #
        # Resolve the default value (if any) by walking the hierarchy.
        # --------------------------------------------------------------- #
        if default_val is not _LOCAL:
            # Priority: own section > alternative section > Globals (if allowed)
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

        # ----------------------------------------------------------------- #
        # Pull the actual value from the caller-supplied ``config`` dict,
        # falling back to the default we just resolved.
        # ----------------------------------------------------------------- #
        value = config.get(qname, default_val)
        if value is _LOCAL:
            # ``_LOCAL`` means “required but not supplied”.
            raise Exception(
                f"Expected '{qname}' in config or section({section}) for "
                + f"{self.__class__.__name__}!"
            )

        if value is default_val and isinstance(value, type):
            value = value()

        # Apply any user-supplied conversion ``factory``.
        if factory:
            value = factory(value)

        setter = getattr(self, f"set_{field_name}", None)
        if setter:
            setter(value)
        else:
            setattr(self, field_name, value)
