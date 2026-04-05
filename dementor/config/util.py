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
import datetime
import random
import string
import secrets

from typing import Any
from collections.abc import Callable
from jinja2.sandbox import SandboxedEnvironment

from dementor.config import get_global_config

# --------------------------------------------------------------------------- #
# Jinja2 sandbox used for safe templating of configuration strings.
# --------------------------------------------------------------------------- #
_SANDBOX = SandboxedEnvironment()


def get_value(section: str, key: str | None, default: Any | None = None) -> Any:
    """
    Retrieve a value from the *global* configuration.

    The function walks a dotted ``section`` path (e.g. ``"http.server"``) and
    returns either the sub-dictionary (when ``key`` is ``None``) or the concrete
    value for ``key``.

    :param section: Section name; may contain ``"."`` to indicate nested tables.
    :type section: str
    :param key: Specific key inside the section, or ``None`` to obtain the whole
        section dictionary.
    :type key: str | None, optional
    :param default: Value returned when *key* is missing.
    :type default: Any, optional
    :return: The requested configuration value or ``default``.
    :rtype: Any
    """
    sections: list[str] = section.split(".")
    config = get_global_config()
    if len(sections) == 1:
        target = config.get(sections[0], {})
    else:
        target = config
        for sec in sections:
            target = target.get(sec, {})
    if key is None:
        return target
    return target.get(key, default)


# --------------------------------------------------------------------------- #
# Simple factories used by :class:`Attribute` definitions.
# --------------------------------------------------------------------------- #
def is_true(value: str) -> bool:
    """
    Convert a string to a boolean using a loose interpretation.

    Recognised truthy values are ``"true"``, ``"1"``, ``"on"``, ``"yes"``
    (case-insensitive).  Anything else evaluates to ``False``.

    :param value: Raw string value.
    :type value: str
    :return: ``True`` for truthy strings, ``False`` otherwise.
    :rtype: bool
    """
    return str(value).lower() in ("true", "1", "on", "yes")


class BytesValue:
    """Parse a configuration value into a fixed-length ``bytes`` object.

    Supports the following input formats (str case):

    - ``"hex:1122334455667788"``  -- explicit hex prefix
    - ``"ascii:1337LEET"``  -- explicit ASCII prefix
    - ``"1122334455667788"``  -- auto-detect hex (when length matches ``2 * self.length``)
    - ``"1337LEET"``  -- auto-detect (try hex first, then encode)
    - ``None``  -- generate ``self.length`` cryptographically random bytes

    When ``length`` is set, the result is validated to be exactly that many bytes.
    """

    def __init__(self, length: int | None = None) -> None:
        """Initialize BytesValue.

        :param length: Desired length for randomly generated tokens when the
            input is ``None``.  If omitted a single byte is generated.
        :type length: int | None, optional
        """
        self.length: int | None = length

    def __call__(self, value: Any) -> bytes:
        """
        Convert *value* to ``bytes``.

        :param value: Input to be converted.
        :type value: Any
        :return: ``bytes`` representation.
        :rtype: bytes
        """
        match value:
            case None:
                return secrets.token_bytes(self.length or 1)
            case str():
                result = self._parse_str(value)
                if self.length is not None and len(result) != self.length:
                    raise ValueError(
                        f"Expected {self.length} bytes, got {len(result)}: {value!r}"
                    )
                return result

            case bytes():
                if self.length is not None and len(value) != self.length:
                    raise ValueError(f"Expected {self.length} bytes, got {len(value)}")
                return value
            case _:
                return self(str(value))

    def _parse_str(self, value: str) -> bytes:
        stripped = value.strip()
        if not stripped:
            raise ValueError("Empty string value")

        lowered = stripped.lower()

        # Preferred explicit prefix forms
        if lowered.startswith("hex:"):
            return bytes.fromhex(stripped[4:].strip())

        if lowered.startswith("ascii:"):
            return stripped[6:].encode("ascii")

        # Auto-detect: try hex first when string length matches 2 * expected bytes
        if self.length is not None and len(stripped) == 2 * self.length:
            try:
                candidate = bytes.fromhex(stripped)
                if len(candidate) == self.length:
                    return candidate
            except ValueError:
                pass  # not valid hex  -- fall through

        # Fallback: when length is known, the auto-detect hex path above
        # already handled the 2*length case; encode directly so that strings
        # like "12345678" are treated as 8 ASCII bytes, not 4 hex bytes.
        # When length is unknown, try hex first for backwards compatibility.
        if self.length is not None:
            return stripped.encode()
        try:
            return bytes.fromhex(stripped)
        except ValueError:
            return stripped.encode()


class HostValue:
    """Parse a host FQDN and derive all host-related configuration values.

    A single ``Host = "HOSTNAME.DOMAIN"`` entry in ``[Globals]`` derives:

    - ``NetBIOSDomainName`` / ``NetBIOSDomain``     -> ``domain.upper()``
    - ``DNSHostName``                               -> ``hostname``
    - ``NetBIOSName``       / ``NetBIOSComputer``   -> ``hostname[:15].upper()``
    - ``DNSDomainName``     / ``DnsDomain``         -> ``domain.lower()``
    - ``DnsComputer``       / ``FQDN``              -> full ``"hostname.domain"``

    :param value: Raw host string, e.g. ``"DC01.contoso.lab"``
    :type value: str
    """

    DEFAULT = "DEMENTOR"

    def __init__(self, value: Any) -> None:
        self._raw = str(value).strip() if value is not None else self.DEFAULT
        if "." in self._raw:
            self.hostname, self.domain = self._raw.split(".", 1)
        else:
            self.hostname = self._raw
            self.domain = ""

    def get_value(self, field: str) -> str:
        """Return the derived configuration value for *field*.

        :param field: Supported field names: ``Host``, ``FQDN``, ``DnsComputer``,
            ``DNSHostName``, ``NetBIOSName``, ``NetBIOSComputer``,
            ``NetBIOSDomainName``, ``NetBIOSDomain``, ``DNSDomainName``,
            ``DnsDomain``, ``DnsTree``.
        :type field: str
        :return: Derived string value.
        :rtype: str
        """
        value: str = self.hostname
        match field:
            case "Host" | "FQDN":
                value = self._raw
            case "DnsComputer":
                # Full FQDN when a domain is present; empty (omit AV_PAIR) otherwise
                value = self._raw if self.domain else ""
            case "DNSHostName":
                value = self.hostname
            case "NetBIOSName" | "NetBIOSComputer":
                value = self.hostname[:15].upper()
            case "NetBIOSDomainName" | "NetBIOSDomain":
                value = self.domain.upper() if self.domain else "WORKGROUP"
            case "DNSDomainName" | "DnsDomain" | "DnsTree":
                value = self.domain.lower() if self.domain else ""
            case _:
                pass
        return value

    def __str__(self) -> str:
        return self._raw

    def __call__(self, value: Any) -> "HostValue":
        """Allow a :class:`HostValue` instance to serve as a factory callable."""
        return HostValue(value)


class HostDerivedValue:
    """Attribute factory that derives a single host-related field from ``Globals.Host``.

    Used as the ``factory`` parameter for :class:`~dementor.config.toml.Attribute`
    definitions.  Resolution rules:

    - If the Attribute resolved a concrete value from any config section, that
      value is returned as-is (after an optional *post_factory* transform).
    - If the Attribute resolved ``None`` (the key was not found anywhere), the
      value is derived lazily from :func:`get_host_value`.

    This removes the need to pre-populate ``[Globals]`` with derived keys — each
    Attribute is self-contained and derives its identity on first access by
    receiving the raw ``Host`` value resolved by the Attribute system.

    When you instead need the full priority chain (explicit field -> fallback to
    Host derivation), use :class:`HostFallbackValue` with the field's own qname.

    :param field: The :class:`HostValue` field to derive (e.g. ``"FQDN"``,
        ``"NetBIOSComputer"``).
    :type field: str
    :param fallback: Hard-coded last-resort value when neither an explicit config
        value nor a usable ``Globals.Host`` is available.
    :type fallback: str
    :param post_factory: Optional callable applied *after* the value has been
        resolved or derived.  Useful for chaining with e.g.
        :func:`format_string` for template expansion.
    :type post_factory: Callable[[str], str] | None
    """

    def __init__(
        self,
        field: str,
        fallback: str = "",
        post_factory: Callable[[str], str] | None = None,
    ) -> None:
        self.field = field
        self.fallback = fallback
        self.post_factory = post_factory

    def __call__(self, value: Any) -> str:
        """Resolve *value* or derive from ``Globals.Host``.

        :param value: Raw value resolved by the Attribute system, or ``None``
            when no configuration key matched.
        :type value: Any
        :return: Final string value for the configuration attribute.
        :rtype: str
        """
        if value is None:
            result = self.fallback
        else:
            result = HostValue(value).get_value(self.field) or self.fallback
        return self.post_factory(result) if self.post_factory else result


class HostFallbackValue:
    """Attribute factory that applies an explicit-first, Host-derived fallback strategy.

    Resolution order when used as an :class:`~dementor.config.toml.Attribute`
    factory:

    1. Any explicit value resolved by the Attribute system (e.g.
       ``[Server].FQDN``, ``[Protocol].FQDN``, ``[Globals].FQDN``) — returned
       as-is.
    2. When the resolved value is ``None`` (nothing set anywhere): derive the
       field from ``Globals.Host`` via :class:`HostValue`.
    3. When ``Globals.Host`` is also absent: return *fallback*.

    Unlike :class:`HostDerivedValue` (which always parses the input through
    :class:`HostValue` and is used with ``qname="Host"``), this class treats
    explicit values as opaque strings and invokes :class:`HostValue` derivation
    only as a last resort.  Use this with the actual field's own ``qname``
    (e.g. ``"FQDN"``, ``"NetBIOSComputer"``) so that each value can be
    configured independently before Host derivation kicks in.

    :param field: :class:`HostValue` field used for Host-based derivation
        (e.g. ``"FQDN"``, ``"NetBIOSComputer"``).
    :type field: str
    :param fallback: Hard-coded last-resort value.
    :type fallback: str
    :param post_factory: Optional callable applied after the value is resolved
        or derived.  Useful for chaining with e.g. :func:`format_string`.
    :type post_factory: Callable[[str], str] | None
    """

    def __init__(
        self,
        field: str,
        fallback: str = "",
        post_factory: Callable[[str], str] | None = None,
    ) -> None:
        self.field = field
        self.fallback = fallback
        self.post_factory = post_factory

    def __call__(self, value: Any) -> str:
        """Resolve *value* with explicit-first, Host-derived fallback.

        :param value: Raw value from the Attribute system, or ``None`` when no
            configuration key matched.
        :type value: Any
        :return: Final string value.
        :rtype: str
        """
        if value is not None:
            result = str(value)
        else:
            host = get_value("Globals", "Host", default=None)
            derived = HostValue(host).get_value(self.field) if host else ""
            result = derived or self.fallback
        return self.post_factory(result) if self.post_factory else result


def random_value(size: int) -> str:
    """
    Produce a random alphabetic string of *size* characters.

    :param size: Number of characters.
    :type size: int
    :return: Random string.
    :rtype: str
    """
    return "".join(random.choice(string.ascii_letters) for _ in range(size))


def format_string(value: str, locals: dict[str, Any] | None = None) -> str:
    """
    Render a Jinja2 template against the global configuration.

    The function creates a sandboxed Jinja2 environment (see
    :mod:`jinja2.sandbox`) and renders *value* with the following global
    variables available:

    * ``config`` - the complete global configuration dictionary.
    * ``random`` - a helper that calls :func:`random_value`.
    * any key/value pairs supplied via the optional *locals* mapping.

    Errors during rendering are caught; the original *value* is returned
    unchanged.

    :param value: Template string to render.
    :type value: str
    :param locals: Additional context variables for the template.
    :type locals: dict[str, Any] | None, optional
    :return: Rendered string or the original *value* on failure.
    :rtype: str
    """
    config = get_global_config()
    try:
        template = _SANDBOX.from_string(value)
        return template.render(config=config, random=random_value, **(locals or {}))
    except Exception as exc:  # pragma: no cover - defensive fallback
        from dementor.log.logger import dm_logger  # noqa: PLC0415

        dm_logger.debug("Template render failed: %s", exc)
        return value


def now() -> str:
    """
    Return the current time formatted as ``YYYY-MM-DD-HH-MM-SS``.

    :return: Formatted timestamp.
    :rtype: str
    """
    return datetime.datetime.now(tz=datetime.UTC).strftime("%Y-%m-%d-%H-%M-%S")
