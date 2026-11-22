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
from typing_extensions import override
from collections.abc import Callable
from jinja2.sandbox import SandboxedEnvironment

from dementor.config import get_global_config

_SANDBOX = SandboxedEnvironment()


def get_value(section: str, key: str | None, default: Any | None = None) -> Any:
    """Retrieve a value from the *global* configuration."""
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


def is_true(value: str) -> bool:
    return str(value).lower() in ("true", "1", "on", "yes")


class BytesValue:
    """Parse a configuration value into a fixed-length ``bytes`` object.

    Supports the following input formats (str case):

    - ``"hex:1122334455667788"``  - explicit hex prefix
    - ``"ascii:1337LEET"``  - explicit ASCII prefix
    - ``"1122334455667788"``  - auto-detect hex (when length matches ``2 * self.length``)
    - ``"1337LEET"``  - auto-detect (try hex first, then encode)
    - ``None``  - generate ``self.length`` cryptographically random bytes

    When ``length`` is set, the result is validated to be exactly that many bytes.
    """

    def __init__(self, length: int | None = None) -> None:
        self.length: int | None = length

    def __call__(self, value: Any) -> bytes:
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

        if lowered.startswith("hex:"):
            return bytes.fromhex(stripped[4:].strip())

        if lowered.startswith("ascii:"):
            return stripped[6:].encode("ascii")

        if self.length is not None and len(stripped) == 2 * self.length:
            try:
                candidate = bytes.fromhex(stripped)
                if len(candidate) == self.length:
                    return candidate
            except ValueError:
                pass

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

    DEFAULT: str = "DEMENTOR"
    DNS_COMPUTER: str = "DnsComputer"
    FQDN: str = "FQDN"
    HOST: str = "Host"
    DNS_HOSTNAME: str = "DNSHostName"
    DNS_DOMAIN: str = "DNSDomain"
    DNS_TREE: str = "DNSTree"
    NETBIOS_NAME: str = "NetBIOSName"
    NETBIOS_COMPUTER: str = "NetBIOSComputer"
    NETBIOS_DOMAIN: str = "NetBIOSDomain"

    def __init__(self, value: Any) -> None:
        self._raw: str = str(value).strip() if value is not None else self.DEFAULT
        if "." in self._raw:
            self.hostname, self.domain = self._raw.split(".", 1)
        else:
            self.hostname: str = self._raw
            self.domain: str = ""

    def get_value(self, field: str) -> str:
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
                value = self.domain.lower() if self.domain else "WORKGROUP"
            case _:
                pass
        return value

    @override
    def __str__(self) -> str:
        return self._raw

    def __call__(self, value: Any) -> "HostValue":
        return HostValue(value)


class HostFallbackValue:
    def __init__(
        self,
        field: str,
        fallback: str = "",
        post_factory: Callable[[str], str] | None = None,
    ) -> None:
        self.field: str = field
        self.fallback: str = fallback
        self.post_factory: Callable[[str], str] | None = post_factory

    def __call__(self, value: Any) -> str:
        if value is not None:
            result = str(value)
        else:
            explicit_value = get_value("Globals", self.field, default=None)
            if explicit_value is not None:
                result = str(explicit_value)
            else:
                host = get_value("Globals", "Host", default=None)
                derived = HostValue(host).get_value(self.field) if host else ""
                result = derived or self.fallback
        return self.post_factory(result) if self.post_factory else result


def random_value(size: int) -> str:
    return "".join(random.choice(string.ascii_letters) for _ in range(size))


def format_string(value: str, locals: dict[str, Any] | None = None) -> str:
    """Render a Jinja2 template against the global configuration."""
    config = get_global_config()
    try:
        template = _SANDBOX.from_string(value)
        return template.render(config=config, random=random_value, **(locals or {}))
    except Exception as exc:  # pragma: no cover - defensive fallback
        from dementor.log.logger import dm_logger  # noqa: PLC0415

        dm_logger.debug("Template render failed: %s", exc)
        return value


def now() -> str:
    return datetime.datetime.now(tz=datetime.UTC).strftime("%Y-%m-%d-%H-%M-%S")
