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
import datetime
import random
import string
import secrets

from typing import Any
from jinja2.sandbox import SandboxedEnvironment

from dementor.config import _get_global_config


_SANDBOX = SandboxedEnvironment()


def get_value(section: str, key: str | None, default=None) -> Any:
    sections = section.split(".")
    config = _get_global_config()
    if len(sections) == 1:
        target = config.get(sections[0], {})
    else:
        target = config
        for section in sections:
            target = target.get(section, {})

    if key is None:
        return target

    return target.get(key, default)


# --- factory methods for attributes ---
def is_true(value: str) -> bool:
    return str(value).lower() in ("true", "1", "on", "yes")


class BytesValue:
    """Parse a configuration value into a fixed-length ``bytes`` object.

    Supports the following input formats (str case):

    - ``"hex:1122334455667788"`` — explicit hex prefix
    - ``"ascii:1337LEET"`` — explicit ASCII prefix
    - ``"1122334455667788"`` — auto-detect hex (when length matches ``2 * self.length``)
    - ``"1337LEET"`` — auto-detect (try hex first, then encode)
    - ``None`` — generate ``self.length`` cryptographically random bytes

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
                    raise ValueError(
                        f"Expected {self.length} bytes, got {len(value)}"
                    )
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
                pass  # not valid hex — fall through

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


def random_value(size: int) -> str:
    return "".join(random.choice(string.ascii_letters) for _ in range(size))


def format_string(value: str, locals: dict[str, Any] | None = None) -> str:
    config = _get_global_config()
    try:
        template = _SANDBOX.from_string(value)
        return template.render(config=config, random=random_value, **(locals or {}))
    except Exception as e:
        # TODO: log that
        return value


def now() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
