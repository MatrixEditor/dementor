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
            target = target[section]

    if key is None:
        return target

    return target.get(key, default)


# --- factory methods for attributes ---
def is_true(value: str) -> bool:
    return str(value).lower() in ("true", "1", "on", "yes")


class BytesValue:
    def __init__(self, length=None) -> None:
        self.length = length

    def __call__(self, value) -> Any:
        match value:
            case None:
                return secrets.token_bytes(self.length or 1)

            case str():
                try:
                    return bytes.fromhex(value)
                except ValueError:
                    return value.encode()

            case bytes():
                return value

            case _:
                return str(value).encode()


def random_value(size: int) -> str:
    return "".join(random.choice(string.ascii_letters) for _ in range(size))


def format_string(value: str) -> str:
    config = _get_global_config()
    try:
        template = _SANDBOX.from_string(value)
        return template.render(config=config, random=random_value)
    except Exception as e:
        # TODO: log that
        return value
