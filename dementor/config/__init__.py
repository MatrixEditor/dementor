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
import sys
import pathlib
import tomllib
import warnings

from typing import Any

from dementor.paths import CONFIG_PATH, DEFAULT_CONFIG_PATH

# Global configuration storage
dm_config: dict[str, Any]


def get_global_config() -> dict[str, Any]:
    return getattr(sys.modules[__name__], "dm_config", {})


def _set_global_config(config: dict[str, Any]) -> None:
    sys.modules[__name__].dm_config = config  # ty:ignore[unresolved-attribute]


def init_from_file(path: str) -> None:
    """Load a TOML configuration file and merge it into the global config.

    If the file does not exist or is not a regular file the function returns
    silently.
    """
    target = pathlib.Path(path)
    if not target.exists() or not target.is_file():
        return

    # By default we completely replace the existing configuration.
    with target.open("rb") as f:
        new_config = tomllib.load(f)
        _set_global_config(new_config)


def init_config(
    default_path: str | None = None,
    user_path: str | None = None,
) -> None:
    try:
        init_from_file(default_path or DEFAULT_CONFIG_PATH)  # 1. bundled defaults
        init_from_file(user_path or CONFIG_PATH)  # 2. user-provided overrides
    except Exception as exc:  # pragma: no cover
        warnings.warn(
            f"dementor.config: failed to load configuration at startup: {exc}",
            RuntimeWarning,
            stacklevel=1,
        )


init_config()

__all__ = [
    "get_global_config",
    "init_config",
    "init_from_file",
]
