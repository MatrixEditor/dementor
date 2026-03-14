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

from typing import Any

from dementor.paths import CONFIG_PATH, DEFAULT_CONFIG_PATH

# --------------------------------------------------------------------------- #
# Global configuration storage
# --------------------------------------------------------------------------- #
dm_config: dict[str, Any]


def get_global_config() -> dict[str, Any]:
    """Return the current global configuration dictionary.

    :return: The configuration mapping, empty if ``init_from_file`` has not
        been called yet.
    :rtype: dict
    """
    return getattr(sys.modules[__name__], "dm_config", {})


def _set_global_config(config: dict[str, Any]) -> None:
    """Replace the current global configuration with *config*.

    The helper mirrors :func:`get_global_config` and writes the value back to
    the module namespace.

    :param config: New configuration dictionary.
    :type config: dict
    """
    sys.modules[__name__].dm_config = config


def init_from_file(path: str) -> None:
    """Load a TOML configuration file and merge it into the global config.

    The function follows a *replace-then-overwrite* strategy: the file at
    *path* is parsed with :mod:`tomllib`.  If the file exists and can be
    read, its content completely replaces the previous ``dm_config`` value.
    The caller is responsible for ordering calls to obtain the desired
    precedence.

    If the file does not exist or is not a regular file the function returns
    silently.

    :param path: Filesystem path to a TOML file.
    :type path: str
    :raises tomllib.TOMLDecodeError: Propagated if the file exists but contains
        invalid TOML.
    """
    target = pathlib.Path(path)
    if not target.exists() or not target.is_file():
        return

    # By default we completely replace the existing configuration.
    with target.open("rb") as f:
        new_config = tomllib.load(f)
        _set_global_config(new_config)


# --------------------------------------------------------------------------- #
# Default initialisation - performed on import so that the rest of the
# package can rely on ``dementor.config.dm_config`` being available.
# --------------------------------------------------------------------------- #
init_from_file(DEFAULT_CONFIG_PATH)  # 1. bundled defaults
init_from_file(CONFIG_PATH)  # 2. user-provided overrides
