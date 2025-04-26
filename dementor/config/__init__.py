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
import sys
import pathlib
import tomllib

from dementor.paths import CONFIG_PATH, DEFAULT_CONFIG_PATH

# global configuration values
dm_config: dict

def _get_global_config() -> dict:
    return getattr(sys.modules[__name__], "dm_config", {})


def _set_global_config(config: dict) -> None:
    setattr(sys.modules[__name__], "dm_config", config)


def init_from_file(path: str) -> None:
    target = pathlib.Path(path)
    if not target.exists() or not target.is_file():
        return

    # by default, we just replace the global config
    with target.open("rb") as f:
        new_config = tomllib.load(f)
        _set_global_config(new_config)


# Default initialization procedure is:
#   1. use default config
#   2. use config file if it exists
#   3. use custom config if specified via CLI
init_from_file(DEFAULT_CONFIG_PATH)
init_from_file(CONFIG_PATH)
