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
import os
import dementor

DEMENTOR_PATH = os.path.expanduser("~/.dementor")
ASSETS_PATH = os.path.join(os.path.dirname(dementor.__file__), "assets")
CONFIG_PATH = os.path.join(DEMENTOR_PATH, "Dementor.toml")
DEFAULT_CONFIG_PATH = os.path.join(ASSETS_PATH, "Dementor.toml")
BANNER_PATH = os.path.join(ASSETS_PATH, "banner.txt")
HTTP_TEMPLATES_PATH = os.path.join(ASSETS_PATH, "www")


if __name__ == "__main__":
    print(f"DefaultWorkspace  : {DEMENTOR_PATH}")
    print(f"AssetsPath        : {ASSETS_PATH}")
    print(f"ConfigPath        : {CONFIG_PATH}")
    print(f"BannerPath        : {BANNER_PATH}")
    print(f"DefaultConfigPath : {DEFAULT_CONFIG_PATH}")
    print(f"HTTPTemplatesPath : {HTTP_TEMPLATES_PATH}")
