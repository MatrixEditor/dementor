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
__all__ = ["CLEARTEXT", "HOST_INFO", "NO_USER", "normalize_client_address"]

# --------------------------------------------------------------------------- #
# Public constants
# --------------------------------------------------------------------------- #
CLEARTEXT = "Cleartext"
NO_USER = "<missing-user>"
HOST_INFO = "_host_info"
BEARER_TOKEN = "BearerToken"  # noqa: S105
DIGEST_MD5 = "digest-md5"

# Backward-compatible aliases so existing imports like
#   from dementor.db import _CLEARTEXT
# keep working without a mass-rename across all protocol files.
# New code should use the unprefixed names above.
_CLEARTEXT = CLEARTEXT
_NO_USER = NO_USER
_HOST_INFO = HOST_INFO


def normalize_client_address(client: str) -> str:
    """Normalize IPv6-mapped IPv4 addresses by stripping IPv6 prefix."""
    return client.removeprefix("::ffff:")
