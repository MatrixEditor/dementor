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

"""Dementor database package -- constants, helpers, and ORM models.

Provides the :class:`~dementor.db.model.DementorDB` wrapper for thread-safe
credential storage, the :class:`~dementor.db.connector.DatabaseConfig` for
``[DB]`` TOML configuration, and engine initialization via
:func:`~dementor.db.connector.create_db`.
"""

__all__ = ["CLEARTEXT", "HOST_INFO", "NO_USER", "normalize_client_address"]

# --------------------------------------------------------------------------- #
# Public constants
# --------------------------------------------------------------------------- #
CLEARTEXT = "Cleartext"
"""Constant indicating plaintext credentials (as opposed to hashes)."""

NO_USER = "<missing-user>"
"""Placeholder string used when username is absent or invalid in credential logging."""

HOST_INFO = "_host_info"
"""Key used in extras dict to store host information for credential logging."""

# Backward-compatible aliases so existing imports like
#   from dementor.db import _CLEARTEXT
# keep working without a mass-rename across all protocol files.
# New code should use the unprefixed names above.
_CLEARTEXT = CLEARTEXT
_NO_USER = NO_USER
_HOST_INFO = HOST_INFO


def normalize_client_address(client: str) -> str:
    """Normalize IPv6-mapped IPv4 addresses by stripping IPv6 prefix.

    Converts addresses like `::ffff:192.168.1.1` to `192.168.1.1` for consistent storage and display.

    :param client: Raw client address string (e.g., from socket).
    :type client: str
    :return: Normalized address without IPv6 mapping prefix.
    :rtype: str

    Example:
    >>> normalize_client_address("::ffff:192.168.1.1")
    '192.168.1.1'
    >>> normalize_client_address("2001:db8::1")
    '2001:db8::1'

    """
    return client.removeprefix("::ffff:")
