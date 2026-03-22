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
import os
import tempfile

from typing import Any
from jinja2.sandbox import SandboxedEnvironment

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

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

    - ``"hex:1122334455667788"`` — explicit hex prefix
    - ``"ascii:1337LEET"`` — explicit ASCII prefix
    - ``"1122334455667788"`` — auto-detect hex (when length matches ``2 * self.length``)
    - ``"1337LEET"`` — auto-detect (try hex first, then encode)
    - ``None`` — generate ``self.length`` cryptographically random bytes

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
    except Exception:  # pragma: no cover - defensive fallback
        # TODO: replace with proper logging once the logging subsystem is ready.
        return value


def now() -> str:
    """
    Return the current time formatted as ``YYYY-MM-DD-HH-MM-SS``.

    :return: Formatted timestamp.
    :rtype: str
    """
    return datetime.datetime.now(tz=datetime.UTC).strftime("%Y-%m-%d-%H-%M-%S")


def generate_self_signed_cert(
    cn: str,
    org: str,
    country: str,
    state: str,
    locality: str,
    validity_days: int,
) -> tuple[str, str, tempfile.TemporaryDirectory]:
    """
    Generate a self-signed certificate and private key in a temporary directory.

    :param cn: Common name for the certificate.
    :param org: Organization name.
    :param country: Country code.
    :param state: State or province.
    :param locality: Locality or city.
    :param validity_days: Number of days the certificate is valid.
    :return: Tuple of (certificate path, key path, temporary directory object).
    """
    # Create temp dir
    temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)

    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Create certificate
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
            x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(
            datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=validity_days)
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName(cn),
                ]
            ),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    # Save private key
    key_id = "".join(random.choices(string.hexdigits))
    key_path = os.path.join(temp_dir.name, f"key_{key_id}.pem")
    with open(key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Save certificate
    cert_id = "".join(random.choices(string.hexdigits))
    cert_path = os.path.join(temp_dir.name, f"cert_{cert_id}.pem")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return cert_path, key_path, temp_dir
