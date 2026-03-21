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
#
# Shared attributes for all configuration classes
from dementor.config.toml import Attribute
from dementor.config.util import is_true

# TLS/Certificate Configuration Attributes
# These attributes are shared across protocols that support TLS and
# certificate-based authentication


ATTR_CERT = Attribute(
    attr_name="certfile",
    qname="Cert",
    default_val=None,
    section_local=False,
)

ATTR_KEY = Attribute(
    attr_name="keyfile",
    qname="Key",
    default_val=None,
    section_local=False,
)

ATTR_TLS = Attribute(
    attr_name="use_ssl",
    qname="TLS",
    default_val=False,
    factory=is_true,
)


# Self-Signed Certificate Generation Attributes
# These attributes configure automatic self-signed certificate generation
# when TLS is enabled but no certificates are provided.
# Similar to QUIC implementation, allows global configuration across protocols.

ATTR_SELF_SIGNED = Attribute(
    attr_name="self_signed",
    qname="EnableSelfSigned",
    default_val=True,
    factory=is_true,
    section_local=False,
)

ATTR_CERT_CN = Attribute(
    attr_name="cert_cn",
    qname="CertCommonName",
    default_val="dementor.local",
    section_local=False,
)

ATTR_CERT_ORG = Attribute(
    attr_name="cert_org",
    qname="CertOrganization",
    default_val="Dementor",
    section_local=False,
)

ATTR_CERT_COUNTRY = Attribute(
    attr_name="cert_country",
    qname="CertCountry",
    default_val="US",
    section_local=False,
)

ATTR_CERT_STATE = Attribute(
    attr_name="cert_state",
    qname="CertState",
    default_val="CA",
    section_local=False,
)

ATTR_CERT_LOCALITY = Attribute(
    attr_name="cert_locality",
    qname="CertLocality",
    default_val="San Francisco",
    section_local=False,
)

ATTR_CERT_VALIDITY_DAYS = Attribute(
    attr_name="cert_validity_days",
    qname="CertValidityDays",
    default_val=365,
    section_local=False,
)

SELFSIGNED_COMMON_ATTRS = [
    ATTR_SELF_SIGNED,
    ATTR_CERT_CN,
    ATTR_CERT_COUNTRY,
    ATTR_CERT_LOCALITY,
    ATTR_CERT_ORG,
    ATTR_CERT_STATE,
    ATTR_CERT_VALIDITY_DAYS,
]
