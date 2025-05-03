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
import struct
import time
import calendar
import secrets

from typing import Tuple
from impacket import ntlm

from dementor.config.toml import Attribute
from dementor.config.session import SessionConfig
from dementor.config.util import is_true, get_value, BytesValue


ATTR_NTLM_CHALLENGE = Attribute(
    "ntlm_challenge",
    "NTLM.Challenge",
    # Documentation states that a random challenge will be used
    default_val=None,
    section_local=False,
    factory=BytesValue(8),
)

ATTR_NTLM_ESS = Attribute(
    "ntlm_ess",
    "NTLM.ExtendedSessionSecurity",
    True,
    section_local=False,
    factory=is_true,
)


def apply_config(session: SessionConfig) -> None:
    challenge = get_value("NTLM", "Challenge", default=None)
    if challenge is None:
        challenge = secrets.token_hex(16)
    else:
        try:
            session.ntlm_challange = bytes.fromhex(challenge)
        except ValueError:
            session.ntlm_challange = challenge.encode()

    session.ntlm_ess = get_value("NTLM", "ExtendedSessionSecurity", default=True)


def NTLM_AUTH_decode_string(data: bytes, flags: int, force_ascii: bool = False) -> str:
    encoding = "cp437"  # unclear, maybe change to ASCII
    if flags & ntlm.NTLMSSP_NEGOTIATE_UNICODE:
        encoding = "utf-16le"

    # The domain name and workstation are always OEM encoded.
    if force_ascii:
        encoding = "ascii"

    return data.decode(encoding)


def NTLM_AUTH_encode_string(string: str, target_flags: int) -> bytes:
    encoding = "cp437"
    if target_flags & ntlm.NTLMSSP_NEGOTIATE_UNICODE:
        encoding = "utf-16le"

    return string.encode(encoding)


def NTLM_AUTH_format_host(
    token: ntlm.NTLMAuthNegotiate,
) -> str:
    target_domain_name: bytes = token["domain_name"]
    target_host_name: bytes = token["host_name"]
    os_version: ntlm.VERSION = token["os_version"]
    neg_flags = token["flags"]

    hostname = NTLM_AUTH_decode_string(target_host_name, neg_flags, True)
    domain = NTLM_AUTH_decode_string(target_domain_name, neg_flags, True)

    target_format = hostname or "<UNKNOWN>"
    domain = domain or "<UNKNOWN>"
    target_format = f"{target_format} (domain: {domain})"

    major = os_version["ProductMajorVersion"]
    minor = os_version["ProductMinorVersion"]
    build = os_version["ProductBuild"]
    return f"{target_format} (OS: {major}.{minor}.{build})"


def NTLM_AUTH_to_hashcat_format(
    challenge: bytes,
    user_name: bytes | str,
    domain_name: bytes | str,
    lanman: bytes,
    ntlm_data: bytes,
    session_flags: int,
) -> Tuple[str, str]:
    # converts the given NTLM Authentication message parameters into a crackable format

    # first, check for SSP
    if session_flags & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
        version = "NTLMv1-SSP" if len(ntlm_data) == 24 else "NTLMv2-SSP"
    else:
        version = "NTLMv1" if len(ntlm_data) == 24 else "NTLMv2"

    if isinstance(user_name, bytes):
        user_name = NTLM_AUTH_decode_string(user_name, session_flags)
    if isinstance(domain_name, bytes):
        domain_name = NTLM_AUTH_decode_string(domain_name, session_flags)

    if len(ntlm_data) > 24:
        value = "%s::%s:%s:%s:%s" % (
            user_name,
            domain_name,
            challenge.hex(),
            ntlm_data.hex()[:32],
            ntlm_data.hex()[32:],
        )
    else:
        value = "%s::%s:%s:%s:%s" % (
            user_name,
            domain_name,
            lanman.hex(),
            ntlm_data.hex(),
            challenge.hex(),
        )

    return (version, value)


def NTLM_new_timestamp() -> int:
    return 116444736000000000 + calendar.timegm(time.gmtime()) * 10000000


def NTLM_split_fqdn(fqdn: str):
    return fqdn.split(".", 1) if "." in fqdn else (fqdn, "WORKGROUP")


def NTLM_AUTH_is_anonymous(token: ntlm.NTLMAuthChallengeResponse) -> bool:
    return token["flags"] & ntlm.NTLMSSP_NEGOTIATE_ANONYMOUS or not token["user_name"]


def NTLM_AUTH_CreateChallenge(
    token: ntlm.NTLMAuthNegotiate | dict,
    name: str,
    domain: str,
    challenge: bytes,
    disable_ess: bool = False,
) -> ntlm.NTLMAuthChallenge:
    neg_flags = token["flags"]
    ans_flags = (
        # T (1 bit): If set, requests the protocol version number.
        ntlm.NTLMSSP_NEGOTIATE_VERSION
        # S (1 bit): If set, indicates that the TargetInfo fields in the CHALLENGE_MESSAGE
        | ntlm.NTLMSSP_NEGOTIATE_TARGET_INFO
        | ntlm.NTLMSSP_TARGET_TYPE_SERVER
        | ntlm.NTLMSSP_REQUEST_TARGET
    )

    # H (1 bit): If set, requests usage of the NTLM v1 session security protocol. NTLMSSP_NEGOTIATE_NTLM MUST
    # be set in the token to the server and the CHALLENGE_MESSAGE to the client.
    if neg_flags & ntlm.NTLMSSP_NEGOTIATE_NTLM:
        ans_flags |= ntlm.NTLMSSP_NEGOTIATE_NTLM

    for flag in (
        ntlm.NTLMSSP_NEGOTIATE_UNICODE,
        ntlm.NTLM_NEGOTIATE_OEM,
        # If set, requests 56-bit encryption.
        ntlm.NTLMSSP_NEGOTIATE_56,
        # If set, requests 128-bit session key negotiation.
        ntlm.NTLMSSP_NEGOTIATE_128,
        # If set, requests an explicit key exchange.
        ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH,
        # If set, requests session key negotiation for message signatures.
        ntlm.NTLMSSP_NEGOTIATE_SIGN,
    ):
        # make sure to use the options from the client
        if neg_flags & flag:
            ans_flags |= flag

    # If set, requests usage of the NTLM v2 session security. NTLM v2 session security is a misnomer because
    # it is not NTLM v2. It is NTLM v1 using the extended session security that is also in NTLM v2.
    for flag in (
        ntlm.NTLMSSP_NEGOTIATE_NTLM2,
        ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY,
    ):
        if neg_flags & flag and not disable_ess:
            ans_flags |= flag

    server_name = NTLM_AUTH_encode_string(name, ans_flags)
    server_domain = NTLM_AUTH_encode_string(domain, ans_flags)
    av_pairs = ntlm.AV_PAIRS()
    av_pairs[ntlm.NTLMSSP_AV_HOSTNAME] = server_name
    av_pairs[ntlm.NTLMSSP_AV_DNS_HOSTNAME] = server_name
    av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME] = server_domain
    av_pairs[ntlm.NTLMSSP_AV_DNS_DOMAINNAME] = server_domain
    av_pairs[ntlm.NTLMSSP_AV_TIME] = struct.pack("<q", NTLM_new_timestamp())

    # now we can build the challenge using the answer flags
    ntlm_challenge = ntlm.NTLMAuthChallenge()
    ntlm_challenge["flags"] = ans_flags
    ntlm_challenge["domain_len"] = len(server_domain)
    ntlm_challenge["domain_max_len"] = ntlm_challenge["domain_len"]
    ntlm_challenge["domain_offset"] = 40 + 16
    ntlm_challenge["challenge"] = challenge
    ntlm_challenge["domain_name"] = server_domain
    ntlm_challenge["TargetInfoFields_len"] = len(av_pairs)
    ntlm_challenge["TargetInfoFields_max_len"] = len(av_pairs)
    ntlm_challenge["TargetInfoFields"] = av_pairs
    ntlm_challenge["TargetInfoFields_offset"] = 40 + 16 + len(server_domain)
    ntlm_challenge["Version"] = b"\xff" * 8  # must be blank here
    ntlm_challenge["VersionLen"] = 8
    return ntlm_challenge


def NTLM_report_auth(
    auth_token: ntlm.NTLMAuthChallengeResponse,
    challenge: bytes,
    client,
    session,
    logger=None,
    extras=None,
) -> None:
    flags = auth_token["flags"]
    hversion, hstring = NTLM_AUTH_to_hashcat_format(
        challenge,
        auth_token["user_name"],
        auth_token["domain_name"],
        auth_token["lanman"],
        auth_token["ntlm"],
        flags,
    )
    if not NTLM_AUTH_is_anonymous(auth_token):
        session.db.add_auth(
            client=client,
            credtype=hversion,
            username=NTLM_AUTH_decode_string(auth_token["user_name"], flags),
            domain=NTLM_AUTH_decode_string(auth_token["domain_name"], flags),
            password=hstring,
            logger=logger,
            extras=extras,
        )
