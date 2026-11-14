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
# pyright: reportAny=false, reportExplicitAny=false, reportUnknownVariableType=false
# pyright: reportUnknownArgumentType=false
import time
import struct
import calendar
import secrets

from typing import Any
from caterpillar.py import LittleEndian, uint16
from impacket import ntlm
from impacket.smb3 import WIN_VERSIONS

from dementor.config.toml import Attribute
from dementor.config.session import SessionConfig
from dementor.config.util import is_true, get_value, BytesValue, HostFallbackValue
from dementor.db import CLEARTEXT, HOST_INFO
from dementor.log.logger import ProtocolLogger, dm_logger

# --- Constants ---------------------------------------------------------------
NTLMV1_RESPONSE_LEN: int = 24

NTLM_CHALLENGE_LEN: int = 8
NTLM_NTPROOFSTR_LEN: int = 16
NTLM_CHALLENGE_MSG_DOMAIN_OFFSET: int = 56
NTLM_ESS_ZERO_PAD: bytes = b"\x00" * 16
NTLM_VERSION_PLACEHOLDER: bytes = b"\x00" * 8
NTLM_VERSION_LEN: int = 8
NTLM_REVISION_W2K3: int = 0x0F
NTLM_FILETIME_EPOCH_OFFSET: int = 116_444_736_000_000_000
NTLM_FILETIME_TICKS_PER_SECOND: int = 10_000_000

NTLM_TRANSPORT_RAW: str = "raw"
NTLM_TRANSPORT_NTLMSSP: str = "ntlmssp"
NTLM_TRANSPORT_CLEARTEXT: str = "cleartext"

NTLM_V1: str = "NetNTLMv1"
NTLM_V1_ESS: str = "NetNTLMv1-ESS"
NTLM_V2: str = "NetNTLMv2"
NTLM_V2_LM: str = "NetLMv2"  # Always paired with NetNTLMv2; both use hashcat -m 5600.


_parse_challenge = BytesValue(NTLM_CHALLENGE_LEN)


# --- Config ------------------------------------------------------------------
def _config_version_to_bytes(value: str | None) -> bytes:
    if value is None or str(value).strip() in ("", "0.0.0"):
        return NTLM_VERSION_PLACEHOLDER
    parts = str(value).strip().split(".")
    major = int(parts[0]) & 0xFF
    minor = int(parts[1]) & 0xFF if len(parts) > 1 else 0
    build = int(parts[2]) & 0xFFFF if len(parts) > 2 else 0
    return (
        bytes([major, minor])
        + build.to_bytes(2, "little")
        + b"\x00\x00\x00"
        + bytes([NTLM_REVISION_W2K3])
    )


ATTR_NTLM_CHALLENGE = Attribute(
    "ntlm_challenge",
    "NTLM.Challenge",
    default_val=None,  # None -> random 8-byte ServerChallenge at startup
    section_local=False,
    factory=_parse_challenge,
)

ATTR_NTLM_DISABLE_ESS = Attribute(
    "ntlm_disable_ess",
    "NTLM.DisableExtendedSessionSecurity",
    False,  # Default: ESS enabled -> NetNTLMv1-ESS hashes
    section_local=False,
    factory=is_true,
)

ATTR_NTLM_DISABLE_NTLMV2 = Attribute(
    "ntlm_disable_ntlmv2",
    "NTLM.DisableNTLMv2",
    False,  # Default: NTLMv2 enabled (TargetInfoFields present)
    section_local=False,
    factory=is_true,
)

ATTR_NTLM_TARGET_TYPE = Attribute(
    "ntlm_target_type",
    "NTLM.TargetType",
    "server",
    section_local=False,
)

ATTR_NTLM_VERSION = Attribute(
    "ntlm_version",
    "NTLM.Version",
    "0.0.0",
    section_local=False,
    factory=_config_version_to_bytes,
)

ATTR_NTLM_NB_COMPUTER = Attribute(
    "ntlm_nb_computer",
    "NTLM.NetBIOSComputer",
    None,
    section_local=False,
    factory=HostFallbackValue("NetBIOSComputer", "DEMENTOR"),
)

ATTR_NTLM_NB_DOMAIN = Attribute(
    "ntlm_nb_domain",
    "NTLM.NetBIOSDomain",
    None,
    section_local=False,
    factory=HostFallbackValue("NetBIOSDomain", "WORKGROUP"),
)

ATTR_NTLM_DNS_COMPUTER = Attribute(
    "ntlm_dns_computer",
    "NTLM.DnsComputer",
    None,
    section_local=False,
    factory=HostFallbackValue("DnsComputer", ""),
)

ATTR_NTLM_DNS_DOMAIN = Attribute(
    "ntlm_dns_domain",
    "NTLM.DnsDomain",
    None,
    section_local=False,
    factory=HostFallbackValue("DnsDomain", ""),
)

ATTR_NTLM_DNS_TREE = Attribute(
    "ntlm_dns_tree",
    "NTLM.DnsTree",
    None,
    section_local=False,
    factory=HostFallbackValue("DnsTree", ""),
)


def _apply_ntlm_field(
    session: SessionConfig,
    key: str,
    attr: str,
    transform,
    factory,
) -> None:
    try:
        raw = get_value("NTLM", key, default=None)
        if raw is None:
            raw = get_value("Globals", key, default=None)
        setattr(session, attr, transform(factory(raw)))
    except (TypeError, ValueError):
        dm_logger.exception("Failed to apply NTLM.%s; using default", key)


def apply_config(session: SessionConfig) -> None:
    session.ntlm_challenge = secrets.token_bytes(NTLM_CHALLENGE_LEN)
    session.ntlm_disable_ess = False
    session.ntlm_disable_ntlmv2 = False
    session.ntlm_target_type = str(ATTR_NTLM_TARGET_TYPE.default_val)
    session.ntlm_version = _config_version_to_bytes(ATTR_NTLM_VERSION.default_val)
    session.ntlm_nb_computer = str(ATTR_NTLM_NB_COMPUTER.factory(None))  # ty:ignore[call-non-callable]
    session.ntlm_nb_domain = str(ATTR_NTLM_NB_DOMAIN.factory(None))  # ty:ignore[call-non-callable]
    session.ntlm_dns_computer = str(ATTR_NTLM_DNS_COMPUTER.factory(None))  # ty:ignore[call-non-callable]
    session.ntlm_dns_domain = str(ATTR_NTLM_DNS_DOMAIN.factory(None))  # ty:ignore[call-non-callable]
    session.ntlm_dns_tree = str(ATTR_NTLM_DNS_TREE.factory(None))  # ty:ignore[call-non-callable]

    try:
        raw_challenge = get_value("NTLM", "Challenge", default=None)
        session.ntlm_challenge = _parse_challenge(raw_challenge)
    except (TypeError, ValueError):
        dm_logger.exception("Failed to parse NTLM Challenge; using random bytes")
    dm_logger.debug(
        "NTLM Challenge set to value: %s with len %d",
        session.ntlm_challenge.hex(),
        len(session.ntlm_challenge),
    )

    _apply_ntlm_field(
        session,
        "DisableExtendedSessionSecurity",
        "ntlm_disable_ess",
        is_true,
        lambda v: v if v is not None else False,
    )
    dm_logger.debug("NTLM DisableExtendedSessionSecurity: %s", session.ntlm_disable_ess)

    _apply_ntlm_field(
        session,
        "DisableNTLMv2",
        "ntlm_disable_ntlmv2",
        is_true,
        lambda v: v if v is not None else False,
    )
    dm_logger.debug("NTLM DisableNTLMv2: %s", session.ntlm_disable_ntlmv2)

    _target_type_default = ATTR_NTLM_TARGET_TYPE.default_val
    _version_default = ATTR_NTLM_VERSION.default_val
    for toml_key, attr_name, transform, factory in (
        (
            "TargetType",
            "ntlm_target_type",
            str,
            lambda v: v if v is not None else _target_type_default,
        ),
        (
            "Version",
            "ntlm_version",
            _config_version_to_bytes,
            lambda v: v if v is not None else _version_default,
        ),
        ("NetBIOSComputer", "ntlm_nb_computer", str, ATTR_NTLM_NB_COMPUTER.factory),
        ("NetBIOSDomain", "ntlm_nb_domain", str, ATTR_NTLM_NB_DOMAIN.factory),
        ("DnsComputer", "ntlm_dns_computer", str, ATTR_NTLM_DNS_COMPUTER.factory),
        ("DnsDomain", "ntlm_dns_domain", str, ATTR_NTLM_DNS_DOMAIN.factory),
        ("DnsTree", "ntlm_dns_tree", str, ATTR_NTLM_DNS_TREE.factory),
    ):
        _apply_ntlm_field(session, toml_key, attr_name, transform, factory)


# --- Encoding ----------------------------------------------------------------
def ntlm_decode_string(
    data: bytes | None,
    negotiate_flags: int,
    is_negotiate_oem: bool = False,
) -> str:
    if not data:
        return ""

    if is_negotiate_oem:
        return data.decode("ascii", errors="replace")

    if negotiate_flags & ntlm.NTLMSSP_NEGOTIATE_UNICODE:
        return data.decode("utf-16-le", errors="replace").rstrip().rstrip("\x00")

    return data.decode("cp437", errors="replace")


def ntlm_encode_string(string: str | None, negotiate_flags: int) -> bytes:
    if not string:
        return b""
    if negotiate_flags & ntlm.NTLMSSP_NEGOTIATE_UNICODE:
        return string.encode("utf-16le")  # No BOM per [MS-NLMP section 2.2]
    return string.encode("cp437", errors="replace")


# --- Extraction --------------------------------------------------------------
def _decode_ntlmssp_os_version(
    token: ntlm.NTLMAuthChallengeResponse | ntlm.NTLMAuthNegotiate,
) -> str:
    major: int | None = None
    minor: int | None = None
    build: int | None = None
    if "Version" in token.fields:
        try:
            ver_raw: bytes = token["Version"]
            major = ver_raw[0]
            minor = ver_raw[1]
            build = uint16.from_bytes(ver_raw[2:4], order=LittleEndian)
        except (IndexError, KeyError, ValueError, struct.error):
            dm_logger.debug("Failed to parse VERSION bytes from NTLM message")
    elif "os_version" in token.fields:
        try:
            ver_obj = token["os_version"]
            major = ver_obj["ProductMajorVersion"]
            minor = ver_obj["ProductMinorVersion"]
            build = ver_obj["ProductBuild"]
        except (KeyError, TypeError):
            dm_logger.debug("Failed to parse os_version from NTLM message")

    if major is None or minor is None or build is None:
        return ""
    # All-zero VERSION = placeholder / not populated
    if major == 0 and minor == 0 and build == 0:
        return ""
    if (major, minor, build) == (6, 1, 0):
        return "Unix - Samba"
    if build in WIN_VERSIONS:
        return f"{WIN_VERSIONS[build]} Build {build}"
    if build:
        return f"{major}.{minor} Build {build}"
    return f"{major}.{minor}"


def _is_anonymous_authenticate(token: ntlm.NTLMAuthChallengeResponse) -> bool:
    try:
        flags: int = token["flags"]
        user_name: bytes = (token["user_name"] or b"").rstrip(b"\x00")
        nt_response: bytes = token["ntlm"] or b""
        lm_response: bytes = token["lanman"] or b""

        is_anon = (
            len(user_name) == 0
            and len(nt_response) == 0
            and (len(lm_response) == 0 or lm_response == b"\x00")
        )
        if is_anon:
            dm_logger.debug("Anonymous AUTHENTICATE_MESSAGE detected")
            return True

        if (
            len(user_name.strip()) == 0
        ):  # user name containts only spaces (comes from netexec)
            dm_logger.debug(
                "Anonymous AUTHENTICATE_MESSAGE detected (username with spaces only)"
            )
            return True

        return bool(flags & ntlm.NTLMSSP_NEGOTIATE_ANONYMOUS)

    except (KeyError, TypeError):
        dm_logger.debug(
            "Failed to check anonymous status in AUTHENTICATE_MESSAGE",
            exc_info=True,
        )
        return False


def ntlm_handle_negotiate_message(
    negotiate: ntlm.NTLMAuthNegotiate,
    logger: ProtocolLogger,
) -> dict[str, str]:
    os_str = _decode_ntlmssp_os_version(negotiate)
    domain_str = ""
    workstation_str = ""
    flags: int = 0
    try:
        flags = negotiate["flags"]
        domain_str = (
            ntlm_decode_string(negotiate["domain_name"], flags, is_negotiate_oem=True)
            or ""
        )
        workstation_str = (
            ntlm_decode_string(negotiate["host_name"], flags, is_negotiate_oem=True) or ""
        )
    except (KeyError, UnicodeDecodeError, TypeError):
        dm_logger.debug("Failed to parse hostname/domain from NEGOTIATE_MESSAGE")

    try:
        parts = [f"flags=0x{flags:08x}"]
        parts.append(f"os={os_str!r}" if os_str else "os=(empty)")
        parts.append(f"domain={domain_str!r}" if domain_str else "domain=(empty)")
        parts.append(
            f"workstation={workstation_str!r}"
            if workstation_str
            else "workstation=(empty)"
        )
        logger.debug("NTLMSSP NEGOTIATE: %s", " ".join(parts), is_client=True)
    except (KeyError, TypeError):
        logger.debug("NTLMSSP NEGOTIATE: (failed to parse fields)", is_client=True)

    # Build return dict with only non-empty values
    fields: dict[str, str] = {}
    if os_str:
        fields["os"] = os_str
    if workstation_str:
        fields["name"] = workstation_str
    if domain_str:
        fields["domain"] = domain_str
    return fields


def ntlm_build_challenge_message(
    token: ntlm.NTLMAuthNegotiate | dict[str, Any],
    *,
    challenge: bytes,
    nb_computer: str = "DEMENTOR",
    nb_domain: str = "WORKGROUP",
    disable_ess: bool = False,
    disable_ntlmv2: bool = False,
    target_type: str = "server",
    version: bytes | None = None,
    dns_computer: str = "",
    dns_domain: str = "",
    dns_tree: str = "",
    log: "ProtocolLogger | None" = None,
) -> ntlm.NTLMAuthChallenge:
    if len(challenge) != NTLM_CHALLENGE_LEN:
        raise ValueError(
            f"challenge must be {NTLM_CHALLENGE_LEN} bytes, got {len(challenge)}"
        )

    # Client's NegotiateFlags from NEGOTIATE_MESSAGE
    client_flags: int = token["flags"]
    target_type_flag = (
        ntlm.NTLMSSP_TARGET_TYPE_DOMAIN
        if target_type == "domain"
        else ntlm.NTLMSSP_TARGET_TYPE_SERVER
    )
    response_flags: int = (
        ntlm.NTLMSSP_REQUEST_TARGET  # TargetName is supplied
        | target_type_flag
    )

    if not disable_ntlmv2:
        response_flags |= ntlm.NTLMSSP_NEGOTIATE_TARGET_INFO

    response_flags |= ntlm.NTLMSSP_NEGOTIATE_NTLM
    response_flags |= ntlm.NTLMSSP_NEGOTIATE_ALWAYS_SIGN

    for flag in (
        ntlm.NTLMSSP_NEGOTIATE_UNICODE,
        ntlm.NTLM_NEGOTIATE_OEM,
        ntlm.NTLMSSP_NEGOTIATE_56,
        ntlm.NTLMSSP_NEGOTIATE_128,
        ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH,
        ntlm.NTLMSSP_NEGOTIATE_SIGN,
        ntlm.NTLMSSP_NEGOTIATE_SEAL,
    ):
        if client_flags & flag:
            response_flags |= flag

    if not disable_ess:
        if client_flags & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
            response_flags |= ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        elif client_flags & ntlm.NTLMSSP_NEGOTIATE_LM_KEY:
            response_flags |= ntlm.NTLMSSP_NEGOTIATE_LM_KEY

    if client_flags & ntlm.NTLMSSP_NEGOTIATE_VERSION:
        response_flags |= ntlm.NTLMSSP_NEGOTIATE_VERSION

    if response_flags & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
        response_flags &= ~ntlm.NTLMSSP_NEGOTIATE_LM_KEY

    if target_type == "domain":
        target_name_str = nb_domain.upper()
    else:
        target_name_str = nb_computer.upper()
    target_name_bytes: bytes = ntlm_encode_string(target_name_str, response_flags)

    version_bytes = version if version is not None else NTLM_VERSION_PLACEHOLDER

    challenge_message = ntlm.NTLMAuthChallenge()
    challenge_message["flags"] = response_flags
    challenge_message["challenge"] = challenge
    challenge_message["domain_len"] = len(target_name_bytes)
    challenge_message["domain_max_len"] = len(target_name_bytes)
    challenge_message["domain_offset"] = NTLM_CHALLENGE_MSG_DOMAIN_OFFSET
    challenge_message["domain_name"] = target_name_bytes
    challenge_message["Version"] = version_bytes
    challenge_message["VersionLen"] = NTLM_VERSION_LEN

    target_info_offset: int = NTLM_CHALLENGE_MSG_DOMAIN_OFFSET + len(target_name_bytes)

    if disable_ntlmv2:
        challenge_message["TargetInfoFields_len"] = 0
        challenge_message["TargetInfoFields_max_len"] = 0
        challenge_message["TargetInfoFields"] = b""
        challenge_message["TargetInfoFields_offset"] = target_info_offset
    else:
        av_pairs = ntlm.AV_PAIRS()
        av_pairs[ntlm.NTLMSSP_AV_HOSTNAME] = nb_computer.encode(
            "utf-16le"
        )  # MsvAvNbComputerName (0x0001)
        av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME] = nb_domain.encode(
            "utf-16le"
        )  # MsvAvNbDomainName (0x0002)
        if dns_computer:
            av_pairs[ntlm.NTLMSSP_AV_DNS_HOSTNAME] = dns_computer.encode(
                "utf-16le"
            )  # MsvAvDnsComputerName (0x0003)
        if dns_domain:
            av_pairs[ntlm.NTLMSSP_AV_DNS_DOMAINNAME] = dns_domain.encode(
                "utf-16le"
            )  # MsvAvDnsDomainName (0x0004)
        if dns_tree:
            av_pairs[ntlm.NTLMSSP_AV_DNS_TREENAME] = dns_tree.encode(
                "utf-16le"
            )  # MsvAvDnsTreeName (0x0005)

        challenge_message["TargetInfoFields_len"] = len(av_pairs)
        challenge_message["TargetInfoFields_max_len"] = len(av_pairs)
        challenge_message["TargetInfoFields"] = av_pairs
        challenge_message["TargetInfoFields_offset"] = target_info_offset

    _log = log if log is not None else dm_logger
    _log.debug(
        "NTLMSSP CHALLENGE: flags=0x%08x challenge=%s target=%s",
        response_flags,
        challenge.hex(),
        target_name_str,
        is_server=True,
    )
    return challenge_message


def ntlm_auth_create_challenge(
    token: "ntlm.NTLMAuthNegotiate | dict[str, Any]",
    nb_computer: str,
    nb_domain: str,
    *,
    challenge: bytes,
    disable_ess: bool = False,
    disable_ntlmv2: bool = False,
) -> "ntlm.NTLMAuthChallenge":
    return ntlm_build_challenge_message(
        token,
        challenge=challenge,
        nb_computer=nb_computer,
        nb_domain=nb_domain,
        disable_ess=disable_ess,
        disable_ntlmv2=disable_ntlmv2,
    )


def _log_ntlmv2_blob(
    auth_token: ntlm.NTLMAuthChallengeResponse,
    log: ProtocolLogger,
) -> str | None:
    target_name: str | None = None
    try:
        nt_response: bytes = auth_token["ntlm"] or b""
        if len(nt_response) <= NTLMV1_RESPONSE_LEN:
            return None  # NTLMv1 - no blob

        blob = nt_response[NTLM_NTPROOFSTR_LEN:]
        if len(blob) < 32:
            return None  # Minimum blob: header(28) + MsvAvEOL(4) = 32 bytes

        client_challenge = blob[16:24]
        av_data = blob[28:]
        if not av_data:
            log.debug(
                "NTLMv2 blob: ClientChallenge=%s (no AV_PAIRs)", client_challenge.hex()
            )
            return None

        av_pairs = ntlm.AV_PAIRS(av_data)
        # impacket AV_PAIRS.__getitem__ returns (length, value_bytes) tuples
        blob_parts: list[str] = [f"ClientChallenge={client_challenge.hex()}"]
        if ntlm.NTLMSSP_AV_TARGET_NAME in av_pairs.fields:
            _, spn_raw = av_pairs[ntlm.NTLMSSP_AV_TARGET_NAME]
            target_name = spn_raw.decode("utf-16-le", errors="replace")
            blob_parts.append(f"SPN={target_name}" if target_name else "SPN=(empty)")

        if ntlm.NTLMSSP_AV_TIME in av_pairs.fields:
            _, ts_raw = av_pairs[ntlm.NTLMSSP_AV_TIME]
            if len(ts_raw) >= 8:
                ts_val = int.from_bytes(ts_raw[:8], "little")
                blob_parts.append(
                    f"Timestamp=0x{ts_val:016x}" if ts_val else "Timestamp=(empty)"
                )

        if ntlm.NTLMSSP_AV_FLAGS in av_pairs.fields:
            _, flags_raw = av_pairs[ntlm.NTLMSSP_AV_FLAGS]
            if len(flags_raw) >= 4:
                av_flags = int.from_bytes(flags_raw[:4], "little")
                blob_parts.append(
                    f"Flags=0x{av_flags:08x}" if av_flags else "Flags=(empty)"
                )

        if ntlm.NTLMSSP_AV_CHANNEL_BINDINGS in av_pairs.fields:
            _, cb_raw = av_pairs[ntlm.NTLMSSP_AV_CHANNEL_BINDINGS]
            blob_parts.append(
                f"ChannelBindings={cb_raw.hex()}"
                if cb_raw != b"\x00" * len(cb_raw)
                else "ChannelBindings=(empty)"
            )

        # MsvAvSingleHost (0x0008) - machine identity claim
        if ntlm.NTLMSSP_AV_RESTRICTIONS in av_pairs.fields:
            _, sh_raw = av_pairs[ntlm.NTLMSSP_AV_RESTRICTIONS]
            blob_parts.append(f"SingleHost={sh_raw.hex()}")

        log.debug("NTLMv2 blob: %s", " ".join(blob_parts), is_client=True)

    except (KeyError, AttributeError, TypeError, struct.error):
        log.debug("Failed to parse NTLMv2 blob AV_PAIRs", exc_info=True)

    return target_name


def _build_ntlm_display_line(
    negotiate_fields: dict[str, str] | None,
    os_str: str,
    user_name: str,
    domain_name: str,
    host_name_str: str,
    spn: str,
) -> str | None:
    ntlm_fields: dict[str, set[str]] = {
        "os": set(),
        "user": set(),
        "domain": set(),
        "name": set(),
        "SPN": set(),
    }
    if negotiate_fields:
        for k, v in negotiate_fields.items():
            if v and k in ntlm_fields:
                ntlm_fields[k].add(v)
    for key, value in (
        ("os", os_str),
        ("user", user_name),
        ("domain", domain_name),
        ("name", host_name_str),
        ("SPN", spn),
    ):
        if value:
            ntlm_fields[key].add(value)

    parts = [
        f"{k}:{','.join(sorted(ntlm_fields[k]))}"
        for k in ("os", "user", "domain", "name", "SPN")
        if ntlm_fields.get(k)
    ]
    return " | ".join(parts) if parts else None


def _build_ntlm_host_info(
    os_str: str, host_name_str: str, domain_name: str
) -> str | None:
    host_parts: list[str] = []
    if os_str:
        host_parts.append(os_str)
    if host_name_str:
        host_parts.append(f"(name: {host_name_str})")
    if domain_name:
        host_parts.append(f"(domain: {domain_name})")
    return " ".join(host_parts) if host_parts else None


def _store_ntlm_captures(
    all_hashes: list[tuple[str, str]],
    *,
    user_name: str,
    domain_name: str,
    os_str: str,
    host_name_str: str,
    client: tuple[str, int],
    session: "SessionConfig",
    logger: "ProtocolLogger | None",
    extras: dict[str, Any] | None,
) -> None:
    extras = extras or {}
    extras[HOST_INFO] = _build_ntlm_host_info(os_str, host_name_str, domain_name)
    for version_label, hashcat_line in all_hashes:
        session.db.add_auth(
            client=client,
            credtype=version_label,
            username=user_name,
            domain=domain_name,
            password=hashcat_line,
            logger=logger,
            extras=extras,
        )


def ntlm_handle_authenticate_message(
    auth_token: ntlm.NTLMAuthChallengeResponse,
    *,
    challenge: bytes,
    client: tuple[str, int],
    session: SessionConfig,
    logger: ProtocolLogger | None = None,
    extras: dict[str, Any] | None = None,
    transport: str = NTLM_TRANSPORT_NTLMSSP,
    negotiate_fields: dict[str, str] | None = None,
) -> bool:
    log = logger or dm_logger

    if _is_anonymous_authenticate(auth_token):
        log.display("Anonymous NTLM login attempt; skipping hash extraction")
        return False

    os_str: str = _decode_ntlmssp_os_version(auth_token)
    host_name_str: str = ""
    try:
        negotiate_flags: int = auth_token["flags"]
        try:
            host_name_str = (
                ntlm_decode_string(auth_token["host_name"], negotiate_flags) or ""
            )
        except (KeyError, UnicodeDecodeError):
            dm_logger.debug("Failed to parse host_name from AUTHENTICATE_MESSAGE")
        mic_str: str = "(absent)"
        try:
            if negotiate_flags & ntlm.NTLMSSP_NEGOTIATE_VERSION:
                mic_val: bytes = auth_token["MIC"]
                mic_str = (
                    mic_val.hex()
                    if mic_val and len(mic_val) == 16 and mic_val != b"\x00" * 16
                    else "(empty)"
                )
        except (KeyError, TypeError):
            log.debug("Failed to parse MIC field", exc_info=True)
            mic_str = "(parse error)"
        auth_parts = [f"flags=0x{negotiate_flags:08x}"]
        auth_parts.append(f"os={os_str!r}" if os_str else "os=(empty)")
        user_name: str = ntlm_decode_string(auth_token["user_name"], negotiate_flags)
        domain_name: str = ntlm_decode_string(auth_token["domain_name"], negotiate_flags)
        auth_parts.append(f"user={user_name!r}" if user_name else "user=(empty)")
        auth_parts.append(f"domain={domain_name!r}" if domain_name else "domain=(empty)")
        auth_parts.append(f"name={host_name_str!r}" if host_name_str else "name=(empty)")
        nt_len = len(auth_token["ntlm"] or b"")
        lm_len = len(auth_token["lanman"] or b"")
        auth_parts.append(f"NT_len={nt_len}")
        auth_parts.append(f"LM_len={lm_len}")
        auth_parts.append(f"MIC={mic_str}")
        log.debug("NTLMSSP AUTHENTICATE: %s", " ".join(auth_parts), is_client=True)
    except (KeyError, UnicodeDecodeError, TypeError):
        log.debug("Failed to parse AUTHENTICATE_MESSAGE fields", exc_info=True)
        try:
            negotiate_flags = auth_token["flags"]
        except KeyError:
            negotiate_flags = 0
        user_name = ""
        domain_name = ""

    # -- Hash extraction ---------------------------------------------------
    try:
        all_hashes = ntlm_to_hashcat(
            server_challenge=challenge,
            user_name=auth_token["user_name"],
            domain_name=auth_token["domain_name"],
            lm_response=auth_token["lanman"],
            nt_response=auth_token["ntlm"],
            negotiate_flags=negotiate_flags,
        )

        if not all_hashes:
            log.debug(
                "AUTHENTICATE_MESSAGE produced no crackable hashes "
                + "(user=%r flags=0x%08x)",
                auth_token["user_name"],
                negotiate_flags,
            )
            return False

        # -- NTLMv2 client blob AV_PAIRs (single debug line) --------------
        spn = _log_ntlmv2_blob(auth_token, log)

        # -- Consolidated display line (Type 1 + Type 3 deduped) -----------
        display_line = _build_ntlm_display_line(
            negotiate_fields, os_str, user_name, domain_name, host_name_str, spn
        )
        if display_line:
            log.debug("NTLM: %s", display_line)

        log.debug(
            "Writing %d hash(es) to capture database for user=%r domain=%r",
            len(all_hashes),
            user_name,
            domain_name,
        )
        _store_ntlm_captures(
            all_hashes,
            user_name=user_name,
            domain_name=domain_name,
            os_str=os_str,
            host_name_str=host_name_str,
            client=client,
            session=session,
            logger=logger,
            extras=extras,
        )

        return bool(all_hashes)

    except ValueError:
        log.exception(
            "Invalid data in AUTHENTICATE_MESSAGE (bad challenge length or "
            + "malformed response fields); skipping capture"
        )
    except (AttributeError, KeyError, IndexError, TypeError, OverflowError):
        log.exception("Failed to extract NTLM hashes from AUTHENTICATE_MESSAGE")

    return False


def ntlm_report_auth(
    auth_token: "ntlm.NTLMAuthChallengeResponse",
    *,
    challenge: bytes,
    client: tuple[str, int],
    logger: "ProtocolLogger | None" = None,
    session: "SessionConfig",
    negotiate_fields: "dict[str, str] | None" = None,
) -> bool:
    return ntlm_handle_authenticate_message(
        auth_token,
        challenge=challenge,
        client=client,
        session=session,
        logger=logger,
        negotiate_fields=negotiate_fields,
    )


def ntlm_split_fqdn(fqdn: str) -> tuple[str, str]:
    if "." in fqdn:
        hostname, domain = fqdn.split(".", 1)
        return hostname, domain
    return fqdn, "WORKGROUP"


def _classify_hash_type(
    nt_response: bytes, lm_response: bytes, negotiate_flags: int
) -> str:
    try:
        nt_len = len(nt_response)
    except TypeError:
        return NTLM_V1

    if nt_len > NTLMV1_RESPONSE_LEN:
        return NTLM_V2

    try:
        ess_by_lm = (
            len(lm_response) == NTLMV1_RESPONSE_LEN
            and lm_response[NTLM_CHALLENGE_LEN:] == NTLM_ESS_ZERO_PAD
        )
    except TypeError:
        return NTLM_V1

    return NTLM_V1_ESS if ess_by_lm else NTLM_V1


def _compute_dummy_lm_responses(server_challenge: bytes) -> set[bytes]:
    return {
        ntlm.ntlmssp_DES_encrypt(NTLM_ESS_ZERO_PAD, server_challenge),
        ntlm.ntlmssp_DES_encrypt(ntlm.DEFAULT_LM_HASH, server_challenge),
    }


def _decode_ntlm_identity_string(
    value: bytes | str, negotiate_flags: int, field: str
) -> str:
    try:
        if isinstance(value, (bytes, bytearray, memoryview)):
            return ntlm_decode_string(bytes(value), negotiate_flags)
    except (UnicodeDecodeError, TypeError):
        dm_logger.debug("Failed to decode %s; using empty string", field, exc_info=True)
        return ""
    else:
        return value or ""


def ntlm_to_hashcat(
    server_challenge: bytes,
    user_name: bytes | str,
    domain_name: bytes | str,
    lm_response: bytes | None,
    nt_response: bytes | None,
    negotiate_flags: int,
) -> list[tuple[str, str]]:
    if len(server_challenge) != NTLM_CHALLENGE_LEN:
        raise ValueError(
            f"server_challenge must be {NTLM_CHALLENGE_LEN} bytes, "
            + f"got {len(server_challenge)}"
        )

    captures: list[tuple[str, str]] = []

    lm_response = lm_response or b""
    nt_response = nt_response or b""

    if not nt_response:
        dm_logger.debug("NtChallengeResponse is empty; skipping hash extraction")
        return captures

    user: str = _decode_ntlm_identity_string(user_name, negotiate_flags, "UserName")
    domain: str = _decode_ntlm_identity_string(domain_name, negotiate_flags, "DomainName")

    try:
        hash_type: str = _classify_hash_type(nt_response, lm_response, negotiate_flags)
    except (TypeError, ValueError, AttributeError):
        dm_logger.debug(
            "_classify_hash_type raised unexpectedly; defaulting to %s",
            NTLM_V1,
            exc_info=True,
        )
        hash_type = NTLM_V1

    dm_logger.debug(
        "Extracting hashes: user=%r domain=%r hash_type=%s nt_len=%d lm_len=%d",
        user,
        domain,
        hash_type,
        len(nt_response),
        len(lm_response),
    )

    server_challenge_hex: str = server_challenge.hex()

    if hash_type == NTLM_V2:
        try:
            nt_proof_str_hex: str = nt_response[:NTLM_NTPROOFSTR_LEN].hex()
            blob_hex: str = nt_response[NTLM_NTPROOFSTR_LEN:].hex()
            captures.append(
                (
                    NTLM_V2,
                    f"{user}::{domain}"
                    + f":{server_challenge_hex}"
                    + f":{nt_proof_str_hex}"
                    + f":{blob_hex}",
                )
            )
            dm_logger.debug("Appended %s hash (nt_len=%d)", NTLM_V2, len(nt_response))
        except (TypeError, AttributeError):
            dm_logger.debug("Failed to format %s hash; skipping", NTLM_V2, exc_info=True)
            return captures

        try:
            if len(lm_response) == NTLMV1_RESPONSE_LEN:
                if lm_response == b"\x00" * NTLMV1_RESPONSE_LEN:
                    dm_logger.debug(
                        "LmChallengeResponse is Z(%d) "
                        + "(MsvAvTimestamp suppression or null LM); skipping %s",
                        NTLMV1_RESPONSE_LEN,
                        NTLM_V2_LM,
                    )
                else:
                    lm_proof_hex: str = lm_response[:NTLM_NTPROOFSTR_LEN].hex()
                    lm_cc_hex: str = lm_response[
                        NTLM_NTPROOFSTR_LEN:NTLMV1_RESPONSE_LEN
                    ].hex()
                    captures.append(
                        (
                            NTLM_V2_LM,
                            f"{user}::{domain}"
                            + f":{server_challenge_hex}"
                            + f":{lm_proof_hex}"
                            + f":{lm_cc_hex}",
                        )
                    )
                    dm_logger.debug("Appended %s companion hash", NTLM_V2_LM)
            else:
                dm_logger.debug(
                    "LmChallengeResponse length %d unexpected for %s; skipping",
                    len(lm_response),
                    NTLM_V2_LM,
                )
        except (TypeError, AttributeError):
            dm_logger.debug(
                "Failed to format %s hash; skipping", NTLM_V2_LM, exc_info=True
            )

        return captures

    if hash_type == NTLM_V1_ESS:
        try:
            nt_response_hex: str = nt_response.hex()
            lm_ess_hex: str = (
                lm_response[:NTLM_CHALLENGE_LEN].hex() + NTLM_ESS_ZERO_PAD.hex()
            )
            captures.append(
                (
                    NTLM_V1_ESS,
                    f"{user}::{domain}"
                    + f":{lm_ess_hex}"
                    + f":{nt_response_hex}"
                    + f":{server_challenge_hex}",
                )
            )
            dm_logger.debug("Appended %s hash", NTLM_V1_ESS)
        except (TypeError, AttributeError):
            dm_logger.debug(
                "Failed to format %s hash; skipping", NTLM_V1_ESS, exc_info=True
            )
        return captures

    try:
        nt_response_hex = nt_response.hex()
        lm_slot_hex: str = ""

        if len(lm_response) == NTLMV1_RESPONSE_LEN:
            if lm_response == nt_response:
                dm_logger.debug(
                    "LmChallengeResponse == NtChallengeResponse "
                    + "(Level 2 duplication); omitting LM slot"
                )
            elif lm_response in _compute_dummy_lm_responses(server_challenge):
                dm_logger.debug(
                    "LmChallengeResponse matches dummy LM hash; omitting LM slot"
                )
            else:
                lm_slot_hex = lm_response.hex()
                dm_logger.debug("Including real LmChallengeResponse in %s hash", NTLM_V1)

        captures.append(
            (
                NTLM_V1,
                f"{user}::{domain}"
                + f":{lm_slot_hex}"
                + f":{nt_response_hex}"
                + f":{server_challenge_hex}",
            )
        )
        dm_logger.debug("Appended %s hash (lm_slot_empty=%s)", NTLM_V1, lm_slot_hex == "")
    except (TypeError, AttributeError):
        dm_logger.debug("Failed to format %s hash; skipping", NTLM_V1, exc_info=True)

    return captures


def _build_smb1_host_info(extras: dict[str, Any], domain: str, fallback: str) -> str:
    host_parts: list[str] = []
    if extras.get("os"):
        host_parts.append(extras.pop("os"))
    if domain:
        host_parts.append(f"(domain: {domain})")
    return " ".join(host_parts) if host_parts else fallback


def ntlm_handle_legacy_raw_auth(
    *,
    user_name: bytes | str,
    domain_name: bytes | str,
    lm_response: bytes | None,
    nt_response: bytes | None,
    challenge: bytes,
    client: tuple[str, int],
    session: SessionConfig,
    logger: ProtocolLogger | None = None,
    extras: dict[str, Any] | None = None,
    transport: str = NTLM_TRANSPORT_RAW,
    cleartext_password: str | None = None,
) -> None:
    log = logger or dm_logger

    user: str = (
        user_name.decode("utf-16-le", errors="replace")
        if isinstance(user_name, (bytes, bytearray, memoryview))
        else (user_name or "")
    )
    domain: str = (
        domain_name.decode("utf-16-le", errors="replace")
        if isinstance(domain_name, (bytes, bytearray, memoryview))
        else (domain_name or "")
    )

    if transport == NTLM_TRANSPORT_CLEARTEXT:
        if not cleartext_password:
            log.debug("Empty cleartext password; skipping capture")
            return

        log.success(
            f"Cleartext password captured: {user}\\{domain}",
        )
        extras = extras or {}
        extras[HOST_INFO] = _build_smb1_host_info(extras, domain, "SMB1 cleartext")
        session.db.add_auth(
            client=client,
            credtype=CLEARTEXT,
            username=user,
            domain=domain,
            password=cleartext_password,
            logger=logger,
            extras=extras,
        )
        return

    lm_response = lm_response or b""
    nt_response = nt_response or b""

    if not user and not nt_response and (not lm_response or lm_response == b"\x00"):
        log.debug("Anonymous SMB1 basic-security login; skipping hash extraction")
        return

    if not nt_response and not lm_response:
        log.debug("Both LM and NT responses empty; skipping")
        return

    try:
        all_hashes = ntlm_to_hashcat(
            server_challenge=challenge,
            user_name=user,
            domain_name=domain,
            lm_response=lm_response,
            nt_response=nt_response,
            negotiate_flags=0,
        )

        if not all_hashes:
            log.debug(
                "SMB1 basic-security auth produced no crackable hashes (user=%r)",
                user,
            )
            return

        log.debug(
            "Writing %d hash(es) from SMB1 basic-security for user=%r",
            len(all_hashes),
            user,
        )
        extras = extras or {}
        extras[HOST_INFO] = _build_smb1_host_info(extras, domain, "SMB1 raw")
        for version_label, hashcat_line in all_hashes:
            session.db.add_auth(
                client=client,
                credtype=version_label,
                username=user,
                domain=domain,
                password=hashcat_line,
                logger=logger,
                extras=extras,
            )

    except ValueError:
        log.exception("Invalid data in SMB1 basic-security auth; skipping capture")
    except (AttributeError, KeyError, IndexError, TypeError, OverflowError):
        log.exception("Failed to extract hashes from SMB1 basic-security auth")


def ntlm_timestamp() -> int:
    return (
        NTLM_FILETIME_EPOCH_OFFSET
        + calendar.timegm(time.gmtime()) * NTLM_FILETIME_TICKS_PER_SECOND
    )
