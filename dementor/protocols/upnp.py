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
import posixpath
import socket
import uuid
import pathlib
import mimetypes

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

from rich.markup import escape

from jinja2.environment import Environment
from jinja2.loaders import FileSystemLoader
from jinja2.exceptions import TemplateNotFound
from jinja2 import select_autoescape

from dementor.config.toml import TomlConfig, Attribute as A
from dementor.config.util import random_value
from dementor.logger import ProtocolLogger, dm_logger
from dementor.servers import ServerThread, bind_server
from dementor.paths import HTTP_TEMPLATES_PATH
from dementor.database import normalize_client_address


def apply_config(session):
    session.upnp_config = TomlConfig.build_config(UPNPConfig)


def create_server_threads(session):
    if session.upnp_enabled:
        yield ServerThread(
            session,
            UPnPServer,
            server_address=(session.bind_address, session.upnp_config.upnp_port),
        )


class UPNPConfig(TomlConfig):
    _section_ = "UPnP"
    _fields_ = [
        A("upnp_port", "Port", 50001),
        A("upnp_uuid", "UUID", str(uuid.uuid4())),
        A("upnp_templates_path", "TemplatesPath", list),
        A("upnp_template", "Template", "upnp-default"),
        A("upnp_dd_path", "DDUri", "/dd.xml"),
        A("upnp_scpd_path", "SCPDUri", "/scpd.xml"),
        A("upnp_present_path", "PresentationUri", "/present.html"),
    ]

    def set_upnp_templates_path(self, path_list):
        dirs = set()
        for templates_dir in path_list:
            path = pathlib.Path(templates_dir)
            if not path.exists() or not path.is_dir():
                dm_logger.error(
                    f"UPnP templates directory {path} does not exist - using default..."
                )
                path = HTTP_TEMPLATES_PATH

            dirs.add(str(path))

        dirs.add(HTTP_TEMPLATES_PATH)
        self.upnp_templates_path = list(dirs)

    def set_upnp_template(self, template):
        self.upnp_template = None
        for templates_dir in self.upnp_templates_path:
            path = pathlib.Path(templates_dir) / template
            if path.exists() and path.is_dir():
                self.upnp_template = str(path)
                return

        if not self.upnp_template:
            self.upnp_template = str(pathlib.Path(HTTP_TEMPLATES_PATH) / "upnp-default")


# --- Simple UPnP HTTP server ---
class UPnPHandler(BaseHTTPRequestHandler):
    def __init__(self, session, request, client_address, server) -> None:
        self.session = session
        self.logger = ProtocolLogger(
            extra={
                "protocol": "UPnP",
                "protocol_color": "dark_cyan",
                "host": normalize_client_address(client_address[0]),
                "port": session.upnp_config.upnp_port,
            }
        )
        super().__init__(request, client_address, server)

    def handle_expect_100(self) -> bool:
        return False

    def version_string(self) -> str:
        return "UPnP/1.0"

    def log_message(self, format: str, *args) -> None:
        pass

    def send_page(self, template, content_type):
        self.logger.debug(escape(f"{self.command} {self.path} 200"), is_server=True)
        path = pathlib.Path(template)
        script = self.server.render(path.name, uuid=self.target_uuid)

        body = script.encode("utf-8", "replace")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.logger.debug(f"Request for {self.path}", is_client=True)
        user_agent = escape(self.headers["User-Agent"])
        if len(user_agent) > 50:
            user_agent = user_agent[:47] + "..."


        elements = self.path.split("/")
        if len(elements) == 0:
            return self.send_error(HTTPStatus.NOT_FOUND)

        # The web service will handle two types of requests:
        #   1. direct file access (e.g. /dd.xml)
        #   2. file access with device UUID (e.g. /<uuid>/dd.xml)
        self.target_uuid = elements[1]
        try:
            # Using this UUID to act as a certain device on the network
            _ = uuid.UUID(f"{{{self.target_uuid}}}")
            target_path = "/".join(elements[2:]).lstrip("/")
        except ValueError:
            self.logger.debug(f"Invalid UUID: {self.target_uuid}", is_client=True)
            self.target_uuid = self.session.upnp_config.upnp_uuid
            target_path = self.path.lstrip("/")

        try:
            path = unquote(target_path, errors="surrogatepass")
        except UnicodeDecodeError:
            path = unquote(target_path)

        path = posixpath.normpath(path)
        try:
            mime_type, _ = mimetypes.guess_file_type(path)
        except AttributeError:
            mime_type, _ = mimetypes.guess_type(path)

        self.logger.success(
            f"Client requested page at [i]{escape(target_path)}[/] ([b]{user_agent}[/])"
        )
        try:
            return self.send_page(target_path, mime_type or "text/html")
        except TemplateNotFound:
            self.logger.debug(f"Invalid path: {target_path}", is_client=True)
            self.send_error(HTTPStatus.NOT_FOUND)


class UPnPServer(ThreadingHTTPServer):
    service_name = "UPnP"

    def __init__(
        self,
        session,
        server_address=None,
        RequestHandlerClass=None,
    ) -> None:
        self.config = session
        self.server_config = session.upnp_config
        if bool(self.config.ipv6):
            self.address_family = socket.AF_INET6

        self.env = Environment(
            loader=FileSystemLoader(self.server_config.upnp_template),
            autoescape=select_autoescape(default=True),
        )
        address = server_address or (self.config.bind_address, 8080)
        super().__init__(address, RequestHandlerClass or UPnPHandler)

    def server_bind(self) -> None:
        bind_server(self, self.config)
        return super().server_bind()

    def finish_request(self, request, client_address) -> None:
        self.RequestHandlerClass(self.config, request, client_address, self)

    def render(self, template, **kwargs):
        return self.env.get_template(template).render(
            **kwargs,
            session=self.config,
            config=self.server_config,
            random=random_value,
        )
