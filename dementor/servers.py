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
import socketserver
import threading
import abc

from typing import Tuple
from socketserver import BaseRequestHandler

from dementor import database
from dementor.logger import ProtocolLoggerMixin, dm_logger
from dementor.config import SessionConfig


class ServerThread(threading.Thread):
    def __init__(self, config: SessionConfig, server_class: type, *args, **kwargs):
        self.config = config
        self.server_class = server_class
        self.args = args
        self.kwargs = kwargs
        super().__init__()

    @property
    def service_name(self) -> str:
        return getattr(
            self.server_class,
            "service_name",
            self.server_class.__name__,
        )

    def run(self) -> None:
        try:
            self.server = self.server_class(self.config, *self.args, **self.kwargs)
            address, port, *_ = self.server.server_address
            dm_logger.debug(f"Starting {self.service_name} Service on {address}:{port}")
            self.server.serve_forever()

        except OSError as e:
            if e.errno == 13:
                dm_logger.error(
                    f"Failed to start server for {self.service_name}: Permission Denied!"
                )
            print(e)
        except Exception as e:
            print(e)


class BaseProtoHandler(BaseRequestHandler, ProtocolLoggerMixin):
    def __init__(self, config: SessionConfig, request, client_address, server) -> None:
        self.client_address = client_address
        self.server = server
        self.config = config
        ProtocolLoggerMixin.__init__(self)
        super().__init__(request, client_address, server)

    @abc.abstractmethod
    def handle_data(self, data, transport) -> None:
        pass

    def handle(self) -> None:
        try:
            if isinstance(self.request, tuple):
                data, transport = self.request
            else:
                transport = self.request
                data = None

            self.handle_data(data, transport)
        except BrokenPipeError:
            pass  # connection closed, maybe log that
        except Exception as e:
            self.logger.exception(e)

    def recv(self, size: int) -> bytes:
        if isinstance(self.request, tuple):
            # UDP can't receive a single packet
            # REVISIT: should we return this here?
            data, transport = self.request
            self.request = (b"", transport)
        else:
            data = self.request.recv(size)

        return data

    def send(self, data: bytes) -> None:
        if isinstance(self.request, tuple):
            _, transport = self.request
            transport.sendto(data, self.client_address)
        else:
            transport = self.request
            transport.send(data)

    @property
    def client_host(self) -> str:
        return database.normalize_client_address(self.client_address[0])

    @property
    def client_port(self) -> int:
        return self.client_address[1]


class ThreadingUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    default_port: int
    default_handler_class: type
    ipv4_only: bool

    allow_reuse_address = True

    def __init__(
        self,
        config: SessionConfig,
        server_address: Tuple[str, int] | None = None,
        RequestHandlerClass: type | None = None,
    ) -> None:
        self.config = config
        self.ipv4_only = getattr(config, "ipv4_only", False)
        if config.ipv6 and not self.ipv4_only:
            self.address_family = socket.AF_INET6

        super().__init__(
            server_address or ("", self.default_port),
            RequestHandlerClass or self.default_handler_class,
        )

    def server_bind(self) -> None:
        bind_server(self, self.config)
        socketserver.UDPServer.server_bind(self)

    def finish_request(self, request, client_address) -> None:
        self.RequestHandlerClass(self.config, request, client_address, self)


def bind_server(server, session):
    interface = session.interface.encode("ascii") + b"\x00"
    server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface)
    if session.ipv6 and not getattr(session, "ipv4_only", False):
        server.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, False)


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    default_port: int
    default_handler_class: type
    ipv4_only: bool

    allow_reuse_address = True

    def __init__(
        self,
        config: SessionConfig,
        server_address: Tuple[str, int] | None = None,
        RequestHandlerClass: type | None = None,
    ) -> None:
        self.config = config
        self.ipv4_only = getattr(config, "ipv4_only", False)
        if config.ipv6 and not self.ipv4_only:
            self.address_family = socket.AF_INET6
        super().__init__(
            server_address or ("", self.default_port),
            RequestHandlerClass or self.default_handler_class,
        )

    def server_bind(self) -> None:
        bind_server(self, self.config)
        socketserver.TCPServer.server_bind(self)

    def finish_request(self, request, client_address) -> None:
        self.RequestHandlerClass(self.config, request, client_address, self)
