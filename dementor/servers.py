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
import traceback
import pathlib
import socket
import socketserver
import threading
import struct
import ssl
import errno
import sys

from io import StringIO
from typing import Any, ClassVar
from socketserver import BaseRequestHandler
from typing_extensions import override

from dementor import db
from dementor.log import hexdump
from dementor.log.logger import ProtocolLogger, dm_logger
from dementor.log.stream import log_host
from dementor.config.session import SessionConfig


class ServerThread(threading.Thread):
    """
    A thread-based server wrapper for running network protocol handlers.

    Provides graceful startup/shutdown and proper error handling.

    :param config: Session configuration object
    :type config: SessionConfig
    :param server_class: The server class to instantiate
    :type server_class: type
    :param args: Additional positional arguments for server_class
    :type args: tuple[Any, ...]
    :param kwargs: Additional keyword arguments for server_class
    :type kwargs: dict[str, Any]
    """

    def __init__(
        self, config: SessionConfig, server_class: type, *args: Any, **kwargs: Any
    ) -> None:
        self.config: SessionConfig = config
        self.server_class: type = server_class
        self.args: tuple[Any, ...] = args
        self.kwargs: dict[str, Any] = kwargs
        self._server: socketserver.BaseServer | None = None
        super().__init__(daemon=False)

    @property
    def service_name(self) -> str:
        """Get the service name from server class or use class name as fallback.

        :return: Service name.
        :rtype: str
        """
        return getattr(
            self.server_class,
            "service_name",
            self.server_class.__name__,
        )

    @property
    def server(self) -> socketserver.BaseServer:
        """Get the server instance if it has been created.

        :return: Server instance.
        :rtype: socketserver.BaseServer
        """
        if not self._server:
            raise ValueError("Server has not been initialized yet")
        return self._server

    @override
    def run(self) -> None:
        """Start and run the server indefinitely until shutdown is requested."""
        address: str = ""
        port: int = 0
        try:
            self._server = self.server_class(self.config, *self.args, **self.kwargs)
            address, port = self.server.server_address[:2]
            dm_logger.debug(f"Starting {self.service_name} Service on {address}:{port}")

            # Run server with periodic stop checks instead of blocking forever
            self.server.serve_forever()

        except OSError as e:
            if e.errno == errno.EACCES:  # Permission denied
                dm_logger.error(
                    f"Failed to start server for {self.service_name}: Permission Denied!"
                )
            elif e.errno == errno.EADDRINUSE:  # Address already in use
                dm_logger.error(
                    f"Failed to start server for {self.service_name}: "
                    f"Address {address}:{port} already in use"
                )
            else:
                dm_logger.error(
                    f"Failed to start server for {self.service_name} ({address}:{port}): {e}"
                )
        except Exception as e:
            dm_logger.exception(
                f"Failed to start server for {self.service_name} ({address}:{port}): {e}"
            )
        finally:
            self.shutdown()

    def shutdown(self) -> None:
        """Gracefully shutdown the server thread."""
        dm_logger.debug(f"Shutting down {self.service_name} Service")
        if self._server is not None:
            try:
                self.server.shutdown()
            except Exception as e:
                dm_logger.warning(f"Error during {self.service_name} shutdown: {e}")


class BaseProtoHandler(BaseRequestHandler):
    """Base handler for protocol-specific request processing.

    Provides common functionality for TCP/UDP protocol handlers including
    data sending/receiving, client tracking, and exception handling.
    """

    class TerminateConnection(Exception):
        """Exception to signal handler should terminate the connection."""

        pass

    def __init__(
        self,
        config: SessionConfig,
        request: socket.socket | tuple[bytes, socket.socket],
        client_address: tuple[str, int],
        server: socketserver.BaseServer,
    ) -> None:
        """Initialize the protocol handler.

        :param config: Session configuration
        :type config: SessionConfig
        :param request: Socket or (data, transport) tuple for UDP
        :type request: socket.socket | tuple[bytes, socket.socket]
        :param client_address: Client address tuple (host, port)
        :type client_address: tuple[str, int]
        :param server: Parent server instance
        :type server: socketserver.BaseServer
        """
        self.client_address: tuple[str, int] = client_address
        self.server: socketserver.BaseServer = server
        self.config: SessionConfig = config
        self.logger: ProtocolLogger = self.proto_logger()
        super(BaseProtoHandler, self).__init__(request, client_address, server)
        log_host(self.client_host)
        _ = self.config.db.add_host(self.client_host)

    def handle_data(self, data: bytes | None, transport: socket.socket) -> None:
        """Process incoming protocol data. Must be implemented by subclasses.

        :param data: Received data bytes (None for TCP)
        :type data: bytes | None
        :param transport: Socket object for sending responses
        :type transport: socket.socket
        """
        raise NotImplementedError(
            "handle_data must be implemented by protocol handlers"
        )

    def proto_logger(self) -> ProtocolLogger:
        """Return the :class:`ProtocolLogger` instance that will be exposed as ``self.logger``.

        Concrete classes typically return ``dm_logger`` or a subclass
        customised for a specific protocol.

        :return: Protocol logger instance.
        :rtype: ProtocolLogger
        """
        raise NotImplementedError

    @override
    def handle(self) -> None:
        """Main request handler. Retrieves data and dispatches to handle_data().

        Handles common exceptions and logs errors appropriately.
        """
        data: bytes | None = None
        try:
            if isinstance(self.request, tuple):
                data, transport = self.request
            else:
                transport = self.request
                data = None

            self.handle_data(data, transport)
        except BaseProtoHandler.TerminateConnection:
            pass
        except BrokenPipeError:
            pass  # connection closed, maybe log that
        except TimeoutError:
            pass
        except OSError as e:
            # Only log unexpected OS errors (not broken pipe/connection reset)
            if e.errno not in (errno.EPIPE, errno.ECONNRESET):
                self.logger.exception(e)
        except Exception as e:
            self.logger.fail(
                f"Error handling request from client ({e.__class__.__name__}) "
                + "- use --debug|--verbose to see traceback"
            )
            out = StringIO()
            traceback.print_exc(file=out)
            data = data or b""
            self.logger.debug(
                f"Error while handling request. Traceback:\n{out.getvalue()}\n"
                + f"Client request:\n{hexdump.hexdump(data)}"
            )

    def recv(self, size: int) -> bytes:
        """Receive data from client.

        Handles both TCP and UDP sockets appropriately.

        :param size: Maximum bytes to receive
        :type size: int
        :return: Received data bytes
        :rtype: bytes
        """
        if isinstance(self.request, tuple):
            # UDP: data already received in tuple
            data, transport = self.request
            self.request = (b"", transport)
        else:
            # TCP: receive from socket
            data = self.request.recv(size)

        return data

    def send(self, data: bytes) -> None:
        """Send data to client.

        Handles both TCP and UDP sockets appropriately.

        :param data: Bytes to send
        :type data: bytes
        """
        if isinstance(self.request, tuple):
            _, transport = self.request
            transport.sendto(data, self.client_address)
        else:
            transport = self.request
            transport.send(data)

    @property
    def client_host(self) -> str:
        """Get normalized client host address.

        :return: Normalized client host address.
        :rtype: str
        """
        return db.normalize_client_address(self.client_address[0])

    @property
    def client_port(self) -> int:
        """Get client port number.

        :return: Client port number.
        :rtype: int
        """
        return self.client_address[1]

    @property
    def server_port(self) -> int:
        """Get server port number.

        :return: Server port number.
        :rtype: int
        """
        return self.server.server_address[1]


class BaseServerProtoHandler(BaseProtoHandler):
    """Extended handler for protocol servers with protocol-specific configuration.

    Adds support for per-protocol configuration objects in addition to
    the session-level configuration.
    """

    def __init__(
        self,
        config: SessionConfig,
        server_config: Any,
        request: socket.socket | tuple[bytes, socket.socket],
        client_address: tuple[str, int],
        server: socketserver.BaseServer,
    ) -> None:
        """Initialize the server protocol handler.

        :param config: Session configuration
        :type config: SessionConfig
        :param server_config: Protocol-specific server configuration
        :type server_config: Any
        :param request: Socket or (data, transport) tuple
        :type request: socket.socket | tuple[bytes, socket.socket]
        :param client_address: Client address tuple
        :type client_address: tuple[str, int]
        :param server: Parent server instance
        :type server: socketserver.BaseServer
        """
        self.server_config: Any = server_config
        super().__init__(config, request, client_address, server)


class ThreadingUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    """Threaded UDP server with IPv6 support and cross-platform binding.

    :var default_port: Default port to listen on
    :var default_handler_class: Handler class for processing requests
    :var ipv4_only: Whether to only use IPv4 (skip IPv6)
    """

    default_port: ClassVar[int]
    default_handler_class: ClassVar[type]
    ipv4_only: bool

    allow_reuse_address: bool = True

    def __init__(
        self,
        config: SessionConfig,
        server_address: tuple[str, int] | None = None,
        RequestHandlerClass: type | None = None,
    ) -> None:
        """Initialize the UDP server.

        :param config: Session configuration
        :type config: SessionConfig
        :param server_address: (host, port) tuple or None to use defaults
        :type server_address: tuple[str, int] | None
        :param RequestHandlerClass: Handler class or None to use default
        :type RequestHandlerClass: type | None
        """
        self.config: SessionConfig = config
        self.ipv4_only = getattr(config, "ipv4_only", False)
        self.stop_flag = threading.Event()
        if config.ipv6 and not self.ipv4_only:
            self.address_family = socket.AF_INET6

        super().__init__(
            server_address or (self.config.bind_address, self.default_port),
            RequestHandlerClass or self.default_handler_class,
        )

    @override
    def server_bind(self) -> None:
        """Bind the server socket with interface and IPv6 settings."""
        bind_server(self, self.config)
        socketserver.UDPServer.server_bind(self)

    @override
    def finish_request(  # pyright: ignore[reportIncompatibleMethodOverride]
        self,
        request: bytes,
        client_address: tuple[str, int],
    ) -> None:
        """Finish a single request by instantiating the handler.

        :param request: The request data
        :type request: bytes
        :param client_address: Client address tuple
        :type client_address: tuple[str, int]
        """
        self.RequestHandlerClass(self.config, request, client_address, self)


def bind_server(
    server: socketserver.TCPServer | socketserver.UDPServer, session: SessionConfig
) -> None:
    """Configure socket options for interface binding and IPv6 behavior.

    Handles platform-specific socket options safely:
    - SO_BINDTODEVICE (Linux only)
    - IPV6_V6ONLY (IPv6 dual-stack behavior)

    :param server: Server instance with socket to configure
    :type server: socketserver.TCPServer | socketserver.UDPServer
    :param session: Session configuration with interface and IPv6 settings
    :type session: SessionConfig
    """
    # Platform-specific: SO_BINDTODEVICE only available on Linux
    if sys.platform == "linux" and hasattr(session, "interface"):
        try:
            interface = (session.interface or "").encode("ascii") + b"\x00"
            server.socket.setsockopt(
                socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface
            )
        except (OSError, AttributeError) as e:
            dm_logger.warning(f"Failed to bind to interface '{session.interface}': {e}")

    # Configure IPv6 dual-stack behavior (affects both IPv4 and IPv6 traffic)
    if session.ipv6 and not getattr(session, "ipv4_only", False):
        try:
            server.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, False)
        except OSError as e:
            dm_logger.warning(f"Failed to set IPV6_V6ONLY: {e}")


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """Threaded TCP server with IPv6 support and cross-platform binding.

    :var default_port: Default port to listen on
    :var default_handler_class: Handler class for processing requests
    :var ipv4_only: Whether to only use IPv4 (skip IPv6)
    """

    default_port: ClassVar[int]
    default_handler_class: ClassVar[type]
    ipv4_only: bool
    allow_reuse_address: bool = True

    def __init__(
        self,
        config: SessionConfig,
        server_address: tuple[str, int] | None = None,
        RequestHandlerClass: type | None = None,
    ) -> None:
        """Initialize the TCP server.

        :param config: Session configuration
        :type config: SessionConfig
        :param server_address: (host, port) tuple or None to use defaults
        :type server_address: tuple[str, int] | None
        :param RequestHandlerClass: Handler class or None to use default
        :type RequestHandlerClass: type | None
        """
        self.config: SessionConfig = config
        self.ipv4_only = getattr(config, "ipv4_only", False)
        self.stop_flag = threading.Event()
        if config.ipv6 and not self.ipv4_only:
            self.address_family = socket.AF_INET6
        super().__init__(
            server_address or (self.config.bind_address, self.default_port),
            RequestHandlerClass or self.default_handler_class,
        )

    @override
    def server_bind(self) -> None:
        """Bind the server socket with interface and IPv6 settings."""
        bind_server(self, self.config)
        socketserver.TCPServer.server_bind(self)

    @override
    def finish_request(  # pyright: ignore[reportIncompatibleMethodOverride]
        self,
        request: socket.socket,
        client_address: tuple[str, int],
    ) -> None:
        """Finish a single request by instantiating the handler.

        :param request: Connected socket
        :type request: socket.socket
        :param client_address: Client address tuple
        :type client_address: tuple[str, int]
        """
        self.RequestHandlerClass(self.config, request, client_address, self)


def create_tls_context(
    server_config: Any,
    server: socketserver.BaseServer | None = None,
    force: bool = False,
) -> ssl.SSLContext | None:
    """Create an SSL/TLS context from server configuration.

    :param server_config: Configuration object with use_ssl, certfile, keyfile attributes
    :type server_config: Any
    :param server: Optional server instance for logging service name
    :type server: socketserver.BaseServer | None
    :param force: Force SSL context creation even if use_ssl is False
    :type force: bool
    :return: Configured SSLContext or None if SSL not needed or files missing
    :rtype: ssl.SSLContext | None

    .. note:: Logs errors if certificate or key files not found.
    """
    if getattr(server_config, "use_ssl", False) or force:
        # if defined use ssl
        cert_path = pathlib.Path(str(getattr(server_config, "certfile", None)))
        key_path = pathlib.Path(str(getattr(server_config, "keyfile", None)))
        if not cert_path.exists() or not key_path.exists():
            service_name = getattr(server, "service_name", "<unknown>")
            dm_logger.error(
                f"({service_name}) Certificate or key file not found: "
                + f"Cert={cert_path} "
                + f"Key={key_path}"
            )
            return None
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        return ssl_context

    return None


def add_mcast_membership(
    target: socket.socket,
    session: SessionConfig,
    group4: str | None = None,
    group6: str | None = None,
    ttl: int = 255,
) -> None:
    """Add multicast group memberships to a socket.

    Handles both IPv4 and IPv6 multicast with platform-specific behavior.
    IPv6 multicast requires interface support (not available on Windows).

    :param target: Socket to configure
    :type target: socket.socket
    :param session: Session configuration with interface and IP info
    :type session: SessionConfig
    :param group4: IPv4 multicast group address (e.g., "224.0.0.1")
    :type group4: str | None
    :param group6: IPv6 multicast group address (e.g., "ff02::1")
    :type group6: str | None
    :param ttl: Time-to-live for multicast packets (default 255)
    :type ttl: int

    .. note:: Logs warnings for IPv6 multicast failures on Windows.
    """
    # Set TTL for all multicast packets
    target.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

    # IPv4 multicast
    if session.ipv4 and group4:
        try:
            mreq = socket.inet_aton(group4) + socket.inet_aton(session.ipv4)
            target.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            target.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
        except OSError as e:
            dm_logger.warning(f"Failed to join IPv4 multicast group {group4}: {e}")

    # IPv6 multicast (requires if_nametoindex, not available on Windows)
    if session.ipv6 and group6:
        try:
            mreq = socket.inet_pton(socket.AF_INET6, group6)
            mreq += struct.pack("@I", socket.if_nametoindex(session.interface))
            target.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
            target.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 1)
        except (OSError, AttributeError) as e:
            if sys.platform == "win32":
                dm_logger.debug(f"IPv6 multicast not fully supported on Windows: {e}")
            else:
                dm_logger.warning(f"Failed to join IPv6 multicast group {group6}: {e}")
