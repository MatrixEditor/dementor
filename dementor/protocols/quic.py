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
# pyright: reportUninitializedInstanceVariable=false
# Heavily inspired by:
#   - https://github.com/xpn/ntlmquic
#   - https://github.com/ctjf/Responder/tree/master
import asyncio
import os
import typing
import datetime
import tempfile

from typing_extensions import override

from dementor.loader import DEFAULT_ATTR, BaseProtocolModule
from dementor.servers import AsyncServerThread, BaseServerThread

from aioquic.asyncio.server import QuicServer, serve
from aioquic.asyncio.protocol import QuicConnectionProtocol, QuicStreamHandler
from aioquic.quic import events
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes


from dementor.config.toml import TomlConfig, Attribute as A
from dementor.config.session import SessionConfig
from dementor.log.logger import ProtocolLogger, dm_logger

__proto__ = ["Quic"]


class QuicServerConfig(TomlConfig):
    _section_ = "QUIC"
    _fields_ = [
        A("quic_port", "Port", 443),
        A("quic_cert_path", "Cert", "", section_local=False),
        A("quic_cert_key", "Key", "", section_local=False),
        A("quic_smb_host", "TargetSMBHost", None),
        A("quic_smb_port", "TargetSMBPort", 445),  # default SMB
        A("quic_self_signed", "SelfSigned", True),
        A("quic_cert_cn", "CertCommonName", "dementor.local"),
        A("quic_cert_org", "CertOrganization", "Dementor"),
        A("quic_cert_country", "CertCountry", "US"),
        A("quic_cert_state", "CertState", "CA"),
        A("quic_cert_locality", "CertLocality", "San Francisco"),
        A("quic_cert_validity_days", "CertValidityDays", 365),
    ]

    if typing.TYPE_CHECKING:
        quic_port: int
        quic_cert_path: str
        quic_cert_key: str
        quic_smb_host: str | None
        quic_smb_port: int
        quic_self_signed: bool
        quic_cert_cn: str
        quic_cert_org: str
        quic_cert_country: str
        quic_cert_state: str
        quic_cert_locality: str
        quic_cert_validity_days: int


class Quic(BaseProtocolModule[QuicServerConfig]):
    name = "QUIC"
    config_ty = QuicServerConfig
    config_enabled_attr = DEFAULT_ATTR
    config_attr = DEFAULT_ATTR

    @override
    def create_server_thread(
        self, session: SessionConfig, server_config: QuicServerConfig
    ) -> BaseServerThread[QuicServerConfig]:
        return QuicServerThread(
            session,
            server_config,
            session.bind_address,
            ipv6=bool(session.ipv6),
        )


class QuicHandler(QuicConnectionProtocol):
    def __init__(
        self,
        config: SessionConfig,
        host: str,
        quic: QuicConnection,
        stream_handler: QuicStreamHandler | None = None,
    ):
        super().__init__(quic, stream_handler)
        self.host: str = host
        self.config: SessionConfig = config
        #  stream_id -> (w, r)
        self.conn_data: dict[int, tuple[asyncio.StreamWriter, asyncio.StreamReader]] = {}
        self.logger: ProtocolLogger = QuicHandler.proto_logger(
            self.config.quic_config.quic_port
        )

    @staticmethod
    def proto_logger(port: int) -> ProtocolLogger:
        return ProtocolLogger(
            extra={
                "protocol": "QUIC",
                "protocol_color": "turquoise2",
                "port": port,
            }
        )

    @property
    def target_smb_host(self):
        return self.config.quic_config.quic_smb_host or self.host

    @override
    def quic_event_received(self, event: events.QuicEvent) -> None:
        match event:
            case events.StreamDataReceived():
                _ = self.config.loop.create_task(
                    self.handle_data(event.stream_id, event.data)
                )

            # terminate connections if present
            case events.StreamReset():
                _ = self.config.loop.create_task(self.close_connection(event.stream_id))

            case events.ConnectionTerminated():
                _ = self.config.loop.create_task(self.close_all_connections())

            case _:
                pass  # ignore other events for now

    async def handle_data(self, stream_id: int, data: bytes):
        if stream_id not in self.conn_data:
            # create new connection
            network_path = self._quic._network_paths[0]
            self.logger.display(
                f"Forwarding QUIC connection to {self.target_smb_host}:{self.config.quic_config.quic_smb_port}",
                host=network_path.addr[0],
            )
            read, write = await asyncio.open_connection(
                self.target_smb_host,
                self.config.quic_config.quic_smb_port,
            )
            self.conn_data[stream_id] = (write, read)

            _ = self.config.loop.create_task(self.proxy_quic_data(stream_id, read))
        else:
            write, read = self.conn_data[stream_id]

        # TODO: add exception handling
        write.write(data)
        await write.drain()  # flush

    async def proxy_quic_data(self, stream_id: int, read: asyncio.StreamReader):
        try:
            while True:
                data = await read.read(8192)
                if not data:
                    break

                self._quic.send_stream_data(stream_id, data)
                self.transmit()
        finally:
            await self.close_connection(stream_id)

    async def close_connection(self, stream_id: int):
        if stream_id in self.conn_data:
            self.logger.debug(
                f"Closing down QUIC connection with {self._quic._network_paths[0].addr[0]}"
            )
            write, _ = self.conn_data.pop(stream_id, (None, None))
            if write is not None:
                write.close()
                await write.wait_closed()

    async def close_all_connections(self):
        for stream_id in self.conn_data:
            await self.close_connection(stream_id)


class QuicServerThread(AsyncServerThread[QuicServerConfig]):
    def __init__(
        self,
        config: SessionConfig,
        server_config: QuicServerConfig,
        host: str,
        ipv6: bool = False,
    ):
        super().__init__(config, server_config)
        self.host: str = host
        self.is_ipv6: bool = ipv6
        self._server: QuicServer | None = None
        self._generated_temp_cert: bool = False

    def generate_self_signed_cert(self) -> None:
        """Generate a self-signed certificate and private key for QUIC server."""
        logger = QuicHandler.proto_logger(self.server_config.quic_port)
        logger.display("Generating self-signed certificate for QUIC server")

        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Create certificate
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(
                    NameOID.COUNTRY_NAME, self.server_config.quic_cert_country
                ),
                x509.NameAttribute(
                    NameOID.STATE_OR_PROVINCE_NAME, self.server_config.quic_cert_state
                ),
                x509.NameAttribute(
                    NameOID.LOCALITY_NAME, self.server_config.quic_cert_locality
                ),
                x509.NameAttribute(
                    NameOID.ORGANIZATION_NAME, self.server_config.quic_cert_org
                ),
                x509.NameAttribute(NameOID.COMMON_NAME, self.server_config.quic_cert_cn),
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
                datetime.datetime.now(datetime.UTC)
                + datetime.timedelta(days=self.server_config.quic_cert_validity_days)
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName(self.server_config.quic_cert_cn),
                    ]
                ),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )

        # Create temporary files
        cert_fd, cert_path = tempfile.mkstemp(suffix=".pem")
        key_fd, key_path = tempfile.mkstemp(suffix=".key")

        # Save private key
        with os.fdopen(key_fd, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        # Save certificate
        with os.fdopen(cert_fd, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        # Update config with temporary paths
        self.server_config.quic_cert_path = cert_path
        self.server_config.quic_cert_key = key_path
        self._generated_temp_cert = True

    def get_service_name(self) -> str:
        return "QUIC"

    def create_handler(self, *args: typing.Any, **kwargs: typing.Any):
        return QuicHandler(self.config, self.host, *args, **kwargs)

    @override
    async def arun(self):
        quic_config = QuicConfiguration(
            alpn_protocols=["smb"],
            is_client=False,
        )

        if not os.path.exists(self.server_config.quic_cert_path) or not os.path.exists(
            self.server_config.quic_cert_key
        ):
            if not self.server_config.quic_self_signed:
                dm_logger.error(
                    "QUIC certificate or key not found and self-signed generation is disabled"
                )
                return
            self.generate_self_signed_cert()

        quic_config.load_cert_chain(
            self.server_config.quic_cert_path,
            self.server_config.quic_cert_key,
        )
        dm_logger.debug(
            f"Starting QUIC server on {self.host}:{self.server_config.quic_port}"
        )
        self._server = await serve(
            host=self.host,
            port=self.server_config.quic_port,
            configuration=quic_config,
            create_protocol=self.create_handler,
        )

    @override
    async def ashutdown(self) -> None:
        if self._server:
            self._server.close()
        if self._generated_temp_cert:
            try:
                if os.path.exists(self.server_config.quic_cert_path):
                    os.remove(self.server_config.quic_cert_path)
                if os.path.exists(self.server_config.quic_cert_key):
                    os.remove(self.server_config.quic_cert_key)
            except OSError as e:
                dm_logger.warning(f"Failed to delete temporary QUIC certificate files: {e}")
