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
# Heavily inspired by:
#   - https://github.com/xpn/ntlmquic
#   - https://github.com/ctjf/Responder/tree/master
import asyncio
import os

from threading import Thread
from typing import Optional

from aioquic.asyncio.server import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol, QuicStreamHandler
from aioquic.quic import events
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection


from dementor.config.toml import TomlConfig, Attribute as A
from dementor.config.session import SessionConfig
from dementor.logger import ProtocolLogger, ProtocolLoggerMixin, dm_logger


class QuicServerConfig(TomlConfig):
    _section_ = "QUIC"
    _fields_ = [
        A("quic_port", "Port", 443),
        A("quic_cert_path", "Cert", None, section_local=False),
        A("quic_cert_key", "Key", None, section_local=False),
        A("quic_smb_host", "TargetSMBHost", None),
        A("quic_smb_port", "TargetSMBPort", 445),  # default SMB
    ]


def apply_config(session):
    if session.quic_enabled:
        session.quic_config = TomlConfig.build_config(QuicServerConfig)


def create_server_threads(session):
    servers = []
    if session.quic_enabled:
        servers.append(QuicServerThread(session, session.bind_address, ipv6=bool(session.ipv6)))

    return servers


class QuicHandler(QuicConnectionProtocol, ProtocolLoggerMixin):
    def __init__(
        self,
        config: SessionConfig,
        host: str,
        quic: QuicConnection,
        stream_handler: Optional[QuicStreamHandler] = None,
    ):
        super().__init__(quic, stream_handler)
        self.host = host
        self.config = config
        #  stream_id -> (w, r)
        self.conn_data = {}
        ProtocolLoggerMixin.__init__(self)

    def proto_logger(self) -> ProtocolLogger:
        return ProtocolLogger(
            extra={
                "protocol": "QUIC",
                "protocol_color": "turquoise2",
                "port": self.config.quic_config.quic_port,
            }
        )

    @property
    def target_smb_host(self):
        return self.config.quic_config.quic_smb_host or self.host

    def quic_event_received(self, event: events.QuicEvent) -> None:
        match event:
            case events.StreamDataReceived():
                self.config.loop.create_task(
                    self.handle_data(event.stream_id, event.data)
                )

            # terminate connections if present
            case events.StreamReset():
                self.config.loop.create_task(self.close_connection(event.stream_id))

            case events.ConnectionTerminated():
                self.config.loop.create_task(self.close_all_connections())

    async def handle_data(self, stream_id, data):
        if stream_id not in self.conn_data:
            # create new connection
            network_path = self._quic._network_paths[0]
            self.logger.display(
                f"Forwarding QUIC connection to {self.target_smb_host}"
                f":{self.config.quic_config.quic_smb_port}",
                host=network_path.addr[0],
            )
            read, write = await asyncio.open_connection(
                self.target_smb_host,
                self.config.quic_config.quic_smb_port,
            )
            self.conn_data[stream_id] = (write, read)

            self.config.loop.create_task(self.proxy_quic_data(stream_id, read))
        else:
            write, read = self.conn_data[stream_id]

        # TODO: add exception handling
        write.write(data)
        await write.drain()  # flush

    async def proxy_quic_data(self, stream_id, read):
        try:
            while True:
                data = await read.read(8192)
                if not data:
                    break

                self._quic.send_stream_data(stream_id, data)
                self.transmit()
        finally:
            await self.close_connection(stream_id)

    async def close_connection(self, stream_id):
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


class QuicServerThread(Thread):
    def __init__(self, config: SessionConfig, host: str, ipv6=False):
        super().__init__()
        self.config = config
        self.host = host
        self.is_ipv6 = ipv6

    def run(self) -> None:
        self.config.loop.create_task(self.arun())

    def create_handler(self, *args, **kwargs):
        return QuicHandler(self.config, self.host, *args, **kwargs)

    async def arun(self):
        quic_config = QuicConfiguration(
            alpn_protocols=["smb"],
            is_client=False,
        )

        if not os.path.exists(self.config.quic_config.quic_cert_path):
            dm_logger.error(
                f"Failed to start QUIC server on {self.host}:{self.config.quic_config.quic_port}: "
                "Certificate file does not exist!"
            )
            return

        if not os.path.exists(self.config.quic_config.quic_cert_key):
            dm_logger.error(
                f"Failed to start QUIC server on {self.host}:{self.config.quic_config.quic_port}: "
                "Certificate key file does not exist!"
            )
            return

        quic_config.load_cert_chain(
            self.config.quic_config.quic_cert_path,
            self.config.quic_config.quic_cert_key,
        )
        dm_logger.debug(
            f"Starting QUIC server on {self.host}:{self.config.quic_config.quic_port}"
        )
        await serve(
            host=self.host,
            port=self.config.quic_config.quic_port,
            configuration=quic_config,
            create_protocol=self.create_handler,
        )
