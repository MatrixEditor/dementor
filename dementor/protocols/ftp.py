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
from dementor.config.toml import TomlConfig, Attribute as A
from dementor.config.util import get_value
from dementor.logger import ProtocolLogger
from dementor.servers import BaseProtoHandler, ThreadingTCPServer, ServerThread
from dementor.database import _CLEARTEXT

ReplyCodes = {
    220: b"220 Service ready for new user.",
    331: b"331 User name okay, need password.",
    501: b"501 Syntax error in parameters or arguments.",
    502: b"502 Command not implemented.",
    530: b"530 Not logged in.",
}


class FTPServerConfig(TomlConfig):
    _section_ = "FTP"
    _fields_ = [A("ftp_port", "Port")]


def apply_config(session) -> None:
    session.ftp_config = []
    if session.ftp_enabled:
        for server_config in get_value("FTP", "Server", default=[]):
            session.ftp_config.append(FTPServerConfig(server_config))


def create_server_threads(session) -> list:
    return [
        ServerThread(session, FTPServer, server_address=("", server_config.ftp_port))
        for server_config in session.ftp_config
    ]


class FTPHandler(BaseProtoHandler):
    def proto_logger(self) -> ProtocolLogger:
        return ProtocolLogger(
            extra={
                "protocol": "FTP",
                "protocol_color": "medium_purple2",
                "host": self.client_host,
                "port": self.server.server_address[1],
            }
        )

    def handle_data(self, data, transport) -> None:
        # Server ready for new user
        self.reply(220)

        data = transport.recv(1024)
        if len(data) < 4:
            # ignore short packets and return error
            self.reply(502)
            return

        if data[:4] == b"USER":
            user_name = data[4:].decode(errors="replace").strip()
            if not user_name:
                self.reply(501)
                return

            self.reply(331)
            data = transport.recv(1024)
            if len(data) >= 4 and data[:4] == b"PASS":
                password = data[4:].decode(errors="replace").strip()

                self.config.db.add_auth(
                    client=self.client_address,
                    credtype=_CLEARTEXT,
                    username=user_name,
                    password=password,
                    logger=self.logger,
                )
                self.reply(502)  # Command not implemented rather than error
                return

        self.reply(501)

    def reply(self, code: int) -> None:
        self.request.send(ReplyCodes[code] + b"\r\n")


class FTPServer(ThreadingTCPServer):
    default_port = 21
    default_handler_class = FTPHandler
    service_name = "FTP"
