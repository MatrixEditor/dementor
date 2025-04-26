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
import os
import struct
import random
import threading

from collections import defaultdict
from typing import Any, Callable
from dataclasses import dataclass

from impacket.dcerpc.v5 import rpcrt, epm
from impacket import ntlm

from dementor.config.toml import TomlConfig, Attribute as A
from dementor.logger import ProtocolLogger, dm_logger
from dementor.protocols.ntlm import (
    NTLM_AUTH_CreateChallenge,
    ATTR_NTLM_ESS,
    ATTR_NTLM_CHALLENGE,
    NTLM_report_auth,
    NTLM_split_fqdn,
)
from dementor.servers import ThreadingTCPServer, BaseProtoHandler
from dementor.loader import ProtocolLoader

rev_rpc_status_codes = {name: value for value, name in rpcrt.rpc_status_codes.items()}


def uuid_name(uuid_bin: bytes) -> str:
    uuid_str, version = rpcrt.bin_to_uuidtup(uuid_bin)
    if uuid_bin == epm.MSRPC_UUID_PORTMAP:
        return f"EPMv4 v{version}"
    elif uuid_str in epm.KNOWN_PROTOCOLS:
        return f"{epm.KNOWN_PROTOCOLS[uuid_str]} v{version}"
    elif uuid_bin in epm.KNOWN_UUIDS:
        return f"{epm.KNOWN_UUIDS[uuid_bin]} v{version}"
    else:
        return f"UUID {uuid_str} v{version}"


class RPCConfig(TomlConfig):
    _section_ = "RPC"
    _fields_ = [
        A("rpc_fqdn", "FQDN", "DEMENTOR", section_local=False),
        A("epm_port", "EPM.TargetPort", 49000),
        A("epm_port_range", "EPM.TargetPortRange", None),
        A("rpc_modules", "Interfaces", list),
        A("rpc_error_code", "ErrorCode", "rpc_s_access_denied"),
        ATTR_NTLM_CHALLENGE,
        ATTR_NTLM_ESS,
    ]

    def set_rcp_error_code(self, value: str | int):
        if isinstance(value, str):
            value = rev_rpc_status_codes[value]

        if not isinstance(value, int):
            dm_logger.error(
                f"Invalid RPC error code: {value} - using default: rpc_s_access_denied"
            )
            value = rev_rpc_status_codes["rpc_s_access_denied"]

        self.rpc_error_code = value

    def set_epm_port_range(self, value: str | dict):
        start = end = None
        match value:
            case dict():
                # must store START and END
                start = value.get("start", 45000)
                end = value.get("end", 49999)

            case str():
                # format [START]-END or START-[END]
                values = value.split("-")
                if len(values) == 2:
                    start = values[0] or 45000
                    end = values[1] or 49999

        self.epm_port_range = None
        if start is not None and end is not None:
            if isinstance(start, str):
                start = int(start)

            if isinstance(end, str):
                end = int(end)

            self.epm_port_range = (start, end)
            self.epm_port = random.randrange(start, end)

    def set_rpc_modules(self, extra_paths: list):
        loader = ProtocolLoader()
        loader.search_path = [os.path.dirname(__file__)]
        loader.search_path.extend(extra_paths)
        self.rpc_modules = [
            loader.load_protocol(path) for path in loader.get_protocols().values()
        ]


@dataclass(slots=True)
class RPCConnection:
    call_id: int = -1
    ctx_id: int = -1
    auth_ctx_id: int = -1
    challenge: ntlm.NTLMAuthChallenge | None = None
    target: Any | None = None


class RPCHandler(BaseProtoHandler):
    def __init__(self, config, request, client_address, server) -> None:
        self.rpc_config = config.rpc_config
        super().__init__(config, request, client_address, server)

    def proto_logger(self) -> ProtocolLogger:
        return ProtocolLogger(
            extra={
                "protocol": "DCE/RPC",
                "protocol_color": "dark_violet",
                "host": self.client_host,
                "port": self.server.server_address[1],
            }
        )

    def _send_fault(self, header, code):
        packet = rpcrt.MSRPCRespHeader()
        packet["flags"] = rpcrt.PFC_FIRST_FRAG | rpcrt.PFC_LAST_FRAG
        packet["frag_len"] = 0
        packet["auth_len"] = 0
        packet["auth_data"] = b""
        packet["call_id"] = header["call_id"]
        packet["type"] = rpcrt.MSRPC_FAULT
        if code:
            packet["pduData"] = struct.pack("<LL", code, 0x00)
            packet["frag_len"] = len(packet)

        self.send(packet.get_packet())

    def handle_data(self, data, transport) -> None:
        transport.settimeout(0.3)
        while True:
            try:
                data = self.recv(8192)
            except OSError:
                break

            if not data:
                return

            header = rpcrt.MSRPCHeader(data)
            match header["type"]:
                case 0x00:  # Request
                    code = self.handle_request(data)
                case 0x0B:  # BIND
                    bind_req = rpcrt.MSRPCBind(header["pduData"])
                    code = self.handle_bind(header, bind_req)
                case 0x10:  # AUTH3
                    code = self.handle_auth3(header)
                case _:
                    code = rev_rpc_status_codes["rpc_fault_cant_perform"]

            if isinstance(code, str):
                code = rev_rpc_status_codes[code]

            if code != 0:
                self.server.rem_conn_by_call_id(header["call_id"])
                self._send_fault(header, code)
                break

    def handle_bind(
        self, header: rpcrt.MSRPCHeader, bind_req: rpcrt.MSRPCBind
    ) -> str | int:
        syntax = ("8a885d04-1ceb-11c9-9fe8-08002b104860", "2.0")
        bind_ack = rpcrt.MSRPCBindAck()

        bind_ack["type"] = rpcrt.MSRPC_BINDACK
        bind_ack["flags"] = rpcrt.PFC_FIRST_FRAG | rpcrt.PFC_LAST_FRAG
        bind_ack["frag_len"] = 0
        bind_ack["auth_len"] = 0
        bind_ack["auth_data"] = b""
        bind_ack["call_id"] = header["call_id"]
        bind_ack["max_tfrag"] = bind_req["max_tfrag"]
        bind_ack["max_rfrag"] = bind_req["max_rfrag"]
        bind_ack["assoc_group"] = 0x0CC5
        bind_ack["ctx_num"] = 0
        bind_ack["SecondaryAddrLen"] = 0

        ctx_items = []
        data = bind_req["ctx_items"]
        conn = self.server.get_conn_by_call_id(header["call_id"])
        endpoints = set()
        for _ in range(bind_req["ctx_num"]):
            result = rpcrt.MSRPC_CONT_RESULT_PROV_REJECT
            ctx_item = rpcrt.CtxItem(data)
            item_result = rpcrt.CtxItemResult()
            data = data[len(ctx_item) :]

            # The syntax must be checked. It will be one of the first entries
            # -> We have to select the right one
            if ctx_item["TransferSyntax"] == rpcrt.uuidtup_to_bin(syntax):
                # accepted, regardless of the abstract syntax (WE WANT TO CATCH 'EM ALL)
                reason = 0
                result = rpcrt.MSRPC_CONT_RESULT_ACCEPT
                bind_ack["SecondaryAddr"] = "135"  # send to the same port
                bind_ack["SecondaryAddrLen"] = 4
                item_result["TransferSyntax"] = rpcrt.uuidtup_to_bin(syntax)
            else:
                reason = 2  # transfer syntax not supported
                item_result["TransferSyntax"] = bytes(16)

            abstract_syntax = ctx_item["AbstractSyntax"]
            endpoints.add(uuid_name(abstract_syntax))
            conn.target = self.server.get_handler_by_uuid(abstract_syntax)

            bind_ack["ctx_num"] += 1
            item_result["Result"] = result
            item_result["Reason"] = reason
            ctx_items.append(item_result)

        bind_ack["Pad"] = "A" * (
            4 - ((bind_ack["SecondaryAddrLen"] + bind_ack._SIZE) % 4)
        )
        bind_ack["ctx_items"] = b"".join([i.getData() for i in ctx_items])

        endpoints_fmt = ", ".join({f"[b]{e}[/b]" for e in endpoints})
        # handle AUTH data if present
        if header["sec_trailer"]:
            sec_trailer = rpcrt.SEC_TRAILER(header["sec_trailer"])
            auth_type = sec_trailer["auth_type"]
            if auth_type != rpcrt.RPC_C_AUTHN_WINNT:
                # reject everything else
                self.logger.display(
                    f"Rejecting Bind request for {endpoints_fmt} using AuthType: {auth_type:#x}"
                )
                return rev_rpc_status_codes["nca_s_unsupported_authn_level"]

            token = header["auth_data"]
            auth_ctx_id = sec_trailer["auth_ctx_id"]
            conn.auth_ctx_id = auth_ctx_id
            (msg_type,) = struct.unpack("<L", token[8:12])
            if msg_type == 0x01:  # NEGOTIATE
                # generate challenge
                negotiate = ntlm.NTLMAuthNegotiate()
                negotiate.fromString(token)
                challenge = NTLM_AUTH_CreateChallenge(
                    negotiate,
                    *NTLM_split_fqdn(self.rpc_config.rpc_fqdn),
                    challenge=self.rpc_config.ntlm_challenge,
                    disable_ess=not self.rpc_config.ntlm_ess,
                )
                bind_ack["auth_data"] = challenge.getData()
                bind_ack["auth_len"] = len(bind_ack["auth_data"])
                bind_ack["sec_trailer"] = sec_trailer.getData()
                if endpoints_fmt:
                    self.logger.display(
                        f"Bind request for {endpoints_fmt} (NTLMSSP_NEGOTIATE)"
                    )
                conn.challenge = challenge
            else:
                self.logger.debug(f"(NTLM) Unhandled message type: {msg_type:#x}")
        else:
            if endpoints_fmt:
                self.logger.display(
                    f"Bind request for {endpoints_fmt} (TransferSyntax Negotiation)"
                )

        bind_ack["frag_len"] = len(bind_ack.getData())
        self.send(bind_ack.getData())
        return 0x00

    def handle_auth3(self, header: rpcrt.MSRPCHeader):
        if not header["sec_trailer"]:
            return rev_rpc_status_codes["nca_s_unsupported_authn_level"]

        sec_trailer = rpcrt.SEC_TRAILER(header["sec_trailer"])
        auth_type = sec_trailer["auth_type"]
        if auth_type != rpcrt.RPC_C_AUTHN_WINNT:
            # reject everything else
            self.logger.display(
                f"Rejecting AUTH3 request using AuthType: {auth_type:#x}"
            )
            return rev_rpc_status_codes["nca_s_unsupported_authn_level"]

        conn = self.server.get_conn_by_call_id(header["call_id"])
        token = header["auth_data"]
        if not conn.challenge:
            # challenge not set, invalid request
            return rev_rpc_status_codes["rpc_fault_cant_perform"]  # REVISIT

        auth_resp = ntlm.NTLMAuthChallengeResponse()
        auth_resp.fromString(token)
        NTLM_report_auth(
            auth_token=auth_resp,
            challenge=conn.challenge["challenge"],
            client=self.client_address,
            logger=self.logger,
            session=self.config,
        )
        return self.rpc_config.rpc_error_code

    def handle_request(self, data):
        request = rpcrt.MSRPCRequestHeader(data)
        conn = self.server.get_conn_by_call_id(request["call_id"])
        conn.ctx_id = request["ctx_id"]
        if not conn.target:
            # Interface not set, we can't handle this
            return rev_rpc_status_codes["nca_s_unk_if"]

        return conn.target(self, request, data)


RPCEndpointHandler = Callable[[RPCHandler, rpcrt.MSRPCHeader, bytes], int]


class MSRPCServer(ThreadingTCPServer):
    default_port = 135
    default_handler_class = RPCHandler
    service_name = "DCE/RPC"

    def __init__(
        self, config, handles=None, server_address=None, RequestHandlerClass=None
    ) -> None:
        self.conn_data = handles or defaultdict(RPCConnection)
        super().__init__(config, server_address, RequestHandlerClass)

    def get_conn_by_call_id(self, call_id: int) -> RPCConnection:
        with threading.Lock():
            conn = self.conn_data[call_id]
            if conn.call_id == -1:
                conn.call_id = call_id
        return conn

    def get_conn_by_auth_ctx_id(self, auth_ctx_id: int) -> RPCConnection:
        conn = next(
            filter(lambda x: x.auth_ctx_id == auth_ctx_id, self.conn_data.values()),
            None,
        )
        if conn is None:
            conn = RPCConnection()
            conn.auth_ctx_id = auth_ctx_id
            self.conn_data[auth_ctx_id] = conn
        return conn

    def rem_conn_by_call_id(self, call_id: int):
        self.conn_data.pop(call_id, None)

    def _module_handler(self, module) -> RPCEndpointHandler | None:
        func = getattr(module, "handle_request", None)
        if func:
            return func

        handler_cls = getattr(module, "RPCEndpointHandlerClass", None)
        if handler_cls:
            return handler_cls()

    def get_handler_by_uuid(self, uuid: bytes) -> RPCEndpointHandler | None:
        uuid_str, _ = rpcrt.bin_to_uuidtup(uuid)
        for module in self.config.rpc_config.rpc_modules:
            mod_uuid = getattr(module, "__uuid__", None)
            if mod_uuid == uuid or mod_uuid == uuid_str:
                return self._module_handler(module)

            if isinstance(mod_uuid, list):
                if uuid in mod_uuid or uuid_str.upper() in mod_uuid:
                    return self._module_handler(module)

        return None
