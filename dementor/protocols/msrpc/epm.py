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
import struct

from impacket.dcerpc.v5 import epm, rpcrt
from dementor.protocols.msrpc.rpc import uuid_name, rev_rpc_status_codes

__uuid__ = epm.MSRPC_UUID_PORTMAP


def handle_request(rpc, request: rpcrt.MSRPCRequestHeader, _data) -> int | str:
    op_num = request["op_num"]
    if op_num == 0x03:
        # Operation: Map (3)
        map_req = epm.ept_map(request["pduData"])
        map_resp = epm.ept_mapResponse()
        map_resp["status"] = 0  # success
        map_resp["num_towers"] = 1
        map_resp["entry_handle"] = map_req["entry_handle"]

        req_tower = epm.EPMTower(b"".join(map_req["map_tower"]["tower_octet_string"]))
        req_floors = req_tower["Floors"]
        resp_tower = epm.EPMTower()
        resp_floors = []

        # First floor will be the interface
        interface = req_floors[0]["InterfaceUUID"]
        interface += struct.pack(
            "<HH", req_floors[0]["MajorVersion"], req_floors[0]["MinorVersion"]
        )
        # Second floor must map to the same syntax -> TODO
        # Third floor MUST be TCP
        resp_floors.extend(req_floors[:3])

        epm_port = epm.EPMPortAddr()
        epm_port["IpPort"] = rpc.rpc_config.epm_port
        resp_floors.append(epm_port)

        epm_host = epm.EPMHostAddr()
        epm_host["Ip4addr"] = socket.inet_aton(rpc.config.ipv4)
        resp_floors.append(epm_host)

        resp_tower["NumberOfFloors"] = len(resp_floors)
        resp_tower["Floors"] = b"".join([i.getData() for i in resp_floors])

        resp_tower_data = epm.twr_p_t()
        resp_tower_data["tower_octet_string"] = resp_tower.getData()
        resp_tower_data["tower_length"] = len(resp_tower_data["tower_octet_string"])
        resp_tower_data["ReferentID"] = 3

        # NOTE: impacket automatically sets "MaximumCount" to 1, which causes connections
        # to fail with Windows systems. We should use 4 (default) or the number mentioned
        # in the request.
        resp_towers = epm.twr_p_t_array()
        resp_towers["Data"] = [resp_tower_data]
        resp_towers["ActualCount"] = 1
        resp_towers["MaximumCount"] = 4
        map_resp["ITowers"] = resp_towers
        rpc.logger.display(f"Map request for [b]{uuid_name(interface)}[/]")

        resp = rpcrt.MSRPCRespHeader()
        resp["type"] = rpcrt.MSRPC_RESPONSE
        resp["call_id"] = request["call_id"]
        resp["ctx_id"] = request["ctx_id"]
        resp["auth_data"] = b""
        resp["flags"] = rpcrt.PFC_FIRST_FRAG | rpcrt.PFC_LAST_FRAG
        resp["pduData"] = map_resp.getData()
        resp["frag_len"] = len(resp.get_packet())
        resp["alloc_hint"] = len(resp.get_packet())
        rpc.send(resp.get_packet())
        return 0

    return rev_rpc_status_codes["nca_s_unk_op"]
