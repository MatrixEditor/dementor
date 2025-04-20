from array import array
from impacket.dcerpc.v5 import dcomrt, rpcrt
from dementor.protocols.msrpc.rpc import rev_rpc_status_codes


__uuid__ = [
    "00000000-0000-0000-C000-000000000046",
    "00000131-0000-0000-C000-000000000046",
    "00000134-0000-0000-C000-000000000046",
    "00000143-0000-0000-C000-000000000046",
    "000001A0-0000-0000-C000-000000000046",
    "18F70770-8E64-11CF-9AF1-0020AF6E72F4",
    "4D9F4AB8-7D1C-11CF-861E-0020AF6E7C57",
    "6050B110-CE87-4126-A114-50AEFCFC95F8",
    "99FCFEC4-5260-101B-BBCB-00AA0021347A",
]


def handle_request(rpc, request: rpcrt.MSRPCRequestHeader, _data) -> int | str:
    op_num = request["op_num"]

    if op_num == dcomrt.ServerAlive2.opnum:
        # build response packet with our IP in answer RR
        alive_resp = dcomrt.ServerAlive2Response()
        alive_resp["pComVersion"] = dcomrt.COMVERSION()
        alive_resp["ErrorCode"] = 0

        bindings = dcomrt.DUALSTRINGARRAY()
        data_buf = array("H")

        # StringBinding: current IPv4 (we could also use hostname here)
        binding = dcomrt.STRINGBINDING()
        binding["wTowerId"] = 0x07  # ncacn_ip_tcp
        binding["aNetworkAddr"] = f"{rpc.config.ipv4}\x00"
        data_buf.extend(array("H", binding.getData()))

        data_buf.append(0x00) # end of string bindings
        sec_offset = len(data_buf)

        # We only support NTLM Authentication
        binding = dcomrt.SECURITYBINDING()
        binding["wAuthnSvc"] = rpcrt.RPC_C_AUTHN_WINNT
        binding["aPrincName"] = "\x00"
        binding["Reserved"] = 0xFFFF
        data_buf.extend(array("H", binding.getData()))
        data_buf.append(0x00) # end of security bindings

        bindings["wNumEntries"] = len(data_buf)
        bindings["wSecurityOffset"] = sec_offset
        bindings["aStringArray"] = data_buf
        alive_resp["ppdsaOrBindings"] = bindings

        resp = rpcrt.MSRPCRespHeader()
        resp["type"] = rpcrt.MSRPC_RESPONSE
        resp["call_id"] = request["call_id"]
        resp["ctx_id"] = request["ctx_id"]
        resp["auth_data"] = b""
        resp["flags"] = rpcrt.PFC_FIRST_FRAG | rpcrt.PFC_LAST_FRAG
        resp["pduData"] = alive_resp.getData()
        resp["frag_len"] = len(resp.get_packet())
        resp["alloc_hint"] = len(resp.get_packet())
        rpc.send(resp.getData())
        return 0

    return rev_rpc_status_codes["nca_s_unk_op"]
