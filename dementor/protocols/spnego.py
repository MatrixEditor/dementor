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
from impacket.spnego import SPNEGO_NegTokenResp, TypesMech, SPNEGO_NegTokenInit


SPNEGO_NTLMSSP_MECH = "NTLMSSP - Microsoft NTLM Security Support Provider"


def negTokenInit_step(
    neg_result: int,
    resp_token: bytes | None = None,
    supported_mech: str | None = None,
) -> SPNEGO_NegTokenResp:
    response = SPNEGO_NegTokenResp()
    response["NegState"] = neg_result.to_bytes(1)
    if supported_mech:
        response["SupportedMech"] = TypesMech[supported_mech]
    if resp_token:
        response["ResponseToken"] = resp_token

    return response


def negTokenInit(mech_types: list) -> SPNEGO_NegTokenInit:
    token_init = SPNEGO_NegTokenInit()
    token_init["MechTypes"] = [TypesMech[x] for x in mech_types]
    return token_init
