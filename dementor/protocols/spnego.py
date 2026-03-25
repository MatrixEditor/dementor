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
"""SPNEGO wrapper functions for building server-side GSS-API tokens.

Provides helpers that construct the SPNEGO negTokenInit (server mechanism
advertisement) and negTokenResp (challenge/reject responses) structures
used during SMB authentication. Wraps impacket's SPNEGO classes with
a simpler interface.

Spec references:
    [MS-SPNG] — SPNEGO Extension
    [RFC4178] — GSS-API Negotiation Mechanism (SPNEGO)
"""

from impacket.spnego import SPNEGO_NegTokenResp, TypesMech, SPNEGO_NegTokenInit

# --- Constants ---------------------------------------------------------------

# Impacket's mechanism name string for NTLMSSP
SPNEGO_NTLMSSP_MECH = "NTLMSSP - Microsoft NTLM Security Support Provider"

# [RFC4178] §4.2.2 / [MS-SPNG]: negState enumeration values for NegTokenResp.
# These indicate the outcome of each round of the SPNEGO exchange.
NEG_STATE_ACCEPT_COMPLETED: int = 0  # Authentication succeeded, context established
NEG_STATE_ACCEPT_INCOMPLETE: int = 1  # More tokens needed, exchange continues
NEG_STATE_REJECT: int = 2  # Authentication failed, mechanism rejected


# --- Functions ---------------------------------------------------------------


def build_neg_token_resp(
    neg_state: int,
    resp_token: bytes | None = None,
    supported_mech: str | None = None,
) -> SPNEGO_NegTokenResp:
    """Build a SPNEGO NegTokenResp message for the server's reply.

    Used during the NTLMSSP exchange to send the CHALLENGE_MESSAGE
    (with ``NEG_STATE_ACCEPT_INCOMPLETE``) or to signal final rejection
    (with ``NEG_STATE_REJECT``) after credential capture.

    Spec: [RFC4178] §4.2.2, [MS-SPNG] §3.2.5.2

    :param neg_state: Negotiation state — one of ``NEG_STATE_ACCEPT_COMPLETED``,
        ``NEG_STATE_ACCEPT_INCOMPLETE``, or ``NEG_STATE_REJECT``
    :type neg_state: int
    :param resp_token: The mechanism-specific response token (e.g., serialized
        NTLMSSP CHALLENGE_MESSAGE bytes), defaults to None
    :type resp_token: bytes | None, optional
    :param supported_mech: Impacket mechanism name string to include as
        the selected mechanism OID, defaults to None
    :type supported_mech: str | None, optional
    :return: Populated NegTokenResp ready for serialization via ``.getData()``
    :rtype: SPNEGO_NegTokenResp
    """
    response = SPNEGO_NegTokenResp()
    response["NegState"] = neg_state.to_bytes(1)
    if supported_mech:
        response["SupportedMech"] = TypesMech[supported_mech]
    if resp_token:
        response["ResponseToken"] = resp_token

    return response


def build_neg_token_init(mech_types: list[str]) -> SPNEGO_NegTokenInit:
    """Build a SPNEGO negTokenInit for the server's mechanism advertisement.

    Sent inside the SMB NEGOTIATE response SecurityBuffer to tell the
    client which authentication mechanisms the server supports.

    Spec: [MS-SPNG] §2.2.1 (NegTokenInit2), §3.2.5.2 (server-initiated)

    :param mech_types: List of impacket mechanism name strings to advertise
        (e.g., ``[SPNEGO_NTLMSSP_MECH]`` for NTLMSSP-only)
    :type mech_types: list[str]
    :return: Populated NegTokenInit ready for serialization via ``.getData()``
    :rtype: SPNEGO_NegTokenInit
    """
    token_init = SPNEGO_NegTokenInit()
    token_init["MechTypes"] = [TypesMech[x] for x in mech_types]
    return token_init
