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
import logging

from collections.abc import Callable
from impacket.spnego import SPNEGO_NegTokenResp, TypesMech, SPNEGO_NegTokenInit, MechTypes

logger = logging.getLogger(__name__)

# Predefined mechanism identifiers
SPNEGO_NTLMSSP_MECH = "NTLMSSP - Microsoft NTLM Security Support Provider"
SPNEGO_KERBEROS_MECH = "Kerberos"


class SPNEGONegotiator:
    # TODO: add logger instance here
    def __init__(self, supported_mechs: list[str], mech_handlers: dict[str, Callable]):
        self.supported_mechs: list[str] = supported_mechs
        self.mech_handlers: dict[str, Callable] = mech_handlers
        self.current_mech: str | None = None

    def process_token(self, token_data: bytes) -> tuple[bytes, bool]:
        logger.debug(
            "SPNEGO: Processing token (len=%d, first_byte=0x%02x)",
            len(token_data),
            token_data[0] if token_data else 0,
        )
        try:
            if token_data[0] == 0x60:  # NegTokenInit (mech-independent token wrapper)
                token = SPNEGO_NegTokenInit(data=token_data)
                return self._handle_neg_token_init(token)

            if token_data[0] == 0xA1:  # NegTokenResp
                token = SPNEGO_NegTokenResp(data=token_data)
                return self._handle_neg_token_resp(token)

        except Exception as e:
            logger.debug("SPNEGO: Token parsing failed: %s", e)
            raise ValueError(f"Failed to parse SPNEGO token: {e}") from e

        raise ValueError("Invalid SPNEGO token format")

    def _handle_neg_token_init(self, token: SPNEGO_NegTokenInit) -> tuple[bytes, bool]:
        mech_types = [MechTypes.get(mech, "") for mech in token["MechTypes"]]
        mech_token = token.fields.get("MechToken")

        logger.debug(
            "SPNEGO: NegTokenInit received; mech_types=%s, has_mech_token=%s",
            mech_types,
            bool(mech_token),
        )

        chosen_mech = None
        for mech in mech_types:
            if mech in self.supported_mechs:
                chosen_mech = mech
                break

        if not chosen_mech:
            logger.debug("SPNEGO: No supported mechanism found; rejecting negotiation")
            response = SPNEGO_NegTokenResp()
            response["NegState"] = b"\x02"  # reject
            return response.getData(), True

        self.current_mech = chosen_mech
        logger.debug("SPNEGO: Chosen mechanism %s", chosen_mech)
        handler = self.mech_handlers[chosen_mech]

        if mech_token:
            response_token, complete = handler(mech_token, is_initiate=True)
        else:
            response_token, complete = handler(None, is_initiate=True)

        logger.debug(
            "SPNEGO: Mechanism handler complete=%s, response_token_len=%s",
            complete,
            len(response_token) if response_token else 0,
        )

        response = build_neg_token_resp(
            0x00 if complete else 0x01, response_token, chosen_mech
        )
        return response.getData(), complete

    def _handle_neg_token_resp(self, token: SPNEGO_NegTokenResp) -> tuple[bytes, bool]:
        if not self.current_mech:
            raise ValueError("No mechanism chosen yet")

        response_token = token.fields.get("ResponseToken")
        logger.debug(
            "SPNEGO: NegTokenResp received for mech=%s, has_response_token=%s",
            self.current_mech,
            bool(response_token),
        )
        handler = self.mech_handlers[self.current_mech]

        final_token, complete = handler(response_token, is_initiate=False)

        logger.debug(
            "SPNEGO: Mechanism handler returned complete=%s, final_token_len=%s",
            complete,
            len(final_token) if final_token else 0,
        )

        # Build final response
        response = build_neg_token_resp(0x00 if complete else 0x01, final_token)
        return response.getData(), complete


NEG_STATE_ACCEPT_COMPLETED: int = 0
NEG_STATE_ACCEPT_INCOMPLETE: int = 1
NEG_STATE_REJECT: int = 2


def build_neg_token_resp(
    neg_state: int,
    resp_token: bytes | None = None,
    supported_mech: str | None = None,
) -> SPNEGO_NegTokenResp:
    response = SPNEGO_NegTokenResp()
    response["NegState"] = neg_state.to_bytes(1)
    if supported_mech:
        response["SupportedMech"] = TypesMech[supported_mech]
    if resp_token:
        response["ResponseToken"] = resp_token

    return response


def build_neg_token_init(mech_types: list[str]) -> SPNEGO_NegTokenInit:
    token_init = SPNEGO_NegTokenInit()
    token_init["MechTypes"] = [TypesMech[x] for x in mech_types]
    return token_init
