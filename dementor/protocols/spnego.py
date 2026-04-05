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
"""
SPNEGO Implementation.

This module provides an abstraction for handling SPNEGO negotiation as defined in RFC 4178.
SPNEGO allows clients and servers to negotiate which security mechanism to use for authentication,
such as Kerberos, NTLM, or others.
"""

import logging

from collections.abc import Callable
from impacket.spnego import SPNEGO_NegTokenResp, TypesMech, SPNEGO_NegTokenInit, MechTypes

logger = logging.getLogger(__name__)

# Predefined mechanism identifiers
SPNEGO_NTLMSSP_MECH = "NTLMSSP - Microsoft NTLM Security Support Provider"
SPNEGO_KERBEROS_MECH = "Kerberos"


class SPNEGONegotiator:
    """Handles SPNEGO negotiation for multiple security mechanisms.

    This class abstracts the SPNEGO protocol flow, allowing pluggable handlers
    for different security mechanisms.

    The negotiator maintains state across multiple rounds of negotiation and
    delegates mechanism-specific processing to user-provided callbacks.

    :ivar supported_mechs: List of mechanism names supported by this negotiator
    :ivar mech_handlers: dictionary mapping mechanism names to handler functions
    :ivar current_mech: The mechanism chosen during negotiation
    """

    # TODO: add logger instance here
    def __init__(self, supported_mechs: list[str], mech_handlers: dict[str, Callable]):
        """Initialize the SPNEGO negotiator.

        :param list supported_mechs: List of mechanism names this negotiator supports
        :param dict mech_handlers: dictionary mapping mechanism names to handler callables.
            Each handler should accept (mech_token: bytes, is_initiate: bool)
            and return a tuple (response_token: bytes, complete: bool)
        """
        self.supported_mechs: list[str] = supported_mechs
        self.mech_handlers: dict[str, Callable] = mech_handlers
        self.current_mech: str | None = None

    def process_token(self, token_data: bytes) -> tuple[bytes, bool]:
        """Process an incoming SPNEGO token and generate a response.

        This method handles the main SPNEGO negotiation flow:

        1. Parse the incoming token as NegTokenInit or NegTokenResp
        2. Determine the appropriate mechanism and delegate to handler
        3. Generate a NegTokenResp with the mechanism's response

        :param bytes token_data: Raw SPNEGO token bytes
        :return: Tuple of (response_bytes, negotiation_complete)
        :rtype: tuple
        :raises ValueError: If token cannot be parsed or mechanism is unsupported
        """
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
        """Handle a NegTokenInit from the client.

        The client proposes mechanisms and may include an initial token for one of them.

        :param SPNEGO_NegTokenInit token: Parsed NegTokenInit
        :return: Tuple of (response_bytes, negotiation_complete)
        :rtype: tuple
        """
        mech_types = [MechTypes.get(mech, "") for mech in token["MechTypes"]]
        mech_token = token.fields.get("MechToken")

        logger.debug(
            "SPNEGO: NegTokenInit received; mech_types=%s, has_mech_token=%s",
            mech_types,
            bool(mech_token),
        )

        # Find the first supported mechanism
        chosen_mech = None
        for mech in mech_types:
            if mech in self.supported_mechs:
                chosen_mech = mech
                break

        if not chosen_mech:
            # Reject negotiation
            logger.debug("SPNEGO: No supported mechanism found; rejecting negotiation")
            response = SPNEGO_NegTokenResp()
            response["NegState"] = b"\x02"  # reject
            return response.getData(), True

        self.current_mech = chosen_mech
        logger.debug("SPNEGO: Chosen mechanism %s", chosen_mech)
        handler = self.mech_handlers[chosen_mech]

        # Call the mechanism handler
        if mech_token:
            response_token, complete = handler(mech_token, is_initiate=True)
        else:
            response_token, complete = handler(None, is_initiate=True)

        logger.debug(
            "SPNEGO: Mechanism handler complete=%s, response_token_len=%s",
            complete,
            len(response_token) if response_token else 0,
        )

        # Build response
        response = build_neg_token_resp(
            0x00 if complete else 0x01, response_token, chosen_mech
        )
        return response.getData(), complete

    def _handle_neg_token_resp(self, token: SPNEGO_NegTokenResp) -> tuple[bytes, bool]:
        """Handle a NegTokenResp from the client.

        This is typically a response to our previous challenge.

        :param SPNEGO_NegTokenResp token: Parsed NegTokenResp
        :return: Tuple of (response_bytes, negotiation_complete)
        :rtype: tuple
        """
        if not self.current_mech:
            raise ValueError("No mechanism chosen yet")

        response_token = token.fields.get("ResponseToken")
        logger.debug(
            "SPNEGO: NegTokenResp received for mech=%s, has_response_token=%s",
            self.current_mech,
            bool(response_token),
        )
        handler = self.mech_handlers[self.current_mech]

        # Call the mechanism handler with the response
        final_token, complete = handler(response_token, is_initiate=False)

        logger.debug(
            "SPNEGO: Mechanism handler returned complete=%s, final_token_len=%s",
            complete,
            len(final_token) if final_token else 0,
        )

        # Build final response
        response = build_neg_token_resp(0x00 if complete else 0x01, final_token)
        return response.getData(), complete


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

    :param neg_state: Negotiation state - one of ``NEG_STATE_ACCEPT_COMPLETED``,
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
    """Create a NegTokenResp for a negotiation step.

    This is a legacy function for simple cases. For complex negotiation,
    use SPNEGONegotiator instead.

    :param int neg_result: Negotiation state (0=complete, 1=incomplete, 2=reject)
    :param bytes|None resp_token: Response token bytes
    :param str|None supported_mech: Supported mechanism name
    :return: NegTokenResp structure
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
