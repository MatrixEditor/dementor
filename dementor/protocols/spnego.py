from impacket.spnego import SPNEGO_NegTokenResp, TypesMech


def negTokenInit_step(
    negResult: int,
    respToken: bytes | None = None,
    supportedMech: str | None = None,
) -> SPNEGO_NegTokenResp:
    response = SPNEGO_NegTokenResp()
    response["NegState"] = negResult.to_bytes(1)
    if supportedMech:
        response["SupportedMech"] = TypesMech[supportedMech]
    if respToken:
        response["ResponseToken"] = respToken

    return response
