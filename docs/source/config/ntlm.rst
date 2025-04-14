
.. _config_ntlm:

NTLM
====

Section ``[NTLM]``
------------------

.. py:currentmodule:: NTLM

.. py:attribute:: Challenge
    :type: HexStr | str
    :value: "1337LEET"

    *Linked to* :attr:`config.SessionConfig.ntlm_challenge`

    Specifies the NTLM challenge value to use during authentication. The value must be exactly ``8`` characters in length
    and can be provided as a hexadecimal string or a plain ASCII string.

    If this option is omitted (i.e., commented out in the configuration), a random challenge will be generated at startup.

    .. container:: demo

        .. code-block:: text
            :emphasize-lines: 21

            NetBIOS Session Service
            SMB2 (Server Message Block Protocol version 2)
                SMB2 Header
                    [...]
                Session Setup Response (0x01)
                    StructureSize: 0x0009
                    Session Flags: 0x0000
                    Blob Offset: 0x00000048
                    Blob Length: 201
                    Security Blob [...]:
                        GSS-API Generic Security Service Application Program Interface
                            Simple Protected Negotiation
                                negTokenTarg
                                    negResult: accept-incomplete (1)
                                    supportedMech: 1.3.6.1.4.1.311.2.2.10 (NTLMSSP - Microsoft NTLM Security Support Provider)
                                    NTLM Secure Service Provider
                                        NTLMSSP identifier: NTLMSSP
                                        NTLM Message Type: NTLMSSP_CHALLENGE (0x00000002)
                                        Target Name: WORKGROUP
                                        [...] Negotiate Flags: 0xe28a0217
                                        NTLM Server Challenge: 74d6b7f11d68baa2
                                        Reserved: 0000000000000000
                                        Target Info
                                        Version 255.255 (Build 65535); NTLM Current Revision 255

.. py:attribute:: ExtendedSessionSecurity
    :value: true
    :type: bool

    *Linked to* :attr:`config.SessionConfig.ntlm_ess`

    Enable Extended Session Security (ESS) for NTLM authentication. ESS results in NTLMv1/v2-SSP
    hashes instead of regular NTLMv1/v2 hashes.


Default Configuration
---------------------

.. code-block:: toml
    :linenos:
    :caption: NTLM configuration section (default values)

    [NTLM]
    Challenge = "1337LEET"
    ExtendedSessionSecurity = true