.. Copyright (c) 2025-Present MatrixEditor
..
.. Permission is hereby granted, free of charge, to any person obtaining a copy
.. of this software and associated documentation files (the "Software"), to deal
.. in the Software without restriction, including without limitation the rights
.. to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
.. copies of the Software, and to permit persons to whom the Software is
.. furnished to do so, subject to the following conditions:
..
.. The above copyright notice and this permission notice shall be included in all
.. copies or substantial portions of the Software.
..
.. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
.. IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
.. FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
.. AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
.. LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
.. OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
.. SOFTWARE.
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