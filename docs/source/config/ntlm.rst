.. _config_ntlm:

NTLM
====

Section ``[NTLM]``
------------------

.. py:currentmodule:: NTLM

.. py:attribute:: Challenge
    :type: HexStr | str
    :value: None (random at startup)

    *Linked to* :attr:`config.SessionConfig.ntlm_challenge`

    Specifies the NTLM ServerChallenge nonce sent in the ``CHALLENGE_MESSAGE``.
    The value must represent exactly ``8`` bytes and can be given in any of the
    following formats:

    - ``"hex:1122334455667788"`` — explicit hex (recommended)
    - ``"ascii:1337LEET"`` — explicit ASCII (recommended)
    - ``"1122334455667788"`` — 16 hex characters (auto-detected as hex)
    - ``"1337LEET"`` — 8 ASCII characters (auto-detected as ASCII)

    If this option is omitted, a cryptographically random challenge is generated
    once at startup and reused for all connections.

    .. note::

        A fixed challenge such as ``"1122334455667788"`` combined with rainbow
        tables can crack NetNTLMv1 hashes offline without GPU resources.  Use a
        random (unset) challenge unless you specifically need a fixed value.

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

.. py:attribute:: DisableExtendedSessionSecurity
    :value: false
    :type: bool

    *Linked to* :attr:`config.SessionConfig.ntlm_disable_ess`

    When ``true``, strips the ``NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY``
    flag from the ``CHALLENGE_MESSAGE``, preventing ESS negotiation.

    **Effect on captured hashes:**

    - ``false`` (default) — ESS is negotiated when the client requests it.
      NTLMv1 clients produce **NetNTLMv1-ESS** hashes (hashcat ``-m 5500``).
      ESS uses ``MD5(ServerChallenge ‖ ClientChallenge)[0:8]`` as the effective
      challenge; hashcat derives this internally from the emitted ``ClientChallenge``
      field.

    - ``true`` — ESS is suppressed.  NTLMv1 clients produce plain **NetNTLMv1**
      hashes.  A fixed :attr:`Challenge` combined with rainbow tables can crack
      these without GPU resources.

    .. note::

        Dementor detects ESS from the ``LmChallengeResponse`` byte structure
        (``len == 24`` and ``LM[8:24] == Z(16)`` per ``[MS-NLMP §3.3.1]``)
        rather than solely from the flag, so classification is accurate even
        when this setting is toggled.

.. py:attribute:: DisableNTLMv2
    :value: false
    :type: bool

    *Linked to* :attr:`config.SessionConfig.ntlm_disable_ntlmv2`

    When ``true``, clears ``NTLMSSP_NEGOTIATE_TARGET_INFO`` and omits the
    ``TargetInfoFields`` (AV_PAIRS) from the ``CHALLENGE_MESSAGE``.

    **Effect on captured hashes:**

    - ``false`` (default) — ``TargetInfoFields`` is populated.  Clients can
      construct an NTLMv2 response and produce **NetNTLMv2** and **NetLMv2** hashes
      (hashcat ``-m 5600``).

    - ``true`` — ``TargetInfoFields`` is empty.  Without it, clients cannot
      build the NTLMv2 blob per ``[MS-NLMP §3.3.2]``.
      LmCompatibilityLevel 0–2 clients fall back to NTLMv1.
      Level 3+ clients (all modern Windows) will **fail authentication** and
      produce **zero captured hashes**.

    .. warning::

        This setting is almost never needed.  Clients at
        ``LmCompatibilityLevel`` 0–2 already send **NTLMv1 unconditionally**
        and will never send NTLMv2 regardless of whether ``TargetInfoFields``
        is present.  This option therefore only affects level 3+ clients (all
        modern Windows defaults), which **require** ``TargetInfoFields`` to
        construct the NTLMv2 blob.  Without it, those clients abort the
        handshake entirely and produce **zero captured hashes**.  Use only
        when exclusively targeting known legacy NTLMv1-only environments.


Protocol Behaviour
------------------

Three-Message Handshake
~~~~~~~~~~~~~~~~~~~~~~~~

Dementor acts as a **capture server**, not an authentication server.  Per
``[MS-NLMP §1.3.1.1]``, the handshake proceeds as follows:

.. code-block:: text

    Client                              Server (Dementor)
      |                                       |
      |--- NEGOTIATE_MESSAGE ---------------► |  inspect client flags
      |◄-- CHALLENGE_MESSAGE ---------------- |  Dementor controls entirely
      |--- AUTHENTICATE_MESSAGE -----------► |  extract & store hashes
      |                                       |

Dementor does not verify responses, compute session keys, or participate in
signing or sealing.  The connection is terminated (or returned to the calling
protocol handler) immediately after the ``AUTHENTICATE_MESSAGE`` is received.

Hash Type Classification
~~~~~~~~~~~~~~~~~~~~~~~~~

Four hash types are extracted, classified from the ``AUTHENTICATE_MESSAGE``
using NT and LM response byte structure per ``[MS-NLMP §3.3]``.  The ESS flag
is cross-checked but the **byte structure is authoritative**:

.. list-table::
   :header-rows: 1
   :widths: 18 15 30 12

   * - Type
     - NT length
     - LM condition
     - HC mode
   * - ``NetNTLMv1``
     - 24 bytes
     - any (real or absent)
     - ``-m 5500``
   * - ``NetNTLMv1-ESS``
     - 24 bytes
     - ``LM[8:24] == Z(16)``
     - ``-m 5500``
   * - ``NetNTLMv2``
     - > 24 bytes
     - n/a
     - ``-m 5600``
   * - ``NetLMv2``
     - > 24 bytes †
     - 24 bytes, non-null
     - ``-m 5600``

† NetLMv2 is always paired with NetNTLMv2 and uses the same hashcat mode.

ESS detection relies on ``len(LM) == 24 and LM[8:24] == Z(16)`` per §3.3.1.
This is reliable even when :attr:`DisableExtendedSessionSecurity` is toggled —
the flag is supplementary, not authoritative.

Hashcat Output Formats
~~~~~~~~~~~~~~~~~~~~~~~

Each captured hash is written in hashcat-compatible format:

.. code-block:: text

    # NetNTLMv1 / NetNTLMv1-ESS  (-m 5500)
    User::Domain:LmResponse(48 hex):NtResponse(48 hex):ServerChallenge(16 hex)

    # NetNTLMv2  (-m 5600)
    User::Domain:ServerChallenge(16 hex):NTProofStr(32 hex):Blob(var hex)

    # NetLMv2  (-m 5600)
    User::Domain:ServerChallenge(16 hex):LMProof(32 hex):ClientChallenge(16 hex)

For **NetNTLMv1-ESS**, the raw ``ServerChallenge`` is emitted (not the derived
``MD5(Server ‖ Client)[0:8]``).  Hashcat ``-m 5500`` auto-detects ESS from
``LM[8:24] == Z(16)`` and derives the mixed challenge internally.

CHALLENGE_MESSAGE Construction
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``CHALLENGE_MESSAGE`` is built directly from the client's
``NEGOTIATE_MESSAGE`` flags:

- **Flag mirroring** — ``SIGN``, ``SEAL``, ``ALWAYS_SIGN``, ``KEY_EXCH``,
  ``56``, ``128``, ``UNICODE``, and ``OEM`` are echoed when requested.
  Failing to echo ``SIGN`` causes strict clients to abort before sending the
  ``AUTHENTICATE_MESSAGE``, losing the capture.
- **ESS** — echoed only when the client requests it and
  :attr:`DisableExtendedSessionSecurity` is ``false``.  When both ESS and
  ``LM_KEY`` are requested, only ESS is returned (§2.2.2.5 flag P mutual
  exclusivity).
- **Version** — a placeholder ``\\xff * 8`` is used.  The VERSION structure
  content is not verified by clients per §2.2.2.10.

AV_PAIRS (``TargetInfoFields``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When :attr:`DisableNTLMv2` is ``false`` (the default), ``TargetInfoFields``
is populated with AV_PAIRs per
`[MS-NLMP §2.2.2.1] <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/83f5e789-660d-4781-8491-5f8c6641f75e>`__,
derived from the FQDN configured in the calling protocol (e.g.
:attr:`SMB.Server.FQDN`).  The table below shows the derivation for each
AvId and gives concrete values for two typical ``FQDN`` settings:

.. list-table::
   :header-rows: 1
   :widths: 10 24 22 30

   * - AvId
     - Constant
     - ``FQDN = "DEMENTOR"``
     - ``FQDN = "server1.corp.example.com"``
   * - ``0x0001``
     - ``MsvAvNbComputerName``
     - ``DEMENTOR``
     - ``SERVER1``
   * - ``0x0002``
     - ``MsvAvNbDomainName``
     - ``WORKGROUP``
     - ``CORP``
   * - ``0x0003``
     - ``MsvAvDnsComputerName``
     - ``DEMENTOR``
     - ``server1.corp.example.com``
   * - ``0x0004``
     - ``MsvAvDnsDomainName``
     - ``WORKGROUP``
     - ``corp.example.com``
   * - ``0x0005``
     - ``MsvAvDnsTreeName``
     - *(omitted — no domain suffix)*
     - ``corp.example.com``

A bare hostname such as ``"DEMENTOR"`` contains no dot, so Dementor treats
the machine as workgroup-joined: the domain fields are set to ``WORKGROUP``
and ``MsvAvDnsTreeName`` is omitted.  A dotted FQDN such as
``"server1.corp.example.com"`` is split at the first dot: ``server1`` becomes
the hostname and ``corp.example.com`` becomes the domain and forest name.

``MsvAvTimestamp`` (``0x0007``) is **intentionally omitted**.  Per §3.3.2
rule 7, if the server includes ``MsvAvTimestamp`` the client MUST suppress its
``LmChallengeResponse`` (set to ``Z(24)``), which eliminates NetLMv2 capture from
all modern Windows clients.

LM Response Filtering
~~~~~~~~~~~~~~~~~~~~~~

For **NetNTLMv1** captures, the LM slot in the hashcat line is omitted when any
of the following conditions hold:

- **Identical response** — ``LmChallengeResponse == NtChallengeResponse``.
  Using the LM copy with the NT one-way function during cracking would yield
  incorrect results.
- **Long-password placeholder** — ``LmChallengeResponse == DESL(Z(16))``.
  Clients send this deterministic value when the password exceeds 14
  characters or the ``NoLMHash`` registry policy is enforced.  It carries no
  crackable material.
- **Empty-password placeholder** — ``LmChallengeResponse == DESL(LMOWFv1(""))``.
  The LM derivative of an empty password; equally uncrackable.

For **NetNTLMv2**, the NetLMv2 companion hash is captured alongside the NetNTLMv2
response unless the client set ``LmChallengeResponse`` to ``Z(24)``.  Clients
only send ``Z(24)`` here when the server included ``MsvAvTimestamp``
(``0x0007``) in the ``CHALLENGE_MESSAGE``, which instructs them to suppress the
LM slot.  Dementor intentionally omits ``MsvAvTimestamp``, so this suppression
never occurs and both NetNTLMv2 and NetLMv2 are always captured.

Anonymous Authentication
~~~~~~~~~~~~~~~~~~~~~~~~~

``AUTHENTICATE_MESSAGE`` tokens are checked for anonymous (null-session) auth
before any hash is extracted.  A token is treated as anonymous when:

- ``NTLMSSP_NEGOTIATE_ANONYMOUS`` (flag ``0x00000800``) is set, **or**
- ``UserName`` is empty, ``NtChallengeResponse`` is empty, and
  ``LmChallengeResponse`` is empty or ``Z(1)`` (per §3.2.5.1.2).

On any parse error the check conservatively returns ``True`` (anonymous) to
avoid writing a malformed capture.  Anonymous tokens are silently discarded.


Default Configuration
---------------------

.. code-block:: toml
    :linenos:
    :caption: NTLM configuration section (all options)

    [NTLM]
    # 8-byte ServerChallenge nonce.  Accepted formats:
    #   "hex:1122334455667788"  — explicit hex (recommended)
    #   "ascii:1337LEET"        — explicit ASCII (recommended)
    #   "1122334455667788"      — 16 hex chars, auto-detected
    #   "1337LEET"              — 8 ASCII chars, auto-detected
    # Omit entirely for a cryptographically random value per run (recommended).
    Challenge = "1337LEET"

    # Strip NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY from CHALLENGE_MESSAGE.
    # false (default): ESS negotiated → NetNTLMv1-ESS hashes (hashcat -m 5500).
    # true:            ESS suppressed → plain NetNTLMv1; crackable with rainbow
    #                  tables when combined with a fixed Challenge above.
    DisableExtendedSessionSecurity = false

    # Omit TargetInfoFields (AV_PAIRS) from CHALLENGE_MESSAGE.
    # false (default): NetNTLMv2 + NetLMv2 captured from all modern clients.
    # true:            Level 0–2 clients fall back to NTLMv1; level 3+ clients
    #                  (all modern Windows) will refuse and produce NO captures.
    DisableNTLMv2 = false


Capture Prerequisites
---------------------

For a hash to be written to the session database, the following conditions
must all hold once Dementor receives the ``AUTHENTICATE_MESSAGE``:

1. **Non-anonymous** — the token must not carry the
   ``NTLMSSP_NEGOTIATE_ANONYMOUS`` flag and must include a non-empty
   ``UserName`` and a non-null ``NtChallengeResponse``.
2. **Parseable** — the NTLM token must be structurally valid; any parse
   error causes the token to be treated as anonymous and discarded.
3. **NT response present** — the ``NtChallengeResponse`` field must be
   non-empty; a missing or zero-length NT response means there is nothing
   to capture.

The LM slot in a NetNTLMv1 hashcat line is additionally subject to the three
filtering conditions described under `LM Response Filtering`_.  Filtering the
LM slot does **not** discard the capture — the NT response is still written;
only the LM field is omitted from the output line.

When a capture is discarded Dementor logs the event but writes nothing to
disk.


LmCompatibilityLevel Reference
--------------------------------

The Windows ``LmCompatibilityLevel`` registry value (HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa)
controls which response types a client sends.  The table below maps each level
to the hash type Dementor captures and the relevant hashcat mode.

.. list-table::
   :header-rows: 1
   :widths: 8 32 20 12

   * - Level
     - Client sends
     - Captured type
     - HC mode
   * - 0
     - LMv1 + NTLMv1
     - NetNTLMv1 (+ NetNTLMv1-ESS when ESS negotiated)
     - ``-m 5500``
   * - 1
     - LMv1 + NTLMv1 (NTLMv1-ESS if ESS is negotiated)
     - NetNTLMv1 / NetNTLMv1-ESS
     - ``-m 5500``
   * - 2
     - NTLMv1 in both LM and NT slots
     - NetNTLMv1 (LM slot filtered — see `LM Response Filtering`_)
     - ``-m 5500``
   * - 3
     - NTLMv2 + LMv2
     - NetNTLMv2 + NetLMv2
     - ``-m 5600``
   * - 4
     - NTLMv2 + LMv2
     - NetNTLMv2 + NetLMv2
     - ``-m 5600``
   * - 5
     - NTLMv2 + LMv2
     - NetNTLMv2 + NetLMv2
     - ``-m 5600``

.. note::

    Windows Vista and later default to **level 3**.  Levels 0–2 are only
    found on legacy systems or when explicitly downgraded via Group Policy.
    Leave :attr:`DisableNTLMv2` at ``false`` (the default) to capture hashes
    from clients at any level.


