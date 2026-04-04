.. _config_ntlm:

NTLM
====

Section ``[NTLM]``
------------------

.. py:currentmodule:: NTLM

Dementor's NTLM module (``ntlm.py``) implements the server side of the
three-message NTLM handshake per `[MS-NLMP] <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/>`__.
It is a **capture module** — it builds a valid ``CHALLENGE_MESSAGE`` to keep
the handshake alive, extracts crackable hashes from the
``AUTHENTICATE_MESSAGE``, formats them for hashcat, and writes them to the
database.  It does not verify responses, compute session keys, or participate
in post-authentication signing, sealing, or encryption.

The ``[NTLM]`` config section provides **global settings** shared by every
protocol that uses NTLM (SMB, HTTP, LDAP, MSSQL, etc.).  All NTLM settings
are configured exclusively in the ``[NTLM]`` section and apply identically to
every protocol — there are no per-protocol overrides.

.. |rarr| unicode:: U+2192


Options
-------

Capture Behaviour
~~~~~~~~~~~~~~~~~

.. py:attribute:: Challenge
    :type: HexStr | str
    :value: None (random at startup)

    *Linked to* :attr:`config.SessionConfig.ntlm_challenge`

    The 8-byte ``ServerChallenge`` nonce sent in the ``CHALLENGE_MESSAGE``.
    Accepts any of the following formats:

    - ``"hex:1122334455667788"`` — explicit hex (recommended)
    - ``"ascii:1337LEET"`` — explicit ASCII (recommended)
    - ``"1122334455667788"`` — 16 hex characters (auto-detected as hex)
    - ``"1337LEET"`` — 8 ASCII characters (auto-detected as ASCII)

    If omitted, a cryptographically random challenge is generated once at
    startup and reused for all connections during that run.

    .. tip::

        **For NTLMv1 cracking:** a fixed challenge such as
        ``"1122334455667788"`` combined with rainbow tables (e.g.
        `crack.sh <https://crack.sh>`__) can crack NTLMv1 hashes offline
        without GPU resources.

        **For NTLMv2 cracking:** the challenge value does not matter —
        NTLMv2 incorporates the challenge into an HMAC-MD5 construction
        that is not amenable to rainbow tables.  Use hashcat ``-m 5600``
        with a wordlist or rules.

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
                                    supportedMech: 1.3.6.1.4.1.311.2.2.10 (NTLMSSP)
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

    Controls whether the server includes ``NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY``
    (flag P, bit 19) in the ``CHALLENGE_MESSAGE``.  ESS is a negotiated
    feature: the client requests it in the ``NEGOTIATE_MESSAGE``, and the
    server decides whether to echo it back.  If the server does not echo
    the flag, the client falls back to plain NTLMv1.

    **Effect on captured hashes:**

    - ``false`` (default) — the server echoes ESS back to clients that
      request it.  NTLMv1 clients (LmCompatibilityLevel 0-2) produce
      **NetNTLMv1-ESS** hashes (hashcat ``-m 5500``).  The effective
      challenge becomes ``MD5(ServerChallenge || ClientChallenge)[0:8]``;
      hashcat derives this internally from the emitted ``ClientChallenge``
      field.

    - ``true`` — the server strips ESS from the response regardless of
      what the client requested.  NTLMv1 clients produce plain
      **NetNTLMv1** hashes instead.  A fixed :attr:`Challenge` combined
      with rainbow tables can crack these without GPU resources.

    NTLMv2 clients (level 3+, all modern Windows) are **unaffected** —
    they always produce NetNTLMv2 regardless of ESS.

    .. note::

        Dementor classifies ESS from the ``LmChallengeResponse`` byte
        structure (``LM[8:24] == Z(16)``) rather than solely from the
        negotiate flag, so classification is accurate even when this setting
        is toggled or when the client and server disagree on ESS.

    .. py:attribute:: ExtendedSessionSecurity
        :value: true
        :type: bool

        .. deprecated:: 1.0.0.dev19
            Renamed to :attr:`DisableExtendedSessionSecurity`.


.. py:attribute:: DisableNTLMv2
    :value: false
    :type: bool

    *Linked to* :attr:`config.SessionConfig.ntlm_disable_ntlmv2`

    When ``true``, clears ``NTLMSSP_NEGOTIATE_TARGET_INFO`` and omits the
    ``TargetInfoFields`` (AV_PAIRs) from the ``CHALLENGE_MESSAGE``.

    **Effect on captured hashes:**

    - ``false`` (default) — ``TargetInfoFields`` is populated.  Clients can
      construct an NTLMv2 response and produce **NetNTLMv2** (and sometimes
      **NetLMv2**) hashes (hashcat ``-m 5600``).

    - ``true`` — ``TargetInfoFields`` is empty.  Without it, clients cannot
      build the NTLMv2 ``NTLMv2_CLIENT_CHALLENGE`` blob per [MS-NLMP]
      §3.3.2.  LmCompatibilityLevel 0-2 clients fall back to NTLMv1.
      **Level 3+ clients** (all modern Windows defaults) **fail
      authentication entirely** and produce **zero captured hashes**.

    .. warning::

        This setting is almost never useful.  Clients at level 0-2 already
        send NTLMv1 unconditionally and will never send NTLMv2 regardless
        of whether ``TargetInfoFields`` is present.  This option therefore
        only affects level 3+ clients, which **require** ``TargetInfoFields``
        to construct the NTLMv2 blob.  Without it, those clients abort the
        handshake and produce zero captures.  Use only when exclusively
        targeting known legacy NTLMv1-only environments.


Server Identity
~~~~~~~~~~~~~~~

These options control the identity values embedded in the NTLM
``CHALLENGE_MESSAGE``.  They determine what appears on the wire, in
captured hash lines, and in NTLMv2 ``AV_PAIR`` structures.  **No client
changes authentication behavior** based on any of these values — they are
cosmetic from the client's perspective but operationally important for
blending in and for hash formatting.

These are configured in the ``[NTLM]`` section and apply globally to all
protocols.

.. py:attribute:: TargetType
    :type: str
    :value: "server"

    *Linked to* :attr:`config.SessionConfig.ntlm_target_type`

    Sets the ``NTLMSSP_TARGET_TYPE`` flag in the ``CHALLENGE_MESSAGE``
    and determines the ``TargetName`` field value:

    - ``"server"`` — sets ``NTLMSSP_TARGET_TYPE_SERVER`` (bit 17);
      ``TargetName`` is the NetBIOS computer name.
    - ``"domain"`` — sets ``NTLMSSP_TARGET_TYPE_DOMAIN`` (bit 16);
      ``TargetName`` is the NetBIOS domain name.

.. py:attribute:: Version
    :type: str
    :value: "0.0.0" (all-zero placeholder)

    *Linked to* :attr:`config.SessionConfig.ntlm_version`

    The ``VERSION`` structure in the ``CHALLENGE_MESSAGE``, formatted as
    ``"major.minor.build"`` (e.g. ``"10.0.20348"`` for Server 2022).
    Clients do not verify this value per [MS-NLMP] §2.2.2.10.

    Common values:

    .. list-table::
        :widths: 20 30
        :header-rows: 1

        * - Version
          - OS
        * - ``"5.1.2600"``
          - Windows XP SP3
        * - ``"6.1.7601"``
          - Windows 7 SP1 / Server 2008 R2
        * - ``"6.3.9600"``
          - Windows 8.1 / Server 2012 R2
        * - ``"10.0.19041"``
          - Windows 10 (20H1)
        * - ``"10.0.20348"``
          - Windows Server 2022

.. py:attribute:: NetBIOSComputer
    :type: str
    :value: "DEMENTOR"

    *Linked to* :attr:`config.SessionConfig.ntlm_nb_computer`

    AV_PAIR ``MsvAvNbComputerName`` (``0x0001``) in the ``CHALLENGE_MESSAGE``
    ``TargetInfoFields``.

.. py:attribute:: NetBIOSDomain
    :type: str
    :value: "WORKGROUP"

    *Linked to* :attr:`config.SessionConfig.ntlm_nb_domain`

    AV_PAIR ``MsvAvNbDomainName`` (``0x0002``).

.. py:attribute:: DnsComputer
    :type: str
    :value: "" (omitted from AV_PAIRs when empty)

    *Linked to* :attr:`config.SessionConfig.ntlm_dns_computer`

    AV_PAIR ``MsvAvDnsComputerName`` (``0x0003``).

.. py:attribute:: DnsDomain
    :type: str
    :value: "" (omitted from AV_PAIRs when empty)

    *Linked to* :attr:`config.SessionConfig.ntlm_dns_domain`

    AV_PAIR ``MsvAvDnsDomainName`` (``0x0004``).

.. py:attribute:: DnsTree
    :type: str
    :value: "" (omitted from AV_PAIRs when empty)

    *Linked to* :attr:`config.SessionConfig.ntlm_dns_tree`

    AV_PAIR ``MsvAvDnsTreeName`` (``0x0005``).


Protocol Behaviour
------------------

Three-Message Handshake
~~~~~~~~~~~~~~~~~~~~~~~

Dementor acts as a **capture server**, not an authentication server.  Per
[MS-NLMP] §1.3.1.1, the handshake proceeds as follows:

.. code-block:: text

    Client                              Server (Dementor)
      |                                       |
      |--- NEGOTIATE_MESSAGE ---------------► |  inspect client flags,
      |                                       |  extract OS/domain/workstation
      |◄-- CHALLENGE_MESSAGE ---------------- |  Dementor controls entirely:
      |                                       |  challenge, flags, AV_PAIRs
      |--- AUTHENTICATE_MESSAGE ------------► |  extract & classify hashes,
      |                                       |  format for hashcat, write to DB
      |                                       |

The connection is terminated (or returned to the calling protocol handler)
immediately after the ``AUTHENTICATE_MESSAGE`` is processed.


CHALLENGE_MESSAGE Construction
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``CHALLENGE_MESSAGE`` is built by ``NTLM_build_challenge_message()``
per [MS-NLMP] §3.2.5.1.1.  It is the **only message Dementor authors** —
the other two are client-originated.

**Flag mirroring:**

The following client-requested flags are echoed back when present:

.. list-table::
    :widths: 30 50 20
    :header-rows: 1

    * - Flag
      - Purpose
      - Letter
    * - ``NEGOTIATE_SIGN``
      - Message signing support
      - D
    * - ``NEGOTIATE_SEAL``
      - Message encryption support
      - E
    * - ``NEGOTIATE_ALWAYS_SIGN``
      - Set session security in connection
      - M
    * - ``NEGOTIATE_KEY_EXCH``
      - Session key negotiation
      - V
    * - ``NEGOTIATE_56``
      - 56-bit encryption
      - W
    * - ``NEGOTIATE_128``
      - 128-bit encryption
      - U
    * - ``NEGOTIATE_UNICODE``
      - UTF-16LE string encoding
      - A
    * - ``NEGOTIATE_OEM``
      - OEM (cp437) string encoding
      - B

.. important::

    Failing to echo ``NEGOTIATE_SIGN`` causes strict clients (e.g. Windows
    10 with ``RequireSecuritySignature = 1``) to abort before sending the
    ``AUTHENTICATE_MESSAGE``, losing the capture entirely.

**ESS / LM_KEY mutual exclusivity:**

When the client requests both ``NEGOTIATE_EXTENDED_SESSIONSECURITY`` (P) and
``NEGOTIATE_LM_KEY`` (G), only ESS is returned.  Per [MS-NLMP] §2.2.2.5,
these flags are mutually exclusive — ESS takes priority.

**Server-set flags:**

- ``NTLMSSP_NEGOTIATE_NTLM`` — always set (NTLM authentication)
- ``NTLMSSP_REQUEST_TARGET`` — always set (TargetName present)
- ``NTLMSSP_TARGET_TYPE_SERVER`` or ``_DOMAIN`` — per :attr:`TargetType`
- ``NTLMSSP_NEGOTIATE_TARGET_INFO`` — set unless :attr:`DisableNTLMv2`
- ``NTLMSSP_NEGOTIATE_VERSION`` — echoed when the client requests it


AV_PAIRs (``TargetInfoFields``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When :attr:`DisableNTLMv2` is ``false`` (the default), ``TargetInfoFields``
is populated with AV_PAIRs per [MS-NLMP] §2.2.2.1.  Each value has an
independent default configured in the ``[NTLM]`` section:

.. list-table::
    :header-rows: 1
    :widths: 10 20 70

    * - AvId
      - Constant
      - Resolution
    * - ``0x0001``
      - ``MsvAvNbComputerName``
      - :attr:`NTLM.NetBIOSComputer` (default ``"DEMENTOR"``)
    * - ``0x0002``
      - ``MsvAvNbDomainName``
      - :attr:`NTLM.NetBIOSDomain` (default ``"WORKGROUP"``)
    * - ``0x0003``
      - ``MsvAvDnsComputerName``
      - :attr:`NTLM.DnsComputer` (default ``""`` — omitted from AV_PAIRs
        when empty)
    * - ``0x0004``
      - ``MsvAvDnsDomainName``
      - :attr:`NTLM.DnsDomain` (default ``""`` — omitted from AV_PAIRs
        when empty)
    * - ``0x0005``
      - ``MsvAvDnsTreeName``
      - :attr:`NTLM.DnsTree` (default ``""`` — omitted from AV_PAIRs
        when empty)
    * - ``0x0007``
      - ``MsvAvTimestamp``
      - **Intentionally omitted** — see below
    * - ``0x0000``
      - ``MsvAvEOL``
      - Always appended (list terminator)

All AV_PAIR values are encoded as **UTF-16LE** per [MS-NLMP] §2.2.1.2,
regardless of the negotiated character set.

**MsvAvTimestamp omission:**

``MsvAvTimestamp`` (``0x0007``) is intentionally omitted from the
``CHALLENGE_MESSAGE``.  Per [MS-NLMP] §3.3.2 rule 7, when the server
includes ``MsvAvTimestamp``, the client **MUST** suppress its
``LmChallengeResponse`` (set it to ``Z(24)``), which eliminates the
NetLMv2 companion hash.

Omitting it allows clients at LmCompatibilityLevel 0-2 (Vista, Server 2008)
to send both NetNTLMv2 and LMv2 responses.  See
`LMv2 Companion Capture`_ for the full picture.


Hash Types and Classification
-----------------------------

Four hash types are extracted from the ``AUTHENTICATE_MESSAGE``, classified
by NT and LM response **byte structure** per [MS-NLMP] §3.3.  The ESS flag
is cross-checked but the byte structure is **authoritative**:

.. list-table::
    :header-rows: 1
    :widths: 18 12 35 12

    * - Type
      - NT length
      - LM condition
      - HC mode
    * - ``NetNTLMv1``
      - 24 bytes
      - any (real LM response or absent)
      - ``-m 5500``
    * - ``NetNTLMv1-ESS``
      - 24 bytes
      - 24 bytes with ``LM[8:24] == Z(16)`` (ESS signature)
      - ``-m 5500``
    * - ``NetNTLMv2``
      - > 24 bytes
      - n/a (NTProofStr + blob)
      - ``-m 5600``
    * - ``NetLMv2``
      - > 24 bytes
      - 24 bytes, non-null, non-Z(24) (LMv2 companion)
      - ``-m 5600``

NetLMv2 is always paired with NetNTLMv2 on the same connection; both use
hashcat ``-m 5600``.


Hashcat Output Formats
~~~~~~~~~~~~~~~~~~~~~~

Each captured hash is written in hashcat-compatible format.  Validated
against hashcat ``module_05500.c`` and ``module_05600.c``:

.. code-block:: text

    # NetNTLMv1 / NetNTLMv1-ESS  (hashcat -m 5500)
    User::Domain:LmResponse(48 hex):NtResponse(48 hex):ServerChallenge(16 hex)

    # NetNTLMv2  (hashcat -m 5600)
    User::Domain:ServerChallenge(16 hex):NTProofStr(32 hex):Blob(var hex)

    # NetLMv2  (hashcat -m 5600)
    User::Domain:ServerChallenge(16 hex):LMProof(32 hex):ClientChallenge(16 hex)

For **NetNTLMv1-ESS**, the raw ``ServerChallenge`` is emitted (not the
derived ``MD5(Server || Client)[0:8]``).  Hashcat ``-m 5500`` auto-detects
ESS from ``LM[8:24] == Z(16)`` and derives the mixed challenge internally.


LM Response Filtering
~~~~~~~~~~~~~~~~~~~~~~

For **NetNTLMv1** captures, the LM slot in the hashcat line is omitted when
any of the following conditions hold:

- **Identical response** — ``LmChallengeResponse == NtChallengeResponse``.
  This occurs at LmCompatibilityLevel 2, where the client copies the NT
  response into both slots.  Using the LM copy with the NT one-way
  function during cracking would yield incorrect results.
- **Long-password placeholder** — ``LmChallengeResponse == DESL(Z(16))``.
  Clients send this deterministic value when the password exceeds 14
  characters or the ``NoLMHash`` registry policy is enforced.  It carries
  no crackable material.
- **Empty-password placeholder** — ``LmChallengeResponse == DESL(LMOWFv1(""))``.
  The LM derivative of an empty password; equally uncrackable.


.. _lmv2_companion:

LMv2 Companion Capture
~~~~~~~~~~~~~~~~~~~~~~~

For **NetNTLMv2** captures, the NetLMv2 companion hash is captured alongside
the primary NetNTLMv2 response when all of the following hold:

1. ``LmChallengeResponse`` is exactly 24 bytes
2. ``LmChallengeResponse`` is not ``Z(24)`` (all zeros)

**When clients suppress LMv2:**

Clients set ``LmChallengeResponse`` to ``Z(24)`` when:

- **MsvAvTimestamp present in CHALLENGE_MESSAGE** — Per [MS-NLMP] §3.3.2
  rule 7, when the server includes ``MsvAvTimestamp`` (``0x0007``) in the
  AV_PAIR list, the client MUST suppress ``LmChallengeResponse``.
  Dementor intentionally omits ``MsvAvTimestamp`` to avoid this.

- **Win 7+ / Server 2008 R2+ defaults** — These versions suppress LMv2
  regardless of LmCompatibilityLevel.  Only Vista and Server 2008 send
  real LMv2 responses.

**Observed behavior** (tested against 14 Windows versions at default
LmCompatibilityLevel 3, Dementor omitting MsvAvTimestamp):

.. list-table::
    :header-rows: 1
    :widths: 55 15

    * - OS
      - LMv2?
    * - Vista SP2, Server 2008
      - **Yes**
    * - Win 7 SP1 and later (all versions through Server 2022)
      - No


Anonymous Authentication
~~~~~~~~~~~~~~~~~~~~~~~~

``AUTHENTICATE_MESSAGE`` tokens are checked for anonymous (null-session)
authentication before any hash is extracted.  A token is treated as
anonymous when:

- ``NTLMSSP_NEGOTIATE_ANONYMOUS`` (flag ``0x00000800``) is set, **or**
- ``UserName`` is empty, ``NtChallengeResponse`` is empty, and
  ``LmChallengeResponse`` is empty or ``Z(1)`` (per §3.2.5.1.2)

On any parse error the check conservatively returns ``True`` (anonymous) to
avoid writing a malformed capture.  Anonymous tokens are silently discarded.

.. note::

    XP SP3 and XP SP0 send an anonymous ``AUTHENTICATE_MESSAGE`` probe
    before the real credential auth on each connection.  This is normal
    SSPI behavior — the anonymous probe is discarded and the real auth
    that follows is captured.


Client Information Leakage
--------------------------

Each NTLM message leaks client metadata that Dementor extracts and logs.
The three messages provide increasingly detailed information:

.. list-table::
    :header-rows: 1
    :widths: 30 15 15 15

    * - Field
      - NEGOTIATE
      - CHALLENGE
      - AUTHENTICATE
    * - OS version (``VERSION`` structure)
      - Yes [1]_
      - *(server-set)*
      - Yes
    * - Workstation name
      - Yes [2]_
      - *(server-set)*
      - Yes
    * - Domain name
      - Yes [2]_
      - *(server-set)*
      - Yes
    * - Username
      - No
      - —
      - Yes
    * - NegotiateFlags
      - Yes
      - *(server-set)*
      - Yes
    * - NTLMv2 blob AV_PAIRs
      - No
      - —
      - Yes (NTLMv2 only)
    * - SPN (``MsvAvTargetName``, 0x0009)
      - No
      - —
      - Yes (NTLMv2 only) [3]_
    * - Client timestamp (``MsvAvTimestamp``, 0x0007)
      - No
      - —
      - Yes (NTLMv2 only)
    * - MIC (Message Integrity Code)
      - No
      - —
      - Yes (if VERSION flag set)
    * - Channel Bindings (``MsvAvChannelBindings``, 0x000A)
      - No
      - —
      - Yes (NTLMv2 only) [4]_
    * - ``MsvAvFlags`` (0x0006)
      - No
      - —
      - Yes (NTLMv2 only)

.. [1] Only when ``NTLMSSP_NEGOTIATE_VERSION`` is set.  XP SP0 does not
   set this flag and sends no VERSION structure.

.. [2] NEGOTIATE_MESSAGE domain and workstation are OEM-encoded and often
   empty on modern clients.  The AUTHENTICATE_MESSAGE values are
   authoritative.

.. [3] The SPN reveals what service the client was trying to reach, e.g.
   ``cifs/10.0.0.50`` or ``HTTP/intranet.corp.com``.  Valuable for
   understanding lateral movement paths.

.. [4] Win 7+ includes Channel Binding Tokens when authenticating over TLS.


Logging
-------

Dementor emits structured log messages at each stage of the NTLM handshake.
All NTLM log messages are prefixed by the calling protocol's logger (e.g.
``SMB``).

**Debug level** (``--debug``):

.. code-block:: text

    C: NTLMSSP NEGOTIATE: flags=0xe2898217 os='Windows 10 Build 19041' domain='CORP' workstation='LAPTOP'
    NTLMSSP CHALLENGE: flags=0xe2898217 challenge=544553544348414c target=NTLMREALM
    C: NTLMSSP AUTHENTICATE: flags=0xe2898217 os='Windows 10 Build 19041' user='jsmith' domain='CORP' name='LAPTOP' NT_len=318 LM_len=24 MIC=aabb...
    NTLMv2 blob: ClientChallenge=aabbccddeeff0011 SPN=cifs/10.0.0.50 Timestamp=0x01d5... Flags=0x00000000 ChannelBindings=(empty)
    Extracting hashes: user='jsmith' domain='CORP' hash_type=NetNTLMv2 nt_len=318 lm_len=24
    Appended NetNTLMv2 hash (nt_len=318)
    Writing 1 hash(es) to capture database for user='jsmith' domain='CORP'

**Display level** (default):

.. code-block:: text

    NTLM: os:Windows 10 Build 19041 | user:jsmith | domain:CORP | name:LAPTOP | SPN:cifs/10.0.0.50

The display line merges fields from both the NEGOTIATE (Type 1) and
AUTHENTICATE (Type 3) messages, with Type 3 values taking priority on
conflicts.  The field set is: ``os``, ``user``, ``domain``, ``name``
(workstation), ``SPN`` (from NTLMv2 blob).

**Success level** (cleartext only):

.. code-block:: text

    Cleartext password captured: jsmith\CORP

Emitted only for SMB1 basic-security cleartext captures (Path B).


LmCompatibilityLevel Reference
-------------------------------

The Windows ``LmCompatibilityLevel`` registry value
(``HKLM\SYSTEM\CurrentControlSet\Control\Lsa``) controls which NTLM
response types a client sends.  This is the **single most important client
setting** for hash capture — it determines what Dementor can extract.

.. list-table::
    :header-rows: 1
    :widths: 6 30 22 10 32

    * - Level
      - Client sends
      - Captured type
      - HC mode
      - Notes
    * - 0
      - LMv1 + NTLMv1
      - NetNTLMv1-ESS (or NetNTLMv1 if server strips ESS)
      - ``5500``
      - Real LM response included; client requests ESS
    * - 1
      - LMv1 + NTLMv1
      - NetNTLMv1-ESS (or NetNTLMv1 if server strips ESS)
      - ``5500``
      - Same as level 0; client requests ESS
    * - 2
      - NTLMv1 in both LM and NT slots
      - NetNTLMv1-ESS (or NetNTLMv1 if server strips ESS)
      - ``5500``
      - LM slot is a copy of NT, filtered out
    * - 3
      - NTLMv2 + LMv2
      - NetNTLMv2 (+ LMv2 [5]_)
      - ``5600``
      - **Default since Vista/Server 2008**
    * - 4
      - NTLMv2 + LMv2; refuse LM at DC
      - NetNTLMv2 (+ LMv2 [5]_)
      - ``5600``
      - Server-side LM refusal (DC only)
    * - 5
      - NTLMv2 + LMv2; refuse LM & NTLM at DC
      - NetNTLMv2 (+ LMv2 [5]_)
      - ``5600``
      - Server-side LM+NTLM refusal (DC only)

.. [5] LMv2 is only captured from Vista and Server 2008.  Win 7+ and
   Server 2008 R2+ suppress LMv2 (``LM = Z(24)``) regardless of
   LmCompatibilityLevel.  See `LMv2 Companion Capture`_.

.. note::

    **Default values:**

    - **Windows Vista and later:** level 3 (send NTLMv2 only)
    - **Windows XP / Server 2003:** level 0 or 1 (send LM + NTLM)
    - **Standalone servers** (non-domain): level 3

    Levels 0-2 are only found on legacy systems or when explicitly
    downgraded via Group Policy (``secpol.msc`` |rarr| Local Policies
    |rarr| Security Options |rarr| "Network security: LAN Manager
    authentication level").

    Leave :attr:`DisableNTLMv2` at ``false`` (the default) to capture
    hashes from clients at **any** level.

**Interaction with Dementor settings:**

.. list-table::
    :header-rows: 1
    :widths: 20 15 15 15 15 20

    * - Dementor setting
      - Level 0-1
      - Level 2
      - Level 3-5
      - Hash captured
      - Use case
    * - Default (all false)
      - NTLMv1-ESS
      - NTLMv1-ESS
      - NTLMv2
      - All types
      - Maximum coverage
    * - DisableESS = true
      - **NTLMv1**
      - **NTLMv1**
      - NTLMv2
      - Plain NTLMv1, easier to crack
      - Rainbow table attack
    * - DisableNTLMv2 = true
      - NTLMv1-ESS
      - NTLMv1-ESS
      - **NONE**
      - Loses all modern clients
      - Legacy-only targeting


Default Configuration
---------------------

.. code-block:: toml
    :linenos:
    :caption: NTLM configuration section (applies to all protocols)

    [NTLM]
    # This section applies to all NTLM-enabled protocols
    # (SMB, HTTP, SMTP, IMAP, POP3, LDAP, MSSQL, RPC).
    # 8-byte ServerChallenge nonce.  Accepted formats:
    #   "hex:1122334455667788"  — explicit hex (recommended)
    #   "ascii:1337LEET"        — explicit ASCII (recommended)
    #   "1122334455667788"      — 16 hex chars, auto-detected
    #   "1337LEET"              — 8 ASCII chars, auto-detected
    # Omit entirely for a cryptographically random value per run.
    # Challenge = "1337LEET"

    # Strip NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY.
    # false (default): ESS negotiated → NetNTLMv1-ESS (hashcat -m 5500).
    # true:            ESS suppressed → plain NetNTLMv1; crackable with
    #                  rainbow tables when combined with a fixed Challenge.
    DisableExtendedSessionSecurity = false

    # Omit TargetInfoFields (AV_PAIRS) from CHALLENGE_MESSAGE.
    # false (default): NetNTLMv2 + NetLMv2 captured from modern clients.
    # true:            Level 0-2 clients fall back to NTLMv1; level 3+
    #                  (all modern Windows) will FAIL — NO captures.
    DisableNTLMv2 = false

    # Server identity in the CHALLENGE_MESSAGE:
    # TargetType = "server"           # or "domain"
    # Version = "10.0.20348"          # Server 2022
    # NetBIOSComputer = "FILESVR01"   # AV_PAIR 0x0001
    # NetBIOSDomain = "CORP"          # AV_PAIR 0x0002
    # DnsComputer = "filesvr01.corp.local"  # AV_PAIR 0x0003
    # DnsDomain = "corp.local"        # AV_PAIR 0x0004
    # DnsTree = "corp.local"          # AV_PAIR 0x0005


Spec References
---------------

.. list-table::
    :widths: 20 80
    :header-rows: 1

    * - Document
      - Covers
    * - **[MS-NLMP]**
      - NT LAN Manager (NTLM) Authentication Protocol
    * - **[MS-NLMP] §1.3.1.1**
      - Three-message handshake overview
    * - **[MS-NLMP] §2.2.1.2**
      - ``CHALLENGE_MESSAGE`` structure
    * - **[MS-NLMP] §2.2.1.3**
      - ``AUTHENTICATE_MESSAGE`` structure
    * - **[MS-NLMP] §2.2.2.1**
      - ``AV_PAIR`` structures (TargetInfoFields)
    * - **[MS-NLMP] §2.2.2.5**
      - ``NegotiateFlags`` (letters A-W)
    * - **[MS-NLMP] §2.2.2.10**
      - ``VERSION`` structure
    * - **[MS-NLMP] §3.2.5.1.1**
      - Server CHALLENGE_MESSAGE construction
    * - **[MS-NLMP] §3.2.5.1.2**
      - Anonymous authentication detection
    * - **[MS-NLMP] §3.3.1**
      - NTLMv1 ``ComputeResponse``
    * - **[MS-NLMP] §3.3.2**
      - NTLMv2 ``ComputeResponse`` (MsvAvTimestamp rule 7)
    * - **KB239869**
      - NTLM 2 authentication enablement
