
.. _config_smb:

SMB
===

Section ``[SMB]``
------------------

Dementor's SMB server implements the SMB protocol from negotiate through
tree connect, with stub handlers for common post-auth commands (create,
read, write, close, query info, query directory, IOCTL, flush, lock,
set info).  The primary goal is NTLM hash capture, but the server also
extracts share paths, filenames, client OS strings, and NetBIOS names.

The server listens on port 445 (direct TCP) and optionally port 139
(NetBIOS session service).  It supports SMB1 and SMB2/3 simultaneously,
negotiating the highest common dialect with each client.

.. tip::

    The default configuration captures hashes from all tested clients:

    - Windows XP RTM through Windows 11 25H2
    - Server 2003 through Server 2025
    - Windows NT 4.0
    - Linux smbclient
    - curl ``smb://``


Authentication Paths
--------------------

Every client connection follows one of three authentication paths, determined
by the first byte of the SMB payload and the client's capabilities.

.. list-table::
    :widths: 18 28 27 27
    :header-rows: 1

    * - Property
      - **Path A: SMB2/3**
      - **Path B: SMB1 Extended**
      - **Path C: SMB1 Basic**
    * - Trigger
      - ``0xFE`` (direct SMB2 packet)
      - ``0xFF`` + ``FLAGS2_EXTENDED_SECURITY`` set
      - ``0xFF`` + ``FLAGS2_EXTENDED_SECURITY`` **not** set
    * - Typical clients
      - Vista through Win 11 25H2, Server 2008 through 2025
      - XP SP3, XP RTM, Server 2003
      - NT 4.0, nmap probes, embedded devices, curl ``smb://``
    * - Negotiate response
      - Selected dialect + SPNEGO token + ServerGUID + negotiate contexts
      - NT LM 0.12 + SPNEGO token + ServerGUID
      - NT LM 0.12 + 8-byte challenge + ServerName + DomainName
    * - Session setup structure
      - ``SMB2_SESSION_SETUP``; ``Buffer`` carries SPNEGO(NTLMSSP)
      - ``SESSION_SETUP_ANDX`` with ``WordCount=12``; ``SecurityBlob`` carries
        NTLMSSP
      - ``SESSION_SETUP_ANDX`` with ``WordCount=13``; ``OemPassword`` and
        ``UnicodePassword`` carry raw LM/NT hashes directly
    * - Auth exchange
      - 3 messages: NEGOTIATE |rarr| CHALLENGE |rarr| AUTHENTICATE
      - 3 messages: NEGOTIATE |rarr| CHALLENGE |rarr| AUTHENTICATE
      - **1 message**: client sends LM+NT responses in a single
        ``SESSION_SETUP`` (the challenge was in the negotiate response)
    * - Hash types produced
      - NetNTLMv2 (``NT_len>24``, blob with AV_PAIRs) + optional LMv2
      - NetNTLMv1-ESS if server echoes ESS, otherwise NetNTLMv1
      - NetNTLMv1-ESS or NetNTLMv1 (depends on ESS); or cleartext if
        the client sends plaintext despite the challenge
    * - SPNEGO wrapping
      - Yes (``negTokenInit`` / ``negTokenResp``)
      - Yes (``negTokenInit`` / ``negTokenResp``)
      - No -- raw challenge/response at the SMB layer
    * - Code path (``smb.py``)
      - ``handle_smb2_negotiate`` |rarr| ``handle_smb2_session_setup``
        |rarr| ``handle_ntlmssp`` |rarr| ``ntlm.py``
      - ``handle_smb1_negotiate`` |rarr| ``handle_smb1_session_setup``
        (WC=12) |rarr| ``handle_ntlmssp`` |rarr| ``ntlm.py``
      - ``handle_smb1_negotiate`` |rarr| ``handle_smb1_session_setup``
        (WC=13) |rarr| ``handle_smb1_session_setup_basic`` |rarr|
        ``NTLM_handle_legacy_raw_auth``

.. |rarr| unicode:: U+2192

.. note::

    **Paths A and B share the same NTLM processing code** --
    ``handle_ntlmssp()`` dispatches to ``NTLM_handle_negotiate_message``,
    ``NTLM_build_challenge_message``, and ``NTLM_handle_authenticate_message``
    in ``ntlm.py``.  The only difference is transport framing.

    **Path C is completely separate** -- there is no NTLMSSP message exchange.
    The 8-byte challenge was sent in the SMB1 negotiate response and the
    client's hashes arrive as raw bytes in a single ``SESSION_SETUP`` request.
    This path uses ``NTLM_handle_legacy_raw_auth``, which feeds into the same
    ``NTLM_to_hashcat`` formatter but bypasses all NTLMSSP parsing.


SMB1-to-SMB2 Upgrade
~~~~~~~~~~~~~~~~~~~~~

When :attr:`AllowSMB1Upgrade` is ``true`` (the default) and :attr:`EnableSMB2`
is ``true``, an SMB1 ``NEGOTIATE`` that includes ``"SMB 2.???"`` or any SMB2
dialect string triggers a protocol transition: the server responds with an
``SMB2_NEGOTIATE_RESPONSE`` and the connection continues as Path A.


Client Information
~~~~~~~~~~~~~~~~~~

SMB-layer fields (NativeOS, NativeLanMan, AccountName, PrimaryDomain,
share path, filenames, NetBIOS CallingName) are extracted and logged per
connection.  NTLM-layer client information (OS version, workstation,
domain, username, SPN, MIC) is documented in the
:ref:`config_ntlm` section under Client Information Leakage.


Options
-------

Transport and Protocol
~~~~~~~~~~~~~~~~~~~~~~

.. py:currentmodule:: SMB

.. py:attribute:: EnableSMB1
    :type: bool
    :value: true

    *Maps to* :attr:`smb.SMBServerConfig.smb_enable_smb1`

    Accept SMB1 (``0xFF``) packets.  When ``false``, SMB1 packets are silently
    dropped at the transport layer.  SMB1-only clients (XP, Server 2003)
    will connect but receive no challenge and capture no hashes.

    SMB2+ clients are completely unaffected by this setting.

.. py:attribute:: EnableSMB2
    :type: bool
    :value: true

    *Maps to* :attr:`smb.SMBServerConfig.smb_enable_smb2`

    Accept SMB2/3 (``0xFE``) packets.  When ``false``, SMB2/3 packets are
    silently dropped.  All modern clients (Vista through Server 2022) send
    direct SMB2 ``NEGOTIATE`` and will capture no hashes with this disabled.

    SMB1-only clients are completely unaffected by this setting.

    .. warning::

        Setting this to ``false`` loses **all modern clients**.  Only use when
        exclusively targeting legacy SMB1 environments.

.. py:attribute:: AllowSMB1Upgrade
    :type: bool
    :value: true

    *Maps to* :attr:`smb.SMBServerConfig.smb_allow_smb1_upgrade`

    Allow SMB1 ``NEGOTIATE`` requests containing SMB2 dialect strings
    (``"SMB 2.???"`` or ``"SMB 2.002"``) to trigger a protocol transition to
    SMB2.  Requires :attr:`EnableSMB2` to also be ``true``.

.. py:attribute:: SMB2MinDialect
    :type: str
    :value: "2.002"

    *Maps to* :attr:`smb.SMBServerConfig.smb2_min_dialect`

    Floor for SMB2/3 dialect negotiation.  Clients whose highest dialect is
    below this minimum will receive ``STATUS_NOT_SUPPORTED`` and capture no
    hashes.  Valid values:

    .. list-table::
        :widths: 15 40 45
        :header-rows: 1

        * - Value
          - Dialect
          - Clients excluded when set as minimum
        * - ``"2.002"``
          - SMB 2.002
          - *(none -- this is the lowest)*
        * - ``"2.1"``
          - SMB 2.1
          - Vista, Server 2008 (only support 2.002)
        * - ``"3.0"``
          - SMB 3.0
          - Above + Win 7, Server 2008 R2 (max 2.1)
        * - ``"3.0.2"``
          - SMB 3.0.2
          - Same as 3.0 (no additional exclusions)
        * - ``"3.1.1"``
          - SMB 3.1.1
          - Above + Win 8.1, Server 2012 R2 (max 3.0.2)

    SMB1-only clients (XP, Server 2003) are **never affected** by this
    setting -- they negotiate via the SMB1 path.

.. py:attribute:: SMB2MaxDialect
    :type: str
    :value: "3.1.1"

    *Maps to* :attr:`smb.SMBServerConfig.smb2_max_dialect`

    Ceiling for SMB2/3 dialect negotiation.  Clients that support higher
    dialects will negotiate down to this value.  Lowering the ceiling does
    **not** exclude any client -- all SMB2+ clients support downward
    negotiation.

    Valid values are the same as :attr:`SMB2MinDialect`.

    .. warning::

        Setting ``SMB2MinDialect`` higher than ``SMB2MaxDialect`` creates an
        invalid range.  No SMB2 dialect can be agreed upon and **all SMB2+
        clients** will fail to negotiate.  SMB1-only clients are unaffected.


SMB Identity
~~~~~~~~~~~~

These values appear in SMB1 negotiate and session-setup responses.  They do
**not** affect the NTLM layer (see the :ref:`config_ntlm` section for that).
No client rejects or changes authentication behavior based on any of these
values.

.. py:attribute:: NetBIOSComputer
    :type: str
    :value: "DEMENTOR"

    *Maps to* :attr:`smb.SMBServerConfig.smb_nb_computer`

    NetBIOS computer name in the SMB1 non-extended negotiate response
    ``ServerName`` field.

.. py:attribute:: NetBIOSDomain
    :type: str
    :value: "WORKGROUP"

    *Maps to* :attr:`smb.SMBServerConfig.smb_nb_domain`

    NetBIOS domain name in the SMB1 non-extended negotiate response
    ``DomainName`` field.

.. py:attribute:: ServerOS
    :type: str
    :value: "Windows"

    *Maps to* :attr:`smb.SMBServerConfig.smb_server_os`

    ``NativeOS`` string in the SMB1 ``SESSION_SETUP_ANDX`` response.  Only
    visible to SMB1 clients.  SMB2 has no equivalent field.

.. py:attribute:: NativeLanMan
    :type: str
    :value: "Windows"

    *Maps to* :attr:`smb.SMBServerConfig.smb_native_lanman`

    ``NativeLanMan`` string in the SMB1 ``SESSION_SETUP_ANDX`` response.


Post-Auth Behaviour
~~~~~~~~~~~~~~~~~~~

.. py:attribute:: CapturesPerConnection
    :type: int
    :value: 0

    *Maps to* :attr:`smb.SMBServerConfig.smb_captures_per_connection`

    Controls multi-credential capture via Windows SSPI retry.

    - ``0`` (default) -- single capture, then ``STATUS_SUCCESS`` so the
      client proceeds to ``TREE_CONNECT`` for share-path capture.  The
      configured :attr:`ErrorCode` is returned on the tree-connect response
      after the path is logged.  This is the recommended setting for most
      environments.

    - ``N`` (where N > 0) -- the first N-1 captures return
      ``STATUS_ACCOUNT_DISABLED`` (``0xC0000072``), which triggers Windows SSPI
      to retry with a different cached credential (e.g. a service account).
      The Nth capture returns ``STATUS_SUCCESS`` for tree-connect path
      capture.

    .. note::

        Multi-credential capture only works when the client has **multiple
        cached credentials** and the SSPI layer retries within the **same TCP
        connection**.  If the client has only one credential (the typical case
        for ``dir \\server\share`` loops), setting CPC > 0 has no additional
        effect over CPC = 0.

.. py:attribute:: ErrorCode
    :type: str | int
    :value: "STATUS_SMB_BAD_UID"

    *Maps to* :attr:`smb.SMBServerConfig.smb_error_code`

    NTSTATUS code returned after the final hash capture.  Accepts integer
    codes or string names from ``impacket.nt_errors``.

    .. list-table::
        :widths: 35 65
        :header-rows: 1

        * - Value
          - Effect
        * - ``"STATUS_SMB_BAD_UID"`` (default)
          - Client disconnects cleanly.
        * - ``"STATUS_ACCESS_DENIED"``
          - Client may retry, then disconnects.
        * - ``"STATUS_LOGON_FAILURE"``
          - Client disconnects cleanly.
        * - ``"STATUS_SUCCESS"``
          - Client proceeds to tree connect.  Useful for extending the
            session to capture tree-connect paths.

    The error code is logged at debug level as
    ``S: ErrorCode=0x{code:08x} (final)`` after each capture.


NTLM Settings
~~~~~~~~~~~~~

NTLM authentication settings (challenge, flags, AV_PAIRs, identity values)
are configured globally in the ``[NTLM]`` section and apply identically to
all protocols including SMB.  There are no per-protocol NTLM overrides.

.. seealso:: :ref:`config_ntlm` for all NTLM options and their effects.


Server Instances
~~~~~~~~~~~~~~~~

.. py:attribute:: Server
    :type: list

    Each ``[[SMB.Server]]`` entry spawns a listener on the specified port.
    Attributes set in ``[SMB]`` serve as defaults for all instances.

    .. py:attribute:: Server.Port
        :type: int

        *Maps to* :attr:`smb.SMBServerConfig.smb_port`

        The TCP port to listen on.  **Required** -- must be specified in each
        ``[[SMB.Server]]`` block.

        Standard ports:

        - **445** -- direct TCP transport (used by all modern clients)
        - **139** -- NetBIOS session service (used by XP/Server 2003 in
          addition to port 445; leaks NetBIOS CallingName)


SMB 3.1.1 Negotiate Contexts
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When the negotiated dialect is SMB 3.1.1, the ``SMB2_NEGOTIATE_RESPONSE``
includes three negotiate contexts:

.. list-table::
    :widths: 35 65
    :header-rows: 1

    * - Context
      - Content
    * - ``SMB2_PREAUTH_INTEGRITY_CAPABILITIES``
      - SHA-512 integrity algorithm with a random 32-byte salt.
    * - ``SMB2_ENCRYPTION_CAPABILITIES``
      - Echoes the client's preferred cipher (default: AES-128-GCM).
    * - ``SMB2_SIGNING_CAPABILITIES``
      - Echoes the client's preferred signing algorithm (default: AES-CMAC).

Dementor does not implement signing, sealing, or encryption -- these contexts
are echoed to keep the handshake alive through hash capture.


Logging
-------

Dementor emits a single summary line per SMB connection at ``info`` level,
combining all SMB-layer fields collected during the session:

.. code-block:: text

    SMB: os:Windows 10.0 | lanman:Windows 10.0 | account:jsmith | domain:CORP | path:\\10.0.0.50\IPC$ | dialect:SMB 3.1.1 | files:srvsvc

Fields included when present: ``os`` (NativeOS), ``lanman`` (NativeLanMan),
``calling`` (NetBIOS CallingName, port 139 only), ``called`` (NetBIOS
CalledName), ``account`` (SMB1 basic-security AccountName), ``domain``
(SMB1 basic-security PrimaryDomain), ``path`` (tree connect UNC path),
``dialect`` (negotiated dialect), ``files`` (deduplicated filenames from
CREATE requests).

At ``debug`` level, each SMB command is logged individually with direction
(``C:`` for client, ``S:`` for server), the command name, and relevant
fields.  For example:

.. code-block:: text

    C: SMB2_NEGOTIATE: Dialects=SMB 2.1, SMB 3.0, SMB 3.0.2, SMB 3.1.1
    S: SMB2_NEGOTIATE: selected dialect SMB 3.1.1
    C: SMB2_SESSION_SETUP (NTLMSSP NEGOTIATE)
    S: SMB2_SESSION_SETUP (NTLMSSP CHALLENGE)
    C: SMB2_SESSION_SETUP (NTLMSSP AUTHENTICATE)
    S: ErrorCode=0x00000000 (STATUS_SUCCESS, awaiting tree connect)
    C: SMB2_TREE_CONNECT: Path=\\10.0.0.50\IPC$
    S: SMB2_TREE_CONNECT IPC$ accepted

NTLM-specific log messages (hash extraction, classification, NTLMv2 blob
parsing) are documented in the :ref:`config_ntlm` Logging section.


Default Configuration
---------------------

.. code-block:: toml
    :linenos:
    :caption: Minimal SMB configuration (all options at defaults)

    [SMB]
    EnableSMB1 = true
    EnableSMB2 = true
    AllowSMB1Upgrade = true
    # SMB2MinDialect = "2.002"
    # SMB2MaxDialect = "3.1.1"
    # NetBIOSComputer = "DEMENTOR"
    # NetBIOSDomain = "WORKGROUP"
    # ServerOS = "Windows"
    # NativeLanMan = "Windows"
    CapturesPerConnection = 0
    ErrorCode = "STATUS_SMB_BAD_UID"

    # NTLM settings are in the [NTLM] section.

    [[SMB.Server]]
    Port = 139

    [[SMB.Server]]
    Port = 445


Spec References
---------------

.. list-table::
    :widths: 20 80
    :header-rows: 1

    * - Document
      - Covers
    * - **[MS-SMB]**
      - SMB1 protocol extensions (NT LM 0.12 dialect)
    * - **[MS-SMB2]**
      - SMB 2.x and 3.x protocol
    * - **[MS-NLMP]**
      - NTLM authentication protocol
    * - **[MS-CIFS]**
      - Original SMB1/CIFS (inherited by [MS-SMB] for non-extended structures)
    * - **[MS-SPNG]**
      - SPNEGO / GSS-API negotiation
