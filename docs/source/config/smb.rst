
.. _config_smb:

SMB
===

Section ``[SMB]``
------------------

.. py:currentmodule:: SMB

.. py:attribute:: Server
    :type: list

    *Each entry corresponds to an instance of* :class:`smb.SMBServerConfig`

    Defines a list of SMB server configuration sections. For instructions on configuring section lists,
    refer to the general configuration guide `Array Tables <https://toml.io/en/v1.0.0#array-of-tables>`_ for TOML.

    Attributes listed below can alternatively be specified in the global ``[SMB]`` section to serve
    as default values for all individual server entries.

    .. py:attribute:: Server.Port
        :type: int

        *Maps to* :attr:`smb.SMBServerConfig.smb_port`

        Specifies the port on which the SMB server instance listens. **This setting is required and cannot be
        used in the** ``[SMB]`` **section**.

        .. important::
            This attribute must be defined within a dedicated ``[[SMB.Server]]`` section.


    .. py:attribute:: Server.ServerOS
        :type: str

        *Map to* :attr:`smb.SMBServerConfig.smb_server_os`. *May also be set in* ``[SMB]``

        Defines the operating system for the SMB server. These values are used when crafting responses.

    .. py:attribute:: Server.ServerName
                      Server.ServerDomain
        :type: str

        *Map to* :attr:`smb.SMBServerConfig.smb_server_XXX`. *May also be set in* ``[SMB]``

        Defines identification metadata for the SMB server. These values are used when crafting responses.

        .. versionremoved:: 1.0.0.dev8
            :code:`ServerName` and :code:`ServerDomain` were merged into :attr:`SMB.Server.FQDN`

    .. py:attribute:: Server.FQDN
        :type: str
        :value: "DEMENTOR"

        *Linked to* :attr:`smb.SMBServerConfig.smb_fqdn`. *Can also be set in* ``[SMB]`` *or* ``[Globals]``

        Specifies the Fully Qualified Domain Name (FQDN) hostname used by the SMB server.
        The hostname portion of the FQDN will be included in server responses. The domain part is optional
        and will point to ``WORKGROUP`` by default.

        .. versionadded:: 1.0.0.dev8


    .. py:attribute:: Server.ErrorCode
        :type: str | int
        :value: nt_errors.STATUS_SMB_BAD_UID

        *Maps to* :attr:`smb.SMBServerConfig.smb_error_code`. *May also be set in* ``[SMB]``

        Specifies the NT status code returned when access is denied. Accepts either integer codes or their
        string representations (e.g., ``"STATUS_ACCESS_DENIED"``). Example values:

        - ``3221225506`` or ``"STATUS_ACCESS_DENIED"``
        - ``5963778`` or ``"STATUS_SMB_BAD_UID"``

        For a comprehensive list of status codes, refer to the ``impacket.nt_errors`` module.

        .. seealso::
            Use case: `Tricking Windows SMB clients into falling back to WebDav`_.


    .. py:attribute:: Server.SMB2Support
        :type: bool
        :value: true

        *Maps to* :attr:`smb.SMBServerConfig.smb2_support`. *May also be set in* ``[SMB]``

        Enables support for the SMB2 protocol. Recommended for improved client compatibility.


    .. py:attribute:: Server.Challenge
        :type: str
        :value: NTLM.Challenge

        *Maps to* :attr:`smb.SMBServerConfig.ntlm_challenge`

        The ServerChallenge nonce used during NTLM authentication. Inherited from
        :attr:`NTLM.Challenge`; set it there to apply a fixed challenge to all
        protocols including SMB.  Set it here (in ``[SMB]`` or ``[[SMB.Server]]``) to
        override the global value for SMB specifically.

        .. seealso:: :attr:`NTLM.Challenge` for accepted formats and behaviour.

    .. py:attribute:: Server.ExtendedSessionSecurity
        :value: true
        :type: bool

        .. versionremoved:: 1.0.0.dev19
            **Deprecated**: renamed to :attr:`DisableExtendedSessionSecurity`

    .. py:attribute:: Server.DisableExtendedSessionSecurity
        :type: bool
        :value: false

        *Linked to* :attr:`smb.SMBServerConfig.ntlm_disable_ess`. *Can also be set in* ``[SMB]``

        .. versionchanged:: 1.0.0.dev19
            Renamed from ``ExtendedSessionSecurity`` to explicit ``DisableExtendedSessionSecurity``

        Per-SMB override for :attr:`NTLM.DisableExtendedSessionSecurity`.  When set in
        ``[SMB]`` it applies to every ``[[SMB.Server]]`` instance; when set inside a
        single ``[[SMB.Server]]`` block it applies only to that port.  Falls back to
        :attr:`NTLM.DisableExtendedSessionSecurity` when not set here.

        .. seealso:: :attr:`NTLM.DisableExtendedSessionSecurity` for full behavioural details.


    .. py:attribute:: Server.DisableNTLMv2
        :type: bool
        :value: false

        *Linked to* :attr:`smb.SMBServerConfig.ntlm_disable_ntlmv2`. *Can also be set in* ``[SMB]``

        Per-SMB override for :attr:`NTLM.DisableNTLMv2`.  When set in ``[SMB]`` it
        applies to every ``[[SMB.Server]]`` instance; when set inside a single
        ``[[SMB.Server]]`` block it applies only to that port.  Falls back to
        :attr:`NTLM.DisableNTLMv2` when not set here.

        .. warning::
            Enabling this against modern Windows clients (``LmCompatibilityLevel`` 3+)
            will produce **zero captured hashes**.  See :attr:`NTLM.DisableNTLMv2` for
            full details.

        .. seealso:: :attr:`NTLM.DisableNTLMv2` for full behavioural details.


.. py:class:: smb.SMBServerConfig

    *Configuration class for entries under* :attr:`SMB.Server`

    Represents the configuration for a single SMB server instance.

    .. py:attribute:: smb_port
        :type: int

        *Corresponds to* :attr:`SMB.Server.Port`


    .. py:attribute:: smb_server_os
        :type: str
        :value: "Windows"

        *Corresponds to* :attr:`SMB.Server.ServerOS`


    .. py:attribute:: smb_server_name
        :type: str
        :value: "DEMENTOR"

        *Corresponds to* :attr:`SMB.Server.ServerName`

        .. versionremoved:: 1.0.0.dev8
            Merged into :attr:`SMB.Server.FQDN`


    .. py:attribute:: smb_server_domain
        :type: str
        :value: "WORKGROUP"

        *Corresponds to* :attr:`SMB.Server.ServerDomain`

        .. versionremoved:: 1.0.0.dev8
            Merged into :attr:`SMB.Server.FQDN`

    .. py:attribute:: smb_fqdn
        :type: str
        :value: "DEMENTOR"

        *Corresponds to* :attr:`SMB.Server.FQDN`

        .. versionadded:: 1.0.0.dev8


    .. py:attribute:: smb_error_code
        :type: str | int
        :value: nt_errors.STATUS_SMB_BAD_UID

        *Corresponds to* :attr:`SMB.Server.ErrorCode`

        You can use :func:`~smb.SMBServerConfig.set_smb_error_code` to set this attribute using a string
        or an integer.


    .. py:attribute:: smb2_support
        :type: bool
        :value: True

        *Corresponds to* :attr:`SMB.Server.SMB2Support`


    .. py:attribute:: ntlm_challenge
        :type: bytes

        *Corresponds to* :attr:`NTLM.Challenge`

        Populated at startup from the global ``[NTLM]`` section. A cryptographically
        random value is used if :attr:`NTLM.Challenge` is not configured.


    .. py:attribute:: ntlm_disable_ess
        :type: bool
        :value: False

        *Corresponds to* :attr:`NTLM.DisableExtendedSessionSecurity`

        When ``True``, ESS is suppressed in the ``CHALLENGE_MESSAGE`` and clients
        produce plain **NetNTLMv1** hashes instead of **NetNTLMv1-ESS**.


    .. py:attribute:: ntlm_disable_ntlmv2
        :type: bool
        :value: False

        *Corresponds to* :attr:`NTLM.DisableNTLMv2`

        When ``True``, ``TargetInfoFields`` is omitted from the ``CHALLENGE_MESSAGE``.
        Level 0-2 clients fall back to NTLMv1; level 3+ clients fail with no capture.


Protocol Behaviour
------------------

Authentication Flow
~~~~~~~~~~~~~~~~~~~

The SMB handler accepts NTLM tokens in two forms:

- **NTLM SSP** -- the security buffer begins with ``NTLMSSP\0`` and is consumed
  directly by the three-message NTLM handshake (``NEGOTIATE → CHALLENGE → AUTHENTICATE``).
- **GSSAPI / SPNEGO** -- the buffer is wrapped in a ``negTokenInit`` (tag ``0x60``) or
  ``negTokenTarg`` (tag ``0xA1``) envelope.  Dementor unwraps the SPNEGO layer,
  performs the NTLM handshake internally, and returns appropriately wrapped
  ``negTokenTarg`` responses.

In both cases the captured hash is passed to :func:`~ntlm.NTLM_report_auth` and stored
in the session database.

Protocol Version Negotiation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

All SMB connections start with an ``SMB_COM_NEGOTIATE`` / ``SMB2_NEGOTIATE``
exchange.  When :attr:`SMB.Server.SMB2Support` is enabled (the default):

- An SMB1 client that includes any SMB2 or SMB3 dialect string receives an
  ``SMB2_NEGOTIATE_RESPONSE`` and the connection is silently upgraded to SMB2/SMB3.
  If the client advertises the wildcard ``"SMB 2.???"`` dialect, Dementor selects
  the highest dialect it supports (``3.1.1``); otherwise it selects the last SMB2
  dialect in the client's list.
- A native SMB2/SMB3 client (``SMB2_NEGOTIATE``) receives a response selecting
  the **highest common dialect** from the supported set (``2.002``, ``2.1``,
  ``3.0``, ``3.0.2``, ``3.1.1``).
- A pure SMB1 client (no SMB2 dialect strings) receives the SMB1 extended-security
  negotiate response and continues over SMB1.

SMB 3.1.1 Negotiate Contexts
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When the negotiated dialect is **SMB 3.1.1**, the ``SMB2_NEGOTIATE_RESPONSE``
includes the mandatory negotiate context list:

- **SMB2_PREAUTH_INTEGRITY_CAPABILITIES** -- SHA-512 integrity algorithm with a
  cryptographically random 32-byte salt.
- **SMB2_ENCRYPTION_CAPABILITIES** -- echoes the cipher the client advertised
  (falls back to AES-128-GCM if the context is absent or unparseable).
- **SMB2_SIGNING_CAPABILITIES** -- echoes the signing algorithm the client
  advertised (falls back to AES-CMAC).

Session Logoff
~~~~~~~~~~~~~~

``SMB2_LOGOFF`` requests are handled: Dementor clears the local authenticated
flag, returns an ``SMB2_LOGOFF_RESPONSE`` with ``STATUS_SUCCESS``, and logs the
event via the protocol logger.

.. note::

    **Tree Connect** (``SMB_COM_TREE_CONNECT_ANDX`` / ``SMB2_TREE_CONNECT``) is
    not currently implemented. Connections are terminated after authentication,
    which is sufficient for credential capture but may prevent some clients from
    retrying via alternative protocols.


Default Configuration
---------------------

.. code-block:: toml
    :linenos:
    :caption: SMB configuration section (all options)

    [SMB]
    # FQDN = "DEMENTOR"                       # also settable in [Globals]
    ServerOS = "Windows"
    SMB2Support = true
    ErrorCode = "STATUS_SMB_BAD_UID"
    # Challenge = "1337LEET"                  # overrides [NTLM] for all SMB servers
    # DisableExtendedSessionSecurity = false  # overrides [NTLM] for all SMB servers
    # DisableNTLMv2 = false                   # overrides [NTLM] for all SMB servers

    [[SMB.Server]]
    Port = 139

    [[SMB.Server]]
    Port = 445
    # Per-server overrides (highest priority):
    # FQDN = "other.corp.com"
    # ServerOS = "Windows Server 2022"
    # ErrorCode = "STATUS_ACCESS_DENIED"
    # SMB2Support = true
    # Challenge = "hex:aabbccddeeff0011"
    # DisableExtendedSessionSecurity = false
    # DisableNTLMv2 = false


.. _Tricking Windows SMB clients into falling back to WebDav: https://www.synacktiv.com/publications/taking-the-relaying-capabilities-of-multicast-poisoning-to-the-next-level-tricking