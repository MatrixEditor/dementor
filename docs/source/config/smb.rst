
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
        :value: "Dementor"

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


    .. py:attribute:: Server.ExtendedSessionSecurity
        :type: bool
        :value: true

        *Maps to* :attr:`smb.SMBServerConfig.smb_ess`. *May also be set in* ``[SMB]``

        Enables Extended Session Security (ESS) during NTLM authentication. When ESS is enabled,
        the server captures NTLMv1/v2-SSP hashes instead of standard NTLMv1/v2 hashes. Resolution
        precedence:

        1. If defined, :attr:`SMB.Server.ExtendedSessionSecurity` takes precedence.
        2. If not, :attr:`SMB.ExtendedSessionSecurity` is used.
        3. Finally, falls back to :attr:`NTLM.ExtendedSessionSecurity` if the above are unset.

    .. py:attribute:: Server.Challenge
        :type: str
        :value: NTLM.Challenge

        *Maps to* :attr:`smb.SMBServerConfig.smb_challenge`. *May also be set in* ``[SMB]``

        Defines the challenge value used during NTLM authentication. Resolution precedence:

        1. :attr:`SMB.Server.Challenge` (if defined)
        2. :attr:`SMB.Challenge` (fallback)
        3. :attr:`NTLM.Challenge` (final fallback)

        .. note::
            If none of the above attributes are set, the SMB server will generate a random challenge
            value for each session.


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


    .. py:attribute:: smb_ess
        :type: bool
        :value: True

        *Corresponds to* :attr:`SMB.Server.ExtendedSessionSecurity`


    .. py:attribute:: smb_challenge
        :type: bytes = b""

        *Corresponds to* :attr:`SMB.Server.Challenge`

        By default, a random challenge will be generated based on the rules described
        in :attr:`SMB.Server.Challenge`.


Default Configuration
---------------------

.. code-block:: toml
    :linenos:
    :caption: SMB configuration section (default values)

    [SMB]
    ServerOS = "Windows"
    FQDN = "DEMENTOR"
    SMB2Support = true
    ErrorCode = "STATUS_SMB_BAD_UID"

    [[SMB.Server]]
    Port = 139

    [[SMB.Server]]
    Port = 445


.. _Tricking Windows SMB clients into falling back to WebDav: https://www.synacktiv.com/publications/taking-the-relaying-capabilities-of-multicast-poisoning-to-the-next-level-tricking