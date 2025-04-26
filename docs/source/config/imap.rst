.. _config_imap:

IMAP
====

Section ``[IMAP]``
------------------

.. versionadded:: 1.0.0.dev5

.. py:currentmodule:: IMAP

.. py:attribute:: Server
    :type: list

    *Each server entry is mapped to an instance of* :class:`imap.IMAPServerConfig`.

    Represents a list of IMAP server configuration sections. For general guidance on defining
    section lists, refer to the TOML documentation for `Array Tables <https://toml.io/en/v1.0.0#array-of-tables>`_.

    .. py:attribute:: Server.Port
        :type: int

        *Linked to* :attr:`imap.IMAPServerConfig.imap_port`

        Defines the port used by the IMAP server instance. **This option is mandatory.**

        .. important::
            This value must be specified within a ``[[IMAP.Server]]`` section.

    The attributes described below may also be specified in the global ``[IMAP]`` section, where they act
    as defaults for all individual server entries — unless explicitly overridden.

    .. py:attribute:: Server.Capabilities
        :type: str
        :value: [ "IMAP4rev1", "IMAP4rev2" ]

        *Linked to* :attr:`imap.IMAPServerConfig.imap_caps`. *Can also be set in* ``[IMAP]``.

        Defines the server capabilities to advertise to the client. According to the IMAP specification, the revision
        (such as `IMAP4rev1`) **must** be returned.

    .. py:attribute:: Server.FQDN
        :type: str
        :value: "Dementor"

        *Linked to* :attr:`imap.IMAPServerConfig.imap_fqdn`. *Can also be set in* ``[IMAP]`` *or* ``[Globals]``.

        Specifies the Fully Qualified Domain Name (FQDN) hostname used by the IMAP server.
        The hostname portion appears in server responses; the domain part is optional.

    .. py:attribute:: Server.Banner
        :type: str
        :value: "IMAP Server ready"

        *Linked to* :attr:`imap.IMAPServerConfig.imap_banner`. *Can also be set in* ``[IMAP]``.

        Defines a custom banner message sent in the server's greeting upon client connection.

    .. py:attribute:: Server.AuthMechanisms
        :type: list[str]
        :value: [ "NTLM", "PLAIN", "LOGIN" ]

        *Linked to* :attr:`imap.IMAPServerConfig.imap_auth_mechs`. *Can also be set in* ``[IMAP]``.

        Lists the authentication mechanisms supported by the server. Currently implemented options:

        - ``LOGIN`` — Base64-encoded challenge-based login.
        - ``PLAIN`` — Sends credentials in cleartext.
        - ``NTLM`` — Implements NTLM authentication per `[MS-SMTPNTLM] <https://winprotocoldocs-bhdugrdyduf5h2e4.b02.azurefd.net/MS-SMTPNTLM/%5bMS-SMTPNTLM%5d.pdf>`_.

        To enforce NTLM-only authentication, remove ``LOGIN`` and ``PLAIN``.
        For downgrade attacks, refer to :attr:`SMTP.Server.Downgrade`.

    .. py:attribute:: Server.Downgrade
        :type: bool
        :value: true

        *Linked to* :attr:`imap.IMAPServerConfig.imap_downgrade`. *Can also be set in* ``[IMAP]``.

        Attempts to downgrade authentication from NTLM to weaker methods like ``LOGIN``.
        Effective only if the client permits plaintext authentication. See :ref:`example_smtp_downgrade` for
        usage examples.

    .. py:attribute:: Server.TLS
        :type: bool
        :value: false

        *Linked to* :attr:`imap.IMAPServerConfig.use_ssl`. *Can also be set in* ``[IMAP]``.

        Enables SSL/TLS for the IMAP server using a custom certificate.

    .. py:attribute:: Server.Cert
        :type: str

        *Linked to* :attr:`imap.IMAPServerConfig.certfile`. *Can also be set in* ``[IMAP]`` *or* ``[Globals]``.

        Specifies the path to the TLS certificate file.

    .. py:attribute:: Server.Key
        :type: str

        *Linked to* :attr:`imap.IMAPServerConfig.keyfile`. *Can also be set in* ``[IMAP]`` *or* ``[Globals]``.

        Specifies the path to the private key file associated with the TLS certificate.

    .. py:attribute:: ExtendedSessionSecurity
        :type: bool
        :value: true

        *Maps to* :attr:`imap.IMAPServerConfig.ntlm_ess`.

        Enables NTLM Extended Session Security (ESS).
        When enabled, NTLMv1/NTLMv2-SSP hashes are captured instead of raw NTLM hashes.
        Resolution precedence:

        1. :attr:`IMAP.ExtendedSessionSecurity`
        2. :attr:`NTLM.ExtendedSessionSecurity` (fallback)

    .. py:attribute:: Challenge
        :type: str
        :value: NTLM.Challenge

        *Maps to* :attr:`imap.IMAPServerConfig.ntlm_challenge`.

        Sets the NTLM challenge value used during authentication.
        Resolution order:

        1. :attr:`IMAP.Challenge`
        2. :attr:`NTLM.Challenge`

Default Configuration
----------------------

.. code-block:: toml
    :linenos:
    :caption: IMAP configuration section (default values)

    [IMAP]
    Banner = "IMAP Server ready"
    AuthMechanisms = ["NTLM", "PLAIN", "LOGIN"]
    Downgrade = true

    [[IMAP.Server]]
    Port = 110

.. note::
    The default configuration does **NOT** include an IMAP server wrapped in an ``SSLContext``.
    To configure a server with TLS enabled, use:

    .. code-block:: toml
        :caption: Dementor.toml

        [IMAP]
        # ...

        [[IMAP.Server]]
        Port = 993
        TLS = true  # must be explicitly set
        Cert = "/path/to/certificate"
        Key = "/path/to/key"
