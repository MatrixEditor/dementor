.. _config_pop3:

POP3
====

Section ``[POP3]``
------------------

.. versionadded:: 1.0.0.dev5

.. py:currentmodule:: POP3

.. py:attribute:: Server
    :type: list

    *Each server entry is mapped to an instance of* :class:`pop3.POP3ServerConfig`

    Represents a list of POP3 server configuration sections. For guidance on defining
    section lists, refer to the general configuration documentation `Array Tables <https://toml.io/en/v1.0.0#array-of-tables>`_ of TOML.

    .. py:attribute:: Server.Port
        :type: int

        *Linked to* :attr:`pop3.POP3ServerConfig.pop3_port`

        Defines the port used by the POP3 server instance. **This option is mandatory.**

        .. important::
            This value must be specified within a ``[[POP3.Server]]`` section.

    The attributes described below may also be specified in the global ``[POP3]`` section, where they will serve
    as default values for all individual server entries — unless explicitly overridden.

    .. py:attribute:: Server.FQDN
        :type: str
        :value: "Dementor"

        *Linked to* :attr:`pop3.POP3ServerConfig.pop3_fqdn`. *Can also be set in* ``[POP3]`` *or* ``[Globals]``

        Specifies the Fully Qualified Domain Name (FQDN) hostname used by the POP3 server.
        The hostname portion of the FQDN will be included in server responses. The domain part is optional.

    .. py:attribute:: Server.Banner
        :type: str
        :value: "POP3 Server ready"

        *Linked to* :attr:`pop3.POP3ServerConfig.pop3_banner`. *Can also be set in* ``[POP3]``

        Defines a custom banner to send in the server's greeting message.

    .. py:attribute:: Server.AuthMechanisms
        :type: list[str]
        :value: [ "NTLM", "PLAIN", "LOGIN" ]

        *Linked to* :attr:`pop3.POP3ServerConfig.pop3_auth_mechs`. *Can also be set in* ``[POP3]``

        Lists the supported SMTP authentication mechanisms. Currently implemented options:

        - ``LOGIN``: Base64-encoded challenge-based login.
        - ``PLAIN``: Sends credentials in cleartext.
        - ``NTLM``: Implements NTLM authentication per `[MS-SMTPNTLM] <https://winprotocoldocs-bhdugrdyduf5h2e4.b02.azurefd.net/MS-SMTPNTLM/%5bMS-SMTPNTLM%5d.pdf>`_

        You may remove ``LOGIN`` and ``PLAIN`` to force NTLM. For downgrade attacks, see :attr:`SMTP.Server.Downgrade`.

    .. py:attribute:: Server.Downgrade
        :type: bool
        :value: true

        *Linked to* :attr:`pop3.POP3ServerConfig.pop3_downgrade`. *Can also be set in* ``[POP3]``

        Attempts to downgrade authentication from NTLM to weaker methods like LOGIN. This is only effective
        if the client is configured to permit plaintext authentication. See :ref:`example_smtp_downgrade` for
        practical usage.

    .. py:attribute:: Server.TLS
        :type: bool
        :value: false

        *Linked to* :attr:`pop3.POP3ServerConfig.use_ssl`. *Can also be set in* ``[POP3]``

        Enables SSL/TLS support using a custom certificate.

    .. py:attribute:: Server.Cert
        :type: str

        *Linked to* :attr:`pop3.POP3ServerConfig.certfile`. *Can also be set in* ``[POP3]`` or ``[Globals]``

        Specifies the path to the certificate used when TLS is enabled.

    .. py:attribute:: Server.Key
        :type: str

        *Linked to* :attr:`pop3.POP3ServerConfig.keyfile`. *Can also be set in* ``[POP3]`` or ``[Globals]``

        Specifies the private key file corresponding to the certificate used for TLS.


    .. py:attribute:: ExtendedSessionSecurity
        :type: bool
        :value: true

        *Maps to* :attr:`pop3.POP3ServerConfig.ntlm_ess`

        Enables NTLM Extended Session Security (ESS). When enabled, NTLMv1/NTLMv2-SSP hashes are
        captured instead of raw NTLM hashes. Resolution precedence:

        1. :attr:`POP3.ExtendedSessionSecurity`
        2. :attr:`NTLM.ExtendedSessionSecurity` (fallback)

    .. py:attribute:: Challenge
        :type: str
        :value: NTLM.Challenge

        *Maps to* :attr:`pop3.POP3ServerConfig.ntlm_challenge`

        Sets the NTLM challenge value. Resolution order:

        1. :attr:`POP3.Challenge`
        2. :attr:`NTLM.Challenge`


Default Configuration
---------------------

.. code-block:: toml
    :linenos:
    :caption: POP3 configuration section (default values)

    [POP3]
    Banner = "POP3 Server ready"
    AuthMechanisms = ["NTLM", "PLAIN", "LOGIN"]
    Downgrade = true

    [[POP3.Server]]
    # plaintext
    Port = 110

.. note::
    The default configuration does **NOT** include a POP3 server wrapped in an ``SSLContext``. You can
    specify a custom POP3 server with TLS enabled like this:

    .. code-block:: toml
        :caption: Dementor.toml

        [POP3]
        # ...

        [[POP3.Server]]
        Port = 995
        TLS = true  # must be set
        Cert = "/path/to/certificate"
        Key = "/path/to/key"