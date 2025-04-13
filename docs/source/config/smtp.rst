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
.. _config_smtp:

SMTP
====

Section: ``[SMTP]``
-------------------

.. py:currentmodule:: SMTP

.. py:attribute:: Server
    :type: list

    *Each server entry is mapped to an instance of* :class:`smtp.SMTPServerConfig`

    Represents a list of SMTP server configuration sections. For guidance on defining
    section lists, refer to the general configuration documentation `Array Tables <https://toml.io/en/v1.0.0#array-of-tables>`_ of TOML.

    Any attribute marked below can also be defined in the ``[SMTP]`` section to apply
    a default value to all server entries.

    .. py:attribute:: Server.Port
        :type: int

        *Linked to* :attr:`smtp.SMTPServerConfig.smtp_port`

        Defines the port used by the SMTP server instance. **This option is mandatory.**

        .. important::
            This value must be specified within a ``[[SMTP.Server]]`` section.


    .. py:attribute:: Server.FQDN
        :type: str
        :value: "DEMENTOR"

        *Linked to* :attr:`smtp.SMTPServerConfig.smtp_fqdn`. *Can also be set in* ``[SMTP]``

        Specifies the Fully Qualified Domain Name (FQDN) hostname used by the SMTP server.
        The hostname portion of the FQDN will be included in server responses. The domain part is optional.

    .. py:attribute:: Server.Ident
        :type: str
        :value: "Dementor 1.0"

        *Linked to* :attr:`smtp.SMTPServerConfig.smtp_ident`. *Can also be set in* ``[SMTP]``

        Defines the SMTP server banner (typically identifier and version) sent to clients.
        This value may influence detection; some antivirus and EDR solutions inspect banners for known patterns.

    .. py:attribute:: Server.AuthMechanisms
        :type: list[str]
        :value: [ "NTLM", "PLAIN", "LOGIN" ]

        *Linked to* :attr:`smtp.SMTPServerConfig.smtp_auth_mechanisms`. *Can also be set in* ``[SMTP]``

        Lists the supported SMTP authentication mechanisms. Currently implemented options:

        - ``LOGIN``: Base64-encoded challenge-based login (via aiosmtpd_).
        - ``PLAIN``: Sends credentials in cleartext (via aiosmtpd_).
        - ``NTLM``: Implements NTLM authentication per `[MS-SMTPNTLM] <https://winprotocoldocs-bhdugrdyduf5h2e4.b02.azurefd.net/MS-SMTPNTLM/%5bMS-SMTPNTLM%5d.pdf>`_

        You may remove ``LOGIN`` and ``PLAIN`` to force NTLM. For downgrade attacks, see :attr:`SMTP.Server.Downgrade`.

    .. py:attribute:: Server.Downgrade
        :type: bool
        :value: true

        *Linked to* :attr:`smtp.SMTPServerConfig.smtp_downgrade`. *Can also be set in* ``[SMTP]``

        Attempts to downgrade authentication from NTLM to weaker methods like LOGIN. This is only effective
        if the client is configured to permit plaintext authentication. See example_smtp_downgrade_attack_ for practical usage.

    .. py:attribute:: Server.TLS
        :type: bool
        :value: false

        *Linked to* :attr:`smtp.SMTPServerConfig.smtp_tls`. *Can also be set in* ``[SMTP]``

        Enables SSL/TLS support using a custom certificate.

    .. py:attribute:: Server.Cert
        :type: str

        *Linked to* :attr:`smtp.SMTPServerConfig.smtp_tls_cert`. *Can also be set in* ``[SMTP]`` or ``[Globals]``

        Specifies the path to the certificate used when TLS is enabled.

    .. py:attribute:: Server.Key
        :type: str

        *Linked to* :attr:`smtp.SMTPServerConfig.smtp_tls_key`. *Can also be set in* ``[SMTP]`` or ``[Globals]``

        Specifies the private key file corresponding to the certificate used for TLS.


    .. py:attribute:: Server.RequireSTARTTLS
        :type: bool
        :value: false

        *Linked to* :attr:`smtp.SMTPServerConfig.smtp_require_starttls`. *Can also be set in* ``[SMTP]``

        Enforces STARTTLS negotiation before any SMTP commands are accepted.


    .. py:attribute:: Server.RequireAUTH
        :type: bool
        :value: false

        *Linked to* :attr:`smtp.SMTPServerConfig.smtp_require_auth`. *Can also be set in* ``[SMTP]``

        Requires SMTP authentication before the client is permitted to send mail.


Python Config
-------------

.. py:class:: smtp.SMTPServerConfig

    Represents the configuration for a single SMTP server instance.

    .. py:attribute:: smtp_port
        :type: int

        *Corresponds to* :attr:`SMTP.Server.Port`

    .. py:attribute:: smtp_tls
        :type: bool
        :value: False

        *Corresponds to* :attr:`SMTP.Server.TLS`.


    .. py:attribute:: smtp_fqdn
        :type: str
        :value: "DEMENTOR"

        *Corresponds to* :attr:`SMTP.Server.FQDN`.

        .. note::
            The format used to describe the FWDN hostname incorporates an optional
            FWDN specification: For instance, using the domain ``CONTOSO.LOCAL`` and
            hostname ``EXAMPLE``, the resulting string would be ``EXAMPLE.CONTOSO.LOCAL``.
            However, the domain is purely optional and won't be used if not present.


    .. py:attribute:: smtp_ident
        :type: str
        :value: "Dementor 1.0dev0"

        *Corresponds to* :attr:`SMTP.Server.Ident`.


    .. py:attribute:: smtp_downgrade
        :type: bool
        :value: False

        *Corresponds to* :attr:`SMTP.Server.Downgrade`.


    .. py:attribute:: smtp_auth_mechanisms
        :type: list[str]
        :value: []

        *Corresponds to* :attr:`SMTP.Server.AuthMechanisms`.

        .. container:: demo

            .. code-block:: console
                :caption: Default auth mechanisms returned by a SMTP server

                $ nc 127.0.0.1 25
                220 DEMENTOR Dementor 1.0
                EHLO foobar
                250-DEMENTOR
                250-SIZE 33554432
                250-8BITMIME
                250-SMTPUTF8
                250-AUTH LOGIN NTLM PLAIN login ntlm plain
                250 HELP



    .. py:attribute:: smtp_require_auth
        :type: bool
        :value: False

        *Corresponds to* :attr:`SMTP.Server.RequireAUTH`.


    .. py:attribute:: smtp_require_starttls
        :type: bool
        :value: False

        *Corresponds to* :attr:`SMTP.Server.RequireSTARTTLS`.


    .. py:attribute:: smtp_tls_cert
        :type: str

        *Corresponds to* :attr:`SMTP.Server.Cert`.


    .. py:attribute:: smtp_tls_key
        :type: str

        *Corresponds to* :attr:`SMTP.Server.Key`.



Default Configuration
---------------------

.. code-block:: toml
    :linenos:
    :caption: SMTP configuration section (default values)

    [SMTP]
    # Global settings for all SMTP servers
    AuthMechanisms = [ "NTLM", "PLAIN", "LOGIN" ]
    FQDN = "DEMENTOR"
    Ident = "Dementor 1.0"
    RequireAUTH = false
    Downgrade = true
    RequireSTARTTLS = false

    # three servers are active by default
    [[SMTP.Server]]
    Port = 25

    [[SMTP.Server]]
    Port = 465

    [[SMTP.Server]]
    Port = 587


.. _aiosmtpd: https://github.com/aio-libs/aiosmtpd