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
.. _config_ldap:


LDAP ⚙️
=======

.. py:currentmodule:: LDAP

.. py:attribute:: Server
    :type: list

    *Each entry maps to an instance of* :class:`ldap.LDAPServerConfig`

    Defines a list of LDAP server configuration sections. For details on configuring section lists,
    see the general configuration guide: :ref:`config_guide_setion_lists`.

    .. py:attribute:: Server.Port
        :type: int

        *Maps to* :attr:`ldap.LDAPServerConfig.ldap_port`

        Specifies the port on which the LDAP server instance listens. **This option is required and must be
        defined within each individual ``[[LDAP.Server]]`` section.**


    .. py:attribute:: Server.Connectionless
        :type: bool

        *Maps to* :attr:`ldap.LDAPServerConfig.ldap_udp`

        Configures the LDAP server to operate over UDP (CLDAP), rather than the default TCP transport.
        **This option must be set within each individual server section and is not allowed in the global ``[LDAP]`` section.**


    The attributes described below may also be specified in the global ``[LDAP]`` section, where they will serve
    as default values for all individual server entries — unless explicitly overridden.


    .. py:attribute:: Server.Capabilities
        :type: list[str]

        *Maps to* :attr:`ldap.LDAPServerConfig.ldap_caps`. *Can also be set in* ``[LDAP]``

        Lists LDAP capabilities returned by the server when queried. Default values include:

        - ``"1.2.840.113556.1.4.800"`` (``LDAP_CAP_ACTIVE_DIRECTORY_OID``):
            Indicates the LDAP server is running Active Directory Domain Services (AD DS). [1]_

        - ``"1.2.840.113556.1.4.1791"`` (``LDAP_CAP_ACTIVE_DIRECTORY_LDAP_INTEG_OID``):
            Specifies that the server supports LDAP signing and sealing with NTLM authentication,
            and can handle subsequent binds over secure channels. [1]_

        - ``"1.2.840.113556.1.4.1670"`` (``LDAP_CAP_ACTIVE_DIRECTORY_V51_OID``):
            Indicates the LDAP server is running at least the Windows Server 2003 version of AD DS. [1]_


    .. py:attribute:: Server.SASLMechanisms
        :type: list[str]

        *Maps to* :attr:`ldap.LDAPServerConfig.ldap_mech`. *Can also be set in* ``[LDAP]``

        Defines the list of supported SASL authentication mechanisms. By default, the server supports:
        GSSAPI, GSS-SPNEGO, and simple binds.


    .. py:attribute:: Server.Timeout
        :type: int

        *Maps to* :attr:`ldap.LDAPServerConfig.ldap_timeout`. *Can also be set in* ``[LDAP]``

        Configures the LDAP operation timeout in seconds. A value of ``0`` disables the timeout (default),
        which may cause issues during tool shutdown. Any non-zero value sets the maximum allowed duration
        for operations.


    .. py:attribute:: Server.FQDN
        :type: str

        *Maps to* :attr:`ldap.LDAPServerConfig.ldap_fqdn`. *Can also be set in* ``[LDAP]``

        Specifies the server's hostname or fully qualified domain name (FQDN). The domain portion is optional.
        Example: ``"HOSTNAME.domain.local"``.


    .. py:attribute:: Server.ErrorCode
        :type: str | int

        *Maps to* :attr:`ldap.LDAPServerConfig.ldap_error_code`. *Can also be set in* ``[LDAP]``

        Sets the LDAP error code to return upon successful authentication. It is recommended to return a valid error
        (rather than success). By default, the server returns ``"unwillingToPerform"``.


    .. py:attribute:: Server.TLS
        :type: bool
        :value: false

        *Maps to* :attr:`ldap.LDAPServerConfig.ldap_tls`. *Can also be set in* ``[LDAP]``

        Enables SSL/TLS encryption using a custom certificate.


    .. py:attribute:: Server.Cert
        :type: str

        *Maps to* :attr:`ldap.LDAPServerConfig.ldap_tls_cert`. *Can also be set in* ``[LDAP]`` or ``[Globals]``

        Specifies the path to the certificate file used when TLS is enabled.


    .. py:attribute:: Server.Key
        :type: str

        *Maps to* :attr:`ldap.LDAPServerConfig.ldap_tls_key`. *Can also be set in* ``[LDAP]`` or ``[Globals]``

        Specifies the path to the private key file associated with the TLS certificate.


Default Configuration
---------------------

.. code-block:: toml
    :linenos:
    :caption: LDAP configuration section (default values)

    [LDAP]
    Timeout = 2
    FQDN = "DEMENTOR"
    TLS = false
    ErrorCode = "unwillingToPerform"

    [[LDAP.Server]]
    Connectionless = false
    Port = 389

    [[LDAP.Server]]
    # means UDP
    Port = 389
    Connectionless = true

.. [1] MS-ADTS LDAP Capabilities: `[MS-ADTS] <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3ed61e6c-cfdc-487d-9f02-5a3397be3772>`_