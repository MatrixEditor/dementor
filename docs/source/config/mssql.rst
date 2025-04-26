.. _config_mssql:

MSSQL
=====

*Dementor* includes a simplified MSSQL server that supports NTLM authentication. However, not all MSSQL
clients can be used to capture credentials. If the client requires encryption (TLS), the current
implementation will terminate the connection.

.. note::
    *Dementor* will show a hint that encryption was requested from the client:

    .. code-block:: console
        :emphasize-lines: 4

        LLMNR  192.168.56.116  5355   [+] Sent poisoned answer to 192.168.56.116
        MDNS   192.168.56.116  5353   [+] Sent poisoned answer to 192.168.56.116
        LLMNR  192.168.56.116  5355   [+] Sent poisoned answer to 192.168.56.116
        MSSQL  192.168.56.116  1433   [*] Pre-Login request for (blank) (Encryption requested)


Section ``[MSSQL]``
-------------------

.. versionadded:: 1.0.0.dev4

.. py:currentmodule:: MSSQL

.. py:attribute:: Port
    :type: int
    :value: 1433

    *Maps to* :attr:`mssql.MSSQLConfig.mssql_port`

    Specifies the port the MSSQL server listens on.

.. py:attribute:: Version
    :type: str
    :value: "9.00.1399.06"

    *Maps to* :attr:`mssql.MSSQLConfig.mssql_server_version`

    Sets the server version string returned to clients.

.. py:attribute:: InstanceName
    :type: str
    :value: "MSSQLServer"

    *Maps to* :attr:`mssql.MSSQLConfig.mssql_instance`

    Specifies the MSSQL instance name returned in SSRP responses. This can be overridden
    via :attr:`SSRP.InstanceName`.

.. py:attribute:: ExtendedSessionSecurity
    :type: bool
    :value: true

    *Maps to* :attr:`mssql.MSSQLConfig.ntlm_ess`

    .. versionchanged:: 1.0.0.dev5
        Internal mapping changed frmo ``mssql_ess`` to ``ntlm_ess``

    Enables NTLM Extended Session Security (ESS). When enabled, NTLMv1/NTLMv2-SSP hashes are
    captured instead of raw NTLM hashes. Resolution precedence:

    1. :attr:`MSSQL.ExtendedSessionSecurity`
    2. :attr:`NTLM.ExtendedSessionSecurity` (fallback)

.. py:attribute:: Challenge
    :type: str
    :value: NTLM.Challenge

    *Maps to* :attr:`mssql.MSSQLServerConfig.ntlm_challenge`

    .. versionchanged:: 1.0.0.dev5
        Internal mapping changed frmo ``mssql_challenge`` to ``ntlm_challenge``

    Sets the NTLM challenge value. Resolution order:

    1. :attr:`MSSQL.Challenge`
    2. :attr:`NTLM.Challenge`

.. py:attribute:: FQDN
    :type: str
    :value: "DEMENTOR"

    *Maps to* :attr:`mssql.MSSQLServerConfig.mssql_fqdn`. *May also be set in* ``[Globals]``

    Sets the Fully Qualified Domain Name (FQDN) returned by the server. The hostname portion
    is used in NTLM responses; the domain portion is optional.

Error Configuration
^^^^^^^^^^^^^^^^^^^

.. py:attribute:: ErrorCode
    :type: int
    :value: 1205

    *Maps to* :attr:`mssql.MSSQLConfig.mssql_error_code`

    Sets the MS-SQL-Server error code to return to clients.

.. py:attribute:: ErrorState
    :type: int
    :value: 1

    *Maps to* :attr:`mssql.MSSQLConfig.mssql_error_state`

    Sets the error state value returned to clients.

.. py:attribute:: ErrorClass
    :type: int
    :value: 1205

    *Maps to* :attr:`mssql.MSSQLConfig.mssql_error_class`

    Sets the error class value returned to clients.

.. py:attribute:: ErrorMessage
    :type: int
    :value: 1205

    *Maps to* :attr:`mssql.MSSQLConfig.mssql_error_msg`

    Sets the error message value returned to clients.

.. _config_ssrp:

Section ``[SSRP]``
------------------

.. versionadded:: 1.0.0.dev4

.. py:currentmodule:: SSRP

.. py:attribute:: InstanceConfig
    :type: str
    :value: ""

    *Maps to* :attr:`mssql.SSRPConfig.ssrp_instance_config`

    Defines extra instance configuration values for SSRP responses. The format must follow
    the ``RESP_DATA`` structure from section *2.2.5 SVR_RESP*. The string **must begin with a
    semicolon and MUST NOT end with one**. For example::

        InstanceConfig = ";rpc;DEMENTOR"

    would be valid.

Inherited from ``[MSSQL]``
^^^^^^^^^^^^^^^^^^^^^^^^^^

.. py:attribute:: FQDN
    :type: str
    :value: MSSQL.FQDN

    *Maps to* :attr:`mssql.SSRPConfig.ssrp_server_name`. *May also be set in* ``[Globals]``

    Defines the server name as described in :attr:`MSSQL.FQDN`.

.. py:attribute:: Version
    :type: str
    :value: MSSQL.Version

    *Maps to* :attr:`mssql.SSRPConfig.ssrp_server_version`. *May also be set in* ``[MSSQL]``

    Defines the server version string as described in :attr:`MSSQL.Version`.

.. py:attribute:: InstanceName
    :type: str
    :value: MSSQL.InstanceName

    *Maps to* :attr:`mssql.SSRPConfig.ssrp_server_instance`. *May also be set in* ``[MSSQL]``

    Sets the server instance name, as described in :attr:`MSSQL.InstanceName`.



Default Configuration
---------------------

.. code-block:: toml
    :linenos:
    :caption: MSSQL and SSRP configuration section (default values)

    [MSSQL]
    ErrorCode = 1205
    Version = "9.00.1399.06"
    InstanceName = "MSSQLServer"

    [SSRP]
    # empty by default