.. _config_mysql:

MySQL
=====

The current server implementation is functional up to the point of client authentication.
NTLM and SPNEGO authentication mechanisms are not yet supported and are planned for a future release.

By default, the server will log any client attempts to initiate SSL negotiation. If a certificate
is not configured, the server will terminate the connection due to the missing TLS implementation.

Section ``[MySQL]``
-------------------

.. versionadded:: 1.0.0.dev7

.. py:currentmodule:: MySQL

.. py:attribute:: Port
    :type: int
    :value: 3306

    *Maps to* :attr:`mysql.MySQLConfig.mysql_port`

    Specifies the port the MySQL server listens on.

.. py:attribute:: ServerVersion
    :type: str
    :value: "8.0.42"

    *Maps to* :attr:`mysql.MySQLConfig.mysql_version`

    Sets the server version string returned to clients.

.. py:attribute:: AuthPlugin
    :type: str
    :value: "mysql_clear_password"

    *Maps to* :attr:`mysql.MySQLConfig.mysql_plugin_name`. *Reserved for future use.*

    .. attention::
        Currently non-functional: support for alternative authentication plugins (e.g.
        ``caching_sha2_password``, ``mysql_native_password``) is planned for a future release.




Error Configuration
^^^^^^^^^^^^^^^^^^^

.. py:attribute:: ErrorCode
    :type: int
    :value: 1045

    *Maps to* :attr:`mysql.MySQLConfig.mysql_error_code`

    Sets the error code returned to clients after authentication.

.. py:attribute:: ErrorMessage
    :type: str
    :value: "Access denied for user"

    *Maps to* :attr:`mysql.MySQLConfig.mysql_error_msg`

    Sets the error message returned to clients.


SSL Configuration
^^^^^^^^^^^^^^^^^

.. py:attribute:: TLS
    :type: bool
    :value: false

    *Maps to* :attr:`mysql.MySQLConfig.use_ssl`

    Enables SSL/TLS support using a custom certificate. The server will set the ``CLIENT_SSL``
    capability flag to prompt clients to upgrade to a secure connection.

.. py:attribute:: Cert
    :type: str

    *Maps to* :attr:`mysql.MySQLConfig.certfile`. *Can also be set in* ``[Globals]``

    Specifies the path to the certificate file used when TLS is enabled.

.. py:attribute:: Key
    :type: str

    *Maps to* :attr:`mysql.MySQLConfig.keyfile`. *Can also be set in* ``[Globals]``

    Specifies the path to the private key file associated with the TLS certificate.


Default Configuration
---------------------

.. code-block:: toml
    :linenos:
    :caption: MySQL configuration section (default values)

    [MySQL]
    Port = 3305
    ServerVersion = "8.0.42"
    ErrorCode = 1045
    ErrorMessage = "Access denied for user"
