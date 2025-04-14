
.. _config_quic:

QUIC
====

Section ``[QUIC]``
------------------

.. py:currentmodule:: QUIC

.. py:attribute:: Port
    :type: int
    :value: 443

    *Maps to* :attr:`quic.QuicServerConfig.quic_port`

    Defines the port on which the QUIC server instance listens.

    .. note::
        Currently, only a single QUIC server instance can be configured. Support for
        multiple instances is not available.


.. py:attribute:: TargetSMBHost
    :type: int

    *Maps to* :attr:`quic.QuicServerConfig.quic_smb_host`

    Specifies the address or hostname of the target SMB server to which connections are forwarded. By
    default, the server forwards to the internal SMB service on port 445.


.. py:attribute:: TargetSMBPort
    :type: int
    :value: 445

    *Maps to* :attr:`quic.QuicServerConfig.quic_smb_port`

    Specifies the port number of the target SMB server for forwarding purposes. If not set,
    the default is port 445.


.. py:attribute:: Cert
    :type: str

    *Maps to* :attr:`quic.QuicServerConfig.quic_cert_path`. *May also be set in* ``[Globals]``

    Specifies the absolute or relative path to the TLS certificate file. **This setting is required.**


.. py:attribute:: Key
    :type: str

    *Maps to* :attr:`quic.QuicServerConfig.quic_cert_key`. *May also be set in* ``[Globals]``

    Specifies the path to the private key file corresponding to the provided TLS certificate. **This setting is required.**


Python Config
-------------

.. py:class:: quic.QuicServerConfig

    Represents the configuration for a single QUIC server instance.

    .. py:attribute:: quic_port
        :type: int
        :value: 443

        *Corresponds to* :attr:`QUIC.Port`


    .. py:attribute:: quic_smb_host
        :type: Optional[str]
        :value: None

        *Corresponds to* :attr:`QUIC.TargetSMBHost`


    .. py:attribute:: quic_smb_port
        :type: int
        :value: 445

        *Corresponds to* :attr:`QUIC.TargetSMBPort`


    .. py:attribute:: quic_cert_path
        :type: str

        *Corresponds to* :attr:`QUIC.Cert`.


    .. py:attribute:: quic_cert_key
        :type: str

        *Corresponds to* :attr:`QUIC.Key`.


Default Configuration
---------------------

.. code-block:: toml
    :linenos:
    :caption: QUIC configuration section (default values)

    [QUIC]
    Port = 443
    # Server startup will fail if the following files are not specified
    Cert = "default.cert"
    Key = "default.key"
