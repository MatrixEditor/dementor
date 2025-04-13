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
