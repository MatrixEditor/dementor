.. _config_dcerpc:

DCE/RPC
=======

The DCE/RPC implementation uses two separate configuration sections, which are both listed below.

Section ``[RPC]``
-----------------

.. versionadded:: 1.0.0.dev2

.. py:currentmodule:: RPC

.. py:attribute:: ErrorCode
    :type: int | str
    :value: "rpc_s_access_denied"

    *Maps to* :attr:`rpc.RPCConfig.rpc_error_code`.

    Specifies the error code to return after successful authentication.

.. py:attribute:: Interfaces
    :type: List[str]

    *Maps to* :attr:`rpc.RPCConfig.rpc_modules`.

    A list of directory paths containing external modules or files to be loaded as extensions
    for specific RPC interfaces. For example, modules located in ``dementor/protocols/msrpc`` will
    always be imported.

    These modules differ slightly from the standard extension mechanism. Each extension module may define:

    .. py:currentmodule:: protocol

    .. py:attribute:: __uuid__
        :type: str | bytes | List[str | bytes]

        Contains one or more interface UUIDs associated with the protocol. If a client connects
        using one of these UUIDs, the associated handler will be invoked.

        .. code-block::
            :caption: Example ``__uuid__`` definition for EPM

            __uuid__ = "E1AF8308-5D1F-11C9-91A4-08002B14A0FA"

        The value may be a string, binary UUID, or a list of either.

    .. py:function:: handle_request(rpc: RPCHandler, request: rpcrt.MSRPCRequestHeader, data) -> int

        *Optional if* :class:`~protocol.RPCEndpointHandlerClass` *is provided.*

        Defines a callback invoked by :class:`~dementor.msrpc.rpc.RPCHandler` for requests matching
        the UUID. The `request` object is from the ``impacket`` library.

        Return values:

        - ``0``: Success — continue listening for additional packets.
        - Any other value: An error is sent in a *FAULT* response and the connection is closed.

    .. py:class:: RPCEndpointHandlerClass()

        *Optional if* :func:`~protocol.handle_request` *is defined.*

        Defines a class to handle RPC requests. It must be instantiable without arguments
        and must implement the ``__call__`` method:

        .. py:function:: __call__(self, rpc: RPCHandler, request: rpcrt.MSRPCRequestHeader, data: bytes) -> int

            Same behavior as :func:`~protocol.handle_request`.

        .. hint::

            You may alias your custom class as `RPCEndpointHandlerClass`:

            .. code-block:: python
                :caption: custom.py

                class MyHandler:
                    ...

                RPCEndpointHandlerClass = MyHandler

    Currently, only two interfaces are implemented: ``EPMv4`` and ``DCOM``. Refer to the source
    code for implementation details.

.. py:currentmodule:: RPC

.. py:attribute:: ExtendedSessionSecurity
    :type: bool
    :value: true

    *Maps to* :attr:`rpc.RPCConfig.ntlm_ess`.

    .. versionchanged:: 1.0.0.dev5
        Internal mapping changed from ``rpc_ntlm_ess`` to ``ntlm_ess``

    Enables Extended Session Security (ESS) during NTLM authentication. With ESS enabled,
    NTLMv1/v2-SSP hashes are captured instead of standard NTLM hashes.

    Resolution precedence:

    1. :attr:`RPC.Server.ExtendedSessionSecurity` (per-server)
    2. :attr:`RPC.ExtendedSessionSecurity` (global fallback)
    3. :attr:`NTLM.ExtendedSessionSecurity` (final fallback)

.. py:attribute:: Server.Challenge
    :type: str
    :value: NTLM.Challenge

    *Maps to* :attr:`rpc.RPCConfig.ntlm_challenge`.

    .. versionchanged:: 1.0.0.dev5
        Internal mapping changed from ``rpc_ntlm_challenge`` to ``ntlm_challenge``

    Sets the NTLM challenge value used during authentication. Resolution precedence:

    1. :attr:`RPC.Server.Challenge`
    2. :attr:`RPC.Challenge`
    3. :attr:`NTLM.Challenge`

.. py:attribute:: Server.FQDN
    :type: str
    :value: "DEMENTOR"

    *Maps to* :attr:`rpc.RPCConfig.rpc_fqdn`. *Can also be set in* ``[Globals]``

    Specifies the Fully Qualified Domain Name (FQDN) used by the server. The hostname part is
    included in NTLM responses. The domain part is optional.

Section ``[EPM]``
-----------------

.. versionadded:: 1.0.0.dev2

.. py:currentmodule:: EPM

.. py:attribute:: TargetPort
    :type: int
    :value: 49000

    *Maps to* :attr:`rpc.RPCConfig.epm_port`.

    Defines the static port used for RPC communication when a client sends a Map request.

.. py:attribute:: TargetPortRange
    :type: str | dict

    *Maps to* :attr:`rpc.RPCConfig.epm_port_range`.

    Overrides :attr:`EPM.TargetPort` and randomly selects a port from a specified range.

    Supported formats:

    - ``[START]-END``: `START` is optional; defaults to ``45000``.
    - ``START-[END]``: `END` is optional; defaults to ``49999``.

    Alternatively, use a dictionary:

    .. code-block:: toml

        PortRange = { start = 45000, end = 49999 }

    .. attention::

        The random port is selected **once at startup** — not per client.

Default Configuration
---------------------

.. code-block:: toml
    :linenos:
    :caption: DCE/RPC configuration (default values)

    [RPC]
    ErrorCode = "rpc_s_access_denied"

    [EPM]
    TargetPort = 49000

.. _MS-RPCE: RPCs://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/290c38b1-92fe-4229-91e6-4fc376610c15
