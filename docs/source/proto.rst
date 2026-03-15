.. _custom_protocols:

Custom Protocols ⚙️
===================

*Dementor* is not limited to a predefined set of protocols and can be extended
with custom implementations. Each protocol extension is defined as a Python module
that implements specific functions recognized by the core engine.

Protocol Module Structure
--------------------------

.. versionchanged:: 1.0.0.dev21

Dementor now uses a class-based system for protocol extensions.  A custom protocol is implemented as a
subclass of :class:`dementor.loader.BaseProtocolModule` and may define the following class
attributes (all optional unless noted):

.. list-table:: Supported class attributes
   :header-rows: 1

   * - Attribute
     - Description
     - Required?
   * - ``name``
     - Human readable protocol name (e.g. ``"POP3"``).
     - Yes
   * - ``config_ty``
     - :class:`~dementor.config.toml.TomlConfig` subclass describing the protocol's configuration schema.
     - No (if configuration is handled manually)
   * - ``config_attr``
     - Name of the attribute on :class:`~dementor.config.session.SessionConfig` where the built configuration object(s) will be stored. Use ``"<DEFAULT>"`` to get ``{name.lower()}_config``.
     - No (defaults to ``"<DEFAULT>"``)
   * - ``config_enabled_attr``
     - Name of the boolean flag on the session that enables the protocol. ``"<DEFAULT>"`` resolves to ``{name.lower()}_enabled``.
     - No
   * - ``config_list``
     - ``True`` if the protocol supports multiple configuration entries (list), ``False`` for a single config.
     - No (defaults to ``False``)
   * - ``poisoner``
     - ``True`` if the protocol can act as a *poisoner* (special handling in the REPL).
     - No (defaults to ``False``)
   * - ``server_ty``
     - Concrete server class used to instantiate threads for each configuration entry. If omitted, the protocol must implement ``create_server_thread`` manually.
     - No

In addition to the attributes, a protocol class can optionally override the following methods:

.. py:function:: Protocol.apply_config(self, session: SessionConfig) -> None

    Called during session setup to populate configuration objects.  The default
    implementation reads ``config_ty`` and stores the result under ``config_attr``
    (handling list vs single config).

.. py:function:: Protocol.create_server_thread(self, session: SessionConfig, server_config: _ConfigTy) -> BaseServerThread

    Create a single server thread for the given configuration.  The default implementation
    uses ``server_ty`` if provided.

.. py:function:: Protocol.create_server_threads(self, session: SessionConfig) -> List[BaseServerThread]

    Returns all server threads for the protocol.  The base implementation respects
    ``config_enabled_attr`` and ``config_list``.


Legacy function-based extensions (defining ``apply_config``) are still supported but will only
use the ``apply_config`` function.

**Module discovery**

Every custom protocol module must expose a top-level ``__proto__`` attribute. This attribute should be a list containing either the protocol class objects or their class names (as strings). The loader uses ``__proto__`` to discover which protocol classes to instantiate.

.. code-block:: python
   :caption: Example __proto__ definition

   __proto__ = ["POP3Protocol"]

The ``__proto__`` entry is required for the loader to register the protocol; otherwise the module will be ignored.

To enable a custom protocol, its Python module must be placed in a directory listed under the
:attr:`Dementor.ExtraModules` setting in your configuration file, the ``protocols`` package
within *Dementor* or within the ``protocols`` directory under ``~/.dementor/protocols``.


.. _howto_custom_protocol:

Example: POP3 Protocol Extension (class-based)
----------------------------------------------

The following example shows the POP3 protocol implementation using the new class-based API.

.. code-block:: python
    :caption: pop3.py

    from threading import Thread
    from dementor.loader import BaseProtocolModule
    from dementor.config import TomlConfig, Attribute as A
    from dementor.servers import ServerThread

    __proto__ = ["POP3Protocol"]

    # Configuration schema for POP3
    class POP3Config(TomlConfig):
        _section_ = "POP3"
        _fields_ = [
            A("pop3_port", "Port", 110),
        ]

    class POP3Server(ThreadingTCPServer):
        def __init__(
            self,
            config,
            server_address=None,
            RequestHandlerClass: type | None = None,
            server_config: POP3ServerConfig | None = None,
        ) -> None:
          ...

    class POP3Protocol(BaseProtocolModule):
        """Protocol implementation for POP3.

        The ``BaseProtocolModule`` base class handles configuration loading and
        thread creation based on the attributes defined below.
        """

        name = "POP3"
        config_ty = POP3Config
        config_attr = "<DEFAULT>"          # results in ``pop3_config`` on the session
        config_enabled_attr = "<DEFAULT>"  # results in ``pop3_enabled`` flag
        config_list = True                 # enabled multiple servers

        # No need to override ``apply_config``

        @override
        def create_server_thread(
            self, session: SessionConfig, server_config: POP3ServerConfig
        ) -> BaseServerThread:
            return ServerThread(
                session,
                server_config,
                POP3Server,
                server_address=(session.bind_address, server_config.pop3_port),
                include_server_config=True, # required, because it is specified in the server's __init__
            )
