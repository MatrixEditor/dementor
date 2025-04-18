.. _custom_protocols:

Custom Protocols ⚙️
===================

*Dementor* is not limited to a predefined set of protocols and can be extended
with custom implementations. Each protocol extension is defined as a Python module
that implements specific functions recognized by the core engine.

Required Functions
------------------

Custom protocol modules may define the following functions:

.. py:function:: apply_config(session: SessionConfig) -> None

    *Optional*

    Applies custom configuration logic to the current :class:`SessionConfig` object.
    This function is called during setup, using global definitions from ``dementor.config``.

.. py:function:: create_server_threads(session: SessionConfig) -> List[Thread]

    *Optional, but recommended*

    Creates and returns server thread objects for this protocol. **Threads must not be started here**
    — they will be started automatically.


To enable a custom protocol, its Python module must be placed in a directory listed under the
:attr:`Dementor.ExtraModules` setting in your configuration file, the ``protocols`` package
within *Dementor* or within the ``protocols`` directory under ``~/.dementor/protocols``.


.. _howto_custom_protocol:

Example: POP3 Protocol Extension
--------------------------------

Below is an example implementation of a POP3 protocol handler with plain-text authentication:

.. code-block:: python
    :caption: pop3.py

    from dementor.config import TomlConfig, Attribute as A

    # Define the custom config section for POP3
    class POP3Config(TomlConfig):
        _section_ = "POP3"
        _fields_ = [
            # Attribute(name, config_key, default_value)
            A("pop3_enabled", "Dementor.POP3", True),  # defined in [Dementor]
            A("pop3_port", "Port", 110),               # defined in [POP3]
        ]

    def apply_config(session: SessionConfig):
        # Populate values from the configuration file
        session.pop3_config = TomlConfig.build_config(POP3Config)

    def create_server_threads(session: SessionConfig):
        is_enabled = session.pop3_config.pop3_enabled
        return [POP3Server(session.pop3_config)] if is_enabled else []

    class POP3Server(Thread):
        def __init__(self, config):
            super().__init__()
            self.config = config
            # Additional setup here

        def run(self):
            # Start listening on self.config.pop3_port
            ...
