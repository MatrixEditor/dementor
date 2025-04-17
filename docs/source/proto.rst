.. _custom_protocols:

Custom Protocols ⚙️
===================

*Dementor* is not limited to a specific set of protocols and can be extended using custom
implementations. Each custom protocol will be expressed as a Python module with special
attributes:

.. py:function:: apply_config(session: SessionConfig) -> None

    *This function is optional*

    Apply custom configuration to the current :class:`SessionConfig` object using the
    global configuration defined in ``dementor.config``.


.. py:function:: create_server_threads(session: SessionConfig) -> List[Thread]

    *This function is optional, but recommended*

    Setup servers for the current protocol implementation but **do not** start them.


A custom protocol can be added by adding its enclosing directory in the :attr:`Dementor.ExtraModules` setting.

.. _howto_custom_protocol:

Example Protocol Extension
--------------------------

Let's take in the POP3 protocol with plain authentication. First, we need to specify
the two functions from above:

.. code-block:: python
    :caption: pop3.py

    from dementor.config import TomlConfig, Attribute as A

    # It is recommended to add another section to the global config
    class POP3Config(TomlConfig):
        _section_ = "POP3"
        _fields_ = [
            # final attr, toml name, default val
            A("pop3_enabled", "Dementor.POP3", True), # defined in [Dementor]
            A("pop3_port", "Port", 110), # defined in [POP3]
        ]

    def apply_config(session: SessionConfig):
        # values will be filled automatically
        session.pop3_config = TomlConfig.build_config(POP3Config)

    def create_server_threads(session: SessionConfig):
        is_enabled = session.pop3_config.pop3_enabled
        return [POP3Server(session.pop3_config)] if is_enabled else []

    class POP3Server(Thread):
        ... # custom implementation