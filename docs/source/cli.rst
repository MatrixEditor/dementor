.. _cli:

CLI ⚙️
======

*Dementor* provides a relatively simple CLI interface that encapsulates all
implemented protocols. Because multicast poisoning requires specific return
addresses, specifying a network interface is always mandatory.

.. code-block:: console
    :caption: *Dementor* does not require root privileges unless protocol servers need to bind to privileged ports

    $ Dementor -I <INTERFACE_NAME>


Command-Line Options
--------------------


-I, --interface NAME

    Specifies the network interface to use. Internally, both IPv4 and IPv6 addresses
    associated with the interface will be queried and used throughout the session.

-A, --analyze

    Starts *Dementor* in *analyze mode*, where no responses will be sent. Services
    will still listen passively and can be used to capture credentials.

-c, --config PATH

    Path to a custom configuration file. If not provided, the default configuration
    will be used from the package installation path (typically ``assets/Dementor.toml``).

--verbose

    Enables verbose output for protocol-specific loggers, including debug-level messages.

--debug

    Activates debug logging for all loggers listed in :attr:`Log.DebugLoggers`.s
