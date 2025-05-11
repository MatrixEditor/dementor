.. _cli:

CLI
===

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

-O, --option OPTION

    Additional option to add on top of the configuration file. This action will overwrite
    any existing setting.The structure of this override follows the format:

    .. code-block:: text

        [Section.]KEY[+]=VALUE

    - ``KEY``:
        May refer to a top-level configuration key in the ``[Dementor]`` configuration section (e.g., ``mDNS``), or include a section (e.g., ``LLMNR.AnswerName``).
    - ``VALUE``:
        Will be automatically parsed into the appropriate type based on the following rules:

        - **Boolean**: ``on``, ``yes``, ``true`` → `True`; ``off``, ``no``, ``false`` → `False`
        - **Lists**: Values enclosed in brackets (e.g., ``["foo", "bar"]``) will be parsed as JSON strings.
        - **Numbers**: Numeric values will be automatically converted to integers or floats where applicable.
        - **Strings**: All other values will be treated as plain strings.

    Examples:

    - ``-OLLMNR.AnswerName=pki-srv`` → Maps to :attr:`LLMNR.AnswerName`, value parsed as string.
    - ``--option mDNS.TTL=340`` → Maps to :attr:`mDNS.TTL`, value parsed as integer.
    - ``--option SMB.SMB2Support=off`` → Maps to :attr:`SMB.Server.SMB2Support`, value parsed as boolean.
    - ``--option Log.DebugLoggers='["asyncio", "quic"]'`` → Maps to :attr:`Log.DebugLoggers`, value parsed as list.
    - ``-O Globals.Ignore+="foobar"`` → Appends the parsed string value to :attr:`Globals.Ignore`

    .. note::
        Overrides made via the ``--option`` flag will **always take precedence** over the values
        defined in the configuration file.

    .. versionchanged:: 1.0.0.dev11
        Options now support an "append" action using the ``+=`` operator for settings storing multiple
        values.

--verbose

    Enables verbose output for protocol-specific loggers, including debug-level messages.

--debug

    Activates debug logging for all loggers listed in :attr:`Log.DebugLoggers`.

-q, --quiet

    Don't print huge banner at startup.