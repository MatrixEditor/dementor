
.. _config_logging:


Logging
=======

Section ``[Log]``
-----------------

.. py:currentmodule:: Log

.. py:attribute:: Enabled
    :type: bool
    :value: true

    *Maps to* :attr:`logger.LoggingConfig.log_enabled`

    Enables writing logs to a file. The logfile name is automatically generated using the
    format ``log_%Y-%m-%d-%H-%M-%S.log`` and cannot be customized. This setting does **not**
    affect terminal output.

.. py:attribute:: LogDir
    :type: RelativePath | RelativeWorkspacePath | AbsolutePath
    :value: "logs"

    *Maps to* :attr:`logger.LoggingConfig.log_dir`

    Specifies the subdirectory (relative to :attr:`Dementor.Workspace` or absolute) where log files
    will be stored. Absolute paths are currently not supported.

.. py:attribute:: DebugLoggers
    :type: list[str]

    *Maps to* :attr:`logger.LoggingConfig.log_debug_loggers`

    Defines a list of additional loggers to enable when the ``--debug`` flag is used
    on the command line. These loggers produce more verbose output useful for troubleshooting.


Section ``[Log.Stream]``
------------------------

A special way to save a live copy of received data can be enabled using custom
*loggins streams*. Each of them provides a unique functionality:

Hosts Logging
^^^^^^^^^^^^^

.. py:currentmodule:: Log.Stream.Hosts

.. py:attribute:: Path
    :type: RelativePath | RelativeWorkspacePath | AbsolutePath

    Enables writing all identified hosts (direct connections or multicast
    queries) to a separate log file. Can be an absolute path ("/" prefixed), a
    relative path to the current working directory ("./" prefixed) or a path
    relative to the workspace directory.

.. py:attribute:: IPv4
    :type: bool
    :value: true

    Enables logging IPv4 addresses (default value is ``true``).

.. py:attribute:: IPv6
    :type: bool
    :value: true

    Enables logging IPv6 addresses (default value is ``true``).

DNS Logging
^^^^^^^^^^^^^

.. py:currentmodule:: Log.Stream.DNS

.. py:attribute:: Path
    :type: RelativePath | RelativeWorkspacePath | AbsolutePath

    Enables writing all captured multicast/broadcast name queries to a separate
    log file. Can be an absolute path ("/" prefixed), a relative path to the
    current working directory ("./" prefixed) or a path relative to the
    workspace directory.

Hash Logging
^^^^^^^^^^^^^

.. py:currentmodule:: Log.Stream.Hashes

.. py:attribute:: Path
    :type: RelativePath | RelativeWorkspacePath | AbsolutePath

    Enables writing all captured hashes to a separate log file or directory.

    Can be an absolute path ("/" prefixed), a relative path to the current
    working directory ("./" prefixed) or a path relative to the workspace
    directory. Additionally, may represent a target non-existing target
    directory.

.. py:attribute:: Split
    :type: bool
    :value: false

    Creates a separate log file for each hash type using the naming scheme
    defined by :attr:`~Log.Stream.Hashes.FilePrefix` and
    :attr:`~Log.Stream.Hashes.FileSuffix`. The default file naming scheme is
    as follows:

    .. code-block:: text

        FileName := {{hash_type}}_{{start_time}}.txt


.. py:attribute:: FilePrefix
    :type: str

    File prefix to use for each hash type. Make sure this value returns a unique
    string for each hash type to avoid overwriting existing files.

    .. note::
        This config variable is a *formatted string*, which uses ``hash_type`` and
        ``time`` as globals, e.g.

        .. code-block:: toml

            [Log.Stream.Hashes]
            FilePrefix = "{{ hash_type }}-capture"

.. py:attribute:: FileSuffix
    :type: str
    :value: ".txt"

    File suffix to use for each hash type.


