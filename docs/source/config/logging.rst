
.. _config_logging:


Logging
=======

Section ``[Log]``
-----------------

.. py:currentmodule:: Log

.. py:attribute:: Enable
    :type: bool
    :value: true

    *Maps to* :attr:`logger.LoggingConfig.log_enabled`

    Enables writing logs to a file. The logfile name is automatically generated using the
    format ``log_%Y-%m-%d-%H-%M-%S.log`` and cannot be customized. This setting does **not**
    affect terminal output.

.. py:attribute:: LogDir
    :type: str
    :value: "logs"

    *Maps to* :attr:`logger.LoggingConfig.log_dir`

    Specifies the subdirectory (relative to :attr:`Dementor.Workspace`) where log files
    will be stored. Absolute paths are currently not supported.

.. py:attribute:: DebugLoggers
    :type: list[str]

    *Maps to* :attr:`logger.LoggingConfig.log_debug_loggers`

    Defines a list of additional loggers to enable when the ``--debug`` flag is used
    on the command line. These loggers produce more verbose output useful for troubleshooting.




