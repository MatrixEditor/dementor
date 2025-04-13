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




