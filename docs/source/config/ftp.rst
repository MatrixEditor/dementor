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
.. _config_ftp:

FTP ⚙️
======

Section: ``[FTP]``
------------------

.. py:currentmodule:: FTP


.. py:attribute:: Server
    :type: list

    *Each server entry is mapped to an instance of* :class:`ftp.FTPServerConfig`

    Represents a list of FTP server configuration sections. For guidance on specifying
    a list of configuration sections, refer to the general configuration documentation:
    :ref:`config_guide_setion_lists`.

    Each server entry supports the following configuration attribute:

    .. py:attribute:: Server.Port
        :type: int

        *Linked to* :attr:`ftp.FTPServerConfig.ftp_port`

        Specifies the port number for the FTP server.
        This attribute is **required** and must be explicitly defined.


Python Config
-------------

.. py:class:: ftp.FTPServerConfig

    *Configuration class for entries under* :attr:`FTP.Server`

    Represents the configuration for a single FTP server instance. Currently, the
    FTP server implementation is minimal, and only the port number is configurable.

    .. py:attribute:: ftp_port
        :type: int

        *Corresponds to* :attr:`FTP.Server.Port`


Default Configuration
---------------------

.. code-block:: toml
    :linenos:
    :caption: FTP configuration section (default values)

    # only one server on port 21
    [[FTP.Server]]
    Port = 21