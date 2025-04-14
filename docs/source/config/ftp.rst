
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
    `Array Tables <https://toml.io/en/v1.0.0#array-of-tables>`_.

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