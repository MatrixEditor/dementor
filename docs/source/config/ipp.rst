.. _config_ipp:

IPP / CUPS
==========

Since version ``1.0.0.dev10``, *Dementor* includes an inbuilt IPP server, which can be utilized to trigger
multiple bugs that may lead to **potential** code execution on systems running the legacy CUPS browsing
service. A practical example of such exploitation can be found in :ref:`example_cups`. The server is built
using the awesome `python-ipp <https://github.com/ctalkington/python-ipp>`_ package.

.. seealso::
    This service was specifically implemented to address `CVE-2024-47076 <https://github.com/OpenPrinting/libcupsfilters/security/advisories/GHSA-w63j-6g73-wmg5>`_,
    `CVE-2024-47175 <https://github.com/OpenPrinting/libppd/security/advisories/GHSA-7xfx-47qg-grp6>`_ and `CVE-2024-47176 <https://github.com/OpenPrinting/cups-browsed/security/advisories/GHSA-rj88-6mr5-rcw8>`_.
    Special thanks to `@Evilsocket <https://www.evilsocket.net>`_ for his initial research and blog entry on `Attacking UNIX Systems via CUPS, Part I <https://www.evilsocket.net/2024/09/26/Attacking-UNIX-systems-via-CUPS-Part-I/>`_.
    You should definitely check that out before attempting to use this server.

Section ``[IPP]``
-----------------

.. versionadded:: 1.0.0.dev10

.. py:currentmodule:: IPP

Server Configuration
^^^^^^^^^^^^^^^^^^^^

.. py:attribute:: Port
    :type: int
    :value: 631

    *Linked to* :attr:`ipp.IPPConfig.ipp_port`

    Specifies the port used by the IPP server instance.

.. py:attribute:: ServerType
    :type: str
    :value: "IPP/1.1"

    *Linked to* :attr:`ipp.IPPConfig.ipp_server_type`

    Defines the server name returned in the `Server <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server>`_ header.
    The value can be a formatted string, supporting templating (Jinja2). For example:

    .. code-block:: toml

        [IPP]
        # ...
        ServerType = "IPP/{{ random(3) }}" # results in: "IPP/cq2"

.. py:attribute:: Server.ExtraHeaders
    :type: List[str]

    *Maps to* :attr:`ipp.IPPConfig.ipp_extra_headers`

    Specifies additional headers to include in all server responses. Each entry must be a fully qualified HTTP header line without CRLF at the end.

Printer Attributes
^^^^^^^^^^^^^^^^^^

The ``get-printer-attributes`` request retrieves a printer's stored attributes. However, some printers may lack certain attributes. Therefore, additional attributes can be configured to be included in the response.

.. py:attribute:: ExtraAttributes
    :type: List[AttributeDict]

    *Maps to* :attr:`ipp.IPPConfig.ipp_extra_attrib`

    Specifies additional attributes to include in the ``get-printer-attributes`` response. Each new attribute requires the following fields:

    .. py:currentmodule:: AttributeDict

    .. py:attribute:: name
        :type: str

        *Required setting*

        Specifies the name of the new attribute (e.g., ``printer-device-id``).

    .. py:attribute:: value
        :type: str | int | list

        *Optional, if* :attr:`AttributeDict.tag` *is defined*

        Specifies the value of the new attribute. Must match the registered data type.

    .. py:attribute:: tag
        :type: int | str

        *Optional setting*

        Specifies the data type of the new attribute. Can be an ``IppTag`` string or an integer.

Example configuration:

.. container:: demo

    .. code-block:: toml

        [IPP]
        ExtraAttributes = [
            { name = "printer-device-id", tag = "TEXT", value = "FOOBAR" },
        ]

.. seealso::
    For a complete list of registered attributes, refer to `Internet Printing Protocol (IPP) Registrations <https://www.iana.org/assignments/ipp-registrations/ipp-registrations.xhtml>`_.

The following attributes can also be overridden using :attr:`IPP.ExtraAttributes`.

.. py:attribute:: PrinterName
    :type: str

    *Maps to* :attr:`ipp.IPPConfig.ipp_printer_name`.

    Defines the printer name to return to clients. If not specified, the printer name will be
    determined by the last path element of the request.

.. py:attribute:: PrinterInfo
    :type: str
    :value: "Printer Info"

    *Maps to* :attr:`ipp.IPPConfig.ipp_printer_info`.

    Defines the printer information attribute.

.. py:attribute:: PrinterLocation
    :type: str
    :value: "outside"

    *Maps to* :attr:`ipp.IPPConfig.ipp_printer_location`.

    Defines the printer location attribute. This will not be used if specified in the CUPS request.

.. py:attribute:: PrinterModel
    :type: str
    :value: "HP 8.0"

    *Maps to* :attr:`ipp.IPPConfig.ipp_printer_model`.

    Defines the printer model attribute. This setting is required by the CUPS client.

.. py:attribute:: DriverUri
    :type: str

    *Maps to* :attr:`ipp.IPPConfig.ipp_driver_uri`.

    Specifies a custom printer driver URI that clients can use to download a driver.

.. py:attribute:: DocumentFormats
    :type: List[str]

    *Maps to* :attr:`ipp.IPPConfig.ipp_supported_formats`.

    Defines the supported print document formats.

.. py:attribute:: DefaultDocumentFormat
    :type: str
    :value: "text/plain"

    *Maps to* :attr:`ipp.IPPConfig.ipp_default_format`.

    Defines the default print document format.

.. py:attribute:: SupportedVersions
    :type: List[str]
    :value: ["1.0", "1.1", "2.0", "2.1", "2.2"]

    *Maps to* :attr:`ipp.IPPConfig.ipp_supported_versions`.

    Specifies the supported IPP versions.

.. py:attribute:: SupportedOperations
    :type: List[str | int]
    :value: range(0x0001, 0x0013)

    *Maps to* :attr:`ipp.IPPConfig.ipp_supported_operations`.

    Specifies the operations supported by the server. These operations cannot be removed unless
    explicitly overridden using :attr:`ExtraAttributes`.

CVE-2024-47175 / CVE-2024-47076
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following settings were introduced to specifically address CVE-2024-47175 and CVE-2024-47076. For
practical usage, refer to :ref:`example_cups`.

.. py:attribute:: RemoteCmd
    :type: str

    *Maps to* :attr:`ipp.IPPConfig.ipp_remote_cmd`.

    Specifies the command to inject into the generated PPD. (CVE-2024-47175)

.. py:attribute:: RemoteCmdAttribute
    :type: str
    :value: "printer-privacy-policy-uri"

    *Maps to* :attr:`ipp.IPPConfig.ipp_remote_cmd_attr`.

    Specifies the printer attribute that stores the malformed text. (CVE-2024-47176)

.. py:attribute:: RemoteCmdCupsFilter
    :type: str

    *Maps to* :attr:`ipp.IPPConfig.ipp_remote_cmd_filter`.

    Specifies the printer attribute that stores the malformed text. (CVE-2024-47176).
    Ensure that *foomatic-rip* is present in this filter string to correctly interpolate
    the ``FoomaticRIPCommandLine``.

Default Configuration
---------------------

.. code-block:: toml
    :linenos:
    :caption: IPP configuration section (default values)

    [IPP]
    Port = 631
    ServerType = "IPP/1.1"
    PrinterInfo = "Printer Info"
    PrinterModel = "HP 8.0"
    PrinterLocation = "outside"
    DefaultDocumentFormat = "text/plain"
    SupportedVersions = ["1.0", "1.1", "2.0", "2.1", "2.2"]
    DocumentFormats = [
        "text/html",
        "text/plain",
        "text/plain; charset = US-ASCII",
        "text/plain; charset = ISO-8859-1",
        "text/plain; charset = utf-8",
        "application/postscript",
        "application/vnd.hp-PCL",
        "application/pdf",
        "application/octet-stream",
    ]
