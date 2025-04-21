.. _config_winrm:

WinRM
=====

.. versionadded:: 1.0.0.dev3

Since WinRM operates over HTTP, all configuration values from the :ref:`config_http` section also apply here.
*WinRM* does not have its own dedicated section; instead, it inherits its configuration settings directly
from the HTTP section.

To configure a custom WinRM server, you can use the following example:

.. code-block:: toml
    :caption: Dementor.toml

    [[HTTP.Server]]
    Port = 5985
    WebDAV = false
    WPAD = false

By default, the service listens on port ``5985``. It can be enabled easily via the :attr:`Dementor.WinRM` shortcut.

If the HTTP configuration (or the ``[Globals]`` section) specifies a certificate and private key, an additional
WinRM service over HTTPS will automatically start on port ``5986``. You can also configure it manually as shown below:

.. code-block:: toml
    :caption: Dementor.toml

    [[HTTP.Server]]
    Port = 5986
    WebDAV = false
    WPAD = false
    TLS = true
    Cert = "/path/to/certfile"
    Key = "/path/to/keyfile"

.. seealso::

    See the :ref:`config_http` section for full details on HTTP service configuration.
