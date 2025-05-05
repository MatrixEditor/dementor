.. _config_http:

HTTP
====

The HTTP server is somewhat more complex than other servers due to its wide
range of configuration options.

.. attention::

    The current HTTP server implementation does not support custom error codes after successful
    authentication. The default returned code is `418 <https://http.cat/status/418>`_.


Section ``[HTTP]``
------------------

.. versionadded:: 1.0.0.dev1

.. py:currentmodule:: HTTP

.. py:attribute:: Server
    :type: list

    *Each entry maps to an instance of* :class:`http.HTTPServerConfig`

    Defines a list of HTTP servers. For details on configuring section lists,
    see the general configuration guide on `Array Tables <https://toml.io/en/v1.0.0#array-of-tables>`_
    for TOML.

    .. py:attribute:: Server.Port
        :type: int

        *Maps to* :attr:`http.HTTPServerConfig.http_port`

        Specifies the port on which the HTTP server instance listens. **This option is required and must be
        defined within each individual** ``[[HTTP.Server]]`` **section.**

    The attributes described below may also be specified in the global ``[HTTP]`` section, where they will serve
    as default values for all individual server entries — unless explicitly overridden.


    .. py:attribute:: Server.ServerType
        :type: str
        :value: "Microsoft-IIS/10.0"

        *Maps to* :attr:`http.HTTPServerConfig.http_server_type`. *May also be set in* ``[HTTP]``

        Specifies the server name returned in the `Server <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server>`_
        header.

        .. versionchanged:: 1.0.0.dev7

            This setting is now a *formatted-string*, which means, it supports templating as specified by
            Jinja2. For instance:

            .. code-block:: toml

                [HTTP]
                # ...
                ServerType = "Foobar-{{ random(10) }}"

            This definition will result in ten random characters appended to ``Foobar-`` for each session.
            More information about *formatted-strings* are coming up in future releases.

    .. py:attribute:: Server.ExtraHeaders
        :type: List[str]

        *Maps to* :attr:`http.HTTPServerConfig.http_extra_headers`. *May also be set in* ``[HTTP]``

        A list of headers to include in all server responses. Each entry must be
        a fully qualified HTTP header line without CRLF at the end.


    .. py:attribute:: Server.TemplatesPath
        :type: List[str]

        *Maps to* :attr:`http.HTTPServerConfig.http_templates`. *May also be set in* ``[HTTP]``

        A list of directories containing templates for custom web pages. You can override the default
        error page template ``error_page.html`` with your own. The default template mimics an IIS error page.

        .. figure:: /_static/images/http-server_page-style.png
            :align: center

            Page style matching Microsoft IIS defaults.


    .. py:attribute:: Server.Methods
        :type: List[str]
        :value: ["GET", "POST", "PUT", "DELETE"]

        *Maps to* :attr:`http.HTTPServerConfig.http_methods`. *May also be set in* ``[HTTP]``

        Defines which HTTP methods are supported. Note: ``OPTIONS``, ``HEAD`` and ``PROPFIND`` are reserved for internal use.

        .. versionchanged:: 1.0.0.dev2

            HTTP method ``HEAD`` will be excluded too.

    .. py:attribute:: Server.AuthSchemes
        :type: List[str]
        :value: ["Basic", "Negotiate", "NTLM", "Bearer"]

        *Maps to* :attr:`http.HTTPServerConfig.http_auth_schemes`. *May also be set in* ``[HTTP]``

        A list of supported authentication schemes. These are returned via the
        `WWW-Authenticate <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/WWW-Authenticate>`_ header.


    .. py:attribute:: Server.WebDAV
        :type: bool
        :value: true

        *Maps to* :attr:`http.HTTPServerConfig.http_webdav_enabled`. *May also be set in* ``[HTTP]``

        Enables WebDAV protocol support. If disabled, requests using ``PROPFIND`` will result in an error page.


    .. py:attribute:: Server.WPAD
        :type: bool
        :value: true

        *Maps to* :attr:`http.HTTPServerConfig.http_wpad_enabled`. *May also be set in* ``[HTTP]``

        Enables hosting of a WPAD configuration file. You can control whether this file requires authentication
        using :attr:`HTTP.Server.WPADAuthRequired`. The actual WPAD script content is controlled by :attr:`Proxy.Script`.

    .. py:attribute:: Server.WPADAuthRequired
        :type: bool
        :value: true

        *Maps to* :attr:`http.HTTPServerConfig.http_wpad_auth`. *May also be set in* ``[HTTP]``

        Determines whether access to the WPAD script requires authentication.

    .. py:attribute:: Server.ExtendedSessionSecurity
        :type: bool
        :value: true

        *Maps to* :attr:`http.HTTPServerConfig.http_ess`. *May also be set in* ``[HTTP]``

        .. versionchanged:: 1.0.0.dev5
            Internal mapping changed from ``http_ess`` to ``ntlm_ess``

        Enables Extended Session Security (ESS) for NTLM authentication. With ESS, NTLMv1/v2-SSP hashes
        are captured instead of raw NTLM hashes. Resolution precedence:

        1. :attr:`HTTP.Server.ExtendedSessionSecurity` (per-instance)
        2. :attr:`HTTP.ExtendedSessionSecurity` (global HTTP fallback)
        3. :attr:`NTLM.ExtendedSessionSecurity` (final fallback)

    .. py:attribute:: Server.Challenge
        :type: str
        :value: NTLM.Challenge

        *Maps to* :attr:`http.HTTPServerConfig.ntlm_challenge`. *May also be set in* ``[HTTP]``

        .. versionchanged:: 1.0.0.dev5
            Internal mapping changed frmo ``http_challenge`` to ``ntlm_challenge``

        Sets the NTLM challenge value used during authentication. Resolution order:

        1. :attr:`HTTP.Server.Challenge`
        2. :attr:`HTTP.Challenge`
        3. :attr:`NTLM.Challenge`

    .. py:attribute:: Server.FQDN
        :type: str
        :value: "DEMENTOR"

        *Linked to* :attr:`http.HTTPServerConfig.http_fqdn`. *May also be set in* ``[HTTP]`` or ``[Globals]``

        Sets the Fully Qualified Domain Name (FQDN) returned by the server. The hostname portion is
        used in NTLM responses. The domain portion is optional.

        .. versionchanged:: 1.0.0.dev7

            This setting is now a *formatted-string*,

    .. py:attribute:: Server.TLS
        :type: bool
        :value: false

        *Linked to* :attr:`http.HTTPServerConfig.http_use_ssl`. *Can also be set in* ``[HTTP]``

        Enables SSL/TLS support using a custom certificate.

        .. versionadded:: 1.0.0.dev3

    .. py:attribute:: Server.Cert
        :type: str

        *Linked to* :attr:`http.HTTPServerConfig.http_cert`. *Can also be set in* ``[HTTP]`` *or* ``[Globals]``

        Specifies the path to the certificate used when TLS is enabled.

        .. versionadded:: 1.0.0.dev3

    .. py:attribute:: Server.Key
        :type: str

        *Linked to* :attr:`http.HTTPServerConfig.http_cert_key`. *Can also be set in* ``[HTTP]`` *or* ``[Globals]``

        Specifies the private key file corresponding to the certificate used for TLS.

        .. versionadded:: 1.0.0.dev3


Default Configuration
---------------------

.. code-block:: toml
    :linenos:
    :caption: HTTP configuration section (default values)

    [HTTP]
    # Global settings for all HTTP servers
    ServerType = "Microsoft-IIS/10.0"
    FQDN = "DEMENTOR"
    ExtraHeaders = [
        "X-Powered-By: Dementor",
    ]
    WebDAV = true
    WPAD = true
    WPADAuthRequired = true
    AuthSchemes = [ "Basic", "Negotiate", "NTLM" ]
    HTTPMethods = [ "GET", "POST", "PUT", "DELETE" ]

    [[HTTP.Server]]
    Port = 80

