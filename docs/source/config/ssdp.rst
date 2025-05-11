.. _config_ssdp:

SSDP
====

Section ``[SSDP]``
------------------

.. versionadded:: 1.0.0.dev11

.. py:currentmodule:: SSDP


.. py:attribute:: Location
    :type: str

    *Linked to* :attr:`ssdp.SSDPConfig.ssdp_location`

    Specifies the target location of the UPnP webserver (will automatically point to the current host if not
    specified). By default the target location will consist of:

    .. code-block::

        LOCATION := http://<HOST>:<LOCAL_PORT>/<UUID>/<dd_path>

    whereby the UUID is taken either from the UPnP configuration (:attr:`UPnP.UUID`) or used from the search
    request. The target device description path is also taken from the UPnP configuration (:attr:`UPnP.DDUri`).


.. py:attribute:: Server
    :type: str
    :value: "OS/1.0 UPnP/1.0 Dementor/1.0"

    *Linked to* :attr:`ssdp.SSDPConfig.ssdp_server`

    Specifies the server type (``Server`` header) that will be returned in SSDP M-SEARCH responses.


.. py:attribute:: MaxAge
    :type: int
    :value: 1800

    *Linked to* :attr:`ssdp.SSDPConfig.ssdp_max_age`

    Defines the duration a response to a multicast search should be valid.

.. py:attribute:: ExtraHeaders
    :type: List[str]

    *Linked to* :attr:`ssdp.SSDPConfig.ssdp_extra_headers`

    Specifies additional headers to include in all server responses. Each entry must be a fully qualified
    SSDP header line without CRLF at the end.


.. py:attribute:: Ignore
    :type: list[str | dict]

    Specifies a list of hosts or UDNs to be blacklisted. For additional context, see :attr:`Globals.Ignore`.
    When this attribute is defined, it overrides the global blacklist configuration.
    If not explicitly set, this attribute has no effect.
    For a comprehensive explanation of how the blacklist is applied, refer to :class:`BlacklistConfigMixin`.

.. py:attribute:: AnswerTo
    :type: list[str | dict]

    Defines a list of hosts or UDNs to which responses should be sent.
    See :attr:`Globals.AnswerTo` for more information.
    When specified, this attribute takes precedence over the global whitelist.
    If omitted, the global configuration remains in effect.
    For detailed behavior and usage, refer to :class:`WhitelistConfigMixin`.


Default Configuration
---------------------

.. code-block:: toml
    :linenos:
    :caption: SSDP configuration section (default values)

    [SSDP]
    Server = "OS/1.0 UPnP/1.0 Dementor/1.0"
    MaxAge = 1800
    ExtraHeaders = [
        # The BOOTID.UPNP.ORG header field represents the boot instance of
        # the device expressed according to a monotonically increasing value
        "BOOTID.UPNP.ORG: 1",
        # The CONFIGID.UPNP.ORG field value shall be a non-negative, 31-bit integer that shall
        # represent the configuration number of a root device
        "CONFIGID.UPNP.ORG: 1337",
        'OPT: "http://schemas.upnp.org/upnp/1/0/"; ns=01',
        "01-NLS: 1",
    ]
