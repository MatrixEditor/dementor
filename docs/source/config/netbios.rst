
.. _config_netbios:

NBTNS
=====

.. _config_netbios_sectioncfg:

Section ``[NetBIOS]``
---------------------

.. py:currentmodule:: NetBIOS

.. py:attribute:: Ignore
    :type: list[str | dict]

    Specifies a list of hosts to be blacklisted. For further context, refer to :attr:`Globals.Ignore`.
    When defined, this attribute overrides the global blacklist configuration.
    If not set, it has no effect.
    For a detailed explanation of how blacklist rules are applied, see :class:`BlacklistConfigMixin`.

.. py:attribute:: Targets
    :type: list[str | dict]

    .. versionchanged:: 1.0.0.dev16
        Renamed from `AnswerTo`

    Defines a list of hosts to which responses should be sent.
    Refer to :attr:`Globals.Targets` for more information.
    When specified, this setting takes precedence over the global whitelist configuration.
    If omitted, the global configuration remains effective.
    For details on how these rules are applied, see :class:`WhitelistConfigMixin`.


Python Config
-------------

.. py:class:: netbios.NBTNSConfig

    Represents the configuration for the ``[NetBIOS]`` section in the TOML file.
    This class incorporates both :class:`WhitelistConfigMixin` and :class:`BlacklistConfigMixin`,
    adding two additional configuration fields.
    For detailed behavior and usage, refer to the respective mixin documentation.

    Currently, there are no additional configuration parameters specific to this class.



.. _config_browser:

Browser
=======

.. _config_browser_sectioncfg:

Section ``[Browser]``
---------------------

.. versionadded:: 1.0.0.dev22
    Detailed configuration attributes added.

.. py:currentmodule:: Browser

.. py:attribute:: DomainName
    :type: str
    :value: "CONTOSO"

    Specifies the NetBIOS domain name to advertise in NETLOGON responses.
    This value is used when responding to PDC queries (LOGON_PRIMARY_QUERY)
    and DC discovery requests (LOGON_SAM_LOGON_REQUEST).

    The domain name should be a valid NetBIOS name (max 15 characters) and
    will be converted to uppercase automatically.

.. py:attribute:: Hostname
    :type: str
    :value: "DC01"

    Specifies the hostname to advertise as the domain controller in NETLOGON
    responses. This value is used when responding to PDC queries and DC
    discovery requests.

    The hostname should be a valid NetBIOS name (max 15 characters) and will
    be converted to uppercase and truncated if necessary.


.. py:attribute:: Ignore
    :type: list[str | dict]

    Specifies a list of hosts to be blacklisted. For further context, refer to :attr:`Globals.Ignore`.
    When defined, this attribute overrides the global blacklist configuration.
    If not set, it has no effect.
    For a detailed explanation of how blacklist rules are applied, see :class:`BlacklistConfigMixin`.

.. py:attribute:: Targets
    :type: list[str | dict]

    Defines a list of hosts to which responses should be sent.
    Refer to :attr:`Globals.Targets` for more information.
    When specified, this setting takes precedence over the global whitelist configuration.
    If omitted, the global configuration remains effective.
    For details on how these rules are applied, see :class:`WhitelistConfigMixin`.


Python Config
^^^^^^^^^^^^^

.. py:class:: netbios.BrowserConfig

    Represents the configuration for the ``[Browser]`` section in the TOML file.
    This class incorporates both :class:`WhitelistConfigMixin` and :class:`BlacklistConfigMixin`,
    along with domain controller identification parameters.

    The Browser protocol implements the NETLOGON mailslot ping protocol per
    [MS-ADTS] § 6.3.5, used for domain controller discovery and PDC verification.

    **Configuration Attributes:**

    .. py:attribute:: browser_domain_name
        :type: str
        :value: "CONTOSO"

        Internal attribute name for :attr:`DomainName`.

    .. py:attribute:: browser_hostname
        :type: str
        :value: "DC01"

        Internal attribute name for :attr:`Hostname`.



