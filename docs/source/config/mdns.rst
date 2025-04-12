.. _config_mdns:

mDNS
====


Section: ``[mDNS]``
-------------------

.. py:currentmodule:: mDNS

.. py:attribute:: TTL
    :type: int
    :value: 120

    *Linked to* :attr:`mdns.MDNSConfig.mdns_ttl`

    Time-To-Live (TTL) for poisoned responses (in seconds). Note that
    smaller times may be spotted by AV or EDR software solutions.


.. py:attribute:: MaxLabels
    :type: int
    :value: 1

    *Linked to* :attr:`mdns.MDNSConfig.mdns_max_labels`

    Maximum number of domain name labels to filter. This option takes precedence
    over :attr:`mDNS.AllowedQueryTypes` and the global/local blacklist and whitelist.
    The default behaviour is to ignore all incoming requests that are searching for
    services with more than one label (excluding :code:`.local`).


.. py:attribute:: AllowedQueryTypes
    :type: list[str | int]
    :value: [ "A", "AAAA", "ALL" ]

    *Linked to* :attr:`mdns.MDNSConfig.mdns_qtypes`

    List of DNS query types that will be responded to. Priority is lower than
    :attr:`mDNS.MaxLabels` but higher than global/local blacklist or whitelist.

    .. note::

        Values of this list must be part of :attr:`dns.dnstypes` if specified as
        string.

.. py:attribute:: Ignore
    :type: list[str | dict]

    *Linked to* :attr:`mdns.MDNSConfig.ignored`

    A list of hosts to blacklist. Please refer to :attr:`Globals.Ignore` for more
    information. If defined here, the global blacklist will be ignored. This
    setting will be ignored if not defined. For a detailed explanation of how this
    rule will be applied, refer to :class:`BlacklistConfigMixin`.


.. py:attribute:: AnswerTo
    :type: list[str | dict]

    *Linked to* :attr:`mdns.MDNSConfig.targets`

    A list of hosts to respond to. Please refer to :attr:`Globals.AnswerTo` for more
    information. If defined here, the global whitelist will be ignored. This
    setting will be ignored if not defined. For a detailed explanation of how this
    rule will be applied, refer to :class:`WhitelistConfigMixin`.


Python Config
-------------

.. py:class:: mdns.MDNSConfig(config: dict)

    Configuration class for its Toml counterpart section. It uses :class:`WhitelistConfigMixin`
    and :class:`BlacklistConfigMixin`, which results in two extra fields in this class. Refer to
    those classes for more information.

    .. py:attribute:: enabled
        :value: True
        :type: bool

        *Corresponds to* :attr:`Dementor.mDNS`

        Enables or disables mDNS poisoning functionality. Please refer to :attr:`Dementor.mDNS`
        for more details on how to configure the Toml configuration file.


    .. py:attribute:: mdns_ttl
        :value: 120
        :type: int

        *Corresponds to* :attr:`mDNS.TTL`

    .. py:attribute:: mdns_max_labels
        :value: 1
        :type: int

        *Corresponds to* :attr:`mDNS.MaxLabels`

    .. py:attribute:: mdns_qtypes
        :value: [1, 28, 255]
        :type: list[str | int]

        *Corresponds to* :attr:`mDNS.AllowedQueryTypes`


Default Configuration
---------------------

.. code-block:: toml
    :linenos:
    :caption: mDNS configuration section (default values)

    [mDNS]
    TTL = 120
    MaxLabels = 1
    AllowedQueryTypes = [ "A", "AAAA", "ALL" ]
