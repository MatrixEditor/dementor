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
.. _config_mdns:

mDNS
====

.. _config_mdns_sectioncfg:

Section: ``[mDNS]``
-------------------

.. py:currentmodule:: mDNS

.. py:attribute:: TTL
    :type: int
    :value: 120

    *Linked to* :attr:`mdns.MDNSConfig.mdns_ttl`

    Specifies the Time-To-Live (TTL), in seconds, for poisoned responses.
    Lower TTL values may increase the likelihood of detection by antivirus (AV) or endpoint detection and response (EDR) solutions.

.. py:attribute:: MaxLabels
    :type: int
    :value: 1

    *Linked to* :attr:`mdns.MDNSConfig.mdns_max_labels`

    Defines the maximum number of domain name labels to be processed.
    This setting overrides :attr:`mDNS.AllowedQueryTypes` as well as global and local blacklist/whitelist configurations.
    By default, all incoming queries that target services with more than one label (excluding :code:`.local`) are ignored.

.. py:attribute:: AllowedQueryTypes
    :type: list[str | int]
    :value: [ "A", "AAAA", "ALL" ]

    *Linked to* :attr:`mdns.MDNSConfig.mdns_qtypes`

    Specifies the list of DNS query types to respond to.
    This attribute has lower priority than :attr:`mDNS.MaxLabels`, but higher priority than global or local blacklist/whitelist rules.

    .. note::

        If query types are provided as strings, they must correspond to valid entries in :attr:`dns.dnstypes`.


.. py:attribute:: Ignore
    :type: list[str | dict]

    Specifies a list of hosts to be blacklisted. For additional context, see :attr:`Globals.Ignore`.
    When this attribute is defined, it overrides the global blacklist configuration.
    If not explicitly set, this attribute has no effect.
    For a comprehensive explanation of how the blacklist is applied, refer to :class:`BlacklistConfigMixin`.

.. py:attribute:: AnswerTo
    :type: list[str | dict]

    Defines a list of hosts to which responses should be sent.
    See :attr:`Globals.AnswerTo` for more information.
    When specified, this attribute takes precedence over the global whitelist.
    If omitted, the global configuration remains in effect.
    For detailed behavior and usage, refer to :class:`WhitelistConfigMixin`.


Python Config
-------------

.. py:class:: mdns.MDNSConfig(config: dict)

    Represents the configuration for the corresponding `[mdns]` section in the TOML file.
    This class incorporates both :class:`WhitelistConfigMixin` and :class:`BlacklistConfigMixin`,
    which introduce two additional configuration fields. For further details on their behavior and usage,
    refer to the respective mixin class documentation.

    .. py:attribute:: enabled
        :type: bool
        :value: True

        *Corresponds to* :attr:`Dementor.mDNS`

        Controls whether mDNS poisoning is enabled.
        See :attr:`Dementor.mDNS` for guidance on configuring this option in the TOML file.

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
