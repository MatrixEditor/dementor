.. _config_netbios:

NBTNS
=====

Section ``[NetBIOS]``
---------------------

.. py:currentmodule:: NetBIOS

.. py:attribute:: Ignore
    :type: list[str | dict]

    Specifies a list of hosts to be blacklisted. For further context, refer to :attr:`Globals.Ignore`.
    When defined, this attribute overrides the global blacklist configuration.
    If not set, it has no effect.
    For a detailed explanation of how blacklist rules are applied, see :class:`BlacklistConfigMixin`.

.. py:attribute:: AnswerTo
    :type: list[str | dict]

    Defines a list of hosts to which responses should be sent.
    Refer to :attr:`Globals.AnswerTo` for more information.
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


