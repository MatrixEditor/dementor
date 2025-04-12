.. _config_llmnr:

LLMNR
=====

Section: ``[LLMNR]``
--------------------

.. py:currentmodule:: LLMNR

.. py:attribute:: AnswerName
    :type: str

    Name to return when responding to queries (can be used for kerberos relay). Example use
    case can be seen in: :ref:`examples_multicast_llmnr_answername`

    .. seealso::

        Synacktiv's excellent article on how to leverage this behaviour to perform
        kerberos relay: `Abusing multicast poisoning for pre-authenticated Kerberos relay over HTTP with Responder and krbrelayx <https://www.synacktiv.com/publications/abusing-multicast-poisoning-for-pre-authenticated-kerberos-relay-over-http-with>`_


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

.. py:class:: llmnr.LLMNRConfig

    Defines the configuration for the `[llmnr]` section in the TOML file.
    This class extends both :class:`WhitelistConfigMixin` and :class:`BlacklistConfigMixin`,
    introducing two additional fields. Refer to the respective mixins for a detailed explanation of their functionality.

    .. py:attribute:: llmnr_answer_name
        :type: Optional[str]
        :value: None

        *Corresponds to* :attr:`LLMNR.AnswerName`

        Specifies a custom name to use in spoofed LLMNR responses.
        The default value is ``None``, which disables spoofed answer names.


Default Configuration
---------------------

.. code-block:: toml
    :linenos:
    :caption: LLMNR configuration section (default values)

    [LLMNR]
    # AnswerName is disabled by default, so this section is empty