.. _config_llmnr:

LLMNR
=====

Section: ``[LLMNR]``
-----------------

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

    A list of hosts to blacklist. Please refer to :attr:`Globals.Ignore` for more
    information. If defined here, the global blacklist will be ignored. This
    setting will be ignored if not defined. For a detailed explanation of how this
    rule will be applied, refer to :class:`BlacklistConfigMixin`.


.. py:attribute:: AnswerTo
    :type: list[str | dict]

    A list of hosts to respond to. Please refer to :attr:`Globals.AnswerTo` for more
    information. If defined here, the global whitelist will be ignored. This
    setting will be ignored if not defined. For a detailed explanation of how this
    rule will be applied, refer to :class:`WhitelistConfigMixin`.

Python Config
-------------

.. py:class:: llmnr.LLMNRConfig

    Configuration class for its Toml counterpart section. It uses :class:`WhitelistConfigMixin`
    and :class:`BlacklistConfigMixin`, which results in two extra fields in this class. Refer to
    those classes for more information.

    .. py:attribute:: llmnr_answer_name
        :value: None
        :type: Optional[str]

        *Corresponds to* :attr:`LLMNR.AnswerName`

        Note that the default value here is ``None`` to disable spoofed answer names.


Default Configuration
---------------------

.. code-block:: toml
    :linenos:
    :caption: LLMNR configuration section (default values)

    [LLMNR]
    # AnswerName is disabled by default, so this section is empty