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


