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
.. _config_main:

Main
====

The main configuration is defined in the ``[Dementor]`` section. This section is
responsible for enabling protocol servers and configuring additional protocols.
Each server can be enabled or disabled **within the configuration file** using
values that can be interpreted as booleans, such as ``true``, ``false``, ``1``,
``"on"``, or ``"off"``.


Section ``[Dementor]``
----------------------

.. py:currentmodule:: Dementor

.. py:attribute:: Workspace
    :type: str
    :value: "~/.dementor/"

    *Maps to* :attr:`config.SessionConfig.workspace_path`

    Specifies the directory where the database is stored and where additional modules
    can be placed. By default, this path points to ``~/.dementor`` in the user's home
    directory. For guidance on how to include custom protocols, refer to
    :ref:`howto_custom_protocol_`.


.. py:attribute:: ExtraModules
    :type: list[str]

    *Maps to* :attr:`config.SessionConfig.extra_modules`

    A list of directories containing custom protocol modules. For instructions on
    including additional protocols, see :ref:`howto_custom_protocol_`. The loading
    mechanism and its priorities are described in :class:`~dementor.loader.ProtocolLoader`.

The following options control servers that perform poisoning in the local network:

.. py:attribute:: LLMNR
    :type: bool
    :value: true

    *Maps to* :attr:`config.SessionConfig.llmnr_enbled`

    Enables or disables LLMNR multicast poisoning. Valid values must be convertible
    to boolean types as described above. Protocol-specific configuration is available
    in :ref:`config_llmnr_sectioncfg`.

.. py:attribute:: mDNS
    :type: bool
    :value: true

    *Maps to* :attr:`config.SessionConfig.mdns_enbled`

    Enables or disables mDNS multicast poisoning. For mDNS protocol configuration
    details, see :ref:`config_mdns_sectioncfg`.

.. py:attribute:: NBTNS
    :type: bool
    :value: true

    *Maps to* :attr:`config.SessionConfig.nbtns_enbled`

    Enables or disables NetBIOS Name Service (NBT-NS) poisoning. For further
    configuration options, see :ref:`config_netbios_sectioncfg`.

The following settings apply to protocol-specific servers that do not perform active
attacks, but instead passively capture credentials:

.. py:attribute:: SMTP
                  SMB
                  NBTDS
                  FTP
                  KDC
                  LDAP
                  QUIC
    :type: bool
    :value: true

    *Maps to* :attr:`config.SessionConfig.XXX_enbled` *(lowercase)*

    Enables or disables the specified protocol service. For details on each protocol,
    refer to the respective documentation section. (Note: ``KDC`` corresponds to the
    Kerberos service).
