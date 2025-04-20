
.. _config_main:

Main
====

The main configuration is defined in the ``[Dementor]`` section. This section is
responsible for enabling protocol servers and configuring additional protocols.
Each server can be enabled or disabled **within the configuration file** using
values that can be interpreted as booleans, such as ``true``, ``false``, ``1``,
``"on"``, or ``"off"``. for more information on the Python side of this
configuration, refer to :class:`~dementor.config.SessionConfig`.


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
    `Array Tables <https://toml.io/en/v1.0.0#array-of-tables>`_.


.. py:attribute:: ExtraModules
    :type: list[str]

    *Maps to* :attr:`config.SessionConfig.extra_modules`

    A list of directories containing custom protocol modules. For instructions on
    including additional protocols, see :ref:`howto_custom_protocol`. The loading
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


.. py:attribute:: HTTP
    :type: bool
    :value: true

    *Maps to* :attr:`config.SessionConfig.http_enbled`

    .. versionadded:: 1.0.0.dev1

    Enables or disables configured HTTP servers. For more details, refer to :ref:`config_http`.


.. py:attribute:: RPC
    :type: bool
    :value: true

    *Maps to* :attr:`config.SessionConfig.msrpc_enabled`

    .. versionadded:: 1.0.0.dev2

    Enables or disables the DCE/RPC service. For more details, refer to :ref:`config_dcerpc`.
