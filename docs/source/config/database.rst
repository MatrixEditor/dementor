
.. _config_database:

Database
========

Section ``[Database]``
----------------------

.. py:currentmodule:: Database

.. py:attribute:: DuplicateCreds
    :type: bool
    :value: false

    *Maps to* :attr:`db.connector.DatabaseConfig.db_duplicate_creds`

    Controls whether duplicate credentials are stored. If set to ``false``, each unique
    credential set is stored and displayed only once.

.. py:attribute:: Dialect
    :type: str
    :value: "sqlite"

    *Maps to* :attr:`db.connector.DatabaseConfig.db_dialect`

    .. versionadded:: 1.0.0.dev14

    Specifies the SQL dialect to use

.. py:attribute:: Driver
    :type: str
    :value: "pysqlite"

    *Maps to* :attr:`db.connector.DatabaseConfig.db_driver`

    .. versionadded:: 1.0.0.dev14

    Specifies the SQL driver (external packages allowed) to be used for the database connection.
    Additional third-party packages must be installed before they can be used.

.. py:attribute:: Path
    :type: RelativePath | RelativeWorkspacePath | AbsolutePath
    :value: "Dementor.db"

    *Maps to* :attr:`db.connector.DatabaseConfig.db_path`

    .. versionadded:: 1.0.0.dev14

    Specifies the database filename. Not used if :attr:`~DB.Url` is set.

.. py:attribute:: Url
    :type: str

    *Maps to* :attr:`db.connector.DatabaseConfig.db_raw_path`

    .. versionadded:: 1.0.0.dev14

    Custom database connection URL to use. Overwrites driver, dialect and path.



.. py:attribute:: Directory
    :type: str

    .. versionremoved:: 1.0.0.dev14

    **DEPRECATED** Specifies a custom directory for storing the database. This setting overrides the default
    directory configured via :attr:`Dementor.Workspace`.


.. py:attribute:: Name
    :type: str
    :value: "Dementor.db"

    .. versionremoved:: 1.0.0.dev14

    **DEPRECATED** Sets the filename of the database to be used.



