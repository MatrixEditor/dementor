
.. _config_database:

Database
========

Section ``[Database]``
----------------------

.. py:currentmodule:: Database

.. py:attribute:: DuplicateCreds
    :type: bool
    :value: false

    *Maps to* :attr:`database.DatabaseConfig.db_duplicate_creds`

    Controls whether duplicate credentials are stored. If set to ``false``, each unique
    credential set is stored and displayed only once.


.. py:attribute:: Directory
    :type: str

    *Maps to* :attr:`database.DatabaseConfig.db_dir`

    Specifies a custom directory for storing the database. This setting overrides the default
    directory configured via :attr:`Dementor.Workspace`.


.. py:attribute:: Name
    :type: str
    :value: "Dementor.db"

    *Maps to* :attr:`database.DatabaseConfig.db_name`

    Sets the filename of the database to be used.



