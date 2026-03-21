
.. _config_database:

Database
========

Section ``[DB]``
----------------

Dementor stores every captured credential (hashes and cleartext passwords) in a
database so you can query them later through the TUI or export them for offline
cracking.  The ``[DB]`` section controls where that database lives and how
duplicates are handled.

.. tip::

    Most users don't need to touch this section.  With no configuration at all,
    Dementor creates a SQLite file called ``Dementor.db`` in your workspace
    directory.  That works out of the box for most engagements.


Choosing a backend
~~~~~~~~~~~~~~~~~~

Dementor supports three database backends.  Pick the one that fits your
use case:

.. list-table::
    :widths: 25 45 30
    :header-rows: 1

    * - Backend
      - When to use it
      - How to configure
    * - **SQLite file** *(default)*
      - Credentials persist to disk across restarts.  Good for most
        engagements.
      - Leave ``Url`` empty.  Optionally set ``Path``.
    * - **SQLite in-memory**
      - Fast, no disk I/O.  Credentials are lost when Dementor exits, but
        the TUI can still query them while running.  Good for quick tests.
      - ``Path = ":memory:"``
    * - **MySQL / MariaDB / PostgreSQL**
      - Shared access across multiple Dementor instances or integration
        with external tooling.  Requires a running database server.
      - Set ``Url`` to a full connection string.


Options
~~~~~~~

.. py:currentmodule:: DB


.. py:attribute:: Url
    :type: str
    :value: *(empty)*

    *Maps to* :attr:`db.connector.DatabaseConfig.db_url`

    .. versionadded:: 1.0.0.dev14

    .. versionchanged:: 1.0.0.dev22

        Renamed internally from ``db_raw_path`` to ``db_url``.  The TOML key
        ``Url`` is unchanged.

    Full `SQLAlchemy database URL <https://docs.sqlalchemy.org/en/20/core/engines.html#database-urls>`_
    for connecting to an external database server.  When set, :attr:`Path` is
    ignored.  Leave empty (the default) to use SQLite via :attr:`Path`.

    .. code-block:: toml

        # MySQL / MariaDB
        Url = "mysql+pymysql://user:pass@127.0.0.1/dementor"

        # PostgreSQL
        Url = "postgresql+psycopg2://user:pass@127.0.0.1/dementor"

    .. note::

        The database driver (e.g. ``pymysql``, ``psycopg2``) must be installed
        separately — it is not bundled with Dementor.


.. py:attribute:: Path
    :type: str
    :value: "Dementor.db"

    *Maps to* :attr:`db.connector.DatabaseConfig.db_path`

    .. versionadded:: 1.0.0.dev14

    Path to the SQLite database file.  Only used when :attr:`Url` is empty.

    * **Relative paths** are resolved from the workspace directory
      (:attr:`Dementor.Workspace`).
    * **Absolute paths** are used as-is.
    * ``:memory:`` creates an in-memory database — fast, but all data is lost
      when Dementor exits.  The TUI can still query credentials while running.

    .. code-block:: toml

        # Default — file in the workspace directory
        Path = "Dementor.db"

        # Subfolder (created automatically if it doesn't exist)
        Path = "data/captures.db"

        # Absolute path
        Path = "/opt/dementor/creds.db"

        # In-memory — fast, but data is lost on exit
        Path = ":memory:"

    .. tip::

        Use ``:memory:`` for quick tests where you don't need persistence.
        The TUI can still query captured credentials while Dementor is running.


.. py:attribute:: DuplicateCreds
    :type: bool
    :value: true

    *Maps to* :attr:`db.connector.DatabaseConfig.db_duplicate_creds`

    Controls whether duplicate credentials are stored in the database.

    * ``true`` *(default)* — Every captured hash is stored, even if the same
      credential was already seen in this session.
    * ``false`` — Only the first capture of each unique credential is stored.
      Subsequent duplicates are silently skipped.

    A credential is considered a duplicate when all four of these fields match
    (case-insensitive):

    * Domain
    * Username
    * Credential type (e.g. ``NetNTLMv2``, ``Cleartext``)
    * Protocol (e.g. ``smb``, ``http``)

    .. note::

        The hash is always written to the log file stream regardless of this
        setting, so no captured data is ever lost — only the database storage
        is affected.

    .. tip::

        Set to ``false`` on long-running engagements to keep the database small
        and the TUI output clean.


Removed options
~~~~~~~~~~~~~~~

The following options have been removed in previous versions.  They are silently
ignored if still present in your configuration file.

.. py:attribute:: Dialect
    :type: str
    :value: "sqlite"

    .. versionadded:: 1.0.0.dev14

    .. versionremoved:: 1.0.0.dev22

        **Removed.**  The SQL dialect is now determined automatically — from
        :attr:`Url` when set, or defaults to ``sqlite`` when using :attr:`Path`.

.. py:attribute:: Driver
    :type: str
    :value: "pysqlite"

    .. versionadded:: 1.0.0.dev14

    .. versionremoved:: 1.0.0.dev22

        **Removed.**  The SQL driver is now determined automatically — from
        :attr:`Url` when set, or defaults to ``pysqlite`` when using :attr:`Path`.

.. py:attribute:: Directory
    :type: str

    .. versionremoved:: 1.0.0.dev14

        **Removed.**  Use :attr:`Path` with an absolute path instead.

.. py:attribute:: Name
    :type: str
    :value: "Dementor.db"

    .. versionremoved:: 1.0.0.dev14

        **Removed.**  Use :attr:`Path` instead.
