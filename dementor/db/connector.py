# Copyright (c) 2025-Present MatrixEditor
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# pyright: reportUninitializedInstanceVariable=false
"""Database engine initialization and configuration.

Reads the ``[DB]`` TOML section via :class:`DatabaseConfig`, builds a
SQLAlchemy :class:`~sqlalchemy.engine.Engine` with backend-specific pool
settings, and exposes :func:`create_db` as the single entry point used
by :func:`~dementor.standalone.serve` at startup.
"""

import typing
from typing import Any

from sqlalchemy import Engine, create_engine
from sqlalchemy.pool import StaticPool

from dementor.config.session import SessionConfig
from dementor.db.model import DementorDB
from dementor.log.logger import dm_logger
from dementor.config.toml import TomlConfig, Attribute as A


class DatabaseConfig(TomlConfig):
    """Configuration mapping for the ``[DB]`` TOML section.

    Users set EITHER ``Url`` (a full SQLAlchemy DSN for any backend,
    e.g. ``mysql+pymysql://user:pass@host/db``) OR ``Path`` (a file
    path for the default SQLite backend, e.g. ``Dementor.db``).

    When ``Url`` is omitted, ``Path`` is resolved relative to the
    session workspace and wrapped into a ``sqlite+pysqlite://`` URL.
    """

    _section_: typing.ClassVar[str] = "DB"
    _fields_: typing.ClassVar[list[A]] = [
        A("db_url", "Url", None),
        A("db_path", "Path", "Dementor.db"),
        A("db_duplicate_creds", "DuplicateCreds", False),
    ]

    if typing.TYPE_CHECKING:  # pragma: no cover - only for static analysis
        db_url: str | None
        db_path: str
        db_duplicate_creds: bool


def init_engine(session: SessionConfig) -> Engine | None:
    """Build a SQLAlchemy ``Engine`` from a :class:`DatabaseConfig`.

    * If ``db_url`` (TOML ``Url``) is supplied it is used verbatim.
    * Otherwise ``db_path`` (TOML ``Path``) is resolved relative to the
      session workspace and wrapped into a ``sqlite+pysqlite://`` URL.

    Sensitive information (user/password) is hidden in the debug output.

    :param session: Current session configuration.
    :type session: SessionConfig
    :return: Configured ``Engine`` instance or ``None`` on failure.
    :rtype: Engine | None
    """
    # --------------------------------------------------------------- #
    # 1.  Resolve URL -- either user-supplied DSN or built from Path.
    # --------------------------------------------------------------- #
    raw_path = session.db_config.db_url
    if raw_path is None:
        # No Url configured -- use the SQLite Path default.
        dialect = "sqlite"
        driver = "pysqlite"
        path = session.db_config.db_path
        if not path:
            return dm_logger.error("Database path not specified!")
        if path == ":memory:":
            path = "/:memory:"
        else:
            real_path = session.resolve_path(path)
            if not real_path.parent.exists():
                dm_logger.debug(f"Creating database directory {real_path.parent}")
                real_path.parent.mkdir(parents=True, exist_ok=True)
            path = f"/{real_path}"
        raw_path = f"{dialect}+{driver}://{path}"
    else:
        # Decompose the user-supplied URL to obtain dialect and driver.
        sql_type, path = raw_path.split("://")
        if "+" in sql_type:
            dialect, driver = sql_type.split("+")
        else:
            dialect = sql_type
            driver = "<default>"

    # --------------------------------------------------------------- #
    # 2.  Mask credentials in the debug log output.
    # --------------------------------------------------------------- #
    # For non-SQLite URLs like mysql+pymysql://user:pass@host/db,
    # replace the user:pass portion with stars so passwords don't
    # appear in log files.
    if dialect != "sqlite":
        first_element, *parts = path.split("/")
        if "@" in first_element:
            first_element = first_element.split("@")[1]
            path = "***:***@" + "/".join([first_element, *parts])

    dm_logger.debug("Using database [%s:%s] at: %s", dialect, driver, path)

    # --------------------------------------------------------------- #
    # 3.  Build the engine with backend-specific pool settings.
    # --------------------------------------------------------------- #
    # All backends use AUTOCOMMIT -- Dementor does individual INSERT/SELECT
    # operations, not multi-statement transactions.
    #
    # pool_reset_on_return=None: the pool's default is to ROLLBACK on
    # every connection checkin, which is wasted work under AUTOCOMMIT.
    #
    # skip_autocommit_rollback=True: tells the dialect itself not to
    # emit ROLLBACK either (SQLAlchemy 2.0.43+).  Together these two
    # settings eliminate every unnecessary ROLLBACK round-trip.
    common: dict[str, Any] = {
        "isolation_level": "AUTOCOMMIT",
        "pool_reset_on_return": None,
        "skip_autocommit_rollback": True,
    }

    # Three pool strategies, one per backend constraint:
    #
    # :memory: SQLite  -> StaticPool  (DB exists only inside one connection;
    #                     a second connection = empty DB.  DementorDB.lock
    #                     serializes all access to that one connection.)
    #
    # File SQLite      -> QueuePool   (SQLAlchemy 2.0 default for file SQLite.
    #                     Each thread checks out its own connection;
    #                     _release() returns it after each operation.)
    #
    # MySQL/PostgreSQL -> QueuePool   (Connection reuse avoids the ~10-50ms
    #                     TCP+auth overhead of opening a new connection per
    #                     query.  LIFO keeps idle connections at the front so
    #                     the server's wait_timeout can expire the rest.)
    if dialect == "sqlite":
        if path == ":memory:" or path.endswith("/:memory:"):
            return create_engine(
                raw_path,
                **common,
                poolclass=StaticPool,
                connect_args={"check_same_thread": False},
            )
        # File-based SQLite: QueuePool is the SQLAlchemy 2.0 default.
        # check_same_thread=False is set automatically by the dialect.
        # DementorDB._release() returns connections after each operation.
        return create_engine(raw_path, **common)

    # MySQL / MariaDB / PostgreSQL: QueuePool.
    #   pool_pre_ping  - detect dead connections before checkout.
    #   pool_use_lifo  - reuse most-recent connection so idle ones expire
    #                    naturally via server-side wait_timeout.
    #   pool_recycle   - hard ceiling: close connections older than 1 hour.
    #   pool_timeout=5 - fail fast on exhaustion (PoolTimeoutError caught
    #                    in model.py); hash file is the primary capture path.
    return create_engine(
        raw_path,
        **common,
        pool_pre_ping=True,
        pool_use_lifo=True,
        pool_size=20,
        max_overflow=40,
        pool_timeout=5,
        pool_recycle=3600,
    )


def create_db(session: SessionConfig) -> DementorDB:
    """Create a fully initialised :class:`DementorDB` ready for use.

    Builds the SQLAlchemy engine via :func:`init_engine` and passes it
    to the :class:`~dementor.db.model.DementorDB` constructor, which
    creates the tables and sets up the scoped session.

    :param session: Current session configuration holding the
        :class:`DatabaseConfig` at ``session.db_config``.
    :type session: SessionConfig
    :return: Ready-to-use database wrapper.
    :rtype: DementorDB
    :raises RuntimeError: If the engine cannot be created (e.g. empty
        ``Path`` with no ``Url``).
    """
    engine = init_engine(session)
    if not engine:
        raise RuntimeError("Failed to create database engine")
    return DementorDB(engine, session)
