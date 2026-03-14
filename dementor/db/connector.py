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
import typing

from sqlalchemy import Engine, create_engine

from dementor.config.session import SessionConfig
from dementor.db.model import DementorDB, ModelBase
from dementor.log.logger import dm_logger
from dementor.config.toml import TomlConfig, Attribute as A


class DatabaseConfig(TomlConfig):
    """
    Configuration mapping for the ``[DB]`` TOML section.

    The attributes correspond to the most common SQLAlchemy connection
    parameters.  All fields are optional - sensible defaults are applied
    when a key is missing.
    """

    _section_: typing.ClassVar[str] = "DB"
    _fields_: typing.ClassVar[list[A]] = [
        A("db_raw_path", "Url", None),
        A("db_path", "Path", "Dementor.db"),
        A("db_duplicate_creds", "DuplicateCreds", False),
        A("db_dialect", "Dialect", None),
        A("db_driver", "Driver", None),
    ]

    if typing.TYPE_CHECKING:  # pragma: no cover - only for static analysis
        db_raw_path: str | None
        db_path: str
        db_duplicate_creds: bool
        db_dialect: str | None
        db_driver: str | None


def init_dementor_db(session: SessionConfig) -> Engine | None:
    """
    Initialise the database engine and create all tables.

    :param session: The active :class:`~dementor.config.session.SessionConfig`
        containing the ``db_config`` attribute.
    :type session: SessionConfig
    :return: The created SQLAlchemy ``Engine`` or ``None`` if an error
        prevented initialisation.
    :rtype: Engine | None
    """
    engine = init_engine(session)
    if engine is not None:
        ModelBase.metadata.create_all(engine)
    return engine


def init_engine(session: SessionConfig) -> Engine | None:
    """
    Build a SQLAlchemy ``Engine`` from a :class:`DatabaseConfig`.

    The logic follows the rules laid out in the SQLAlchemy documentation
    (see https://docs.sqlalchemy.org/en/20/core/engines.html#database-urls).

    * If ``db_raw_path`` is supplied it is used verbatim.
    * Otherwise a URL is composed from ``dialect``, ``driver`` and ``path``.
      For SQLite the path is resolved relative to the session's
      ``resolve_path`` helper; missing directories are created on the fly.

    Sensitive information (user/password) is hidden in the debug output.

    :param session: Current session configuration.
    :type session: SessionConfig
    :return: Configured ``Engine`` instance or ``None`` on failure.
    :rtype: Engine | None
    """
    # --------------------------------------------------------------- #
    # 1.  Resolve "raw" URL - either provided by the user or built.
    # --------------------------------------------------------------- #
    raw_path = session.db_config.db_raw_path
    if raw_path is None:
        # Build the URL manually when the user didn't provide a full DSN.
        dialect = session.db_config.db_dialect or "sqlite"
        driver = session.db_config.db_driver or "pysqlite"
        path = session.db_config.db_path
        if not path:
            return dm_logger.error("Database path not specified!")
        # :memory: is a special SQLite in-memory database.
        if dialect == "sqlite" and path != ":memory:":
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

    if dialect != "sqlite":
        first_element, *parts = path.split("/")
        if "@" in first_element:
            # keep only the “host:port” part, replace user:pass with stars
            first_element = first_element.split("@")[1]
            path = "***:***@" + "/".join([first_element, *parts])

    dm_logger.debug("Using database [%s:%s] at: %s", dialect, driver, path)
    return create_engine(raw_path, isolation_level="AUTOCOMMIT", future=True)


def create_db(session: SessionConfig) -> DementorDB:
    """
    High-level helper that returns a fully-initialised :class:`DementorDB`.

    :param session: Current session configuration.
    :type session: SessionConfig
    :return: Ready-to-use :class:`DementorDB` instance.
    :rtype: DementorDB
    :raises Exception: If the engine cannot be created.
    """
    engine = init_engine(session)
    if not engine:
        raise RuntimeError("Failed to create database engine")
    return DementorDB(engine, session)
