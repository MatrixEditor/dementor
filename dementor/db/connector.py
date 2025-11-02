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
import sqlite3
from sqlalchemy import Engine, create_engine

from dementor.config.session import SessionConfig
from dementor.db.model import DementorDB, ModelBase
from dementor.log.logger import dm_logger
from dementor.config.toml import TomlConfig, Attribute as A


class DatabaseConfig(TomlConfig):
    _section_ = "DB"
    _fields_ = [
        A("db_raw_path", "Url", None),
        A("db_path", "Path", "Dementor.db"),
        A("db_duplicate_creds", "DuplicateCreds", False),
        A("db_dialect", "Dialect", None),
        A("db_driver", "Driver", None),
    ]


def init_dementor_db(session: SessionConfig) -> Engine | None:
    engine = init_engine(session)
    if engine is not None:
        ModelBase.metadata.create_all(engine)
    return engine


def init_engine(session: SessionConfig) -> Engine | None:
    # based on dialect and driver configuration
    raw_path = session.db_config.db_raw_path
    if raw_path is None:
        # fall back to constructing the path manually
        dialect = session.db_config.db_dialect or "sqlite"
        driver = session.db_config.db_driver or "pysqlite"
        path = session.db_config.db_path
        if not path:
            return dm_logger.error("Database path not specified!")

        if dialect == "sqlite":
            if path != ":memory:":
                path = f"/{session.resolve_path(path)}"

        # see https://docs.sqlalchemy.org/en/20/core/engines.html#database-urls
        raw_path = f"{dialect}+{driver}://{path}"
    else:
        sql_type, path = raw_path.split("://")
        if sql_type.count("+") > 0:
            dialect, driver = sql_type.split("+")
        else:
            dialect = sql_type
            driver = "<default>"

    if dialect != "sqlite":
        first_element, *parts = path.split("/")
        if "@" in first_element:
            first_element = first_element.split("@")[1]
            path = "***:***@" + "/".join([first_element] + list(parts))

    dm_logger.debug("Using database [%s:%s] at: %s", dialect, driver, path)
    return create_engine(raw_path, isolation_level="AUTOCOMMIT", future=True)


def create_db(session: SessionConfig) -> DementorDB:
    # TODO: add support for custom database implementations
    engine = init_engine(session)
    if not engine:
        raise Exception("Failed to create database engine")
    return DementorDB(engine, session)
