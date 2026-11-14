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
from typing import Any

from sqlalchemy import Engine, create_engine
from sqlalchemy.pool import StaticPool

from dementor.config.session import SessionConfig
from dementor.db.model import DementorDB
from dementor.log.logger import dm_logger
from dementor.config.toml import TomlConfig, Attribute as A


class DatabaseConfig(TomlConfig):
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
    raw_path = session.db_config.db_url
    if raw_path is None:
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
        sql_type, path = raw_path.split("://")
        if "+" in sql_type:
            dialect, driver = sql_type.split("+")
        else:
            dialect = sql_type
            driver = "<default>"

    if dialect != "sqlite":
        first_element, *parts = path.split("/")
        if "@" in first_element:
            first_element = first_element.split("@")[1]
            path = "***:***@" + "/".join([first_element, *parts])

    dm_logger.debug("Using database [%s:%s] at: %s", dialect, driver, path)

    # Enable/Disable these settings if you like
    common: dict[str, Any] = {
        "isolation_level": "AUTOCOMMIT",
        "pool_reset_on_return": None,
        # "skip_autocommit_rollback": True,
    }

    if dialect == "sqlite":
        if path == ":memory:" or path.endswith("/:memory:"):
            return create_engine(
                raw_path,
                **common,
                poolclass=StaticPool,
                connect_args={"check_same_thread": False},
            )
        return create_engine(raw_path, **common)

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
    engine = init_engine(session)
    if not engine:
        raise RuntimeError("Failed to create database engine")
    return DementorDB(engine, session)
