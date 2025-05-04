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
import threading
import sqlite3
import pathlib

from datetime import datetime
from typing import Any, Tuple
from rich import markup

from sqlalchemy.engine import Engine, create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.schema import MetaData, Table
from sqlalchemy import sql
from sqlalchemy.exc import NoSuchTableError, NoInspectionAvailable, OperationalError


from dementor.logger import dm_logger, dm_console_lock
from dementor.config.toml import TomlConfig, Attribute as A


class DatabaseConfig(TomlConfig):
    _section_ = "DB"
    _fields_ = [
        A("db_dir", "Directory", None),
        A("db_name", "Name", "Dementor.db"),
        A("db_duplicate_creds", "DuplicateCreds", False),
    ]


def init_dementor_db(session) -> str:
    workspace_path = session.workspace_path
    if session.db_config.db_dir:
        workspace_path = session.db_config.db_dir

    name = session.db_config.db_name
    db_path = pathlib.Path(workspace_path) / name
    if not db_path.exists():
        dm_logger.info("Initializing Dementor database")
        # TODO: check for parent dirs
        if not db_path.parent.exists():
            dm_logger.info(f"Creating directory {db_path.parent}")
            db_path.parent.mkdir(parents=True, exist_ok=True)

        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute("PRAGMA journal_mode = OFF")
        cursor.execute("PRAGMA foreign_keys = 1")
        DementorDB.db_schema(cursor)

        # commit and save changes
        conn.commit()
        conn.close()
    return db_path


def init_engine(db_path: str) -> Engine:
    return create_engine(
        f"sqlite:///{db_path}",
        isolation_level="AUTOCOMMIT",
        future=True,
    )


def normalize_client_address(client: str) -> str:
    return client.removeprefix("::ffff:")


_CLEARTEXT = "Cleartext"
_NO_USER = "<missing-user>"


class DementorDB:
    def __init__(self, engine: Engine, config) -> None:
        self.db_engine = engine
        self.db_path = engine.url.database
        self.metadata = MetaData()
        self.config = config

        with self.db_engine.connect():
            try:
                # reflect tables
                self.CredentialsTable = Table(
                    "credentials",
                    self.metadata,
                    autoload_with=self.db_engine,
                )
                self.HostsTable = Table(
                    "hosts",
                    self.metadata,
                    autoload_with=self.db_engine,
                )
            except (NoSuchTableError, NoInspectionAvailable):
                dm_logger.error(f"Failed to connect to database {self.db_path}!")
                raise

        session_factory = sessionmaker(bind=self.db_engine, expire_on_commit=True)
        session_ty = scoped_session(session_factory)

        self.session = session_ty()
        self.lock = threading.Lock()

    # now, lets create those tables
    @staticmethod
    def db_schema(cursor: sqlite3.Cursor) -> None:
        cursor.execute(
            """CREATE TABLE "credentials" (
                "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                "timestamp" TEXT NOT NULL,
                "protocol" TEXT NOT NULL,
                "credtype" TEXT NOT NULL,
                "client" TEXT NOT NULL,
                "hostname" TEXT,
                "domain" TEXT,
                "username" TEXT NOT NULL,
                "password" TEXT
            )"""
        )

        cursor.execute(
            """CREATE TABLE "hosts" (
                "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                "hostname" TEXT NOT NULL,
                "ip" TEXT NOT NULL,
                "port" INTEGER NOT NULL,
                "banner" TEXT,
                "os" TEXT
            )"""
        )

    def close(self) -> None:
        self.session.close()

    def db_exec(self, *args, **kwargs):
        self.lock.acquire()
        result = self.session.execute(*args, **kwargs)
        self.lock.release()
        return result

    def add_auth(
        self,
        client: Tuple[str, int],
        credtype: str,
        username: str,
        password: str,
        logger: Any = None,
        protocol: str | None = None,
        domain: str | None = None,
        hostname: str | None = None,
        extras: dict | None = None,
        custom: bool = False,
    ) -> None:
        if not logger and not protocol:
            dm_logger.error(
                f"Failed to add {credtype} for {username} on {client[0]}:{client[1]}: "
                "Protocol must be present either in the logger or as a parameter!"
            )
            return

        target_logger = logger or dm_logger
        protocol = str(protocol or logger.extra["protocol"])
        client_address, port, *_ = client
        client_address = normalize_client_address(client_address)

        target_logger.debug(
            f"Adding {credtype} for {username} on {client_address}: "
            f"{logger} | {protocol} | {domain} | {hostname} | {username} | {password}"
        )

        q = sql.select(self.CredentialsTable).filter(
            sql.func.lower(self.CredentialsTable.c.domain)
            == sql.func.lower(domain or ""),
            sql.func.lower(self.CredentialsTable.c.username)
            == sql.func.lower(username),
            sql.func.lower(self.CredentialsTable.c.credtype)
            == sql.func.lower(credtype),
            sql.func.lower(self.CredentialsTable.c.protocol)
            == sql.func.lower(protocol),
        )
        results = self.db_exec(q).all()
        text = "Password" if credtype == _CLEARTEXT else "Hash"
        username_text = markup.escape(username)
        is_blank = len(str(username).strip()) == 0
        if is_blank:
            username_text = "(blank)"

        full_name = (
            f" for [b]{username_text}[/]/[b]{markup.escape(domain)}[/]"
            if domain
            else f" for [b]{username_text}[/]"
        )
        if is_blank:
            full_name = ""

        if not results or self.config.db_config.db_duplicate_creds:
            # just insert a new row
            q = sql.insert(self.CredentialsTable).values(
                {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "protocol": protocol.lower(),
                    "credtype": credtype.lower(),
                    "client": f"{client_address}:{port}",
                    "hostname": hostname or "",
                    "domain": (domain or "").lower(),
                    "username": username.lower(),
                    "password": password,
                }
            )
            try:
                self.db_exec(q)
            except OperationalError as e:
                # attempt to write on a read-only database
                if "readonly database" in str(e):
                    dm_logger.warning(
                        f"Failed to add {credtype} for {username} on {client_address}: "
                        "Database is read-only! (maybe restart in sudo mode?)"
                    )
                else:
                    raise
            with dm_console_lock:
                head_text = text if not custom else ""
                credtype = markup.escape(credtype)
                target_logger.success(
                    f"Captured {credtype} {head_text}{full_name} from {client_address}:",
                    host=hostname or client_address,
                    locked=True,
                )
                if username != _NO_USER:
                    target_logger.highlight(
                        f"{credtype} Username: {username_text}",
                        host=hostname or client_address,
                        locked=True,
                    )

                target_logger.highlight(
                    (
                        f"{credtype} {text}: {markup.escape(password)}"
                        if not custom
                        else f"{credtype}: {markup.escape(password)}"
                    ),
                    host=hostname or client_address,
                    locked=True,
                )
                if extras:
                    target_logger.highlight(
                        f"{credtype} Extras:",
                        host=hostname or client_address,
                        locked=True,
                    )

                for name, value in (extras or {}).items():
                    target_logger.highlight(
                        f"  {name}: {markup.escape(value)}",
                        host=hostname or client_address,
                        locked=True,
                    )

        else:
            target_logger.highlight(
                f"Skipping previously captured {credtype} {text} for {full_name} from {client_address}",
                host=hostname or client_address,
            )
