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
# pyright: reportUnusedCallResult=false
import datetime
import threading

from typing import Any
from rich import markup
from sqlalchemy.exc import NoInspectionAvailable, NoSuchTableError, OperationalError
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    scoped_session,
    sessionmaker,
)
from sqlalchemy import Engine, ForeignKey, Text, sql


from dementor.db import _CLEARTEXT, _NO_USER, normalize_client_address
from dementor.log.logger import dm_logger
from dementor.log import dm_console_lock
from dementor.log.stream import log_to


class ModelBase(DeclarativeBase):
    pass


class HostInfo(ModelBase):
    __tablename__ = "hosts"

    id: Mapped[int] = mapped_column(primary_key=True)
    ip: Mapped[str] = mapped_column(Text, nullable=False)
    hostname: Mapped[str] = mapped_column(Text, nullable=True)
    domain: Mapped[str] = mapped_column(Text, nullable=True)


class HostExtra(ModelBase):
    __tablename__ = "extras"

    id: Mapped[int] = mapped_column(primary_key=True)
    host: Mapped[int] = mapped_column(ForeignKey("hosts.id"))
    key: Mapped[str] = mapped_column(Text, nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)


class Credential(ModelBase):
    __tablename__ = "credentials"

    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[str] = mapped_column(Text, nullable=False)
    protocol: Mapped[str] = mapped_column(Text, nullable=False)
    credtype: Mapped[str] = mapped_column(Text, nullable=False)
    client: Mapped[str] = mapped_column(Text, nullable=False)
    host: Mapped[int] = mapped_column(ForeignKey("hosts.id"))
    hostname: Mapped[str] = mapped_column(Text, nullable=True)
    domain: Mapped[str] = mapped_column(Text, nullable=True)
    username: Mapped[str] = mapped_column(Text, nullable=False)
    password: Mapped[str] = mapped_column(Text, nullable=True)


class DementorDB:
    def __init__(self, engine: Engine, config) -> None:
        self.db_engine = engine
        self.db_path = engine.url.database
        self.metadata = ModelBase.metadata
        self.config = config
        with self.db_engine.connect():
            try:
                self.metadata.create_all(self.db_engine, checkfirst=True)
            except (NoSuchTableError, NoInspectionAvailable):
                dm_logger.error(f"Failed to connect to database {self.db_path}!")
                raise

        session_factory = sessionmaker(bind=self.db_engine, expire_on_commit=True)
        session_ty = scoped_session(session_factory)

        self.session = session_ty()
        self.lock = threading.Lock()

    def close(self) -> None:
        self.session.close()

    def _execute(self, q):
        try:
            return self.session.scalars(q)
        except OperationalError as e:
            if "no such column" in str(e).lower():
                dm_logger.error(
                    "Could not execute SQL - you are probably using an outdated Dementor.db"
                )
            else:
                raise e

    def commit(self):
        try:
            self.session.commit()
        except OperationalError as e:
            if "no such column" in str(e).lower():
                dm_logger.error(
                    "Could not execute SQL - you are probably using an outdated Dementor.db"
                )
            else:
                raise e

    def add_host(
        self,
        ip: str,
        hostname: str | None = None,
        domain: str | None = None,
        extras: dict[str, str] | None = None,
    ) -> HostInfo | None:
        with self.lock:
            q = sql.select(HostInfo).where(HostInfo.ip == ip)
            result = self._execute(q)
            if result is None:
                return None

            host = result.one_or_none()
            if not host:
                host = HostInfo(ip=ip, hostname=hostname, domain=domain)
                self.session.add(host)
                self.commit()
            else:
                host.domain = host.domain or domain or ""
                host.hostname = host.hostname or hostname or ""
                self.commit()

            if extras:
                for key, value in extras.items():
                    self.add_host_extra(host.id, key, value, no_lock=True)
            return host

    def add_host_extra(
        self, host_id: int, key: str, value: str, no_lock: bool = False
    ) -> None:
        if not no_lock:
            self.lock.acquire()

        q = sql.select(HostExtra).where(HostExtra.host == host_id, HostExtra.key == key)
        result = self._execute(q)
        if result is None:
            return

        extra = result.one_or_none()
        if not extra:
            extra = HostExtra(host=host_id, key=key, value=value)
            self.session.add(extra)
            self.commit()
        else:
            extra.value = f"{extra.value}\0{extra.value}"

        if not no_lock:
            self.lock.release()

    def add_auth(
        self,
        client: tuple[str, int],
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
                + "Protocol must be present either in the logger or as a parameter!"
            )
            return

        target_logger = logger or dm_logger
        protocol = str(protocol or logger.extra["protocol"])
        client_address, port, *_ = client
        client_address = normalize_client_address(client_address)

        target_logger.debug(
            f"Adding {credtype} for {username} on {client_address}: "
            + f"{logger} | {protocol} | {domain} | {hostname} | {username} | {password}"
        )

        host = self.add_host(client_address, hostname, domain)
        q = sql.select(Credential).filter(
            sql.func.lower(Credential.domain) == sql.func.lower(domain or ""),
            sql.func.lower(Credential.username) == sql.func.lower(username),
            sql.func.lower(Credential.credtype) == sql.func.lower(credtype),
            sql.func.lower(Credential.protocol) == sql.func.lower(protocol),
        )
        result = self._execute(q)
        if result is None or host is None:
            return

        results = result.all()
        text = "Password" if credtype == _CLEARTEXT else "Hash"
        username_text = markup.escape(username)
        is_blank = len(str(username).strip()) == 0
        if is_blank:
            username_text = "(blank)"

        full_name = (
            f" for [b]{markup.escape(domain)}[/]/[b]{username_text}[/]"
            if domain
            else f" for [b]{username_text}[/]"
        )
        if is_blank:
            full_name = ""

        if not results or self.config.db_config.db_duplicate_creds:
            if credtype != _CLEARTEXT:
                log_to("hashes", type=credtype, value=password)
            # just insert a new row
            cred = Credential(
                timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                protocol=protocol.lower(),
                credtype=credtype.lower(),
                client=f"{client_address}:{port}",
                hostname=hostname or "",
                domain=(domain or "").lower(),
                username=username.lower(),
                password=password,
                host=host.id,
            )
            try:
                with self.lock:
                    self.session.add(cred)
                    self.session.commit()
            except OperationalError as e:
                # attempt to write on a read-only database
                if "readonly database" in str(e):
                    dm_logger.fail(
                        f"Failed to add {credtype} for {username} on {client_address}: "
                        + "Database is read-only! (maybe restart in sudo mode?)"
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
