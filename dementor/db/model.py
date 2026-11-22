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
# pyright: reportUnusedCallResult=false, reportAny=false, reportExplicitAny=false
import contextlib
import datetime
import json
import threading

from typing import Any, TypeVar

from rich import markup
from sqlalchemy import Engine, ForeignKey, MetaData, ScalarResult, Text, sql
from sqlalchemy.exc import (
    NoInspectionAvailable,
    NoSuchTableError,
    OperationalError,
    TimeoutError as PoolTimeoutError,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    scoped_session,
    sessionmaker,
    Session,
)
from sqlalchemy.sql.selectable import TypedReturnsRows

from dementor.config.session import SessionConfig
from dementor.db import (
    CLEARTEXT,
    HOST_INFO,
    NO_USER,
    normalize_client_address,
)
from dementor.log.logger import dm_logger
from dementor.log import dm_console_lock
from dementor.log.stream import log_to


_T = TypeVar("_T")


class ModelBase(DeclarativeBase):
    """Base class for all ORM models."""


class HostInfo(ModelBase):
    __tablename__: str = "hosts"

    id: Mapped[int] = mapped_column(primary_key=True)
    ip: Mapped[str] = mapped_column(Text, nullable=False)
    hostname: Mapped[str] = mapped_column(Text, nullable=True)
    domain: Mapped[str] = mapped_column(Text, nullable=True)


class HostExtra(ModelBase):
    __tablename__: str = "extras"

    id: Mapped[int] = mapped_column(primary_key=True)
    host: Mapped[int] = mapped_column(ForeignKey("hosts.id"))
    key: Mapped[str] = mapped_column(Text, nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)


class Credential(ModelBase):
    __tablename__: str = "credentials"

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
    def __init__(self, engine: Engine, config: SessionConfig) -> None:
        self.db_engine: Engine = engine
        self.db_path: str = str(engine.url.database or ":memory:")
        self.metadata: MetaData = ModelBase.metadata
        self.config: SessionConfig = config

        with self.db_engine.connect():
            try:
                self.metadata.create_all(self.db_engine, checkfirst=True)
            except (NoSuchTableError, NoInspectionAvailable) as exc:
                dm_logger.error(f"Failed to connect to database {self.db_path}! {exc}")
                raise

        session_factory = sessionmaker(bind=self.db_engine, expire_on_commit=False)
        self._scoped_session: scoped_session[Session] = scoped_session(session_factory)
        self.lock: threading.Lock = threading.Lock()

    @property
    def session(self) -> Session:
        return self._scoped_session()

    def close(self) -> None:
        self._scoped_session.remove()
        self.db_engine.dispose()

    def _release(self) -> None:
        self._scoped_session.remove()

    def _handle_db_error(self, exc: OperationalError) -> None:
        self.session.rollback()
        if "no such column" in str(exc).lower():
            dm_logger.error(
                "Could not execute SQL - you are probably using an outdated Dementor.db"
            )
        else:
            raise exc

    def _execute(self, q: TypedReturnsRows[tuple[_T]]) -> ScalarResult[_T] | None:
        try:
            return self.session.scalars(q)
        except OperationalError as exc:
            self._handle_db_error(exc)
            return None
        except PoolTimeoutError:
            dm_logger.warning("Database connection pool exhausted; skipping query")
            return None
        except Exception:
            self.session.rollback()
            raise

    def commit(self) -> None:
        try:
            self.session.commit()
        except OperationalError as exc:
            self._handle_db_error(exc)
        except Exception:
            self.session.rollback()
            raise

    def add_host(
        self,
        ip: str,
        hostname: str | None = None,
        domain: str | None = None,
        extras: dict[str, str] | None = None,
    ) -> HostInfo | None:
        """Insert a host row if it does not already exist."""
        try:
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
                    # Preserve existing values; only fill missing data.
                    new_domain = host.domain or domain or ""
                    new_hostname = host.hostname or hostname or ""
                    if host.domain != new_domain or host.hostname != new_hostname:
                        host.domain = new_domain
                        host.hostname = new_hostname
                        self.commit()

                if extras:
                    for key, value in extras.items():
                        self.add_host_extra(host.id, key, value, _locked=True)
                return host
        finally:
            self._release()

    def add_host_extra(
        self, host_id: int, key: str, value: str, *, _locked: bool = False
    ) -> None:
        """Store an arbitrary extra attribute for a host."""
        lock: threading.Lock | contextlib.nullcontext[None] = (
            contextlib.nullcontext() if _locked else self.lock
        )
        with lock:
            q = sql.select(HostExtra).where(
                HostExtra.host == host_id, HostExtra.key == key
            )
            result = self._execute(q)
            if result is None:
                return
            extra = result.one_or_none()
            if not extra:
                extra = HostExtra(host=host_id, key=key, value=json.dumps([str(value)]))
                self.session.add(extra)
                self.commit()
            else:
                values: list[str] = json.loads(extra.value)
                values.append(value)
                extra.value = json.dumps(values)
                self.commit()

    # --------------------------------------------------------------------- #
    # Credential capture
    # --------------------------------------------------------------------- #
    def _check_duplicate(
        self,
        protocol: str,
        credtype: str,
        username: str,
        domain: str | None,
    ) -> bool:
        q = sql.select(Credential).filter(
            sql.func.lower(Credential.domain) == sql.func.lower(domain or ""),
            sql.func.lower(Credential.username) == sql.func.lower(username),
            sql.func.lower(Credential.credtype) == sql.func.lower(credtype),
            sql.func.lower(Credential.protocol) == sql.func.lower(protocol),
        )
        result = self._execute(q)
        if result is None:
            return True
        return len(result.all()) > 0

    def _log_credential(
        self,
        target_logger: Any,
        credtype: str,
        username: str,
        password: str,
        domain: str | None,
        hostname: str | None,
        client_address: str,
        extras: dict[str, str] | None,
        host_info: str | None,
        custom: bool,
        *,
        is_duplicate: bool,
    ) -> None:
        text = "Password" if credtype == CLEARTEXT else "Hash"
        username_text = markup.escape(username)
        if not str(username).strip():
            username_text = "(blank)"

        full_name = (
            f" for [b]{markup.escape(domain)}[/]/[b]{username_text}[/]"
            if domain
            else f" for [b]{username_text}[/]"
        )
        if host_info:
            full_name += f" on [b]{markup.escape(host_info)}[/]"

        if is_duplicate:
            target_logger.highlight(
                f"Skipping previously captured {credtype} {text}"
                + f" for {full_name} from {client_address}",
                host=hostname or client_address,
            )
            return

        with dm_console_lock:
            head_text = text if not custom else ""
            credtype_esc = markup.escape(credtype)
            target_logger.success(
                f"Captured {credtype_esc} {head_text}{full_name} from {client_address}:",
                host=hostname or client_address,
                locked=True,
            )
            if username != NO_USER:
                target_logger.highlight(
                    f"{credtype_esc} Username: {username_text}",
                    host=hostname or client_address,
                    locked=True,
                )
            target_logger.highlight(
                (
                    f"{credtype_esc} {text}: {markup.escape(password)}"
                    if not custom
                    else f"{credtype_esc}: {markup.escape(password)}"
                ),
                host=hostname or client_address,
                locked=True,
            )
            if extras:
                target_logger.highlight(
                    f"{credtype_esc} Extras:",
                    host=hostname or client_address,
                    locked=True,
                )
                for name, value in extras.items():
                    target_logger.highlight(
                        f"  {name}: {markup.escape(value)}",
                        host=hostname or client_address,
                        locked=True,
                    )

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
        extras: dict[str, str] | None = None,
        custom: bool = False,
    ) -> None:
        """Store a captured credential in the database and emit user-friendly logs."""
        if not logger and not protocol:
            dm_logger.error(
                f"Failed to add {credtype} for {username} on {client[0]}:{client[1]}: "
                + "Protocol must be present either in the logger or as a parameter!"
            )
            return

        target_logger = logger or dm_logger
        protocol = str(protocol or getattr(logger, "extra", {}).get("protocol", ""))
        client_address, port, *_ = client
        client_address = normalize_client_address(client_address)

        target_logger.debug(
            f"Adding {credtype} for {username} on {client_address}: "
            f"{target_logger} | {protocol} | {domain} | {hostname} | {username} | {password}"
        )

        host = self.add_host(client_address, hostname, domain)
        if host is None:
            return

        host_info: str | None = extras.pop(HOST_INFO, None) if extras else None
        db_write_ok = False
        is_duplicate = False
        allow_dupes = self.config.db_config.db_duplicate_creds

        try:
            with self.lock:
                is_duplicate = not allow_dupes and self._check_duplicate(
                    protocol, credtype, username, domain
                )

                if not is_duplicate:
                    if credtype != CLEARTEXT:
                        log_to("hashes", type=credtype, value=password)

                    cred = Credential(
                        timestamp=datetime.datetime.now(tz=datetime.UTC).strftime(
                            "%Y-%m-%d %H:%M:%S"
                        ),
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
                        self.session.add(cred)
                        self.session.commit()
                        db_write_ok = True
                    except PoolTimeoutError:
                        dm_logger.warning(
                            f"Database pool exhausted; dropped {credtype} "
                            + f"for {username} on {client_address}"
                        )
                    except OperationalError as e:
                        self.session.rollback()
                        if "readonly database" in str(e).lower():
                            dm_logger.fail(
                                f"Failed to add {credtype} for {username} on "
                                + f"{client_address}: Database is read-only! "
                                + "(maybe restart in sudo mode?)"
                            )
                        else:
                            raise
        finally:
            self._release()

        if is_duplicate:
            self._log_credential(
                target_logger,
                credtype,
                username,
                password,
                domain,
                hostname,
                client_address,
                extras,
                host_info,
                custom,
                is_duplicate=True,
            )
        elif db_write_ok:
            self._log_credential(
                target_logger,
                credtype,
                username,
                password,
                domain,
                hostname,
                client_address,
                extras,
                host_info,
                custom,
                is_duplicate=False,
            )
