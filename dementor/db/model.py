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
# pyright: reportUnusedCallResult=false, reportAny=false, reportExplicitAny=false, reportPrivateUsage=false
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
from dementor.db import _CLEARTEXT, _NO_USER, normalize_client_address
from dementor.log.logger import dm_logger
from dementor.log import dm_console_lock
from dementor.log.stream import log_to


_T = TypeVar("_T")


class ModelBase(DeclarativeBase):
    """
    Base class for all ORM models.

    It exists solely to give a common ``metadata`` object that can be used
    for ``create_all`` / ``drop_all`` calls.
    """

    pass


class HostInfo(ModelBase):
    """Stores basic host information from network scans.

    Each row represents a unique IP address with optional hostname and domain.

    :param id: Primary key (auto-incremented).
    :type id: int
    :param ip: IPv4/IPv6 address in normalized form (e.g., `192.168.1.1` or `2001:db8::1`).
    :type ip: str
    :param hostname: Resolved hostname (if available).
    :type hostname: str | None
    :param domain: Domain name associated with the host (e.g., `corp.local`).
    :type domain: str | None
    """

    __tablename__: str = "hosts"

    id: Mapped[int] = mapped_column(primary_key=True)
    ip: Mapped[str] = mapped_column(Text, nullable=False)
    hostname: Mapped[str] = mapped_column(Text, nullable=True)
    domain: Mapped[str] = mapped_column(Text, nullable=True)


class HostExtra(ModelBase):
    """Stores additional metadata about hosts (key-value pairs).

    Used for storing OS fingerprints, open ports, services, etc., associated with a `HostInfo`.

    :param id: Primary key.
    :type id: int
    :param host: Foreign key to `HostInfo.id`.
    :type host: int
    :param key: Metadata key (e.g., "os", "service").
    :type key: str
    :param value: Metadata value.
    :type value: str
    """

    __tablename__: str = "extras"

    id: Mapped[int] = mapped_column(primary_key=True)
    host: Mapped[int] = mapped_column(ForeignKey("hosts.id"))
    key: Mapped[str] = mapped_column(Text, nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)


class Credential(ModelBase):
    """Stores captured authentication credentials.

    Each row represents a unique credential (username/password or hash) captured during a session.

    :param id: Primary key.
    :type id: int
    :param timestamp: ISO-formatted datetime string of capture.
    :type timestamp: str
    :param protocol: Protocol used (e.g., `smb`, `rdp`, `ssh`).
    :type protocol: str
    :param credtype: Type of credential (`"Cleartext"` or hash type like `"ntlm"`, `"sha256"`).
    :type credtype: str
    :param client: Client address and port as `IP:PORT`.
    :type client: str
    :param host: Foreign key to `HostInfo.id`.
    :type host: int
    :param hostname: Hostname associated with credential (denormalized for performance).
    :type hostname: str | None
    :param domain: Domain name associated with credential.
    :type domain: str | None
    :param username: Username (lowercased for case-insensitive matching).
    :type username: str
    :param password: Plaintext password or hash value.
    :type password: str | None
    """

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
    """Thread-safe wrapper around SQLAlchemy engine for Dementor's database operations.

    Manages ORM sessions, locks, and schema initialization. Provides high-level methods
    for adding hosts, extras, and credentials while handling duplicates and logging.
    """

    def __init__(self, engine: Engine, config: "SessionConfig") -> None:
        self.db_engine: Engine = engine
        self.db_path: str = str(engine.url.database)
        self.metadata: MetaData = ModelBase.metadata
        self.config: "SessionConfig" = config

        # Ensure tables exist; any problem is reported immediately.
        with self.db_engine.connect():
            try:
                self.metadata.create_all(self.db_engine, checkfirst=True)
            except (NoSuchTableError, NoInspectionAvailable) as exc:
                dm_logger.error(f"Failed to connect to database {self.db_path}! {exc}")
                raise

        session_factory = sessionmaker(bind=self.db_engine, expire_on_commit=True)
        self.session: Session = scoped_session(session_factory)()
        self.lock: threading.Lock = threading.Lock()

    # --------------------------------------------------------------------- #
    # Low-level helpers
    # --------------------------------------------------------------------- #
    def close(self) -> None:
        """Close the underlying SQLAlchemy session."""
        self.session.close()

    def _execute(self, q: TypedReturnsRows[tuple[_T]]) -> ScalarResult[_T] | None:
        """Execute a SQLAlchemy query and handle common operational errors.

        :param q: SQLAlchemy query object.
        :type q: Select | Insert | Update | Delete
        :return: Query result or `None` if error occurred.
        :rtype: Any
        """
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
        """Commit the current transaction and handle schema-related errors."""
        try:
            self.session.commit()
        except OperationalError as e:
            if "no such column" in str(e).lower():
                dm_logger.error(
                    "Could not execute SQL - you are probably using an outdated Dementor.db"
                )
            else:
                raise e

    # --------------------------------------------------------------------- #
    # Public CRUD-style helpers
    # --------------------------------------------------------------------- #
    def add_host(
        self,
        ip: str,
        hostname: str | None = None,
        domain: str | None = None,
        extras: dict[str, str] | None = None,
    ) -> HostInfo | None:
        """
        Insert a host row if it does not already exist.

        The method is *idempotent*: calling it repeatedly with the same
        ``ip`` will never create duplicate rows; instead the existing row
        is updated with any newly supplied ``hostname``/``domain`` values.

        :param ip: IPv4/IPv6 address of the host.
        :type ip: str
        :param hostname: Optional human-readable hostname.
        :type hostname: str | None, optional
        :param domain: Optional DNS domain.
        :type domain: str | None, optional
        :param extras: Optional mapping of extra key/value attributes.
        :type extras: Mapping[str, str] | None, optional
        :return: The persisted :class:`HostInfo` object or ``None`` on failure.
        :rtype: HostInfo | None
        """
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
        """
        Store an arbitrary extra attribute for a host.

        ``extras`` are stored in a separate table to keep the ``hosts`` row
        small and to allow multiple values per host.

        :param host_id: Primary key of the target ``HostInfo``.
        :type host_id: int
        :param key: Attribute name.
        :type key: str
        :param value: Attribute value.
        :type value: str
        :param no_lock: Skip acquiring lock if `True` (internal use).
        :type no_lock: bool, optional
        """
        if not no_lock:
            self.lock.acquire()
        try:
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
                # REVISIT:
                values: list[str] = json.loads(extra.value)
                values.append(value)
                extra.value = json.dumps(values)
        finally:
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
        extras: dict[str, str] | None = None,
        custom: bool = False,
    ) -> None:
        """
        Store a captured credential in the database and emit user-friendly logs.

        The method performs a duplicate-check (unless the global config
        ``db_duplicate_creds`` is ``True``) and respects read-only database
        mode.

        :param client: ``(ip, port)`` tuple of the remote endpoint.
        :type client: tuple[str, int]
        :param credtype: ``_CLEARTEXT`` for passwords or a hash algorithm name.
        :type credtype: str
        :param username: Username that was observed.
        :type username: str
        :param password: Password or hash value.
        :type password: str
        :param logger: Optional logger that provides a ``debug``/``success``/…
            interface; defaults to the global ``dm_logger``.
        :type logger: Any, optional
        :param protocol: Protocol name (e.g. ``"ssh"``); if omitted it is taken
            from ``logger.extra["protocol"]``.
        :type protocol: str | None, optional
        :param domain: Optional domain name associated with the credential.
        :type domain: str | None, optional
        :param hostname: Optional host name for the remote system.
        :type hostname: str | None, optional
        :param extras: Optional additional key/value data to store alongside
            the credential.
        :type extras: Mapping[str, str] | None, optional
        :param custom: When ``True`` the output omits the standard “Captured …”
            prefix (used for artificial credentials).
        :type custom: bool, optional
        """
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
            + f"{target_logger} | {protocol} | {domain} | {hostname} | {username} | {password}"
        )

        # Ensure the host exists (or create it) before linking the cred.
        host = self.add_host(client_address, hostname, domain)
        if host is None:
            return

        # Build the duplicate-check query (case-insensitive).
        q = sql.select(Credential).filter(
            sql.func.lower(Credential.domain) == sql.func.lower(domain or ""),
            sql.func.lower(Credential.username) == sql.func.lower(username),
            sql.func.lower(Credential.credtype) == sql.func.lower(credtype),
            sql.func.lower(Credential.protocol) == sql.func.lower(protocol),
        )
        result = self._execute(q)
        if result is None:
            return

        results = result.all()
        text = "Password" if credtype == _CLEARTEXT else "Hash"
        username_text = markup.escape(username)
        if len(str(username).strip()) == 0:
            username_text = "(blank)"

        # Human-readable part used in log messages.
        full_name = (
            f" for [b]{markup.escape(domain)}[/]/[b]{username_text}[/]"
            if domain
            else f" for [b]{username_text}[/]"
        )
        host_info: str | None = extras.pop("host_info") if extras else None
        if host_info:
            full_name += f" on [b]{markup.escape(host_info)}[/]"

        if not results or self.config.db_config.db_duplicate_creds:
            if credtype != _CLEARTEXT:
                log_to("hashes", type=credtype, value=password)

            cred = Credential(
                # REVISIT: replace with util.now()
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
                # Special handling for read-only SQLite databases.
                if "readonly database" in str(e).lower():
                    dm_logger.fail(
                        f"Failed to add {credtype} for {username} on {client_address}: "
                        + "Database is read-only! (maybe restart in sudo mode?)"
                    )
                else:
                    raise

            with dm_console_lock:
                head_text = text if not custom else ""
                credtype_esc = markup.escape(credtype)
                target_logger.success(
                    f"Captured {credtype_esc} {head_text}{full_name} from {client_address}:",
                    host=hostname or client_address,
                    locked=True,
                )
                if username != _NO_USER:
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
        else:
            # Credential already present - only emit a short notice.
            target_logger.highlight(
                f"Skipping previously captured {credtype} {text} for {full_name} from {client_address}",
                host=hostname or client_address,
            )
