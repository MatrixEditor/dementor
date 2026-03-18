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
"""ORM models and thread-safe database wrapper for Dementor.

Defines the three ORM tables (``hosts``, ``extras``, ``credentials``) and
the :class:`DementorDB` class that protocol handlers call to store captured
credentials.  All public methods are thread-safe via a combination of
:func:`~sqlalchemy.orm.scoped_session` (one session per thread) and a
:class:`threading.Lock` that serializes writes.
"""

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

    def __init__(self, engine: Engine, config: SessionConfig) -> None:
        """Initialise the database wrapper.

        Creates all ORM tables if they do not exist, sets up a
        :func:`~sqlalchemy.orm.scoped_session` registry for thread-local
        sessions, and allocates the write lock.

        :param engine: A configured SQLAlchemy engine (from :func:`init_engine`).
        :type engine: Engine
        :param config: The active session configuration.
        :type config: SessionConfig
        :raises NoSuchTableError: If table creation fails due to a schema issue.
        :raises NoInspectionAvailable: If the engine cannot be inspected.
        """
        self.db_engine: Engine = engine
        self.db_path: str = str(engine.url.database or ":memory:")
        self.metadata: MetaData = ModelBase.metadata
        self.config: SessionConfig = config

        # Verify DB connectivity and create tables on first run.
        # checkfirst=True avoids errors on subsequent starts.
        with self.db_engine.connect():
            try:
                self.metadata.create_all(self.db_engine, checkfirst=True)
            except (NoSuchTableError, NoInspectionAvailable) as exc:
                dm_logger.error(f"Failed to connect to database {self.db_path}! {exc}")
                raise

        # expire_on_commit=False: ORM objects keep their attributes after
        # _release() detaches them from the session.  Without this, accessing
        # host.id after _release() would raise a DetachedInstanceError.
        session_factory = sessionmaker(bind=self.db_engine, expire_on_commit=False)

        # Store the scoped_session *registry*, not a Session instance.
        # The .session property calls _scoped_session() to get the
        # thread-local Session on demand.  This is the fix for the original
        # concurrency bug where all threads shared one Session/connection.
        self._scoped_session: scoped_session[Session] = scoped_session(session_factory)

        # Serializes all DB writes.  Both the duplicate check and the INSERT
        # run inside this lock to prevent TOCTOU races.  Reads (TUI queries)
        # do not acquire it -- they get their own session via scoped_session.
        self.lock: threading.Lock = threading.Lock()

    @property
    def session(self) -> Session:
        """Return the thread-local session from the scoped_session registry.

        Each thread gets its own Session instance, preventing concurrent access
        to a shared database connection (which corrupts pymysql's packet
        sequence on MySQL/MariaDB backends).
        """
        return self._scoped_session()

    # --------------------------------------------------------------------- #
    # Low-level helpers
    # --------------------------------------------------------------------- #
    def close(self) -> None:
        """Close all thread-local sessions and dispose of the engine."""
        self._scoped_session.remove()
        self.db_engine.dispose()

    def _release(self) -> None:
        """Return this thread's DB connection to the pool.

        Called at the end of every public method so handler threads don't
        hold connections while doing non-DB work (SMB tree-connect, logoff,
        Rich rendering, etc.).  The scoped_session transparently creates a
        fresh session on next access.
        """
        # remove() does close() + clears the thread-local registry entry.
        # Plain close() would leave a stale registry entry that prevents the
        # pool from reclaiming the connection when the thread dies.
        self._scoped_session.remove()

    def _handle_db_error(self, exc: OperationalError) -> None:
        """Rollback and handle common OperationalError patterns.

        Detects outdated schema errors (``no such column``) and logs a
        user-friendly message instead of crashing.  All other
        OperationalErrors are re-raised after rollback.

        :param exc: The caught OperationalError.
        :type exc: OperationalError
        :raises OperationalError: If the error is not a known schema issue.
        """
        self.session.rollback()
        if "no such column" in str(exc).lower():
            dm_logger.error(
                "Could not execute SQL - you are probably using an outdated Dementor.db"
            )
        else:
            raise exc

    def _execute(self, q: TypedReturnsRows[tuple[_T]]) -> ScalarResult[_T] | None:
        """Execute a SQLAlchemy query and handle common operational errors.

        Catches :class:`OperationalError` (schema mismatch),
        :class:`PoolTimeoutError` (pool exhaustion), and generic exceptions,
        rolling back the session in each case so subsequent operations are
        not poisoned.

        :param q: A SQLAlchemy selectable (e.g. from :func:`sqlalchemy.sql.select`).
        :type q: TypedReturnsRows[tuple[_T]]
        :return: Scalar result set, or ``None`` if a recoverable error occurred.
        :rtype: ScalarResult[_T] | None
        """
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
        """Commit the current transaction and handle schema-related errors."""
        try:
            self.session.commit()
        except OperationalError as exc:
            self._handle_db_error(exc)
        except Exception:
            self.session.rollback()
            raise

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
        # try/finally guarantees _release() runs even if an exception
        # propagates, so we never leak a DB connection from this thread.
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
        """Store an arbitrary extra attribute for a host.

        Values are stored as a JSON array in the ``extras`` table.  If the
        key already exists for the given host, the new value is appended to
        the array; otherwise a new row is created.

        :param host_id: Primary key of the target :class:`HostInfo`.
        :type host_id: int
        :param key: Attribute name (e.g. ``"os"``, ``"service"``).
        :type key: str
        :param value: Attribute value to store or append.
        :type value: str
        :param _locked: When ``True``, the caller already holds ``self.lock``
            (internal use by :meth:`add_host`), defaults to ``False``.
        :type _locked: bool, optional
        """
        # When called from add_host() the lock is already held, so we use
        # nullcontext() as a no-op context manager to avoid a deadlock.
        # When called standalone (e.g. from a protocol handler), we acquire
        # the real lock to serialize the read-modify-write on the JSON array.
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
        """Check if a credential with the same key fields already exists.

        The comparison is case-insensitive on all four fields.  Must be
        called while ``self.lock`` is held to prevent a TOCTOU race with
        the subsequent INSERT.

        :param protocol: Protocol name (e.g. ``"smb"``).
        :type protocol: str
        :param credtype: Credential type (e.g. ``"NetNTLMv2"``).
        :type credtype: str
        :param username: Username to match.
        :type username: str
        :param domain: Domain to match, or ``None`` (matches empty string).
        :type domain: str | None
        :return: ``True`` if a duplicate exists, ``False`` otherwise.
            Returns ``True`` on DB error to avoid silent data loss.
        :rtype: bool
        """
        q = sql.select(Credential).filter(
            sql.func.lower(Credential.domain) == sql.func.lower(domain or ""),
            sql.func.lower(Credential.username) == sql.func.lower(username),
            sql.func.lower(Credential.credtype) == sql.func.lower(credtype),
            sql.func.lower(Credential.protocol) == sql.func.lower(protocol),
        )
        result = self._execute(q)
        if result is None:
            return True  # DB error -- treat as exists to avoid silent data loss
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
        """Emit user-facing log messages for a captured or skipped credential.

        For new captures, acquires :data:`dm_console_lock` and emits a
        multi-line Rich-formatted block (type, username, hash/password,
        extras).  For duplicates, emits a single "Skipping" line.

        :param target_logger: Logger instance with ``success``/``highlight``
            methods (typically a :class:`ProtocolLogger`).
        :type target_logger: Any
        :param credtype: Credential type label (e.g. ``"NetNTLMv2"``).
        :type credtype: str
        :param username: Captured username.
        :type username: str
        :param password: Captured password or hashcat-formatted hash line.
        :type password: str
        :param domain: Domain name, or ``None``.
        :type domain: str | None
        :param hostname: Hostname of the remote system, or ``None``.
        :type hostname: str | None
        :param client_address: Normalized client IP address.
        :type client_address: str
        :param extras: Additional key-value metadata to display, or ``None``.
        :type extras: dict[str, str] | None
        :param host_info: Human-readable host description for the display
            line (e.g. ``"Windows 10 Build 19041 (name: WS01)"``), or ``None``.
        :type host_info: str | None
        :param custom: When ``True``, omit the "Hash"/"Password" label from
            the success line (used for non-standard credential types).
        :type custom: bool
        :param is_duplicate: When ``True``, only emit the "Skipping" line.
        :type is_duplicate: bool
        """
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
                f" for {full_name} from {client_address}",
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
        """Store a captured credential in the database and emit user-friendly logs.

        The duplicate check and INSERT are atomic (both inside ``self.lock``)
        to prevent race conditions.  Display logging only runs after a
        successful DB write.  The connection is released via :meth:`_release`
        in a ``finally`` block so handler threads never leak connections.

        :param client: ``(ip, port)`` tuple of the remote endpoint.
        :type client: tuple[str, int]
        :param credtype: ``CLEARTEXT`` for passwords, or a hash algorithm
            name like ``"NetNTLMv2"``.
        :type credtype: str
        :param username: Username that was observed.
        :type username: str
        :param password: Password or hashcat-formatted hash line.
        :type password: str
        :param logger: Protocol logger with ``success``/``highlight``
            methods.  When ``None``, ``protocol`` must be supplied
            explicitly, defaults to ``None``.
        :type logger: Any, optional
        :param protocol: Protocol name (e.g. ``"smb"``).  When ``None``,
            it is read from ``logger.extra["protocol"]``, defaults to ``None``.
        :type protocol: str | None, optional
        :param domain: Domain name associated with the credential,
            defaults to ``None``.
        :type domain: str | None, optional
        :param hostname: Hostname of the remote system,
            defaults to ``None``.
        :type hostname: str | None, optional
        :param extras: Additional key-value metadata to store alongside
            the credential.  The special key :data:`HOST_INFO` is popped
            for display only, defaults to ``None``.
        :type extras: dict[str, str] | None, optional
        :param custom: When ``True``, omit the "Hash"/"Password" label
            from the success log line (used for non-standard credential
            types), defaults to ``False``.
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
            f"{target_logger} | {protocol} | {domain} | {hostname} | {username} | {password}"
        )

        # Ensure the host exists (or create it) before linking the cred.
        # add_host() releases its own connection via _release().
        host = self.add_host(client_address, hostname, domain)
        if host is None:
            return

        # Pop host_info from extras before DB storage.
        host_info: str | None = extras.pop(HOST_INFO, None) if extras else None

        # --- Phase 1: critical section (duplicate check + insert) ---
        # Both operations must be inside the same lock acquisition to prevent
        # a TOCTOU race where two threads both pass the duplicate check and
        # both insert.  This was the original race condition bug.
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
                        # Pool is temporarily full.  The hash was already
                        # written to the file stream (log_to above), so
                        # we just skip the DB insert rather than crashing.
                        dm_logger.warning(
                            f"Database pool exhausted; dropped {credtype} "
                            f"for {username} on {client_address}"
                        )
                    except OperationalError as e:
                        # Rollback so the session isn't left in a broken
                        # state (which would cause PendingRollbackError
                        # on every subsequent operation from this thread).
                        self.session.rollback()
                        if "readonly database" in str(e).lower():
                            dm_logger.fail(
                                f"Failed to add {credtype} for {username} on "
                                f"{client_address}: Database is read-only! "
                                "(maybe restart in sudo mode?)"
                            )
                        else:
                            raise
        finally:
            self._release()

        # --- Phase 2: display logging OUTSIDE the DB lock ---
        # Rich rendering is slow; holding the lock during it would block
        # all other handler threads from writing to the database.
        # Only log if the write actually succeeded (db_write_ok) or if
        # we're reporting a duplicate skip -- never on write failure.
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
