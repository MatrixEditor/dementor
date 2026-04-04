# ruff: noqa: S105, S106
"""Comprehensive test suite for dementor.db (__init__, connector, model).

All tests use SQLite :memory: with StaticPool -- no external DB required.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from sqlalchemy import create_engine, inspect, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.pool import StaticPool

import dementor.db as db_module
from dementor.db import (
    CLEARTEXT,
    HOST_INFO,
    NO_USER,
    _CLEARTEXT,
    _HOST_INFO,
    _NO_USER,
    normalize_client_address,
)
from dementor.db.connector import DatabaseConfig, create_db, init_engine
from dementor.db.model import (
    Credential,
    DementorDB,
    HostExtra,
    HostInfo,
)


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def engine():
    """In-memory SQLite engine shared across threads via StaticPool."""
    return create_engine(
        "sqlite+pysqlite:///:memory:",
        isolation_level="AUTOCOMMIT",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )


@pytest.fixture
def config():
    """Mock SessionConfig with DuplicateCreds=False."""
    cfg = MagicMock()
    cfg.db_config.db_duplicate_creds = False
    return cfg


@pytest.fixture
def config_dupes():
    """Mock SessionConfig with DuplicateCreds=True."""
    cfg = MagicMock()
    cfg.db_config.db_duplicate_creds = True
    return cfg


@pytest.fixture
def db(engine, config):
    """DementorDB with dedup enabled."""
    d = DementorDB(engine, config)
    yield d
    d.close()


@pytest.fixture
def db_dupes(engine, config_dupes):
    """DementorDB with DuplicateCreds=True."""
    d = DementorDB(engine, config_dupes)
    yield d
    d.close()


@pytest.fixture
def logger():
    """Mock logger with protocol=SMB."""
    lg = MagicMock()
    lg.extra = {"protocol": "SMB"}
    return lg


# ===================================================================
# __init__.py
# ===================================================================
class TestConstantValues:
    def test_cleartext(self) -> None:
        assert CLEARTEXT == "Cleartext"

    def test_no_user(self) -> None:
        assert NO_USER == "<missing-user>"

    def test_host_info(self) -> None:
        assert HOST_INFO == "_host_info"


class TestConstantAliases:
    def test_cleartext_alias_identity(self) -> None:
        assert _CLEARTEXT is CLEARTEXT

    def test_no_user_alias_identity(self) -> None:
        assert _NO_USER is NO_USER

    def test_host_info_alias_identity(self) -> None:
        assert _HOST_INFO is HOST_INFO


class TestAllExports:
    def test_all_contains_public_names(self) -> None:

        assert "CLEARTEXT" in db_module.__all__
        assert "NO_USER" in db_module.__all__
        assert "HOST_INFO" in db_module.__all__
        assert "normalize_client_address" in db_module.__all__

    def test_all_does_not_contain_aliases(self) -> None:

        assert "_CLEARTEXT" not in db_module.__all__
        assert "_NO_USER" not in db_module.__all__
        assert "_HOST_INFO" not in db_module.__all__


class TestNormalizeClientAddress:
    def test_strips_ipv6_mapped_v4(self) -> None:
        assert normalize_client_address("::ffff:192.168.1.1") == "192.168.1.1"

    def test_strips_ipv6_mapped_private(self) -> None:
        assert normalize_client_address("::ffff:10.0.0.50") == "10.0.0.50"

    def test_leaves_plain_ipv4(self) -> None:
        assert normalize_client_address("10.0.0.1") == "10.0.0.1"

    def test_leaves_real_ipv6(self) -> None:
        assert normalize_client_address("2001:db8::1") == "2001:db8::1"

    def test_leaves_localhost(self) -> None:
        assert normalize_client_address("127.0.0.1") == "127.0.0.1"

    def test_empty_string(self) -> None:
        assert normalize_client_address("") == ""

    def test_only_prefix_itself(self) -> None:
        assert normalize_client_address("::ffff:") == ""


# ===================================================================
# connector.py  -- DatabaseConfig
# ===================================================================
class TestDatabaseConfig:
    def test_default_fields_from_empty_config(self) -> None:
        # Note: TomlConfig resolves defaults from the global Dementor.toml,
        # so db_duplicate_creds is True (set in shipped config).
        cfg = DatabaseConfig({})
        assert cfg.db_url is None
        assert cfg.db_path == "Dementor.db"
        # The shipped Dementor.toml sets DuplicateCreds = true
        assert cfg.db_duplicate_creds is True

    def test_code_default_duplicate_creds(self) -> None:
        # The Attribute default in code is False; this is overridden by TOML.
        field = next(
            f for f in DatabaseConfig._fields_ if f.attr_name == "db_duplicate_creds"
        )
        assert field.default_val is False

    def test_loads_url_from_dict(self) -> None:

        cfg = DatabaseConfig({"Url": "sqlite:///:memory:"})
        assert cfg.db_url == "sqlite:///:memory:"

    def test_loads_path_from_dict(self) -> None:

        cfg = DatabaseConfig({"Path": "custom.db"})
        assert cfg.db_path == "custom.db"

    def test_loads_duplicate_creds_from_dict(self) -> None:

        cfg = DatabaseConfig({"DuplicateCreds": True})
        assert cfg.db_duplicate_creds is True

    def test_section_name(self) -> None:

        assert DatabaseConfig._section_ == "DB"


# ===================================================================
# connector.py  -- init_engine
# ===================================================================
class TestInitEngine:
    def _make_session(
        self, *, db_url=None, db_path="Dementor.db", tmpdir=None
    ) -> MagicMock:
        session = MagicMock()
        session.db_config.db_url = db_url
        session.db_config.db_path = db_path
        if tmpdir:
            session.resolve_path.return_value = Path(tmpdir) / db_path
        else:
            session.resolve_path.return_value = Path(tempfile.gettempdir()) / db_path
        return session

    def test_sqlite_memory_returns_engine(self) -> None:

        session = self._make_session(db_path=":memory:")
        engine = init_engine(session)
        assert engine is not None
        assert "memory" in str(engine.url)
        engine.dispose()

    def test_sqlite_file_returns_engine(self) -> None:

        with tempfile.TemporaryDirectory() as tmpdir:
            session = self._make_session(db_path="test.db", tmpdir=tmpdir)
            engine = init_engine(session)
            assert engine is not None
            assert "test.db" in str(engine.url)
            engine.dispose()

    def test_sqlite_file_creates_directory(self) -> None:

        with tempfile.TemporaryDirectory() as tmpdir:
            subdir = os.path.join(tmpdir, "subdir")
            session = self._make_session(db_path="test.db")
            session.resolve_path.return_value = Path(subdir) / "test.db"
            engine = init_engine(session)
            assert engine is not None
            assert os.path.isdir(subdir)
            engine.dispose()

    def test_empty_path_returns_none(self) -> None:

        session = self._make_session(db_path="")
        result = init_engine(session)
        assert result is None

    def test_url_overrides_path(self) -> None:

        session = self._make_session(db_url="sqlite:///:memory:", db_path="ignored.db")
        engine = init_engine(session)
        assert engine is not None
        assert "memory" in str(engine.url)
        engine.dispose()

    def test_mysql_url_parsed(self) -> None:
        pytest.importorskip("pymysql")
        session = self._make_session(db_url="mysql+pymysql://user:pass@fakehost/fakedb")
        engine = init_engine(session)
        assert engine is not None
        assert engine.dialect.name == "mysql"
        engine.dispose()

    def test_url_without_driver(self) -> None:

        session = self._make_session(db_url="sqlite:///:memory:")
        engine = init_engine(session)
        assert engine is not None
        engine.dispose()


# ===================================================================
# connector.py  -- create_db
# ===================================================================
class TestCreateDb:
    def test_returns_dementor_db(self) -> None:

        session = MagicMock()
        session.db_config.db_url = None
        session.db_config.db_path = ":memory:"
        db = create_db(session)
        assert isinstance(db, DementorDB)
        db.close()

    def test_raises_on_engine_failure(self) -> None:

        session = MagicMock()
        session.db_config.db_url = None
        session.db_config.db_path = ""
        with pytest.raises(RuntimeError, match="Failed to create database engine"):
            create_db(session)


# ===================================================================
# model.py  -- DementorDB init / lifecycle
# ===================================================================
class TestDementorDBInit:
    def test_creates_all_three_tables(self, engine, config) -> None:
        db = DementorDB(engine, config)
        with engine.connect() as conn:
            tables = inspect(conn).get_table_names()
        assert "hosts" in tables
        assert "extras" in tables
        assert "credentials" in tables
        db.close()

    def test_db_path_memory(self, engine, config) -> None:
        db = DementorDB(engine, config)
        assert db.db_path == ":memory:"
        db.close()

    def test_db_path_file(self, config) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test.db")
            eng = create_engine(
                f"sqlite+pysqlite:///{path}", isolation_level="AUTOCOMMIT"
            )
            db = DementorDB(eng, config)
            assert db.db_path == path
            db.close()

    def test_stores_engine_reference(self, engine, config) -> None:
        db = DementorDB(engine, config)
        assert db.db_engine is engine
        db.close()

    def test_stores_config_reference(self, engine, config) -> None:
        db = DementorDB(engine, config)
        assert db.config is config
        db.close()

    def test_has_lock(self, db) -> None:
        assert isinstance(db.lock, type(threading.Lock()))


class TestSession:
    def test_returns_session_object(self, db) -> None:
        assert db.session is not None

    def test_same_session_in_same_thread(self, db) -> None:
        s1 = db.session
        s2 = db.session
        assert s1 is s2

    def test_different_session_per_thread(self, db) -> None:
        main_session = db.session
        other: list[object] = [None]

        def worker():
            other[0] = db.session

        t = threading.Thread(target=worker)
        t.start()
        t.join()
        assert other[0] is not main_session

    def test_new_session_after_release(self, db) -> None:
        s1 = db.session
        db._release()
        s2 = db.session
        assert s1 is not s2


class TestCloseAndRelease:
    def test_close_does_not_raise(self, engine, config) -> None:
        db = DementorDB(engine, config)
        db.close()

    def test_release_does_not_raise(self, db) -> None:
        _ = db.session
        db._release()

    def test_release_from_thread_is_isolated(self, db) -> None:
        errors: list[Exception] = []

        def worker():
            try:
                _ = db.session
                db._release()
            except Exception as e:
                errors.append(e)

        t = threading.Thread(target=worker)
        t.start()
        t.join()
        assert errors == []
        assert db.session is not None

    def test_session_works_after_release(self, db) -> None:
        db.add_host("1.2.3.4")
        # add_host calls _release internally
        host = db.add_host("1.2.3.4")
        assert host is not None


# ===================================================================
# model.py  -- add_host
# ===================================================================
class TestAddHost:
    def test_creates_new_host(self, db) -> None:
        host = db.add_host("10.0.0.1")
        assert host is not None
        assert host.ip == "10.0.0.1"
        assert host.id is not None

    def test_with_hostname(self, db) -> None:
        host = db.add_host("10.0.0.2", hostname="WS01")
        assert host is not None
        assert host.hostname == "WS01"

    def test_with_domain(self, db) -> None:
        host = db.add_host("10.0.0.3", domain="CORP")
        assert host is not None
        assert host.domain == "CORP"

    def test_with_hostname_and_domain(self, db) -> None:
        host = db.add_host("10.0.0.4", hostname="WS01", domain="CORP")
        assert host is not None
        assert host.hostname == "WS01"
        assert host.domain == "CORP"

    def test_idempotent_returns_same_id(self, db) -> None:
        h1 = db.add_host("10.0.0.5")
        h2 = db.add_host("10.0.0.5")
        assert h1 is not None
        assert h2 is not None
        assert h1.id == h2.id

    def test_fills_missing_hostname(self, db) -> None:
        db.add_host("10.0.0.6")
        h2 = db.add_host("10.0.0.6", hostname="LATE")
        assert h2 is not None
        assert h2.hostname == "LATE"

    def test_fills_missing_domain(self, db) -> None:
        db.add_host("10.0.0.7")
        h2 = db.add_host("10.0.0.7", domain="LATE")
        assert h2 is not None
        assert h2.domain == "LATE"

    def test_does_not_overwrite_existing_hostname(self, db) -> None:
        db.add_host("10.0.0.8", hostname="FIRST")
        h2 = db.add_host("10.0.0.8", hostname="SECOND")
        assert h2 is not None
        assert h2.hostname == "FIRST"

    def test_does_not_overwrite_existing_domain(self, db) -> None:
        db.add_host("10.0.0.9", domain="FIRST")
        h2 = db.add_host("10.0.0.9", domain="SECOND")
        assert h2 is not None
        assert h2.domain == "FIRST"

    def test_no_extras(self, db) -> None:
        host = db.add_host("10.0.0.10", extras=None)
        assert host is not None

    def test_empty_extras(self, db) -> None:
        host = db.add_host("10.0.0.11", extras={})
        assert host is not None

    def test_with_single_extra(self, db) -> None:
        host = db.add_host("10.0.0.12", extras={"os": "Win10"})
        assert host is not None
        result = db.session.scalars(
            select(HostExtra).where(HostExtra.host == host.id)
        ).all()
        db._release()
        assert len(result) == 1

    def test_with_multiple_extras(self, db) -> None:
        host = db.add_host("10.0.0.13", extras={"os": "Win10", "arch": "x64"})
        assert host is not None
        result = db.session.scalars(
            select(HostExtra).where(HostExtra.host == host.id)
        ).all()
        db._release()
        assert len(result) == 2

    def test_different_ips_create_different_hosts(self, db) -> None:
        h1 = db.add_host("10.0.0.14")
        h2 = db.add_host("10.0.0.15")
        assert h1 is not None
        assert h2 is not None
        assert h1.id != h2.id


# ===================================================================
# model.py  -- add_host_extra
# ===================================================================
class TestAddHostExtra:
    def test_creates_new_extra(self, db) -> None:
        host = db.add_host("10.0.0.20")
        assert host is not None
        db.add_host_extra(host.id, "service", "smb")
        result = db.session.scalars(
            select(HostExtra).where(HostExtra.host == host.id, HostExtra.key == "service")
        ).one()
        db._release()
        assert json.loads(result.value) == ["smb"]

    def test_appends_to_existing_key(self, db) -> None:
        host = db.add_host("10.0.0.21")
        assert host is not None
        db.add_host_extra(host.id, "port", "445")
        db.add_host_extra(host.id, "port", "139")
        result = db.session.scalars(
            select(HostExtra).where(HostExtra.host == host.id, HostExtra.key == "port")
        ).one()
        db._release()
        assert json.loads(result.value) == ["445", "139"]

    def test_appends_three_values(self, db) -> None:
        host = db.add_host("10.0.0.22")
        assert host is not None
        for v in ["a", "b", "c"]:
            db.add_host_extra(host.id, "tag", v)
        result = db.session.scalars(
            select(HostExtra).where(HostExtra.host == host.id, HostExtra.key == "tag")
        ).one()
        db._release()
        assert json.loads(result.value) == ["a", "b", "c"]

    def test_different_keys_are_separate_rows(self, db) -> None:
        host = db.add_host("10.0.0.23")
        assert host is not None
        db.add_host_extra(host.id, "os", "Linux")
        db.add_host_extra(host.id, "arch", "x86_64")
        result = db.session.scalars(
            select(HostExtra).where(HostExtra.host == host.id)
        ).all()
        db._release()
        assert len(result) == 2

    def test_locked_parameter_works(self, db) -> None:
        """_locked=True used internally by add_host (via extras dict)."""
        host = db.add_host("10.0.0.24")
        assert host is not None
        # Simulate what add_host does: call with _locked=True while holding lock
        with db.lock:
            db.add_host_extra(host.id, "test_key", "test_val", _locked=True)
        result = db.session.scalars(
            select(HostExtra).where(HostExtra.host == host.id)
        ).one()
        db._release()
        assert json.loads(result.value) == ["test_val"]

    def test_value_stored_as_string(self, db) -> None:
        host = db.add_host("10.0.0.25")
        assert host is not None
        db.add_host_extra(host.id, "count", "42")
        result = db.session.scalars(
            select(HostExtra).where(HostExtra.host == host.id, HostExtra.key == "count")
        ).one()
        db._release()
        assert json.loads(result.value) == ["42"]


# ===================================================================
# model.py  -- add_auth: basic storage
# ===================================================================
class TestAddAuth:
    def test_stores_all_fields(self, db, logger) -> None:
        db.add_auth(
            client=("10.0.0.30", 12345),
            credtype="NetNTLMv2",
            username="admin",
            password="hash123",
            logger=logger,
            domain="CORP",
            hostname="WS01",
        )
        cred = db.session.scalars(select(Credential)).one()
        db._release()
        assert cred.username == "admin"
        assert cred.password == "hash123"
        assert cred.protocol == "smb"
        assert cred.domain == "corp"
        assert cred.hostname == "WS01"
        assert cred.client == "10.0.0.30:12345"

    def test_credtype_lowercased(self, db, logger) -> None:
        db.add_auth(
            client=("10.0.0.31", 445),
            credtype="NetNTLMv2",
            username="u",
            password="h",
            logger=logger,
        )
        cred = db.session.scalars(select(Credential)).one()
        db._release()
        assert cred.credtype == "netntlmv2"

    def test_stores_cleartext(self, db, logger) -> None:
        db.add_auth(
            client=("10.0.0.32", 445),
            credtype=CLEARTEXT,
            username="u",
            password="P@ss",
            logger=logger,
        )
        cred = db.session.scalars(select(Credential)).one()
        db._release()
        assert cred.credtype == "cleartext"

    def test_creates_host_row(self, db, logger) -> None:
        db.add_auth(
            client=("10.0.0.33", 445),
            credtype="NetNTLMv1",
            username="u",
            password="h",
            logger=logger,
        )
        hosts = db.session.scalars(select(HostInfo)).all()
        db._release()
        assert len(hosts) == 1
        assert hosts[0].ip == "10.0.0.33"

    def test_reuses_existing_host(self, db, logger) -> None:
        db.add_host("10.0.0.34", hostname="PRE")
        db.add_auth(
            client=("10.0.0.34", 445),
            credtype="NetNTLMv2",
            username="u",
            password="h",
            logger=logger,
        )
        hosts = db.session.scalars(select(HostInfo)).all()
        db._release()
        assert len(hosts) == 1

    def test_normalizes_ipv6(self, db, logger) -> None:
        db.add_auth(
            client=("::ffff:10.0.0.35", 445),
            credtype="NetNTLMv2",
            username="u",
            password="h",
            logger=logger,
        )
        cred = db.session.scalars(select(Credential)).one()
        db._release()
        assert cred.client == "10.0.0.35:445"

    def test_lowercases_username(self, db, logger) -> None:
        db.add_auth(
            client=("10.0.0.36", 445),
            credtype="NetNTLMv2",
            username="ADMIN",
            password="h",
            logger=logger,
        )
        cred = db.session.scalars(select(Credential)).one()
        db._release()
        assert cred.username == "admin"

    def test_lowercases_domain(self, db, logger) -> None:
        db.add_auth(
            client=("10.0.0.37", 445),
            credtype="NetNTLMv2",
            username="u",
            password="h",
            domain="CORP.LOCAL",
            logger=logger,
        )
        cred = db.session.scalars(select(Credential)).one()
        db._release()
        assert cred.domain == "corp.local"

    def test_none_domain_stored_as_empty(self, db, logger) -> None:
        db.add_auth(
            client=("10.0.0.38", 445),
            credtype="NetNTLMv2",
            username="u",
            password="h",
            logger=logger,
            domain=None,
        )
        cred = db.session.scalars(select(Credential)).one()
        db._release()
        assert cred.domain == ""

    def test_none_hostname_stored_as_empty(self, db, logger) -> None:
        db.add_auth(
            client=("10.0.0.39", 445),
            credtype="NetNTLMv2",
            username="u",
            password="h",
            logger=logger,
            hostname=None,
        )
        cred = db.session.scalars(select(Credential)).one()
        db._release()
        assert cred.hostname == ""

    def test_password_stored_verbatim(self, db, logger) -> None:
        raw = "Admin::CORP:544553544348414c:AABBCCDD:0101blob"
        db.add_auth(
            client=("10.0.0.40", 445),
            credtype="NetNTLMv2",
            username="u",
            password=raw,
            logger=logger,
        )
        cred = db.session.scalars(select(Credential)).one()
        db._release()
        assert cred.password == raw

    def test_timestamp_format(self, db, logger) -> None:
        db.add_auth(
            client=("10.0.0.41", 445),
            credtype="NetNTLMv2",
            username="u",
            password="h",
            logger=logger,
        )
        cred = db.session.scalars(select(Credential)).one()
        db._release()
        date, time = cred.timestamp.split(" ")
        assert len(date.split("-")) == 3
        assert len(time.split(":")) == 3

    def test_credential_fk_links_to_host(self, db, logger) -> None:
        db.add_auth(
            client=("10.0.0.42", 445),
            credtype="NetNTLMv2",
            username="u",
            password="h",
            logger=logger,
        )
        cred = db.session.scalars(select(Credential)).one()
        host = db.session.scalars(select(HostInfo).where(HostInfo.id == cred.host)).one()
        db._release()
        assert host.ip == "10.0.0.42"


# ===================================================================
# model.py  -- add_auth: protocol resolution
# ===================================================================
class TestAddAuthProtocol:
    def test_from_logger_extra(self, db) -> None:
        lg = MagicMock()
        lg.extra = {"protocol": "HTTP"}
        db.add_auth(
            client=("10.0.0.50", 80),
            credtype="Token",
            username="u",
            password="t",
            logger=lg,
        )
        cred = db.session.scalars(select(Credential)).one()
        db._release()
        assert cred.protocol == "http"

    def test_from_parameter(self, db) -> None:
        db.add_auth(
            client=("10.0.0.51", 1433),
            credtype="NetNTLMv2",
            username="u",
            password="h",
            protocol="MSSQL",
        )
        cred = db.session.scalars(select(Credential)).one()
        db._release()
        assert cred.protocol == "mssql"

    def test_parameter_overrides_logger(self, db) -> None:
        lg = MagicMock()
        lg.extra = {"protocol": "HTTP"}
        db.add_auth(
            client=("10.0.0.52", 445),
            credtype="NetNTLMv2",
            username="u",
            password="h",
            logger=lg,
            protocol="LDAP",
        )
        cred = db.session.scalars(select(Credential)).one()
        db._release()
        assert cred.protocol == "ldap"

    def test_no_protocol_no_logger_skips(self, db) -> None:
        db.add_auth(
            client=("10.0.0.53", 445),
            credtype="NetNTLMv2",
            username="u",
            password="h",
        )
        creds = db.session.scalars(select(Credential)).all()
        db._release()
        assert len(creds) == 0


# ===================================================================
# model.py  -- add_auth: duplicate detection
# ===================================================================
class TestDuplicateDetection:
    def test_dedup_skips_second(self, db, logger) -> None:
        for _ in range(2):
            db.add_auth(
                client=("10.0.0.60", 445),
                credtype="NetNTLMv2",
                username="admin",
                password="h",
                domain="CORP",
                logger=logger,
            )
        creds = db.session.scalars(select(Credential)).all()
        db._release()
        assert len(creds) == 1

    def test_dedup_case_insensitive_username(self, db, logger) -> None:
        db.add_auth(
            client=("10.0.0.61", 445),
            credtype="NetNTLMv2",
            username="ADMIN",
            password="h1",
            logger=logger,
        )
        db.add_auth(
            client=("10.0.0.61", 445),
            credtype="NetNTLMv2",
            username="admin",
            password="h2",
            logger=logger,
        )
        creds = db.session.scalars(select(Credential)).all()
        db._release()
        assert len(creds) == 1

    def test_dedup_case_insensitive_credtype(self, db, logger) -> None:
        db.add_auth(
            client=("10.0.0.62", 445),
            credtype="NetNTLMv2",
            username="u",
            password="h1",
            logger=logger,
        )
        db.add_auth(
            client=("10.0.0.62", 445),
            credtype="netntlmv2",
            username="u",
            password="h2",
            logger=logger,
        )
        creds = db.session.scalars(select(Credential)).all()
        db._release()
        assert len(creds) == 1

    def test_dedup_case_insensitive_domain(self, db, logger) -> None:
        db.add_auth(
            client=("10.0.0.63", 445),
            credtype="NetNTLMv2",
            username="u",
            password="h1",
            domain="CORP",
            logger=logger,
        )
        db.add_auth(
            client=("10.0.0.63", 445),
            credtype="NetNTLMv2",
            username="u",
            password="h2",
            domain="corp",
            logger=logger,
        )
        creds = db.session.scalars(select(Credential)).all()
        db._release()
        assert len(creds) == 1

    def test_different_credtype_not_deduped(self, db, logger) -> None:
        db.add_auth(
            client=("10.0.0.64", 445),
            credtype="NetNTLMv1",
            username="u",
            password="h1",
            logger=logger,
        )
        db.add_auth(
            client=("10.0.0.64", 445),
            credtype="NetNTLMv2",
            username="u",
            password="h2",
            logger=logger,
        )
        creds = db.session.scalars(select(Credential)).all()
        db._release()
        assert len(creds) == 2

    def test_different_user_not_deduped(self, db, logger) -> None:
        db.add_auth(
            client=("10.0.0.65", 445),
            credtype="NetNTLMv2",
            username="admin",
            password="h1",
            logger=logger,
        )
        db.add_auth(
            client=("10.0.0.65", 445),
            credtype="NetNTLMv2",
            username="guest",
            password="h2",
            logger=logger,
        )
        creds = db.session.scalars(select(Credential)).all()
        db._release()
        assert len(creds) == 2

    def test_different_domain_not_deduped(self, db, logger) -> None:
        db.add_auth(
            client=("10.0.0.66", 445),
            credtype="NetNTLMv2",
            username="u",
            password="h1",
            domain="A",
            logger=logger,
        )
        db.add_auth(
            client=("10.0.0.66", 445),
            credtype="NetNTLMv2",
            username="u",
            password="h2",
            domain="B",
            logger=logger,
        )
        creds = db.session.scalars(select(Credential)).all()
        db._release()
        assert len(creds) == 2

    def test_different_protocol_not_deduped(self, db) -> None:
        db.add_auth(
            client=("10.0.0.67", 445),
            credtype="NetNTLMv2",
            username="u",
            password="h1",
            protocol="SMB",
        )
        db.add_auth(
            client=("10.0.0.67", 80),
            credtype="NetNTLMv2",
            username="u",
            password="h2",
            protocol="HTTP",
        )
        creds = db.session.scalars(select(Credential)).all()
        db._release()
        assert len(creds) == 2

    def test_duplicate_creds_true_stores_all(self, db_dupes, logger) -> None:
        for i in range(3):
            db_dupes.add_auth(
                client=("10.0.0.68", 445),
                credtype="NetNTLMv2",
                username="u",
                password=f"h{i}",
                domain="D",
                logger=logger,
            )
        creds = db_dupes.session.scalars(select(Credential)).all()
        db_dupes._release()
        assert len(creds) == 3

    def test_same_ip_different_port_still_deduped(self, db, logger) -> None:
        """Dedup keys are domain/user/credtype/protocol, NOT client IP:port."""
        db.add_auth(
            client=("10.0.0.69", 445),
            credtype="NetNTLMv2",
            username="u",
            password="h1",
            logger=logger,
        )
        db.add_auth(
            client=("10.0.0.69", 12345),
            credtype="NetNTLMv2",
            username="u",
            password="h2",
            logger=logger,
        )
        creds = db.session.scalars(select(Credential)).all()
        db._release()
        assert len(creds) == 1


# ===================================================================
# model.py  -- add_auth: HOST_INFO extras
# ===================================================================
class TestAddAuthExtras:
    def test_host_info_popped(self, db, logger) -> None:
        extras = {HOST_INFO: "WS.corp", "os": "Win10"}
        db.add_auth(
            client=("10.0.0.70", 445),
            credtype="NetNTLMv2",
            username="u",
            password="h",
            logger=logger,
            extras=extras,
        )
        assert HOST_INFO not in extras
        assert "os" in extras  # other keys preserved

    def test_none_extras(self, db, logger) -> None:
        db.add_auth(
            client=("10.0.0.71", 445),
            credtype="NetNTLMv2",
            username="u",
            password="h",
            logger=logger,
            extras=None,
        )
        creds = db.session.scalars(select(Credential)).all()
        db._release()
        assert len(creds) == 1

    def test_empty_extras(self, db, logger) -> None:
        db.add_auth(
            client=("10.0.0.72", 445),
            credtype="NetNTLMv2",
            username="u",
            password="h",
            logger=logger,
            extras={},
        )
        creds = db.session.scalars(select(Credential)).all()
        db._release()
        assert len(creds) == 1


# ===================================================================
# model.py  -- add_auth: logging
# ===================================================================
class TestAddAuthLogging:
    def test_success_logs_captured(self, db, logger) -> None:
        db.add_auth(
            client=("10.0.0.80", 445),
            credtype="NetNTLMv2",
            username="u",
            password="h",
            logger=logger,
        )
        logger.success.assert_called_once()
        assert "Captured" in logger.success.call_args[0][0]

    def test_duplicate_logs_skipping(self, db, logger) -> None:
        db.add_auth(
            client=("10.0.0.81", 445),
            credtype="NetNTLMv2",
            username="u",
            password="h1",
            logger=logger,
        )
        logger.reset_mock()
        db.add_auth(
            client=("10.0.0.81", 445),
            credtype="NetNTLMv2",
            username="u",
            password="h2",
            logger=logger,
        )
        assert any("Skipping" in str(c) for c in logger.highlight.call_args_list)

    def test_no_user_skips_username_line(self, db, logger) -> None:
        db.add_auth(
            client=("10.0.0.82", 445),
            credtype="Token",
            username=NO_USER,
            password="tok",
            logger=logger,
        )
        calls = [str(c) for c in logger.highlight.call_args_list]
        assert not any("Username" in c for c in calls)

    def test_custom_flag_omits_hash_label(self, db, logger) -> None:
        db.add_auth(
            client=("10.0.0.83", 445),
            credtype="Custom",
            username="u",
            password="v",
            logger=logger,
            custom=True,
        )
        msg = logger.success.call_args[0][0]
        assert "Hash" not in msg
        assert "Password" not in msg

    def test_cleartext_label_says_password(self, db, logger) -> None:
        db.add_auth(
            client=("10.0.0.84", 445),
            credtype=CLEARTEXT,
            username="u",
            password="p",
            logger=logger,
        )
        msg = logger.success.call_args[0][0]
        assert "Password" in msg

    def test_hash_label_says_hash(self, db, logger) -> None:
        db.add_auth(
            client=("10.0.0.85", 445),
            credtype="NetNTLMv2",
            username="u",
            password="h",
            logger=logger,
        )
        msg = logger.success.call_args[0][0]
        assert "Hash" in msg

    def test_domain_appears_in_log(self, db, logger) -> None:
        db.add_auth(
            client=("10.0.0.86", 445),
            credtype="NetNTLMv2",
            username="u",
            password="h",
            domain="TESTDOM",
            logger=logger,
        )
        msg = logger.success.call_args[0][0]
        assert "TESTDOM" in msg

    def test_extras_logged(self, db, logger) -> None:
        db.add_auth(
            client=("10.0.0.87", 445),
            credtype="NetNTLMv2",
            username="u",
            password="h",
            logger=logger,
            extras={"SPN": "cifs/server"},
        )
        calls = [str(c) for c in logger.highlight.call_args_list]
        assert any("SPN" in c for c in calls)
        assert any("cifs/server" in c for c in calls)

    def test_no_log_on_failed_write(self, db, logger) -> None:
        """When add_host returns None, no credential is stored or logged."""
        db.add_auth(
            client=("10.0.0.88", 445),
            credtype="NetNTLMv2",
            username="u",
            password="h",
            # no logger, no protocol -> early return before DB write
        )
        logger.success.assert_not_called()


# ===================================================================
# model.py  -- _check_duplicate
# ===================================================================
class TestCheckDuplicate:
    def test_false_on_empty_db(self, db) -> None:
        assert db._check_duplicate("smb", "NetNTLMv2", "u", "D") is False

    def test_true_after_insert(self, db, logger) -> None:
        db.add_auth(
            client=("10.0.0.90", 445),
            credtype="NetNTLMv2",
            username="u",
            password="h",
            domain="D",
            logger=logger,
        )
        assert db._check_duplicate("smb", "netntlmv2", "u", "d") is True

    def test_case_insensitive(self, db, logger) -> None:
        db.add_auth(
            client=("10.0.0.91", 445),
            credtype="NetNTLMv2",
            username="ADMIN",
            password="h",
            domain="CORP",
            logger=logger,
        )
        assert db._check_duplicate("SMB", "NETNTLMV2", "admin", "corp") is True

    def test_none_domain_matches_empty(self, db, logger) -> None:
        db.add_auth(
            client=("10.0.0.92", 445),
            credtype="NetNTLMv2",
            username="u",
            password="h",
            logger=logger,
        )
        assert db._check_duplicate("smb", "netntlmv2", "u", None) is True

    def test_different_domain_returns_false(self, db, logger) -> None:
        db.add_auth(
            client=("10.0.0.93", 445),
            credtype="NetNTLMv2",
            username="u",
            password="h",
            domain="A",
            logger=logger,
        )
        assert db._check_duplicate("smb", "netntlmv2", "u", "B") is False


# ===================================================================
# model.py  -- error handling
# ===================================================================
class TestErrorHandling:
    def test_handle_db_error_reraises_unknown(self, db) -> None:
        exc = OperationalError("random error", {}, Exception())
        with pytest.raises(OperationalError):
            db._handle_db_error(exc)

    def test_handle_db_error_swallows_schema_error(self, db) -> None:
        exc = OperationalError("no such column: foo", {}, Exception())
        db._handle_db_error(exc)

    def test_handle_db_error_swallows_case_variants(self, db) -> None:
        exc = OperationalError("No Such Column: bar", {}, Exception())
        db._handle_db_error(exc)

    def test_execute_succeeds(self, db) -> None:
        result = db._execute(select(Credential))
        assert result is not None

    def test_commit_succeeds(self, db) -> None:
        db.session.add(HostInfo(ip="99.99.99.99"))
        db.commit()
        hosts = db.session.scalars(select(HostInfo)).all()
        db._release()
        assert any(h.ip == "99.99.99.99" for h in hosts)


# ===================================================================
# model.py  -- connection release
# ===================================================================
class TestConnectionRelease:
    def test_add_host_releases(self, db) -> None:
        db.add_host("10.0.0.100")
        assert db.session is not None
        db._release()

    def test_add_auth_releases(self, db, logger) -> None:
        db.add_auth(
            client=("10.0.0.101", 445),
            credtype="NetNTLMv2",
            username="u",
            password="h",
            logger=logger,
        )
        assert db.session is not None
        db._release()

    def test_early_return_no_leak(self, db) -> None:
        db.add_auth(
            client=("10.0.0.102", 445), credtype="NetNTLMv2", username="u", password="h"
        )
        assert db.session is not None
        db._release()

    def test_sequential_operations_work(self, db, logger) -> None:
        """Multiple add_auth calls in sequence (simulates a handler thread)."""
        for i in range(5):
            db.add_auth(
                client=(f"10.0.0.{110 + i}", 445),
                credtype="NetNTLMv2",
                username=f"user{i}",
                password=f"hash{i}",
                logger=logger,
            )
        creds = db.session.scalars(select(Credential)).all()
        db._release()
        assert len(creds) == 5


# ===================================================================
# model.py  -- thread safety
# ===================================================================
class TestThreadSafety:
    def test_concurrent_add_host_same_ip(self, db) -> None:
        errors: list[Exception] = []

        def worker():
            try:
                db.add_host("10.0.0.120")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []
        hosts = db.session.scalars(
            select(HostInfo).where(HostInfo.ip == "10.0.0.120")
        ).all()
        db._release()
        assert len(hosts) == 1

    def test_concurrent_add_auth_different_users(self, db_dupes) -> None:
        errors: list[Exception] = []

        def worker(i: int):
            try:
                lg = MagicMock()
                lg.extra = {"protocol": "SMB"}
                db_dupes.add_auth(
                    client=(f"10.0.0.{130 + i}", 445),
                    credtype="NetNTLMv2",
                    username=f"user{i}",
                    password=f"hash{i}",
                    logger=lg,
                )
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []
        creds = db_dupes.session.scalars(select(Credential)).all()
        db_dupes._release()
        assert len(creds) == 10

    def test_atomic_dedup_insert(self, db) -> None:
        """Concurrent threads with same cred: exactly 1 stored."""
        errors: list[Exception] = []

        def worker():
            try:
                lg = MagicMock()
                lg.extra = {"protocol": "SMB"}
                db.add_auth(
                    client=("10.0.0.140", 445),
                    credtype="NetNTLMv2",
                    username="shared",
                    password="h",
                    domain="D",
                    logger=lg,
                )
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []
        creds = db.session.scalars(select(Credential)).all()
        db._release()
        assert len(creds) == 1

    def test_concurrent_add_host_extra(self, db) -> None:
        host = db.add_host("10.0.0.150")
        assert host is not None
        errors: list[Exception] = []

        def worker(i: int):
            try:
                db.add_host_extra(host.id, "tag", f"val{i}")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []
