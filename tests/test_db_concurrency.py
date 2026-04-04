"""Concurrency stress tests for DementorDB.

Spawns multiple threads that call add_auth() simultaneously and verifies:
  - Zero exceptions (no PendingRollbackError, no packet sequence errors)
  - All credentials are persisted (no lost writes)

Tests run against SQLite backends only (no external DB required):
  1. SQLite :memory: (StaticPool, single shared connection)
  2. SQLite file (QueuePool, SQLAlchemy 2.0 default)
"""

import os
import tempfile
import threading
from unittest.mock import MagicMock

from sqlalchemy import create_engine, select
from sqlalchemy.pool import StaticPool

from dementor.db.model import Credential, DementorDB

THREAD_COUNT = 20


def _make_config(*, duplicate_creds: bool = True) -> MagicMock:
    config = MagicMock()
    config.db_config.db_duplicate_creds = duplicate_creds
    return config


def _make_logger() -> MagicMock:
    logger = MagicMock()
    logger.extra = {"protocol": "SMB"}
    return logger


def _worker(
    db: DementorDB,
    index: int,
    errors: list[Exception],
) -> None:
    try:
        db.add_auth(
            client=(f"10.0.0.{index}", 12345),
            credtype="NetNTLMv2",
            username=f"user{index}",
            password=f"hash_value_{index}",
            protocol="SMB",
            domain=f"DOMAIN{index}",
            logger=_make_logger(),
        )
    except Exception as exc:
        errors.append(exc)


def _run_concurrent_test(db: DementorDB) -> list[Exception]:
    errors: list[Exception] = []
    threads = [
        threading.Thread(target=_worker, args=(db, i, errors))
        for i in range(THREAD_COUNT)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    return errors


# --- SQLite :memory: ---------------------------------------------------------
def test_concurrent_add_auth_sqlite_memory() -> None:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        isolation_level="AUTOCOMMIT",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    db = DementorDB(engine, _make_config())

    errors = _run_concurrent_test(db)
    assert errors == [], f"Got {len(errors)} errors: {errors}"

    creds = db.session.scalars(select(Credential)).all()
    assert len(creds) == THREAD_COUNT, f"Expected {THREAD_COUNT}, got {len(creds)}"
    db.close()


# --- SQLite file --------------------------------------------------------------
def test_concurrent_add_auth_sqlite_file() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        engine = create_engine(
            f"sqlite+pysqlite:///{db_path}",
            isolation_level="AUTOCOMMIT",
        )
        db = DementorDB(engine, _make_config())

        errors = _run_concurrent_test(db)
        assert errors == [], f"Got {len(errors)} errors: {errors}"

        creds = db.session.scalars(select(Credential)).all()
        assert len(creds) == THREAD_COUNT, f"Expected {THREAD_COUNT}, got {len(creds)}"
        db.close()
