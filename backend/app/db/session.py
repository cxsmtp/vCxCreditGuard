"""Engine and session management.

Sync SQLAlchemy throughout. FastAPI runs plain ``def`` endpoints in a worker
thread, and the scheduler is a background thread, so a thread scoped session per
unit of work is the simplest correct model here.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings

logger = logging.getLogger(__name__)

# PostgreSQL session timeouts, in milliseconds. See build_engine.
PG_LOCK_TIMEOUT_MS = 15_000
PG_STATEMENT_TIMEOUT_MS = 120_000
PG_IDLE_IN_TRANSACTION_TIMEOUT_MS = 900_000

_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def _ensure_sqlite_directory(url: str) -> None:
    prefix = "sqlite:///"
    if not url.startswith(prefix) or url.startswith("sqlite:///:memory:"):
        return
    path = Path(url[len(prefix) :])
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)


def build_engine(url: str) -> Engine:
    connect_args: dict[str, object] = {}
    if url.startswith("sqlite"):
        _ensure_sqlite_directory(url)
        # The scheduler thread and request threads share the engine.
        connect_args["check_same_thread"] = False
        engine = create_engine(url, connect_args=connect_args, pool_pre_ping=True, future=True)

        @event.listens_for(engine, "connect")
        def _sqlite_pragmas(dbapi_connection, _record):  # type: ignore[no-untyped-def]
            # The driver's own transaction handling starts a transaction lazily
            # and does not know about SAVEPOINT: a savepoint that is the first
            # write then begins, and on release commits, a transaction of its
            # own. Turning it off and issuing BEGIN ourselves (below) gives
            # SQLite the same transaction and savepoint semantics as PostgreSQL.
            dbapi_connection.isolation_level = None
            cursor = dbapi_connection.cursor()
            # WAL lets readers run while a single writer holds the lock, so the
            # scheduler's writes do not block dashboard reads, and concurrent
            # writers queue on busy_timeout instead of dead-locking.
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            # A cycle (org sync + ingest + enforce) writes a lot in one go; a
            # login landing mid-cycle must wait for that write lock rather than
            # failing with "database is locked". 30s is generous headroom for
            # this single-node, low-concurrency deployment.
            cursor.execute("PRAGMA busy_timeout=30000")
            cursor.close()

        @event.listens_for(engine, "begin")
        def _sqlite_begin(connection):  # type: ignore[no-untyped-def]
            connection.exec_driver_sql("BEGIN")

        return engine

    if url.startswith("postgresql"):
        # Server side safety nets, so a stuck session cannot hang the product:
        #  * lock_timeout - nothing waits on a lock for longer than this; it fails
        #    and is retried instead of queueing every request behind it.
        #  * statement_timeout - no single statement runs away.
        #  * idle_in_transaction_session_timeout - a transaction left open by a
        #    thread that died or hung is ended by the server, releasing its locks.
        # They are deliberately generous: normal work finishes in milliseconds.
        connect_args["options"] = (
            f"-c lock_timeout={PG_LOCK_TIMEOUT_MS} "
            f"-c statement_timeout={PG_STATEMENT_TIMEOUT_MS} "
            f"-c idle_in_transaction_session_timeout={PG_IDLE_IN_TRANSACTION_TIMEOUT_MS}"
        )
    return create_engine(
        url,
        connect_args=connect_args,
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=10,
        future=True,
    )


def get_engine() -> Engine:
    global _engine
    if _engine is None:
        _engine = build_engine(get_settings().database_url)
    return _engine


def get_session_factory() -> sessionmaker[Session]:
    global _session_factory
    if _session_factory is None:
        _session_factory = sessionmaker(
            bind=get_engine(), autoflush=False, expire_on_commit=False, class_=Session
        )
    return _session_factory


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional scope for background work: commit on success, roll back on error."""
    session = get_session_factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_db() -> Iterator[Session]:
    """FastAPI dependency. Routes commit explicitly; this only guarantees cleanup."""
    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()


def reset_engine() -> None:
    """Test helper: dispose the engine so the next call rebuilds from settings."""
    global _engine, _session_factory
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _session_factory = None
