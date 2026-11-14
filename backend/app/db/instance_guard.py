"""Exactly one running instance per database.

Two things in this utility are correct only within a single process: the
scheduler (one cycle at a time is also guarded in the database, but two
schedulers still double every poll and notification) and the per-target lock
that stops an admin's Restore racing the cycle's re-verification of the same
user or project. Run two copies against one database - a second replica, a
second uvicorn worker, an old container that was never stopped - and those
guarantees quietly stop holding.

So the process takes an exclusive claim on the database when it starts and
holds it until it exits. A second instance fails to start, saying why, instead
of running in a configuration nobody tested.

* PostgreSQL: a session level advisory lock on a dedicated connection. It is
  released by the server the moment the holder's connection goes away, so a
  crashed instance never blocks its replacement.
* SQLite: an exclusive lock on a file next to the database, released by the
  operating system when the process exits.
"""

from __future__ import annotations

import logging
import os
import threading
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, text

from app.core.config import ConfigError

logger = logging.getLogger(__name__)

# Arbitrary, fixed: "CXCG" as a 32-bit integer pair for pg_advisory_lock(int, int).
_PG_LOCK_CLASS = 0x43584347
_PG_LOCK_OBJECT = 1

_ALREADY_RUNNING = (
    "Another CxCreditGuard instance is already running against this database. Run exactly "
    "one: a single container, with a single worker process. If you are replacing a "
    "container, stop the old one first (this is what `docker compose up -d` does)."
)

_lock = threading.Lock()
_holders = 0
_held: Any = None
# The claim's connection died and has not been re-established yet.
_lost = False


def acquire(engine: Engine) -> None:
    """Claim the database for this process, or raise :class:`ConfigError`."""
    global _holders, _held
    with _lock:
        if _holders:
            # The same process starting the app again (tests do this).
            _holders += 1
            return
        if engine.dialect.name == "postgresql":
            _held = _acquire_postgres(engine)
        elif engine.dialect.name == "sqlite":
            _held = _acquire_sqlite(engine)
        else:
            _held = None
        _holders = 1


def release() -> None:
    global _holders, _held, _lost
    with _lock:
        if not _holders:
            return
        _holders -= 1
        if _holders:
            return
        held, _held = _held, None
        _lost = False
    try:
        if held is not None:
            held.close()
    except Exception:  # noqa: BLE001 - shutting down; the OS or server releases it anyway
        logger.debug("Releasing the instance claim failed", exc_info=True)


def still_held(engine: Engine) -> bool:
    """Check the claim before doing scheduled work; take it again if it was lost.

    A PostgreSQL advisory lock lives exactly as long as its connection. If the
    database restarts, or the network drops that one idle connection, the claim
    is gone while this process carries on, and a second instance could then
    start. So the scheduler asks before each cycle: a lost claim is taken again,
    and if another instance holds it by now, this one stops doing scheduled work
    rather than run alongside it.
    """
    global _held, _lost
    with _lock:
        if not _holders or engine.dialect.name != "postgresql":
            return True
        if _held is not None:
            try:
                _held.execute(text("SELECT 1"))
                _held.commit()
                return True
            except Exception:  # noqa: BLE001 - any failure means the connection is gone
                logger.warning(
                    "The single-instance claim on the database was lost; taking it again"
                )
            try:
                _held.close()
            except Exception:  # noqa: BLE001 - already broken
                logger.debug("Closing the lost claim's connection failed", exc_info=True)
            _held = None
            _lost = True
        if not _lost:
            return True
        try:
            _held = _acquire_postgres(engine)
            _lost = False
        except ConfigError:
            return False
        except Exception:  # noqa: BLE001 - database unreachable: the cycle fails by itself
            logger.warning("Could not re-take the single-instance claim", exc_info=True)
        return True


def _acquire_postgres(engine: Engine) -> Any:
    connection = engine.connect()
    try:
        claimed = connection.execute(
            text("SELECT pg_try_advisory_lock(:cls, :obj)"),
            {"cls": _PG_LOCK_CLASS, "obj": _PG_LOCK_OBJECT},
        ).scalar()
        # End the transaction the SELECT began: the lock is session level and
        # survives it, and the connection must not sit "idle in transaction".
        connection.commit()
    except Exception:
        connection.close()
        raise
    if not claimed:
        connection.close()
        raise ConfigError(_ALREADY_RUNNING)
    # Detached from the pool so it is never handed to anyone else, and closing
    # it really closes it (which is what releases the lock).
    connection.detach()
    return connection


class _FileClaim:
    def __init__(self, handle: Any) -> None:
        self._handle = handle

    def close(self) -> None:
        self._handle.close()


def _acquire_sqlite(engine: Engine) -> Any:
    database = engine.url.database
    if not database or database == ":memory:":
        return None
    path = Path(f"{database}.instance.lock")
    handle = path.open("a+")
    try:
        import fcntl
    except ImportError:  # not available on Windows: best effort there
        handle.close()
        return None
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        handle.close()
        raise ConfigError(_ALREADY_RUNNING) from exc
    handle.seek(0)
    handle.truncate()
    handle.write(f"{os.getpid()}\n")
    handle.flush()
    return _FileClaim(handle)
