"""Making a read-check-write safe against a concurrent request doing the same.

A check such as "is this token still unused", "is another Admin left" or "how
many attempts has this address made" is only as good as the read behind it.
Read without a lock, two requests can both pass the check and both write, and
the second write is based on a value that was already out of date.

The two databases need different things for that:

* **PostgreSQL** (READ COMMITTED): a row lock (``SELECT ... FOR UPDATE``) or a
  transaction-scoped advisory lock. The second transaction waits for the first
  to commit, and its next statement then sees what the first wrote.
* **SQLite**: one writer at a time, but the driver only opens a transaction at
  the first write, so a read before it is not protected by anything. Taking
  the write lock up front (``BEGIN IMMEDIATE``) makes the second writer wait
  for the first to commit before it reads. ``FOR UPDATE`` does not exist there.

Every lock taken here is held until the caller's transaction ends.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

# Keys for pg_advisory_xact_lock(bigint). Arbitrary but fixed, and distinct from
# the audit chain's (0x43784347) and the instance guard's two-integer key.
ADMIN_SET_LOCK_KEY = 0x4378434700000001
CREDIT_REQUEST_FILING_LOCK_KEY = 0x4378434700000002


def is_postgresql(session: Session) -> bool:
    return session.get_bind().dialect.name == "postgresql"


def begin_write(session: Session) -> None:
    """On SQLite, take the database write lock now, unless this transaction has it.

    From here to the end of the transaction no one else can write, and every
    read sees the latest committed data. A no-op on PostgreSQL, which locks rows.
    """
    connection = session.connection()
    if connection.dialect.name != "sqlite":
        return
    raw = connection.connection.dbapi_connection
    # The driver opens its transaction at the first write: a transaction that
    # is open already holds the write lock.
    if raw is not None and not raw.in_transaction:
        # Waits on busy_timeout, like any other writer.
        connection.exec_driver_sql("BEGIN IMMEDIATE")


def serialize(session: Session, key: int) -> None:
    """Let only one transaction at a time past this point for ``key``.

    PostgreSQL: a transaction-scoped advisory lock. SQLite: the database write
    lock, which serialises every writer anyway.
    """
    if is_postgresql(session):
        session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": key})
    else:
        begin_write(session)


def insert_ignoring_conflict(session: Session, model: Any) -> Any:
    """INSERT ... ON CONFLICT DO NOTHING for ``model``, in the dialect's own spelling.

    For a row two requests may both find missing and both create: the second
    insert does nothing (on PostgreSQL it first waits for the first to commit)
    instead of failing on the unique constraint.
    """
    if is_postgresql(session):
        from sqlalchemy.dialects.postgresql import insert as dialect_insert
    else:
        from sqlalchemy.dialects.sqlite import insert as dialect_insert
    return dialect_insert(model).on_conflict_do_nothing()


def lock_row(session: Session, instance: Any) -> None:
    """Lock ``instance``'s row and reload it, so a check on it sees the latest state."""
    begin_write(session)
    # FOR UPDATE on PostgreSQL; SQLite has no such clause and needs none.
    session.refresh(instance, with_for_update=True)
