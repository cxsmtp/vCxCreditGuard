"""The database backup taken before every version switch.

SQLite (the single container's database): a consistent copy through SQLite's
own online backup API, into ``<data>/backups``. The launcher puts it back if the
new version changed the schema and then failed to start, and a manual rollback
puts it back when the schema changed since the update.

PostgreSQL: the app cannot dump it (the image has no ``pg_dump``); those
deployments keep their own scheduled dumps (``deploy/backup``). The updater then
says so, and does not install a release that changes the schema without an
admin's explicit go-ahead.
"""

from __future__ import annotations

import contextlib
import logging
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import Engine, text

logger = logging.getLogger(__name__)

KEEP_PRE_UPDATE = 3


@dataclass(frozen=True)
class DatabaseBackup:
    kind: str  # "sqlite" | "postgresql" | other dialect name
    path: Path | None
    revision: str | None
    note: str = ""

    def as_dict(self) -> dict[str, str | None]:
        return {
            "db_kind": self.kind,
            "backup": str(self.path) if self.path else None,
            "db_revision": self.revision,
        }


def current_revision(engine: Engine) -> str | None:
    try:
        with engine.connect() as conn:
            value = conn.execute(text("SELECT version_num FROM alembic_version LIMIT 1")).scalar()
    except Exception:  # noqa: BLE001 - no table yet is not an error here
        return None
    return str(value) if value else None


def sqlite_file(engine: Engine) -> Path | None:
    if engine.dialect.name != "sqlite":
        return None
    database = engine.url.database
    if not database or database == ":memory:":
        return None
    return Path(database).resolve()


def backup_database(engine: Engine, backups_dir: Path, *, label: str) -> DatabaseBackup:
    """Back the database up before a switch. Never raises for PostgreSQL."""
    revision = current_revision(engine)
    source = sqlite_file(engine)
    if source is None:
        return DatabaseBackup(
            engine.dialect.name,
            None,
            revision,
            "The app cannot back up a PostgreSQL database itself; keep your own dumps "
            "(deploy/backup) current.",
        )
    backups_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    safe_label = "".join(c if c.isalnum() or c in ".-" else "-" for c in label)[:60]
    target = backups_dir / f"pre-update-{stamp}-{safe_label}.sqlite3"
    with (
        contextlib.closing(sqlite3.connect(str(source), timeout=30)) as src,
        contextlib.closing(sqlite3.connect(str(target))) as dst,
    ):
        src.backup(dst)
    target.chmod(0o600)
    _prune(backups_dir)
    logger.info("Database backed up before an update to %s", target.name)
    return DatabaseBackup("sqlite", target, revision)


def _prune(backups_dir: Path) -> None:
    old = sorted(backups_dir.glob("pre-update-*.sqlite3"))
    for extra in old[:-KEEP_PRE_UPDATE]:
        with contextlib.suppress(OSError):
            extra.unlink()
