"""New installs start watching only, behind the readiness checklist

Revision ID: b3e7f1a9c2d5
Revises: a8d4f2c6e9b3
Create Date: 2026-11-25

A data migration. On an empty database (a new install: no app user, no
budget, no Checkmarx connection yet) enforcement starts paused, in watch-only
mode, with the readiness gate set (``readiness.gate``): turning enforcement on
then needs a green readiness checklist or an admin's typed override
(app/services/readiness.py). An existing install is left exactly as it is,
enforcing or not. Downgrading removes the gate; a watch-only pause stays as
an ordinary pause.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import sqlalchemy as sa

from alembic import op

revision = "b3e7f1a9c2d5"
down_revision = "a8d4f2c6e9b3"
branch_labels = None
depends_on = None

GATE = "readiness.gate"
PAUSED = "enforcement.paused"
REASON = "enforcement.pause_reason"
WATCH_ONLY = (
    "Watch-only: a new install watches and warns but restricts nobody until the readiness "
    "checklist is green (Settings → Enforcement)."
)


def _empty(bind: sa.engine.Connection) -> bool:
    for table in ("utility_user", "credit_limit", "cx_connection"):
        if bind.execute(sa.text(f"SELECT 1 FROM {table} LIMIT 1")).first() is not None:  # noqa: S608
            return False
    return True


def upgrade() -> None:
    bind = op.get_bind()
    if not _empty(bind):
        return
    now = datetime.now(UTC)
    for key, value in ((GATE, True), (PAUSED, True), (REASON, WATCH_ONLY)):
        bind.execute(sa.text("DELETE FROM app_setting WHERE key = :k"), {"k": key})
        bind.execute(
            sa.text(
                "INSERT INTO app_setting (key, value, is_secret, created_at, updated_at) "
                "VALUES (:k, :v, :s, :now, :now)"
            ),
            {"k": key, "v": json.dumps(value), "s": False, "now": now},
        )


def downgrade() -> None:
    op.get_bind().execute(sa.text("DELETE FROM app_setting WHERE key = :k"), {"k": GATE})
