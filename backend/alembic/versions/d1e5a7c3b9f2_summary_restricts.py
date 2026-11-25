"""Keep restricting from summary totals where the summary was chosen

Revision ID: d1e5a7c3b9f2
Revises: c9f2b6d4e8a1
Create Date: 2026-11-25

Period budgets fed by the consumption summary now warn instead of
restricting, unless ``usage.summary_restricts`` is on. An install whose admin
explicitly chose the summary only (``usage.source`` stored as "summary") gets
it switched on, so it keeps restricting as before. Every other install (no
stored choice, or the activity log) is left alone. Downgrading removes the
setting.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import sqlalchemy as sa

from alembic import op

revision = "d1e5a7c3b9f2"
down_revision = "c9f2b6d4e8a1"
branch_labels = None
depends_on = None

SOURCE = "usage.source"
RESTRICTS = "usage.summary_restricts"


def upgrade() -> None:
    bind = op.get_bind()
    stored = bind.execute(
        sa.text("SELECT value FROM app_setting WHERE key = :k"), {"k": SOURCE}
    ).scalar()
    try:
        chosen = json.loads(stored) if stored is not None else None
    except (TypeError, ValueError):
        chosen = None
    if chosen != "summary":
        return
    exists = bind.execute(
        sa.text("SELECT 1 FROM app_setting WHERE key = :k"), {"k": RESTRICTS}
    ).first()
    if exists is not None:
        return
    bind.execute(
        sa.text(
            "INSERT INTO app_setting (key, value, is_secret, created_at, updated_at) "
            "VALUES (:k, :v, :s, :now, :now)"
        ),
        {"k": RESTRICTS, "v": json.dumps(True), "s": False, "now": datetime.now(UTC)},
    )


def downgrade() -> None:
    op.get_bind().execute(sa.text("DELETE FROM app_setting WHERE key = :k"), {"k": RESTRICTS})
