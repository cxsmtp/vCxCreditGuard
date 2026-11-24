"""Mappings of unmatched project and application names

Revision ID: d8b3f6a2c5e1
Revises: c4e7a2d9f1b6
Create Date: 2026-11-24

* ``entity_mapping`` - an admin's mapping of a project or application name in
  the consumption feed that matches no synced entity to the one it belongs to,
  one row per (dimension, reported name) so concurrent mappings never
  overwrite each other. Mappings made before this table (stored as the
  ``attribution.entity_mappings`` setting) are moved into it, and moved back on
  downgrade.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import sqlalchemy as sa

from alembic import op

revision = "d8b3f6a2c5e1"
down_revision = "c4e7a2d9f1b6"
branch_labels = None
depends_on = None

SETTING = "attribution.entity_mappings"


def upgrade() -> None:
    bind = op.get_bind()
    # Re-runnable: SQLite DDL is not transactional, so a run that stopped half
    # way may have left the table behind (with rows, and the setting gone).
    # Its rows are kept, and merged with whatever the setting still holds.
    rows: dict[tuple[str, str], dict] = {}
    if "entity_mapping" in sa.inspect(bind).get_table_names():
        for view, key, entity_id, mapped_at, mapped_by in bind.execute(
            sa.text(
                "SELECT view_by, subject_key, entity_id, mapped_at, mapped_by FROM entity_mapping"
            )
        ):
            rows[(view, key)] = {
                "view_by": view,
                "subject_key": key,
                "entity_id": entity_id,
                "mapped_at": mapped_at if isinstance(mapped_at, datetime) else datetime.now(UTC),
                "mapped_by": mapped_by,
            }
        op.drop_table("entity_mapping")
    table = op.create_table(
        "entity_mapping",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("view_by", sa.String(16), nullable=False),
        sa.Column("subject_key", sa.String(320), nullable=False),
        sa.Column("entity_id", sa.String(64), nullable=False),
        sa.Column("mapped_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("mapped_by", sa.String(128), nullable=True),
        sa.UniqueConstraint("view_by", "subject_key", name="entity_mapping_subject"),
    )
    row = bind.execute(
        sa.text("SELECT value FROM app_setting WHERE key = :key"), {"key": SETTING}
    ).first()
    stored = None
    if row is not None and row[0]:
        try:
            stored = json.loads(row[0])
        except ValueError:
            stored = None
    now = datetime.now(UTC)
    for view, mapping in (stored or {}).items() if isinstance(stored, dict) else []:
        if view not in ("project", "application") or not isinstance(mapping, dict):
            continue
        for name, entity_id in mapping.items():
            key = str(name).strip().lower()[:320]
            if key and isinstance(entity_id, str) and entity_id and (view, key) not in rows:
                # Names that normalise to the same key: inserted once.
                rows[(view, key)] = {
                    "view_by": view,
                    "subject_key": key,
                    "entity_id": entity_id[:64],
                    "mapped_at": now,
                    "mapped_by": None,
                }
    if rows:
        op.bulk_insert(table, list(rows.values()))
    bind.execute(sa.text("DELETE FROM app_setting WHERE key = :key"), {"key": SETTING})


def downgrade() -> None:
    bind = op.get_bind()
    stored: dict[str, dict[str, str]] = {}
    for view, key, entity_id in bind.execute(
        sa.text("SELECT view_by, subject_key, entity_id FROM entity_mapping")
    ):
        stored.setdefault(view, {})[key] = entity_id
    if stored:
        now = datetime.now(UTC)
        bind.execute(
            sa.text(
                "INSERT INTO app_setting (key, value, is_secret, created_at, updated_at) "
                "VALUES (:key, :value, :secret, :now, :now)"
            ),
            {"key": SETTING, "value": json.dumps(stored), "secret": False, "now": now},
        )
    op.drop_table("entity_mapping")
