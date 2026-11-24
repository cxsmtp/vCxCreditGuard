"""Forward-only attribution: usage anchors

Revision ID: f9c1e4b7a2d3
Revises: d8b3f6a2c5e1
Create Date: 2026-11-24

* ``usage_anchor`` - where a reported name's usage starts counting towards an
  entity: its reported total when an admin mapped it (or when it started to
  match by itself). Only what it reports beyond that counts, so a mapping never
  brings history into a budget period, whenever it is made.
* ``usage_record.attributed_credits`` - what of a row's credits counts towards
  its entity (null: all of it).
* ``usage_record.held_reason``/``held_readings`` - a name kept on the entity
  it counted towards while it briefly does not match it (or is missing).
* ``limit_period_state.baseline_names`` - what each name counted towards a
  budget when its baseline was taken.
* ``unresolved_subject.automation_noticed_at`` - the "new automation identity"
  notice is raised once per subject ever. Subjects already known to be
  automation are marked here, silently, so the first cycle after the upgrade
  raises no burst of notices.

Mappings made before this revision (project and application names in
``entity_mapping``, user subjects in ``unresolved_subject.mapped_user_id``) are
anchored at offset 0, with the latest live reading's id: they have always
counted in full, so every stored period baseline already contains what they
reported. Anchoring them at their current total instead would take that total
out of the readings but not out of the baselines, and every budget they feed
would silently lose that much of its current period. New mappings are anchored
at the name's total when they are made. Downgrading drops the table and the
columns.
"""

from __future__ import annotations

from datetime import UTC, datetime

import sqlalchemy as sa

from alembic import op

revision = "f9c1e4b7a2d3"
down_revision = "d8b3f6a2c5e1"
branch_labels = None
depends_on = None

DEMO_PERIOD_PARAM = "__demo__"
EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def _columns(bind, table: str) -> set[str]:  # type: ignore[no-untyped-def]
    return {column["name"] for column in sa.inspect(bind).get_columns(table)}


def _when(value: object) -> datetime:
    """A stored timestamp as a datetime (SQLite hands back text), or the epoch."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            return EPOCH
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    return EPOCH


def upgrade() -> None:
    bind = op.get_bind()
    # Re-runnable on SQLite, whose DDL is not transactional.
    if "usage_anchor" in sa.inspect(bind).get_table_names():
        op.drop_table("usage_anchor")
    op.create_table(
        "usage_anchor",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("view_by", sa.String(16), nullable=False),
        sa.Column("subject_key", sa.String(320), nullable=False),
        sa.Column("entity_id", sa.String(64), nullable=False),
        sa.Column("offset_credits", sa.Numeric(18, 4), nullable=False),
        sa.Column("snapshot_id", sa.Integer(), nullable=True),
        sa.Column("anchored_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reason", sa.String(16), nullable=False),
        sa.Column("reference_actions", sa.JSON(), nullable=True),
        sa.Column("released_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("released_credits", sa.Numeric(18, 4), nullable=True),
        sa.Column("release_reason", sa.String(16), nullable=True),
        sa.Column("removed_from", sa.String(64), nullable=True),
        sa.Column("removed_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("view_by", "subject_key", name="usage_anchor_subject"),
    )
    record_columns = _columns(bind, "usage_record")
    with op.batch_alter_table("usage_record") as batch:
        if "attributed_credits" not in record_columns:
            batch.add_column(sa.Column("attributed_credits", sa.Numeric(18, 4), nullable=True))
        if "held_reason" not in record_columns:
            batch.add_column(sa.Column("held_reason", sa.String(16), nullable=True))
        if "held_readings" not in record_columns:
            batch.add_column(sa.Column("held_readings", sa.Integer(), nullable=True))
    if "baseline_names" not in _columns(bind, "limit_period_state"):
        with op.batch_alter_table("limit_period_state") as batch:
            batch.add_column(sa.Column("baseline_names", sa.JSON(), nullable=True))
    if "automation_noticed_at" not in _columns(bind, "unresolved_subject"):
        with op.batch_alter_table("unresolved_subject") as batch:
            batch.add_column(
                sa.Column("automation_noticed_at", sa.DateTime(timezone=True), nullable=True)
            )

    now = datetime.now(UTC)
    bind.execute(
        sa.text(
            "UPDATE unresolved_subject SET automation_noticed_at = :now "
            "WHERE is_bot = :yes AND automation_noticed_at IS NULL"
        ),
        {"now": now, "yes": True},
    )
    mappings: list[tuple[str, str, str, object]] = [
        (view, key, entity_id, mapped_at)
        for view, key, entity_id, mapped_at in bind.execute(
            sa.text("SELECT view_by, subject_key, entity_id, mapped_at FROM entity_mapping")
        )
    ]
    mappings += [
        ("user", key, user_id, EPOCH)
        for key, user_id in bind.execute(
            sa.text(
                "SELECT subject_key, mapped_user_id FROM unresolved_subject "
                "WHERE mapped_user_id IS NOT NULL"
            )
        )
    ]
    latest: dict[str, int | None] = {}
    for view, key, entity_id, mapped_at in mappings:
        if view not in latest:
            row = bind.execute(
                sa.text(
                    "SELECT id FROM usage_snapshot WHERE view_by = :view AND held_reason IS NULL "
                    "AND (period_param IS NULL OR period_param <> :demo) "
                    "ORDER BY collected_at DESC, id DESC LIMIT 1"
                ),
                {"view": view, "demo": DEMO_PERIOD_PARAM},
            ).first()
            latest[view] = row[0] if row else None
        bind.execute(
            sa.text(
                "INSERT INTO usage_anchor (view_by, subject_key, entity_id, offset_credits, "
                "snapshot_id, anchored_at, reason) VALUES (:view, :key, :entity, 0, "
                ":sid, :at, 'mapping')"
            ),
            # Anchored when the mapping was made (a user pin has no date: the
            # epoch), never at the upgrade: a restriction applied before the
            # upgrade keeps measuring the name from its own pinned reading.
            {
                "view": view,
                "key": key,
                "entity": entity_id,
                "sid": latest[view],
                "at": _when(mapped_at),
            },
        )


def downgrade() -> None:
    # Drops every anchor and the forward-only figures with them: after a
    # downgrade, mapped names count in full again (as before this revision),
    # and an upgrade after that anchors existing mappings at 0.
    with op.batch_alter_table("limit_period_state") as batch:
        batch.drop_column("baseline_names")
    with op.batch_alter_table("unresolved_subject") as batch:
        batch.drop_column("automation_noticed_at")
    with op.batch_alter_table("usage_record") as batch:
        batch.drop_column("held_readings")
        batch.drop_column("held_reason")
        batch.drop_column("attributed_credits")
    op.drop_table("usage_anchor")
