"""The usage ledger: when names last rose, bounded doubts, count-existing seeds

Revision ID: e2a7c4f9b1d8
Revises: b3e8d1f6a9c4
Create Date: 2026-11-25

* ``usage_record.last_rise_at`` and ``usage_missing_name.last_rise_at`` - when
  a name's total last rose. A remembered name is forgotten once that is older
  than the lookback window (nothing it reported can still be in it). Existing
  remembered names take the time they were last read, which forgets them no
  sooner than before.
* ``usage_missing_name.doubts`` - how many doubted readings a held fall has
  lasted through (after a few it is kept as a ceiling, no longer reported).
* ``ix_usage_delta_observed`` - for the retention prune.
* The open period of an active budget that counts usage already reported
  gets a counter, if it has none, seeded with what the rows of its own entity
  grew by up to the latest live reading of the period, name by name, from
  the highest total any earlier reading of the run gave it (the last one
  before the period and every one in it; names in no earlier reading bring
  nothing, so no history comes in), and only over the readings since the
  lookback window last changed (totals read over
  different windows are not comparable). Turning "count existing usage" off
  then keeps the period's usage from before the upgrade. A budget fed by a
  roll-up (a group's projects or members, an application's projects), or with
  fewer than two such readings in its period, gets a counter at zero.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

import sqlalchemy as sa

from alembic import op

revision = "e2a7c4f9b1d8"
down_revision = "b3e8d1f6a9c4"
branch_labels = None
depends_on = None

DEMO_PERIOD_PARAM = "__demo__"
VIEW_OF = {"user": "user", "project": "project", "application": "application", "group": "group"}


def _columns(bind, table: str) -> set[str]:  # type: ignore[no-untyped-def]
    return {column["name"] for column in sa.inspect(bind).get_columns(table)}


def _when(value: object) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    return None


def upgrade() -> None:
    bind = op.get_bind()
    if "last_rise_at" not in _columns(bind, "usage_record"):
        with op.batch_alter_table("usage_record") as batch:
            batch.add_column(sa.Column("last_rise_at", sa.DateTime(timezone=True), nullable=True))
    missing_columns = _columns(bind, "usage_missing_name")
    if "last_rise_at" not in missing_columns or "doubts" not in missing_columns:
        with op.batch_alter_table("usage_missing_name") as batch:
            if "last_rise_at" not in missing_columns:
                batch.add_column(
                    sa.Column("last_rise_at", sa.DateTime(timezone=True), nullable=True)
                )
            if "doubts" not in missing_columns:
                batch.add_column(
                    sa.Column("doubts", sa.Integer(), nullable=False, server_default="0")
                )
    bind.execute(
        sa.text(
            "UPDATE usage_missing_name SET last_rise_at = last_seen_at WHERE last_rise_at IS NULL"
        )
    )
    indexes = {index["name"] for index in sa.inspect(bind).get_indexes("usage_delta")}
    if "ix_usage_delta_observed" not in indexes:
        op.create_index("ix_usage_delta_observed", "usage_delta", ["observed_at"])
    _seed_count_existing(bind)


def _seed_count_existing(bind) -> None:  # type: ignore[no-untyped-def]
    now = datetime.now(UTC)
    rows = bind.execute(
        sa.text(
            "SELECT l.id, l.entity_type, l.entity_id, s.period_key, s.period_start, "
            "s.period_end FROM credit_limit l JOIN limit_period_state s ON s.limit_id = l.id "
            "WHERE l.count_existing_usage = :yes AND l.is_active = :yes "
            "AND l.period_type IN ('monthly', 'quarterly')"
        ),
        {"yes": True},
    ).all()
    for limit_id, entity_type, entity_id, period_key, period_start, period_end in rows:
        end, start = _when(period_end), _when(period_start)
        if start is None or (end is not None and end <= now):
            continue
        exists = bind.execute(
            sa.text("SELECT 1 FROM budget_usage WHERE limit_id = :l AND period_key = :k"),
            {"l": limit_id, "k": period_key},
        ).first()
        if exists is not None:
            continue
        credits = _reported_since(bind, str(entity_type), str(entity_id), start)
        bind.execute(
            sa.text(
                "INSERT INTO budget_usage (limit_id, period_key, credits, actions, updated_at) "
                "VALUES (:l, :k, :c, NULL, :now)"
            ).bindparams(
                sa.bindparam("c", type_=sa.Numeric(18, 4)),
                sa.bindparam("now", type_=sa.DateTime(timezone=True)),
            ),
            {"l": limit_id, "k": period_key, "c": credits, "now": now},
        )


def _reported_since(bind, entity_type: str, entity_id: str, start: datetime) -> Decimal:  # type: ignore[no-untyped-def]
    """What the entity's own rows grew by from the first live reading of the
    period to the latest; zero when that cannot be told."""
    view = VIEW_OF.get(entity_type)
    if view is None:
        return Decimal(0)
    snapshots = bind.execute(
        sa.text(
            "SELECT id, collected_at, period_param FROM usage_snapshot WHERE view_by = :v "
            "AND held_reason IS NULL AND period_param <> :demo ORDER BY collected_at, id"
        ),
        {"v": view, "demo": DEMO_PERIOD_PARAM},
    ).all()
    # Only the run of readings since the lookback window last changed: totals
    # read over different windows are not comparable.
    run: list = []
    for row in snapshots:
        if run and row[2] != run[-1][2]:
            run = []
        run.append(row)
    in_period = [row[0] for row in run if (_when(row[1]) or start) >= start]
    before_period = [row[0] for row in run if (_when(row[1]) or start) < start]
    if len(in_period) < 2:
        return Decimal(0)

    def totals(snapshot_id: int) -> dict[str, Decimal]:
        return {
            str(key): Decimal(str(value or 0))
            for key, value in bind.execute(
                sa.text(
                    "SELECT subject_key, credits_used FROM usage_record "
                    "WHERE snapshot_id = :s AND entity_id = :e"
                ),
                {"s": snapshot_id, "e": entity_id},
            )
        }

    # Name by name, from the highest total any earlier reading of the run
    # gave it (the last one before the period, and every one in it): a reading
    # that reported it low (a short listing) is never taken for the start, and
    # a name that came to count towards the entity meanwhile, present in no
    # earlier reading, brings no history with it.
    start_totals: dict[str, Decimal] = {}
    for snapshot_id in before_period[-1:] + in_period[:-1]:
        for key, value in totals(snapshot_id).items():
            start_totals[key] = max(start_totals.get(key, value), value)
    latest = totals(in_period[-1])
    return sum(
        (max(Decimal(0), latest[key] - start_totals[key]) for key in latest if key in start_totals),
        Decimal(0),
    )


def downgrade() -> None:
    op.drop_index("ix_usage_delta_observed", table_name="usage_delta")
    with op.batch_alter_table("usage_missing_name") as batch:
        batch.drop_column("doubts")
        batch.drop_column("last_rise_at")
    with op.batch_alter_table("usage_record") as batch:
        batch.drop_column("last_rise_at")
