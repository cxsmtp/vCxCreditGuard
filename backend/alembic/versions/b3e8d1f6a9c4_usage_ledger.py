"""The usage ledger: period budgets count increases

Revision ID: b3e8d1f6a9c4
Revises: f9c1e4b7a2d3
Create Date: 2026-11-25

* ``usage_delta`` - every live reading's increase per reported name, attributed
  to the entity the name counted towards when it was observed, with the time
  of the reading it is measured from (``since``).
* ``usage_missing_name`` - the last total of a name the last reading lacked
  (or whose fall a doubted reading reported), with when it was read and the
  entity it counted towards.
* ``budget_usage`` - each budget's counter per period of observation.
* ``usage_entity_offset`` - how far names joining or leaving a project shifted
  its Auto Triage figure (Auto Triage attribution subtracts it).
* ``unresolved_subject.automation_noticed_at`` - the "new automation identity"
  notice is raised once per subject ever. Subjects already known to be
  automation are marked here, silently, so the first cycle after the upgrade
  raises no burst of notices.

Every budget period still open at the upgrade (of a budget that does not
count usage already reported) has its counter seeded with the usage it shows
now (``credits_used`` less the Auto Triage credits charged to people, which
are added separately), so no open period jumps or loses anything. The ledger
then starts from the latest live reading: every name's total in it is where
its increases are counted from, and every name an earlier live reading had
and the latest lacks is remembered with its last total (``usage_missing_name``),
so its return adds only what it reported since.

A database already at the unreleased usage-anchor schema (revision
f9c1e4b7a2d3 as it once was) loses what that added here: its tables and
columns are dropped if present.

Downgrading drops the tables and the column: period budgets then go back to
a baseline taken when their period opened (counters are lost; an open period
keeps the baseline it had).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import sqlalchemy as sa

from alembic import op

revision = "b3e8d1f6a9c4"
down_revision = "f9c1e4b7a2d3"
branch_labels = None
depends_on = None

COUNTS_EXISTING_PERIODS = ("lifetime", "custom")
DEMO_PERIOD_PARAM = "__demo__"
FUSION_MODEL = "fusion_model:"
# How far back each lookback window reaches (app.checkmarx.usage.PERIOD_DAYS).
PERIOD_DAYS = {
    "last_month": 31,
    "last_30_days": 30,
    "last_90_days": 90,
    "last_180_days": 180,
    "last_year": 365,
}
# What the unreleased usage-anchor schema added.
ANCHOR_TABLES = ("usage_anchor", "usage_name_state")
ANCHOR_COLUMNS = {
    "usage_record": ("attributed_credits", "held_reason", "held_readings", "held_since"),
    "limit_period_state": ("baseline_names",),
}


def _json(value: object) -> object:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return None
    return value


def _counts(actions: object, raw: object) -> dict[str, int]:
    """A stored row's per action counts as the ledger keeps them (the same as
    ``app.services.ledger.counts_of``, which a migration must not import)."""
    counts: dict[str, int] = {}
    actions = _json(actions)
    for action, count in (actions if isinstance(actions, dict) else {}).items():
        if isinstance(count, int) and not isinstance(count, bool):
            counts[str(action)] = counts.get(str(action), 0) + count
    raw = _json(raw)
    performed = raw.get("actionsPerformed") if isinstance(raw, dict) else None
    entries = performed.get("actions") if isinstance(performed, dict) else None
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, dict):
            continue
        action, count = entry.get("actionType"), entry.get("transactionCount")
        if not isinstance(action, str) or not isinstance(count, int) or isinstance(count, bool):
            continue
        key = action.strip().lower().replace("-", "_").replace(" ", "_")
        if key in ("fusion", "fusion_scan", "fusionscan") or key.startswith(
            ("fusion_scan_", "fusionscan_")
        ):
            counts[FUSION_MODEL + key] = counts.get(FUSION_MODEL + key, 0) + count
    return counts


def _seed_missing_names(bind, now: datetime) -> None:  # type: ignore[no-untyped-def]
    """Every name an earlier live reading had and the latest one lacks is
    remembered with its last total, so its return counts only what it adds."""
    views = [
        row[0]
        for row in bind.execute(
            sa.text(
                "SELECT DISTINCT view_by FROM usage_snapshot "
                "WHERE held_reason IS NULL AND period_param <> :demo"
            ),
            {"demo": DEMO_PERIOD_PARAM},
        )
    ]
    for view in views:
        latest = bind.execute(
            sa.text(
                "SELECT id, period_param FROM usage_snapshot WHERE view_by = :view "
                "AND held_reason IS NULL AND period_param <> :demo "
                "ORDER BY collected_at DESC, id DESC LIMIT 1"
            ),
            {"view": view, "demo": DEMO_PERIOD_PARAM},
        ).first()
        if latest is None:
            continue
        latest_id, period = latest
        present = {
            row[0]
            for row in bind.execute(
                sa.text("SELECT subject_key FROM usage_record WHERE snapshot_id = :id"),
                {"id": latest_id},
            )
        }
        seen: set[str] = set()
        rows = bind.execute(
            sa.text(
                "SELECT r.subject_key, r.credits_used, r.actions, r.raw, s.collected_at, "
                "r.entity_id "
                "FROM usage_record r JOIN usage_snapshot s ON s.id = r.snapshot_id "
                "WHERE s.view_by = :view AND s.held_reason IS NULL AND s.period_param = :period "
                "AND s.id <> :latest ORDER BY s.collected_at DESC, s.id DESC"
            ),
            {"view": view, "period": period, "latest": latest_id},
        )
        horizon = now - timedelta(days=PERIOD_DAYS.get(period, 365))
        for key, credits, actions, raw, collected_at, entity_id in rows:
            if key in present or key in seen:
                continue
            seen.add(key)
            seen_at = _when(collected_at) or now
            if seen_at < horizon:
                continue  # nothing of that total is left in the window
            bind.execute(
                sa.text(
                    "INSERT INTO usage_missing_name (view_by, subject_key, last_total, "
                    "last_actions, missing_since, last_seen_at, period_param, entity_id, kind) "
                    "VALUES (:view, :key, :total, :actions, :now, :since, :period, :entity, "
                    "'missing')"
                ).bindparams(
                    sa.bindparam("total", type_=sa.Numeric(18, 4)),
                    sa.bindparam("actions", type_=sa.JSON()),
                    sa.bindparam("since", type_=sa.DateTime(timezone=True)),
                    sa.bindparam("now", type_=sa.DateTime(timezone=True)),
                ),
                {
                    "view": view,
                    "key": key,
                    "total": Decimal(str(credits or 0)),
                    "actions": _counts(actions, raw),
                    "since": seen_at,
                    "now": now,
                    "period": period,
                    "entity": entity_id,
                },
            )


def _columns(bind, table: str) -> set[str]:  # type: ignore[no-untyped-def]
    return {column["name"] for column in sa.inspect(bind).get_columns(table)}


def _when(value: object) -> datetime | None:
    """A stored timestamp as an aware datetime (SQLite hands back text)."""
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
    tables = set(sa.inspect(bind).get_table_names())
    # Re-runnable on SQLite, whose DDL is not transactional.
    for table in ("usage_delta", "usage_missing_name", "budget_usage", "usage_entity_offset"):
        if table in tables:
            op.drop_table(table)
    op.create_table(
        "usage_delta",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("snapshot_id", sa.Integer(), nullable=False),
        sa.Column("view_by", sa.String(16), nullable=False),
        sa.Column("subject_key", sa.String(320), nullable=False),
        sa.Column("entity_type", sa.String(16), nullable=True),
        sa.Column("entity_id", sa.String(64), nullable=True),
        sa.Column("credits", sa.Numeric(18, 4), nullable=False),
        sa.Column("actions", sa.JSON(), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("since", sa.DateTime(timezone=True), nullable=False),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("snapshot_id", "view_by", "subject_key", name="usage_delta_reading"),
    )
    op.create_index("ix_usage_delta_entity", "usage_delta", ["view_by", "entity_id", "observed_at"])
    op.create_index("ix_usage_delta_subject", "usage_delta", ["view_by", "subject_key"])
    op.create_table(
        "usage_missing_name",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("view_by", sa.String(16), nullable=False),
        sa.Column("subject_key", sa.String(320), nullable=False),
        sa.Column("last_total", sa.Numeric(18, 4), nullable=False),
        sa.Column("last_actions", sa.JSON(), nullable=True),
        sa.Column("missing_since", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("period_param", sa.String(32), nullable=False),
        sa.Column("entity_id", sa.String(64), nullable=True),
        sa.Column("kind", sa.String(16), nullable=False, server_default="missing"),
        sa.UniqueConstraint("view_by", "subject_key", name="usage_missing_name_subject"),
    )
    op.create_table(
        "budget_usage",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "limit_id",
            sa.Integer(),
            sa.ForeignKey(
                "credit_limit.id", ondelete="CASCADE", name="fk_budget_usage_limit_id_credit_limit"
            ),
            nullable=False,
        ),
        sa.Column("period_key", sa.String(64), nullable=False),
        sa.Column("credits", sa.Numeric(18, 4), nullable=False),
        sa.Column("actions", sa.JSON(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("limit_id", "period_key", name="budget_usage_period"),
    )
    op.create_index("ix_budget_usage_limit_id", "budget_usage", ["limit_id"])
    op.create_table(
        "usage_entity_offset",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("view_by", sa.String(16), nullable=False),
        sa.Column("entity_id", sa.String(64), nullable=False),
        sa.Column("auto_triage_transactions", sa.Integer(), nullable=False),
        sa.Column("auto_triage_credits", sa.Numeric(18, 4), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("view_by", "entity_id", name="usage_entity_offset_entity"),
    )
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
        ).bindparams(sa.bindparam("now", type_=sa.DateTime(timezone=True))),
        {"now": now, "yes": True},
    )

    _seed_missing_names(bind, now)

    # Seed the counter of every open period with what it shows now.
    open_periods: dict[int, tuple[datetime | None, str, object, object]] = {}
    for limit_id, period_key, period_start, period_end, used, attributed in bind.execute(
        sa.text(
            "SELECT s.limit_id, s.period_key, s.period_start, s.period_end, s.credits_used, "
            "s.attributed_credits FROM limit_period_state s "
            "JOIN credit_limit l ON l.id = s.limit_id "
            "WHERE l.period_type NOT IN ('lifetime', 'custom') "
            "AND (l.count_existing_usage IS NULL OR l.count_existing_usage = :no)"
        ),
        {"no": False},
    ):
        end = _when(period_end)
        if end is not None and end <= now:
            continue
        start = _when(period_start)
        known = open_periods.get(limit_id)
        if known is not None and known[0] is not None and start is not None and known[0] >= start:
            continue
        open_periods[limit_id] = (start, period_key, used, attributed)
    for limit_id, (_start, period_key, used, attributed) in open_periods.items():
        credits = max(Decimal(0), Decimal(str(used or 0)) - Decimal(str(attributed or 0)))
        bind.execute(
            sa.text(
                "INSERT INTO budget_usage (limit_id, period_key, credits, actions, updated_at) "
                "VALUES (:limit_id, :key, :credits, NULL, :now)"
            ).bindparams(
                sa.bindparam("credits", type_=sa.Numeric(18, 4)),
                sa.bindparam("now", type_=sa.DateTime(timezone=True)),
            ),
            {"limit_id": limit_id, "key": period_key, "credits": credits, "now": now},
        )

    # What the unreleased usage-anchor schema added, if this database has it.
    for table in ANCHOR_TABLES:
        if table in tables:
            op.drop_table(table)
    for table, columns in ANCHOR_COLUMNS.items():
        present = [column for column in columns if column in _columns(bind, table)]
        if present:
            with op.batch_alter_table(table) as batch:
                for column in present:
                    batch.drop_column(column)


def downgrade() -> None:
    with op.batch_alter_table("unresolved_subject") as batch:
        batch.drop_column("automation_noticed_at")
    op.drop_index("ix_budget_usage_limit_id", table_name="budget_usage")
    op.drop_table("budget_usage")
    op.drop_table("usage_entity_offset")
    op.drop_table("usage_missing_name")
    op.drop_index("ix_usage_delta_subject", table_name="usage_delta")
    op.drop_index("ix_usage_delta_entity", table_name="usage_delta")
    op.drop_table("usage_delta")
