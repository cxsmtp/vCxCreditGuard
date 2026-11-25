"""Eighth review of realfix: e2a7c4f9b1d8 seeds the open period of a budget
that counts existing usage with what its names grew by between the period's
first and latest live readings, whatever lookback window each was taken in.
A widened lookback window (last_90_days -> last_year) makes every total jump
by history; the seed takes that history as the period's usage, which counts
once "count existing usage" is turned off. Synthetic data only."""

from __future__ import annotations

from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace

from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session

from alembic import command
from app.db.base import utcnow
from app.db.migrate import alembic_config
from app.models import BudgetUsage
from app.services.periods import current_window
from tests.test_usage_ledger_migration import _url


def test_a_lookback_change_is_not_seeded_as_period_usage(tmp_path: Path) -> None:
    url = _url(tmp_path)
    config = alembic_config(url)
    command.upgrade(config, "b3e8d1f6a9c4")
    now = utcnow()
    window = current_window(
        SimpleNamespace(period_type="monthly", custom_period_start=None, custom_period_end=None),
        now,
    )
    engine = create_engine(url)
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO credit_limit (id, entity_type, entity_id, credit_limit, period_type, "
                "warning_threshold_pct, enforce, is_active, include_member_usage, "
                "count_existing_usage, hold_until_released, created_at, updated_at) VALUES "
                "(7, 'project', 'proj-1', 1000, 'monthly', 80, :no, :yes, :no, :yes, :no, "
                ":now, :now)"
            ),
            {"no": False, "yes": True, "now": now},
        )
        connection.execute(
            text(
                "INSERT INTO limit_period_state (limit_id, period_key, period_start, period_end, "
                "credits_used, baseline_credits, reported_total, baseline_at, usage_available, "
                "status) VALUES (7, :k, :s, :e, 900, 0, 900, :now, :yes, 'ok')"
            ),
            {"k": window.key, "s": window.start, "e": window.end, "now": now, "yes": True},
        )
        # Same usage both times; the second reading looks a year back, not 90 days.
        for at, period, credits in (
            (window.start + timedelta(minutes=5), "last_90_days", 100),
            (now - timedelta(minutes=5), "last_year", 900),
        ):
            snapshot = connection.execute(
                text(
                    "INSERT INTO usage_snapshot (collected_at, view_by, period_param, "
                    "total_credits, pages_fetched) VALUES (:at, 'project', :p, 0, 1) "
                    "RETURNING id"
                ),
                {"at": at, "p": period},
            ).scalar_one()
            connection.execute(
                text(
                    "INSERT INTO usage_record (snapshot_id, view_by, subject_key, entity_type, "
                    "entity_id, credits_used) VALUES (:s, 'project', 'payments/web', 'project', "
                    "'proj-1', :c)"
                ),
                {"s": snapshot, "c": credits},
            )
    command.upgrade(config, "head")
    with Session(engine) as session:
        counter = session.scalar(select(BudgetUsage).where(BudgetUsage.limit_id == 7))
        assert counter is None or counter.credits == Decimal("0")
    engine.dispose()
