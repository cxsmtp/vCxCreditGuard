"""Ninth review of realfix: e2a7c4f9b1d8 seeds a count-existing budget's open
period with latest minus first in-period total, name by name. When the first
reading of the period reported a name low in a listing the completeness
checks doubt (one row short), the recovery is seeded as period usage, though
the ledger itself would hold that fall and count nothing. Synthetic data."""

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


def test_a_doubted_first_reading_of_the_period_is_not_seeded_as_usage(tmp_path: Path) -> None:
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
                "status) VALUES (7, :k, :s, :e, 1000, 0, 1000, :now, :yes, 'ok')"
            ),
            {"k": window.key, "s": window.start, "e": window.end, "now": now, "yes": True},
        )
        # Nobody used anything: 1000 throughout, except the period's first
        # reading, one row short (2 items said, 1 served), reporting 400.
        for at, credits, items in (
            (window.start - timedelta(minutes=25), 1000, 1),
            (window.start + timedelta(minutes=5), 400, 2),
            (now - timedelta(minutes=5), 1000, 1),
        ):
            snapshot = connection.execute(
                text(
                    "INSERT INTO usage_snapshot (collected_at, view_by, period_param, "
                    "total_credits, total_items, pages_fetched) VALUES "
                    "(:at, 'project', 'last_year', :c, :i, 1) RETURNING id"
                ),
                {"at": at, "c": credits, "i": items},
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
