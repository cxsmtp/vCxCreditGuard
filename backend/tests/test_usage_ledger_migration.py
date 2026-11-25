"""The usage ledger migration (fifth review of realfix): an open period keeps
the usage it showed before the upgrade, and a name an earlier reading had
counts only what it adds when it returns. Synthetic data only."""

from __future__ import annotations

from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace

from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.orm import Session

from alembic import command
from app.db.base import utcnow
from app.db.migrate import alembic_config
from app.models import BudgetUsage, LimitPeriodState, UsageMissingName, UsageRecord, UsageSnapshot
from app.services import evaluation, ledger
from app.services.periods import current_window
from tests.conftest import TEST_DATABASE_URL, USING_SQLITE

BEFORE = "d8b3f6a2c5e1"


def _url(tmp_path: Path) -> str:
    if USING_SQLITE:
        return f"sqlite:///{(tmp_path / 'ledger-upgrade.db').as_posix()}"
    engine = create_engine(TEST_DATABASE_URL)
    with engine.begin() as connection:
        connection.exec_driver_sql("DROP SCHEMA IF EXISTS public CASCADE")
        connection.exec_driver_sql("CREATE SCHEMA public")
    engine.dispose()
    return TEST_DATABASE_URL


def _seed(connection, now) -> None:  # type: ignore[no-untyped-def]
    for lid, period, existing in [(1, "monthly", False), (2, "lifetime", False)]:
        connection.execute(
            text(
                "INSERT INTO credit_limit (id, entity_type, entity_id, credit_limit, period_type, "
                "warning_threshold_pct, enforce, is_active, include_member_usage, "
                "count_existing_usage, hold_until_released, created_at, updated_at) VALUES "
                "(:id, 'project', :e, 1000, :p, 80, :no, :yes, :no, :x, :no, :now, :now)"
            ),
            {
                "id": lid,
                "e": f"proj-{lid}",
                "p": period,
                "x": existing,
                "no": False,
                "yes": True,
                "now": now,
            },
        )
    window = current_window(
        SimpleNamespace(period_type="monthly", custom_period_start=None, custom_period_end=None),
        now,
    )
    connection.execute(
        text(
            "INSERT INTO limit_period_state (limit_id, period_key, period_start, period_end, "
            "credits_used, baseline_credits, reported_total, baseline_at, usage_available, "
            "status) VALUES (1, :k, :s, :e, 42.5, 57.5, 100, :now, :yes, 'ok')"
        ),
        {"k": window.key, "s": window.start, "e": window.end, "now": now, "yes": True},
    )
    ids = {}
    for name, at in [("earlier", now - timedelta(days=2)), ("latest", now - timedelta(hours=1))]:
        ids[name] = connection.execute(
            text(
                "INSERT INTO usage_snapshot (collected_at, view_by, period_param, "
                "total_credits, pages_fetched) VALUES (:at, 'project', 'last_year', 0, 1) "
                "RETURNING id"
            ),
            {"at": at},
        ).scalar_one()
    for name, key, credits in [
        ("earlier", "example-org/gone", 55),
        ("earlier", "payments/api", 90),
        ("latest", "payments/api", 100),
    ]:
        connection.execute(
            text(
                "INSERT INTO usage_record (snapshot_id, view_by, subject_key, entity_type, "
                "entity_id, credits_used) VALUES (:s, 'project', :k, 'project', 'proj-1', :c)"
            ),
            {"s": ids[name], "k": key, "c": credits},
        )


def test_open_periods_keep_their_usage_and_returning_names_add_only_increases(
    tmp_path: Path,
) -> None:
    url = _url(tmp_path)
    config = alembic_config(url)
    command.upgrade(config, BEFORE)
    now = utcnow()
    engine = create_engine(url)
    with engine.begin() as connection:
        _seed(connection, now)
    command.upgrade(config, "head")

    with Session(engine) as session:
        counter = session.scalar(select(BudgetUsage).where(BudgetUsage.limit_id == 1))
        assert counter is not None and counter.credits == Decimal("42.5")
        # Lifetime budgets count totals: no counter.
        assert session.scalar(select(BudgetUsage).where(BudgetUsage.limit_id == 2)) is None
        gone = session.scalar(select(UsageMissingName))
        assert (gone.subject_key, gone.last_total) == ("example-org/gone", Decimal("55"))

        evaluation.evaluate_all(session, now=now)
        session.commit()
        state = session.scalar(select(LimitPeriodState).where(LimitPeriodState.limit_id == 1))
        assert state.credits_used == Decimal("42.5")

        # The next reading: 5 more under the name, and the old name back with 5 more.
        snapshot = UsageSnapshot(
            collected_at=now,
            view_by="project",
            period_param="last_year",
            total_credits=Decimal("160"),
            pages_fetched=1,
        )
        session.add(snapshot)
        session.flush()
        records = [
            UsageRecord(
                snapshot_id=snapshot.id,
                view_by="project",
                subject_key=key,
                entity_type="project",
                entity_id="proj-1",
                credits_used=Decimal(credits),
            )
            for key, credits in [("payments/api", 105), ("example-org/gone", 60)]
        ]
        session.add_all(records)
        session.flush()
        ledger.record_reading(session, "project", snapshot, records)
        session.commit()
        evaluation.evaluate_all(session, now=now + timedelta(minutes=1))
        session.commit()
        session.expire_all()
        state = session.scalar(select(LimitPeriodState).where(LimitPeriodState.limit_id == 1))
        assert state.credits_used == Decimal("52.5")
    engine.dispose()


def test_a_database_at_the_replaced_anchor_revision_reaches_the_ledger(tmp_path: Path) -> None:
    """f9c1e4b7a2d3 once added usage anchors (never released). A database
    stamped with it still upgrades: the ledger migration removes that schema."""
    url = _url(tmp_path)
    config = alembic_config(url)
    command.upgrade(config, "f9c1e4b7a2d3")
    engine = create_engine(url)
    with engine.begin() as connection:
        for table in ("usage_anchor", "usage_name_state"):
            connection.execute(text(f"CREATE TABLE {table} (id INTEGER PRIMARY KEY)"))
        for table, column, kind in [
            ("usage_record", "attributed_credits", "NUMERIC(18, 4)"),
            ("usage_record", "held_reason", "VARCHAR(16)"),
            ("usage_record", "held_readings", "INTEGER"),
            ("usage_record", "held_since", "TIMESTAMP"),
            ("limit_period_state", "baseline_names", "TEXT"),
            ("unresolved_subject", "automation_noticed_at", "TIMESTAMP"),
        ]:
            connection.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {kind}"))
    command.upgrade(config, "head")
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    assert not {"usage_anchor", "usage_name_state"} & tables
    assert "usage_delta" in tables
    record_columns = {c["name"] for c in inspector.get_columns("usage_record")}
    assert not {"attributed_credits", "held_reason", "held_readings", "held_since"} & record_columns
    assert "baseline_names" not in {c["name"] for c in inspector.get_columns("limit_period_state")}
    assert "automation_noticed_at" in {
        c["name"] for c in inspector.get_columns("unresolved_subject")
    }
    with engine.begin() as connection:
        version = connection.execute(text("SELECT version_num FROM alembic_version")).scalar()
    assert version == "b3e8d1f6a9c4"
    # And back down the whole chain, and up again.
    command.downgrade(config, BEFORE)
    command.upgrade(config, "head")
    engine.dispose()
