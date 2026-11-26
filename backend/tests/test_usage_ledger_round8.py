"""The usage ledger after the eighth review of realfix: a collapse of the
whole feed accepted only because it persisted keeps a ceiling; a closed
month of a budget now quarterly is not raised later. Synthetic data only."""

# ruff: noqa: F811 - the connected fixture is imported by name

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import UsageMissingName
from app.models.enums import EntityType, PeriodType
from app.services import ledger, limits_service
from tests.test_real_tenant_usage import connected, live_tenant  # noqa: F401
from tests.test_review_followups import ACTOR, _limit
from tests.test_usage_ledger_round7 import _Run, _tenant


def test_a_persisting_collapse_of_the_whole_feed_is_not_counted_when_it_ends(
    db: Session, connected, monkeypatch
) -> None:
    tenant = _tenant()
    connected(tenant)
    run = _Run(db, monkeypatch, datetime(2027, 1, 5, 6, tzinfo=UTC))
    run.step()
    web = _limit(db, EntityType.PROJECT, "proj-web")
    run.step()
    saved = [dict(row) for row in tenant.consumption["project"]]
    # Every project reports a tenth of its usage, for long enough that the
    # collapse is accepted (3 readings over 2 hours).
    for row in tenant.consumption["project"]:
        row["creditsUsed"] = str(int(float(row["creditsUsed"]) // 10))
    for _ in range(4):
        run.step(hours=1)
    held = db.scalar(select(UsageMissingName).where(UsageMissingName.subject_key == "payments/web"))
    assert held is not None and held.kind == ledger.COLLAPSE
    # Still collapsed in believed readings: the ceiling stays.
    run.step(hours=1)
    # The feed recovers: nothing was used.
    tenant.consumption["project"] = saved
    run.step()
    run.step()
    assert run.used(web) == 0
    tenant.set_entity_credits(view="project", name="payments/web", credits=1012)
    run.step()
    assert run.used(web) == 12


def test_a_closed_month_of_a_budget_now_quarterly_is_not_raised(
    db: Session, connected, monkeypatch
) -> None:
    tenant = _tenant()
    connected(tenant)
    run = _Run(db, monkeypatch, datetime(2027, 1, 31, 20, tzinfo=UTC))
    run.step()
    web = _limit(db, EntityType.PROJECT, "proj-web")
    run.step()
    january = run.used(web, "2027-01")
    # Read late in January, not evaluated; then the budget becomes quarterly.
    tenant.set_entity_credits(view="project", name="payments/web", credits=1020)
    run.clock[0] = datetime(2027, 1, 31, 23, 50, tzinfo=UTC)
    run.step(hours=0, evaluate=False)
    limits_service.update_limit(
        db, limit=web, changes={"period_type": PeriodType.QUARTERLY}, actor=ACTOR
    )
    db.commit()
    run.clock[0] = datetime(2027, 2, 1, 1, tzinfo=UTC)
    run.step(hours=0)
    assert run.used(web, "2027-01") == january
    assert run.used(web, "2027-Q1") == 20


def _thirty_day_window(db: Session) -> None:
    from app.services import settings_store

    settings_store.set_value(db, settings_store.KEY_USAGE_PERIOD, "last_30_days")
    db.commit()


def _absent_then_back(tenant, run, at: datetime) -> None:  # type: ignore[no-untyped-def]
    rows = tenant.consumption["project"]
    tenant.consumption["project"] = [r for r in rows if r["name"] != "payments/web"]
    run.clock[0] = at
    run.step(hours=0)
    tenant.consumption["project"] = rows
    run.step()
    run.step()


def test_a_believed_fall_counts_as_a_rise_for_forgetting(
    db: Session, connected, monkeypatch
) -> None:
    """Usage spent while older usage rolled out faster is never seen as a
    rise; the believed fall that hides it keeps the name remembered, so a
    later absence does not bring that usage back as new."""
    _thirty_day_window(db)
    tenant = _tenant()
    connected(tenant)
    run = _Run(db, monkeypatch, datetime(2027, 12, 1, 6, tzinfo=UTC))
    run.step()
    web = _limit(db, EntityType.PROJECT, "proj-web")
    run.step()
    tenant.set_entity_credits(view="project", name="payments/web", credits=1100)
    run.step()  # Dec 1: the last rise
    tenant.set_entity_credits(view="project", name="payments/web", credits=200)
    run.step(hours=24 * 19)  # Dec 20: a believed fall, with new usage in it
    # Jan 5 (35 days after the last rise, 16 after the fall): absent, back.
    _absent_then_back(tenant, run, datetime(2028, 1, 5, 0, 30, tzinfo=UTC))
    assert run.used(web) == 0


def test_a_name_is_remembered_for_two_days_beyond_the_window(
    db: Session, connected, monkeypatch
) -> None:
    """A day-granular or calendar window may still hold usage a little past
    its nominal length: the name is forgotten only two days after it."""
    _thirty_day_window(db)
    tenant = _tenant()
    connected(tenant)
    run = _Run(db, monkeypatch, datetime(2027, 12, 1, 6, tzinfo=UTC))
    run.step()
    web = _limit(db, EntityType.PROJECT, "proj-web")
    run.step()
    tenant.set_entity_credits(view="project", name="payments/web", credits=1100)
    run.step()  # Dec 1: the last rise
    # Dec 31 18:00 (30.5 days later): absent, then back with the same total.
    _absent_then_back(tenant, run, datetime(2027, 12, 31, 18, tzinfo=UTC))
    assert run.used(web) == 100
