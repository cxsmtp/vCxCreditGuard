"""Sixth review of realfix: an increase observed before a period rolled over
must not land in the new period's counter (I1)."""

# ruff: noqa: F811 - the connected fixture is imported by name

from __future__ import annotations

from datetime import timedelta
from decimal import Decimal

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models import LimitPeriodState, UsageDelta
from app.models.enums import EntityType
from app.services import connection as connection_service
from app.services import cycle, evaluation, ingestion
from app.services.periods import current_window
from tests.test_real_tenant_usage import connected, live_tenant  # noqa: F401
from tests.test_review_followups import _limit


def _states(db: Session, limit) -> dict[str, Decimal]:  # type: ignore[no-untyped-def]
    db.expire_all()
    return {
        s.period_key: s.credits_used
        for s in db.scalars(select(LimitPeriodState).where(LimitPeriodState.limit_id == limit.id))
    }


def test_increase_observed_before_rollover_lands_in_new_period(
    db: Session,
    connected,  # noqa: F811
) -> None:
    tenant = live_tenant()
    tenant.set_entity_credits(view="project", name="payments/web", credits=1000)
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    web = _limit(db, EntityType.PROJECT, "proj-web")
    cycle.run_cycle(trigger="manual")  # this month's period opens, counter 0
    this_month = current_window(web, utcnow()).key

    # 30 credits spent this month, observed by a reading taken this month ...
    tenant.set_entity_credits(view="project", name="payments/web", credits=1030)
    client = connection_service.get_client(db)
    ingestion.ingest_usage(db, client)
    db.commit()
    delta = db.scalar(select(UsageDelta).where(UsageDelta.subject_key == "payments/web"))
    assert delta is not None and delta.credits == 30
    # ... but evaluated (the cycle's later step, or the next cycle) after midnight.
    next_month = (utcnow().replace(day=1) + timedelta(days=32)).replace(
        day=1, hour=0, minute=1, second=0, microsecond=0
    )
    assert delta.observed_at < next_month
    evaluation.evaluate_all(db, now=next_month)
    db.commit()
    states = _states(db, web)
    new_key = current_window(web, next_month).key
    # The usage was observed in this month: it must not be new-month usage.
    assert states.get(new_key, Decimal(0)) == 0, states
    assert states.get(this_month) == 30, states


def test_downtime_across_rollover_brings_last_month_into_new_period(
    db: Session,
    connected,
    monkeypatch,  # noqa: F811
) -> None:
    """The tool is down (or in demo mode) from the 25th to the 3rd: every credit
    spent from the 25th to the 30th lands in the new month's counter."""
    tenant = live_tenant()
    tenant.set_entity_credits(view="project", name="payments/web", credits=1000)
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    web = _limit(db, EntityType.PROJECT, "proj-web")
    cycle.run_cycle(trigger="manual")
    # Spent this month, after the last reading; nothing more after the rollover.
    tenant.set_entity_credits(view="project", name="payments/web", credits=1090)
    third = (utcnow().replace(day=1) + timedelta(days=32)).replace(
        day=3, hour=9, minute=0, second=0, microsecond=0
    )
    monkeypatch.setattr(ingestion, "utcnow", lambda: third)
    client = connection_service.get_client(db)
    ingestion.ingest_usage(db, client)
    db.commit()
    evaluation.evaluate_all(db, now=third)
    db.commit()
    states = _states(db, web)
    # History from before the period began must never land in its counter.
    assert states.get(current_window(web, third).key, Decimal(0)) == 0, states
