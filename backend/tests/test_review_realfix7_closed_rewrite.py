"""Seventh review (should-fix): _settle_closed_periods decides by the budget's
*current* configuration. A closed period counted from totals (count existing
usage on) is rewritten to its ledger counter once the switch is turned off
in a later period."""

# ruff: noqa: F811

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import LimitPeriodState
from app.models.enums import EntityType, PeriodType
from app.services import connection as connection_service
from app.services import evaluation, ingestion, limits_service, org_sync
from tests.test_real_tenant_usage import connected, live_tenant  # noqa: F401
from tests.test_review_followups import ACTOR


def test_a_closed_period_keeps_its_figure_when_the_switch_changes_later(
    db: Session, connected, monkeypatch
) -> None:
    tenant = live_tenant()
    tenant.set_entity_credits(view="project", name="payments/web", credits=1000)
    tenant.set_entity_credits(view="project", name="payments/api", credits=20000)
    connected(tenant)
    client = connection_service.get_client(db)
    clock = [datetime(2027, 1, 20, 6, tzinfo=UTC)]
    monkeypatch.setattr(ingestion, "utcnow", lambda: clock[0])

    def step(hours: float = 1) -> None:
        clock[0] += timedelta(hours=hours)
        org_sync.sync_org_model(db, client)
        db.commit()
        ingestion.ingest_usage(db, client)
        db.commit()
        evaluation.evaluate_all(db, now=clock[0])
        db.commit()

    step()
    web = limits_service.create_limit(
        db,
        data=limits_service.LimitInput(
            entity_type=EntityType.PROJECT,
            entity_id="proj-web",
            credit_limit=5000,
            period_type=PeriodType.MONTHLY,
            enforce=False,
            count_existing_usage=True,
        ),
        actor=ACTOR,
    )
    db.commit()
    step()
    tenant.set_entity_credits(view="project", name="payments/web", credits=1010)
    step()

    def january() -> object:
        db.expire_all()
        return db.scalar(
            select(LimitPeriodState).where(
                LimitPeriodState.limit_id == web.id, LimitPeriodState.period_key == "2027-01"
            )
        ).credits_used

    closed = january()
    step(hours=24 * 14)  # February
    assert january() == closed
    limits_service.update_limit(db, limit=web, changes={"count_existing_usage": False}, actor=ACTOR)
    db.commit()
    step()
    assert january() == closed
