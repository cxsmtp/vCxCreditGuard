"""Seventh review of realfix: README says every active budget is fed whatever
its period type, so "switching it back mid-period loses nothing". That holds
for count_existing_usage, but not for a period-type switch: while a monthly
budget is lifetime (or custom), its increases go to the "lifetime" counter,
so switched back to monthly in the same month it has lost them."""

# ruff: noqa: F811

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import LimitPeriodState
from app.models.enums import EntityType, PeriodType
from app.services import connection as connection_service
from app.services import evaluation, ingestion, limits_service, org_sync
from tests.test_real_tenant_usage import connected, live_tenant  # noqa: F401
from tests.test_review_followups import ACTOR


@pytest.mark.parametrize("interlude", [PeriodType.LIFETIME, "existing"])
def test_switching_a_monthly_budget_away_and_back_loses_nothing(
    db: Session, connected, monkeypatch, interlude
) -> None:
    tenant = live_tenant()
    tenant.set_entity_credits(view="project", name="payments/web", credits=1000)
    tenant.set_entity_credits(view="project", name="payments/api", credits=20000)
    connected(tenant)
    client = connection_service.get_client(db)
    clock = [datetime(2027, 1, 5, 6, tzinfo=UTC)]
    monkeypatch.setattr(ingestion, "utcnow", lambda: clock[0])

    def step(credits: int | None = None) -> None:
        if credits is not None:
            tenant.set_entity_credits(view="project", name="payments/web", credits=credits)
        clock[0] += timedelta(hours=1)
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
        ),
        actor=ACTOR,
    )
    db.commit()
    step()
    step(1010)  # 10 this month

    def switch(changes: dict) -> None:
        limits_service.update_limit(db, limit=web, changes=changes, actor=ACTOR)
        db.commit()

    if interlude == "existing":
        switch({"count_existing_usage": True})
    else:
        switch({"period_type": interlude})
    step(1030)  # 20 more
    if interlude == "existing":
        switch({"count_existing_usage": False})
    else:
        switch({"period_type": PeriodType.MONTHLY})
    step(1035)  # 5 more
    db.expire_all()
    state = db.scalar(
        select(LimitPeriodState).where(
            LimitPeriodState.limit_id == web.id, LimitPeriodState.period_key == "2027-01"
        )
    )
    assert state.credits_used == 35
