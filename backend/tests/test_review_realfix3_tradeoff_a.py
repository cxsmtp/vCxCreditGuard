"""Third review of realfix, trade-off (a): unmapping a name that added usage in
an earlier period must not take the target's own usage of this period with it.

Synthetic data only (tests/fake_tenant.py).
"""

from __future__ import annotations

from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models.enums import EntityType
from app.services import connection as connection_service
from app.services import cycle, evaluation, ingestion
from tests.test_real_tenant_usage import connected, live_tenant  # noqa: F401
from tests.test_review_followups import NAME, _limit, _map, _state


def test_unmap_after_rollover_keeps_the_targets_own_usage(
    db: Session,
    connected,  # noqa: F811
    admin_client: TestClient,
) -> None:
    tenant = live_tenant()
    tenant.set_entity_credits(view="project", name=NAME, credits=870)
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    project = _limit(db, EntityType.PROJECT, "proj-api")
    cycle.run_cycle(trigger="manual")  # baseline 8
    _map(admin_client, "proj-api")
    tenant.set_entity_credits(view="project", name=NAME, credits=920)  # +50 while mapped
    cycle.run_cycle(trigger="manual")
    assert _state(db, project).credits_used == 50

    # Next month: the new period's baseline is 8 + 50.
    now = utcnow()
    next_month = (now.replace(day=1) + timedelta(days=32)).replace(day=2)
    evaluation.evaluate_all(db, now=next_month)
    db.commit()
    # The project itself spends 5 in the new period.
    tenant.set_entity_credits(view="project", name="payments/api", credits=13, entity_id="proj-api")
    ingestion.ingest_usage(db, connection_service.get_client(db))
    db.commit()
    evaluation.evaluate_all(db, now=next_month + timedelta(hours=1))
    db.commit()
    assert _state_for(db, project, next_month).credits_used == 5

    _map(admin_client, None)
    evaluation.evaluate_all(db, now=next_month + timedelta(hours=2))
    db.commit()
    state = _state_for(db, project, next_month)
    # The 5 the project itself spent this period still count.
    assert state.credits_used == 5, (state.credits_used, state.baseline_credits)


def _state_for(db, limit, moment):  # type: ignore[no-untyped-def]
    from sqlalchemy import select

    from app.models import LimitPeriodState

    db.expire_all()
    return db.scalar(
        select(LimitPeriodState)
        .where(LimitPeriodState.limit_id == limit.id)
        .order_by(LimitPeriodState.period_start.desc())
        .limit(1)
    )
