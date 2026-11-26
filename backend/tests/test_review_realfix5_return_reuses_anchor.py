"""Fifth review of realfix: an entity whose deletion was confirmed comes back (same id).
A mapped name re-uses its old anchor, so everything it reported since it was
mapped - history from before the current period - becomes the new period's
usage. Synthetic data only."""

from __future__ import annotations

from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models import LimitPeriodState
from app.models.enums import EntityType
from app.services import connection as connection_service
from app.services import cycle, evaluation, ingestion
from tests.test_real_tenant_usage import connected, live_tenant  # noqa: F401
from tests.test_review_followups import NAME, _limit, _map


def _state_for(db, limit, moment):  # type: ignore[no-untyped-def]
    db.expire_all()
    return db.scalar(
        select(LimitPeriodState)
        .where(
            LimitPeriodState.limit_id == limit.id,
            LimitPeriodState.period_start <= moment,
        )
        .order_by(LimitPeriodState.period_start.desc())
    )


def test_returning_project_does_not_bring_mapped_history_into_a_new_period(
    db: Session,
    connected,  # noqa: F811
    admin_client: TestClient,
) -> None:
    tenant = live_tenant()
    tenant.set_entity_credits(view="project", name=NAME, credits=870)
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    project = _limit(db, EntityType.PROJECT, "proj-api")
    cycle.run_cycle(trigger="manual")
    _map(admin_client, "proj-api")  # anchored at 870
    tenant.set_entity_credits(view="project", name=NAME, credits=1870)  # +1000 this month
    cycle.run_cycle(trigger="manual")

    # proj-api disappears from Checkmarx (for example the key lost sight of it,
    # or it was archived), its deletion is confirmed, and the name is released.
    saved = [p for p in tenant.projects if p["id"] == "proj-api"]
    tenant.projects = [p for p in tenant.projects if p["id"] != "proj-api"]
    for _ in range(3):
        cycle.run_cycle(trigger="manual", force_org_sync=True)
    for _ in range(9):
        ingestion.ingest_usage(db, connection_service.get_client(db))
        db.commit()

    # Next month opens while it is gone.
    next_month = (utcnow().replace(day=1) + timedelta(days=32)).replace(day=2)
    evaluation.evaluate_all(db, now=next_month)
    db.commit()

    # It comes back, same id, with no new usage at all.
    tenant.projects.extend(saved)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    ingestion.ingest_usage(db, connection_service.get_client(db))
    db.commit()
    evaluation.evaluate_all(db, now=next_month + timedelta(hours=1))
    db.commit()
    state = _state_for(db, project, next_month)
    assert state.credits_used == 0, (state.credits_used, state.baseline_credits)
