"""Fifth review of realfix: a rename the feed reports first, with the sync bringing it only
after a period rollover (a 7-day org refresh). The renamed name takes over in
full, so what it reported in the previous period lands in the new one."""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models import LimitPeriodState
from app.models.enums import EntityType
from app.services import connection as connection_service
from app.services import cycle, evaluation, ingestion, org_sync
from tests.test_real_tenant_usage import connected, live_tenant  # noqa: F401
from tests.test_review_followups import _limit


def test_feed_first_rename_across_a_rollover(db: Session, connected) -> None:  # noqa: F811
    tenant = live_tenant()
    tenant.set_entity_credits(view="project", name="payments/web", credits=1000)
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    web = _limit(db, EntityType.PROJECT, "proj-web")
    cycle.run_cycle(trigger="manual")
    # Feed first: the history and 200 credits of last month's usage under the new name.
    tenant.consumption["project"] = [
        r for r in tenant.consumption["project"] if r["name"] != "payments/web"
    ]
    tenant.set_entity_credits(view="project", name="payments/web2", credits=1200)
    client = connection_service.get_client(db)
    for _ in range(3):
        ingestion.ingest_usage(db, client)
        db.commit()
    next_month = (utcnow().replace(day=1) + timedelta(days=32)).replace(day=2)
    evaluation.evaluate_all(db, now=next_month)
    db.commit()
    # The sync brings the rename in the new month; no usage since the rollover.
    for p in tenant.projects:
        if p["id"] == "proj-web":
            p["name"] = "payments/web2"
    org_sync.sync_org_model(db, client)
    db.commit()
    ingestion.ingest_usage(db, client)
    db.commit()
    evaluation.evaluate_all(db, now=next_month + timedelta(hours=1))
    db.commit()
    db.expire_all()
    state = db.scalar(
        select(LimitPeriodState)
        .where(LimitPeriodState.limit_id == web.id)
        .order_by(LimitPeriodState.period_start.desc())
    )
    assert state.credits_used == 0, (state.period_key, state.credits_used, state.baseline_credits)
