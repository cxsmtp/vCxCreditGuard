"""Seventh review of realfix: a project whose usage ages out of the lookback
window leaves the feed (a name is listed only while it has usage in the
window). It is remembered as missing with its old total, and forgotten only
once its *last sighting* is older than the lookback window. Used again before
that, its new usage is compared with the stale total: up to all of it reads
as a fall and is never counted. Not among the documented under-counts.

Here (last_30_days): the project's last rise is observed on day 0, its usage
has all aged out by day 31 (it leaves the feed), and on day 33 it spends 80
new credits, which are compared with the 110 it last had."""

# ruff: noqa: F811

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import LimitPeriodState
from app.models.enums import EntityType, PeriodType
from app.services import connection as connection_service
from app.services import evaluation, ingestion, limits_service, org_sync, settings_store
from tests.test_real_tenant_usage import connected, live_tenant  # noqa: F401
from tests.test_review_followups import ACTOR


def test_usage_after_a_name_aged_out_counts(db: Session, connected, monkeypatch) -> None:
    settings_store.set_value(db, settings_store.KEY_USAGE_PERIOD, "last_30_days")
    db.commit()
    tenant = live_tenant()
    tenant.set_entity_credits(view="project", name="payments/web", credits=100)
    tenant.set_entity_credits(view="project", name="payments/api", credits=20000)
    connected(tenant)
    client = connection_service.get_client(db)
    clock = [datetime(2027, 1, 1, 6, tzinfo=UTC)]
    monkeypatch.setattr(ingestion, "utcnow", lambda: clock[0])

    def step(hours: float = 0.5) -> None:
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
            credit_limit=1000,
            period_type=PeriodType.QUARTERLY,
            enforce=False,
        ),
        actor=ACTOR,
    )
    db.commit()
    step()
    tenant.set_entity_credits(view="project", name="payments/web", credits=110)
    step()  # day 0: a rise of 10, counted
    for _ in range(30):
        step(hours=24)
    # Day 31: everything it had is older than 30 days; the feed stops listing it.
    tenant.consumption["project"] = [
        r for r in tenant.consumption["project"] if r["name"] != "payments/web"
    ]
    step(hours=24)
    step(hours=48)
    # Day 33: used again, 80 credits, all new.
    tenant.set_entity_credits(view="project", name="payments/web", credits=80)
    step()
    step()
    db.expire_all()
    state = db.scalar(select(LimitPeriodState).where(LimitPeriodState.limit_id == web.id))
    assert (state.period_key, state.credits_used) == ("2027-Q1", 90)
