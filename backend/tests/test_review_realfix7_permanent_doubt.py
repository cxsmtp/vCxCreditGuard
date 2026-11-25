"""Seventh review of realfix: the completeness check "fewer distinct rows
than the feed says it has" misfires on every reading of a healthy tenant
whose feed carries one row the parser skips (no name, email or id: counted in
totalItems, never in the distinct rows). Every reading is then doubted, no
reading ever confirms a fall, and a name whose older usage really rolled out
of the lookback window has every credit it spends afterwards held back, for
up to the whole lookback window (365 days by default). Nothing reports it."""

# ruff: noqa: F811

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models import UsageMissingName
from app.models.enums import EntityType
from app.services import connection as connection_service
from app.services import evaluation, ingestion, org_sync
from tests.test_real_tenant_usage import connected, live_tenant  # noqa: F401
from tests.test_review_followups import _limit, _state


def test_a_nameless_row_does_not_hold_real_roll_downs_forever(
    db: Session, connected, monkeypatch
) -> None:
    tenant = live_tenant()
    tenant.set_entity_credits(view="project", name="payments/web", credits=1000)
    tenant.set_entity_credits(view="project", name="payments/api", credits=20000)
    # One row with no identity, as the parser already expects to meet.
    tenant.consumption["project"].append({"creditsUsed": "3"})
    connected(tenant)
    client = connection_service.get_client(db)
    clock = [utcnow()]
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
    web = _limit(db, EntityType.PROJECT, "proj-web")
    step()
    tenant.set_entity_credits(view="project", name="payments/web", credits=1010)
    step()
    assert _state(db, web).credits_used == 10
    # Older usage rolls out of the window (a real, complete reading).
    tenant.set_entity_credits(view="project", name="payments/web", credits=400)
    step()
    # Then the project spends 300 credits over the next few days.
    for credits in (500, 600, 700):
        tenant.set_entity_credits(view="project", name="payments/web", credits=credits)
        step(hours=24)
    held = db.scalars(select(UsageMissingName).where(UsageMissingName.kind == "dip")).all()
    assert (_state(db, web).credits_used, [h.subject_key for h in held]) == (310, [])
