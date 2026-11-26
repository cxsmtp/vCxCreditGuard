"""Seventh review of realfix: a project renamed and renamed back. The old name
is remembered (kind missing) with its total from before the first rename; when
it returns, the ledger starts it from that stale total, so the usage the
intermediate name already counted is counted a second time (I1)."""

# ruff: noqa: F811

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models.enums import EntityType
from app.services import connection as connection_service
from app.services import evaluation, ingestion, org_sync
from tests.test_real_tenant_usage import connected, live_tenant  # noqa: F401
from tests.test_review_followups import _limit, _state


def _rename(tenant, old: str, new: str) -> None:  # type: ignore[no-untyped-def]
    for p in tenant.projects:
        if p["id"] == "proj-web":
            p["name"] = new
    for r in tenant.consumption["project"]:
        if r["name"] == old:
            r["name"] = new


@pytest.mark.parametrize("hours_between", [0.5, 6.0])
def test_rename_and_rename_back_counts_each_credit_once(
    db: Session, connected, monkeypatch, hours_between: float
) -> None:
    tenant = live_tenant()
    tenant.set_entity_credits(view="project", name="payments/web", credits=1000)
    tenant.set_entity_credits(view="project", name="payments/api", credits=20000)
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
    group = _limit(db, EntityType.GROUP, "grp-payments")
    step()
    # Renamed, and 20 credits used.
    _rename(tenant, "payments/web", "payments/web2")
    tenant.set_entity_credits(view="project", name="payments/web2", credits=1020)
    step()
    assert _state(db, web).credits_used == 20
    step(hours=hours_between)
    # Renamed back, and 10 more credits used: 30 in all.
    _rename(tenant, "payments/web2", "payments/web")
    tenant.set_entity_credits(view="project", name="payments/web", credits=1030)
    step()
    step()
    assert (_state(db, web).credits_used, _state(db, group).credits_used) == (30, 30)
