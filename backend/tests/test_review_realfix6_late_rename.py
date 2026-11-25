"""Sixth review of realfix (should-fix): the first-sighting rule assumes a name
absent from the previous reading had nothing. A project whose row is absent
for longer than one org refresh + 1h and then comes back under a new name
(the sync already knows the rename) counts its whole history."""

# ruff: noqa: F811 - the connected fixture is imported by name

from __future__ import annotations

from datetime import timedelta

from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models.enums import EntityType
from app.services import connection as connection_service
from app.services import evaluation, ingestion, org_sync
from tests.test_real_tenant_usage import connected, live_tenant  # noqa: F401
from tests.test_review_followups import _limit, _state


def test_rename_after_a_long_absence_counts_history(
    db: Session,
    connected,
    monkeypatch,  # noqa: F811
) -> None:
    tenant = live_tenant()
    tenant.set_entity_credits(view="project", name="payments/web", credits=1000)
    # Enough other usage that the absence is not a collapse of the whole feed.
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
    step()
    # The row is absent from the feed for a few hours ...
    saved = [r for r in tenant.consumption["project"] if r["name"] == "payments/web"]
    tenant.consumption["project"] = [
        r for r in tenant.consumption["project"] if r["name"] != "payments/web"
    ]
    step()
    step(hours=3)
    # ... and comes back under the project's new name, with the same history.
    for p in tenant.projects:
        if p["id"] == "proj-web":
            p["name"] = "payments/web2"
    row = dict(saved[0], name="payments/web2")
    tenant.consumption["project"].append(row)
    step()
    assert _state(db, web).credits_used == 0, _state(db, web).credits_used
