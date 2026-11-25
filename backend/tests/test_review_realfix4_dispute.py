"""Fourth review of realfix: a user's consumption subject that becomes
disputed (a second person with the same name is synced) used to stop counting
at once, and the admin's resolution (mapping it back to the same user)
anchored it afresh, so the period's usage of that subject was lost. It now
keeps counting, flagged, until resolved, and mapping it back changes nothing.

Synthetic data only (tests/fake_tenant.py).
"""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import UnresolvedSubject, UsageRecord
from app.models.enums import EntityType
from app.services import cycle, ingestion
from tests.test_real_tenant_usage import connected, live_tenant  # noqa: F401
from tests.test_review_followups import _limit, _state


def test_a_dispute_resolved_back_to_the_same_user_keeps_the_period(
    db: Session,
    connected,  # noqa: F811
    admin_client: TestClient,
) -> None:
    tenant = live_tenant()
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    bob = _limit(db, EntityType.USER, "user-bob")
    cycle.run_cycle(trigger="manual")  # baseline 5
    tenant.set_user_credits(name="Bob Baker", credits=105)
    cycle.run_cycle(trigger="manual")
    assert _state(db, bob).credits_used == 100

    # A second Bob Baker joins: "Bob Baker" no longer resolves on its own.
    tenant.add_user(
        user_id="user-bob2",
        username="bob.baker",
        email=None,
        first_name="Bob",
        last_name="Baker",
    )
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    db.expire_all()
    latest = ingestion.latest_live_snapshot(db, "user")
    row = db.scalar(
        select(UsageRecord).where(
            UsageRecord.snapshot_id == latest.id, UsageRecord.subject_key == "bob baker"
        )
    )
    subject = db.scalar(
        select(UnresolvedSubject).where(UnresolvedSubject.subject_key == "bob baker")
    )
    # Disputed, and raised for the admin, but it keeps counting towards the
    # user it counted towards (flagged as kept) until the admin resolves it.
    assert subject is not None and subject.status == "disputed", subject and subject.status
    assert row.entity_id == "user-bob" and row.held_reason == ingestion.HELD_KEPT
    assert _state(db, bob).credits_used == 100

    # The admin settles it: this subject is the original Bob.
    r = admin_client.post(f"/api/usage/unresolved/{subject.id}/map", json={"user_id": "user-bob"})
    assert r.status_code == 200, r.text
    cycle.run_cycle(trigger="manual")
    state = _state(db, bob)
    assert state.credits_used == 100, (state.credits_used, state.baseline_credits)
