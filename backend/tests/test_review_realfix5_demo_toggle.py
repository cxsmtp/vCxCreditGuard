"""Fifth review of realfix: turning demo mode on and off again must not turn a real budget's
history into period usage. Synthetic data only."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.enums import EntityType
from app.services import cycle
from tests.test_real_tenant_usage import connected, live_tenant  # noqa: F401
from tests.test_review_followups import _limit, _state


def test_demo_on_and_off_counts_no_history(
    db: Session,
    connected,  # noqa: F811
    admin_client: TestClient,
) -> None:
    tenant = live_tenant()
    tenant.set_entity_credits(view="project", name="payments/web", credits=5000)
    tenant.set_user_credits(name="Bob Baker", credits=4000)
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    web = _limit(db, EntityType.PROJECT, "proj-web")
    bob = _limit(db, EntityType.USER, "user-bob")
    cycle.run_cycle(trigger="manual")
    assert _state(db, web).credits_used == 0

    assert admin_client.post("/api/ops/demo/seed").status_code == 200
    cycle.run_cycle(trigger="manual")
    assert admin_client.post("/api/ops/demo/clear").status_code == 200
    cycle.run_cycle(trigger="manual")
    web_state, bob_state = _state(db, web), _state(db, bob)
    assert (web_state.credits_used, bob_state.credits_used) == (0, 0), (
        web_state.credits_used,
        web_state.baseline_credits,
        bob_state.credits_used,
    )


def test_demo_mode_setting_on_and_off_counts_no_history(
    db: Session,
    connected,  # noqa: F811
    admin_client: TestClient,
) -> None:
    tenant = live_tenant()
    tenant.set_entity_credits(view="project", name="payments/web", credits=5000)
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    web = _limit(db, EntityType.PROJECT, "proj-web")
    cycle.run_cycle(trigger="manual")
    assert admin_client.post("/api/ops/demo/seed").status_code == 200
    cycle.run_cycle(trigger="manual")
    # Demo mode switched off in Settings, demo data left in place.
    assert admin_client.put("/api/settings", json={"demo_mode": False}).status_code == 200
    cycle.run_cycle(trigger="manual")
    state = _state(db, web)
    assert state.credits_used == 0, (state.credits_used, state.baseline_credits)
