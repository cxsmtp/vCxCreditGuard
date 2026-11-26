"""Review 4: a rename the feed reports first, with the org sync more than
hold_readings readings away (a 2-minute cycle and the default 30-minute org
refresh is 15 readings; hold_readings defaults to 8). The old name's carry
runs out, budgets lower their baselines, and when the sync brings the new
name it counts "in full": the project's history becomes this period's usage.

Synthetic data only (tests/fake_tenant.py).
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.enums import EntityType
from app.services import cycle
from tests.test_real_tenant_usage import connected, live_tenant  # noqa: F401
from tests.test_review_followups import _limit, _state


def test_rename_with_the_sync_15_readings_away(
    db: Session,
    connected,  # noqa: F811
) -> None:
    tenant = live_tenant()
    tenant.set_entity_credits(view="project", name="payments/web", credits=1000, entity_id=None)
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    project = _limit(db, EntityType.PROJECT, "proj-web")
    cycle.run_cycle(trigger="manual")  # baseline 1000
    tenant.set_entity_credits(view="project", name="payments/web", credits=1100, entity_id=None)
    cycle.run_cycle(trigger="manual")
    assert _state(db, project).credits_used == 100

    for p in tenant.projects:
        if p["id"] == "proj-web":
            p["name"] = "payments/web-v2"
    rows = tenant.consumption["project"]
    tenant.consumption["project"] = [r for r in rows if r["name"] != "payments/web"]
    tenant.set_entity_credits(view="project", name="payments/web-v2", credits=1100)
    for _ in range(14):  # 2-minute cycles until the 30-minute org refresh
        cycle.run_cycle(trigger="manual")
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    cycle.run_cycle(trigger="manual")
    state = _state(db, project)
    assert state.credits_used == 100, (state.credits_used, state.baseline_credits)
