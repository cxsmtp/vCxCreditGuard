"""Review 4: a project whose deletion is settled (two complete listings, or
hold_readings readings) and that then comes back. Its names count "in full"
again while every budget it fed lowered its baseline when it left: the
pre-period history comes back as this period's usage.

Synthetic data only (tests/fake_tenant.py).
"""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from app.models.enums import EntityType
from app.models.org import CxProject
from app.services import cycle
from tests.test_real_tenant_usage import connected, live_tenant  # noqa: F401
from tests.test_review_followups import _limit, _state


@pytest.mark.parametrize(
    "settled_by", ["two_complete_listings", "hold_readings", "control_one_listing"]
)
def test_a_project_that_comes_back_brings_no_history(
    db: Session,
    connected,  # noqa: F811
    settled_by: str,
) -> None:
    tenant = live_tenant()
    # A long-lived project: 1,000 credits of history inside the lookback window.
    tenant.set_entity_credits(view="project", name="payments/web", credits=1000, entity_id=None)
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    project = _limit(db, EntityType.PROJECT, "proj-web")
    group = _limit(db, EntityType.GROUP, "grp-payments")
    cycle.run_cycle(trigger="manual")  # baselines: 1000 and 1008
    tenant.set_entity_credits(view="project", name="payments/web", credits=1100, entity_id=None)
    cycle.run_cycle(trigger="manual")
    assert _state(db, project).credits_used == 100
    assert _state(db, group).credits_used == 100

    # A complete listing without the project (it is briefly invisible to the
    # key, or the tenant answers a consistent but short listing).
    web = next(p for p in tenant.projects if p["id"] == "proj-web")
    tenant.projects.remove(web)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    db.expire_all()
    assert db.get(CxProject, "proj-web").is_deleted
    if settled_by == "two_complete_listings":
        cycle.run_cycle(trigger="manual", force_org_sync=True)
    elif settled_by == "hold_readings":
        for _ in range(3):
            cycle.run_cycle(trigger="manual")
    cycle.run_cycle(trigger="manual")

    # It comes back; nobody spent anything.
    tenant.projects.append(web)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    cycle.run_cycle(trigger="manual")
    p, g = _state(db, project), _state(db, group)
    # Never more than what was spent this period (over-counting restricts).
    assert p.credits_used <= 100, (p.credits_used, p.baseline_credits)
    assert g.credits_used <= 100, (g.credits_used, g.baseline_credits)
