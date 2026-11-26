"""Fifth review of realfix: a project that joins a group (or an application, through the
application fallback) mid-period brings its whole history into that budget's
period. Synthetic data only."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.enums import EntityType
from app.services import cycle
from tests.test_real_tenant_usage import connected, live_tenant  # noqa: F401
from tests.test_review_followups import _limit, _state


def test_project_joining_a_group_brings_no_history(db: Session, connected) -> None:  # noqa: F811
    tenant = live_tenant()
    tenant.set_entity_credits(view="project", name="platform/tools", credits=5000)
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    group = _limit(db, EntityType.GROUP, "grp-payments")
    cycle.run_cycle(trigger="manual")
    assert _state(db, group).credits_used == 0
    # proj-tools is moved into Payments in Checkmarx; no new usage anywhere.
    for p in tenant.projects:
        if p["id"] == "proj-tools":
            p["groups"] = ["grp-payments"]
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    cycle.run_cycle(trigger="manual")
    state = _state(db, group)
    assert state.credits_used == 0, (state.credits_used, state.baseline_credits)


def test_project_joining_an_application_fallback_brings_no_history(
    db: Session,
    connected,  # noqa: F811
) -> None:
    tenant = live_tenant()
    # No application row: the application's figure is the sum of its projects.
    tenant.consumption["application"] = []
    tenant.set_entity_credits(view="project", name="platform/tools", credits=5000)
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    app = _limit(db, EntityType.APPLICATION, "app-payments")
    cycle.run_cycle(trigger="manual")
    assert _state(db, app).credits_used == 0
    for a in tenant.applications:
        if a["id"] == "app-payments":
            a["projectIds"].append("proj-tools")
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    cycle.run_cycle(trigger="manual")
    state = _state(db, app)
    assert state.credits_used == 0, (state.credits_used, state.baseline_credits)


def test_project_leaving_a_group_keeps_period_usage(db: Session, connected) -> None:  # noqa: F811
    tenant = live_tenant()
    tenant.set_entity_credits(view="project", name="payments/web", credits=1000)
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    group = _limit(db, EntityType.GROUP, "grp-payments")
    cycle.run_cycle(trigger="manual")
    tenant.set_entity_credits(view="project", name="payments/api", credits=58)  # +50 in period
    cycle.run_cycle(trigger="manual")
    assert _state(db, group).credits_used == 50
    for p in tenant.projects:
        if p["id"] == "proj-web":
            p["groups"] = ["grp-platform"]
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    cycle.run_cycle(trigger="manual")
    state = _state(db, group)
    assert state.credits_used == 50, (state.credits_used, state.baseline_credits)


def test_one_sync_flap_of_a_group_link_counts_no_history(db: Session, connected) -> None:  # noqa: F811
    tenant = live_tenant()
    tenant.set_entity_credits(view="project", name="payments/web", credits=5000)
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    group = _limit(db, EntityType.GROUP, "grp-payments")
    cycle.run_cycle(trigger="manual")
    web = next(p for p in tenant.projects if p["id"] == "proj-web")
    # One complete project listing returns proj-web without its group.
    web["groups"] = []
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    web["groups"] = ["grp-payments"]
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    cycle.run_cycle(trigger="manual")
    state = _state(db, group)
    assert state.credits_used == 0, (state.credits_used, state.baseline_credits)
