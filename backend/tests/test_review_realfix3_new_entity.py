"""Third review of realfix: an entity created in Checkmarx whose first usage is read before
the next org sync never has that usage counted (it is anchored away when the
sync brings the entity).

Synthetic data only (tests/fake_tenant.py).
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.enums import EntityType
from app.services import cycle
from tests.test_real_tenant_usage import connected, live_tenant  # noqa: F401
from tests.test_review_followups import _limit, _state


def test_a_new_projects_first_scan_counts_towards_its_group(
    db: Session,
    connected,  # noqa: F811
) -> None:
    tenant = live_tenant()
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    group = _limit(db, EntityType.GROUP, "grp-payments")
    cycle.run_cycle(trigger="manual")  # baseline 12
    # A team creates a project and scans it at once, between two org syncs.
    tenant.add_project(project_id="proj-new", name="payments/new", group_ids=["grp-payments"])
    tenant.set_entity_credits(view="project", name="payments/new", credits=400)
    cycle.run_cycle(trigger="manual")  # org sync not due: the name is unmatched
    cycle.run_cycle(trigger="manual", force_org_sync=True)  # the sync brings it
    state = _state(db, group)
    assert state.credits_used == 400, (state.credits_used, state.baseline_credits)


def test_a_new_users_first_usage_counts_towards_their_budget(
    db: Session,
    connected,  # noqa: F811
) -> None:
    tenant = live_tenant()
    tenant.add_user(
        user_id="user-dan",
        username="dan.doe@example.com",
        email="dan.doe@example.com",
        first_name="Dan",
        last_name="Doe",
        groups=["Payments"],
    )
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    group = _limit(db, EntityType.GROUP, "grp-payments", existing=False)
    group.include_member_usage = True
    db.commit()
    cycle.run_cycle(trigger="manual")
    # A new hire, added to IAM and spending before the next org sync.
    tenant.add_user(
        user_id="user-eve",
        username="eve.evans@example.com",
        email="eve.evans@example.com",
        first_name="Eve",
        last_name="Evans",
        groups=["Payments"],
    )
    tenant.set_user_credits(name="Eve Evans", email="eve.evans@example.com", credits=300)
    cycle.run_cycle(trigger="manual")
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    eve = _limit(db, EntityType.USER, "user-eve")  # noqa: F841 (created after; see group)
    state = _state(db, group)
    assert state.credits_used == 300, (state.credits_used, state.baseline_credits)
