"""Review 4: re-mapping a name from one project to another project of the same
group: for the group's budget nothing moved, yet it loses the name's usage
within the period.

Synthetic data only (tests/fake_tenant.py).
"""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.enums import EntityType
from app.services import cycle
from tests.test_real_tenant_usage import connected, live_tenant  # noqa: F401
from tests.test_review_followups import NAME, _limit, _map, _state


def test_moving_a_name_within_a_group_keeps_the_groups_period(
    db: Session,
    connected,  # noqa: F811
    admin_client: TestClient,
) -> None:
    tenant = live_tenant()
    tenant.set_entity_credits(view="project", name=NAME, credits=870)
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    _map(admin_client, "proj-api")
    group = _limit(db, EntityType.GROUP, "grp-payments")
    cycle.run_cycle(trigger="manual")  # baseline 12
    tenant.set_entity_credits(view="project", name=NAME, credits=920)  # +50 this period
    cycle.run_cycle(trigger="manual")
    assert _state(db, group).credits_used == 50

    _map(admin_client, "proj-web")  # same group
    cycle.run_cycle(trigger="manual")
    state = _state(db, group)
    assert state.credits_used == 50, (state.credits_used, state.baseline_credits)
