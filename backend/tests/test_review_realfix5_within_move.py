"""Fifth review of realfix: a name mapped during the period (so not in the period's
baseline_names) and then remapped to another project of the same group or
application: the budget loses what the name counted there, although the move
stays inside the budget ("nothing is lost or gained there")."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.enums import EntityType
from app.services import cycle
from tests.test_real_tenant_usage import connected, live_tenant  # noqa: F401
from tests.test_review_followups import NAME, _limit, _map, _state


@pytest.mark.parametrize(
    "budget", [(EntityType.GROUP, "grp-payments"), (EntityType.APPLICATION, "app-payments")]
)
def test_move_within_a_budget_of_a_name_mapped_this_period(
    db: Session,
    connected,  # noqa: F811
    admin_client: TestClient,
    budget,  # type: ignore[no-untyped-def]
) -> None:
    tenant = live_tenant()
    tenant.consumption["application"] = []
    tenant.set_entity_credits(view="project", name=NAME, credits=870)
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    limit = _limit(db, *budget)
    cycle.run_cycle(trigger="manual")
    _map(admin_client, "proj-api")
    tenant.set_entity_credits(view="project", name=NAME, credits=900)
    cycle.run_cycle(trigger="manual")
    assert _state(db, limit).credits_used == 30
    _map(admin_client, "proj-web")  # the admin corrects the project, same group/app
    cycle.run_cycle(trigger="manual")
    state = _state(db, limit)
    assert state.credits_used == 30, (state.credits_used, state.baseline_credits)
