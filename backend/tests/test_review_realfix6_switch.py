"""Sixth review of realfix: a period budget switched to "count existing usage"
and back within one period. While it counts existing usage it is not fed by
the ledger, so the increases observed meanwhile are lost from the period once
it is a period budget again (not among the documented losses)."""

# ruff: noqa: F811 - the connected fixture is imported by name

from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.enums import EntityType
from app.services import cycle, limits_service
from tests.test_real_tenant_usage import connected, live_tenant  # noqa: F401
from tests.test_review_followups import ACTOR, _limit, _state


def test_switch_to_count_existing_and_back_loses_the_increases(
    db: Session,
    connected,  # noqa: F811
) -> None:
    tenant = live_tenant()
    tenant.set_entity_credits(view="project", name="payments/web", credits=1000)
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    web = _limit(db, EntityType.PROJECT, "proj-web")
    cycle.run_cycle(trigger="manual")
    tenant.set_entity_credits(view="project", name="payments/web", credits=1010)
    cycle.run_cycle(trigger="manual")
    assert _state(db, web).credits_used == 10
    limits_service.update_limit(db, limit=web, changes={"count_existing_usage": True}, actor=ACTOR)
    db.commit()
    tenant.set_entity_credits(view="project", name="payments/web", credits=1050)
    cycle.run_cycle(trigger="manual")
    limits_service.update_limit(db, limit=web, changes={"count_existing_usage": False}, actor=ACTOR)
    db.commit()
    cycle.run_cycle(trigger="manual")
    # 50 credits were observed this period while the name counted towards proj-web.
    used = _state(db, web).credits_used
    assert used == 50, used
