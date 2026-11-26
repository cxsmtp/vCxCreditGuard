"""Fifth review of realfix: a project renamed in Checkmarx while a new project takes its old
name (new id), with the sync learning it before the feed does."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.enums import EntityType
from app.services import cycle
from tests.test_real_tenant_usage import connected, live_tenant  # noqa: F401
from tests.test_review_followups import _limit, _state


def _rename_and_recreate(tenant) -> None:  # type: ignore[no-untyped-def]
    for p in tenant.projects:
        if p["id"] == "proj-web":
            p["name"] = "payments/web-legacy"
    tenant.add_project(project_id="proj-web2", name="payments/web", group_ids=["grp-payments"])


def test_rename_and_recreate_sync_first_never_counts_history(
    db: Session,
    connected,  # noqa: F811
) -> None:
    tenant = live_tenant()
    tenant.set_entity_credits(view="project", name="payments/web", credits=1000)
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    web = _limit(db, EntityType.PROJECT, "proj-web")
    group = _limit(db, EntityType.GROUP, "grp-payments")
    cycle.run_cycle(trigger="manual")
    # 50 credits of real usage in the period.
    tenant.set_entity_credits(view="project", name="payments/web", credits=1050)
    cycle.run_cycle(trigger="manual")
    assert _state(db, web).credits_used == 50
    assert _state(db, group).credits_used == 50

    # The sync learns first: proj-web is now "payments/web-legacy", and a new
    # project proj-web2 took the name "payments/web". The feed still reports the
    # old name with proj-web's history.
    _rename_and_recreate(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    cycle.run_cycle(trigger="manual")
    after_sync = (_state(db, web).credits_used, _state(db, group).credits_used)

    # Then the feed catches up: proj-web's history under its new name, nothing
    # under the old one (proj-web2 has not been used yet).
    tenant.consumption["project"] = [
        r for r in tenant.consumption["project"] if r["name"] != "payments/web"
    ]
    tenant.set_entity_credits(view="project", name="payments/web-legacy", credits=1050)
    for _ in range(3):
        cycle.run_cycle(trigger="manual")
    web_state, group_state = _state(db, web), _state(db, group)
    # I1: no history becomes usage. I2: the 50 counted stays.
    assert web_state.credits_used == 50, (
        after_sync,
        web_state.credits_used,
        web_state.baseline_credits,
    )
    assert group_state.credits_used == 50, (after_sync, group_state.credits_used)
