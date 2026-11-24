"""Third review of realfix: a project renamed in Checkmarx. The feed reports the project's
usage under its new name; the org sync learns the new name on its own
schedule. Either order must leave the period's usage as it was.

Synthetic data only (tests/fake_tenant.py).
"""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from app.models.enums import EntityType
from app.services import cycle
from tests.test_real_tenant_usage import connected, live_tenant  # noqa: F401
from tests.test_review_followups import _limit, _state


def _rename_in_tenant(tenant) -> None:  # type: ignore[no-untyped-def]
    for project in tenant.projects:
        if project["id"] == "proj-web":
            project["name"] = "payments/web-v2"


def _rename_in_feed(tenant) -> None:  # type: ignore[no-untyped-def]
    rows = tenant.consumption["project"]
    tenant.consumption["project"] = [r for r in rows if r["name"] != "payments/web"]
    tenant.set_entity_credits(view="project", name="payments/web-v2", credits=104)


@pytest.mark.parametrize("sync_first", [True, False])
def test_rename_keeps_the_periods_usage(
    db: Session,
    connected,  # noqa: F811
    sync_first: bool,
) -> None:
    tenant = live_tenant()
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    project = _limit(db, EntityType.PROJECT, "proj-web")
    cycle.run_cycle(trigger="manual")  # baseline 4
    tenant.set_entity_credits(view="project", name="payments/web", credits=104)
    cycle.run_cycle(trigger="manual")
    assert _state(db, project).credits_used == 100

    _rename_in_tenant(tenant)
    if sync_first:
        cycle.run_cycle(trigger="manual", force_org_sync=True)  # the feed has the old name
        _rename_in_feed(tenant)
        cycle.run_cycle(trigger="manual")
    else:
        _rename_in_feed(tenant)
        cycle.run_cycle(trigger="manual")  # the sync is not due: the new name is unmatched
        cycle.run_cycle(trigger="manual", force_org_sync=True)
    cycle.run_cycle(trigger="manual")
    state = _state(db, project)
    assert state.credits_used == 100, (state.credits_used, state.baseline_credits)
