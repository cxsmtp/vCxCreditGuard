"""Sixth review of realfix: claims of unattributed increases.

The docs: a mapping counts forward only; unattributed usage is claimed by the
entity the name first counts towards "if that entity was synced after the usage
(within one org refresh plus an hour of it)". The code claims every waiting
increase observed after ``created - window``, including the ones observed long
after the entity was synced, so a later mapping imports the name's history."""

# ruff: noqa: F811 - the connected fixture is imported by name

from __future__ import annotations

import httpx
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.enums import EntityType
from app.services import cycle
from tests.test_real_tenant_usage import connected, live_tenant  # noqa: F401
from tests.test_review_followups import _limit, _state

NAME = "example-org/repo-a"


def test_mapping_imports_usage_observed_after_the_entity_was_synced(
    db: Session,
    connected,
    admin_client: TestClient,  # noqa: F811
) -> None:
    tenant = live_tenant()
    tenant.set_entity_credits(view="project", name=NAME, credits=1000)
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    cycle.run_cycle(trigger="manual")
    # The unmatched name spends 10 (counted towards nothing).
    tenant.set_entity_credits(view="project", name=NAME, credits=1010)
    cycle.run_cycle(trigger="manual")
    # A new, unrelated project is synced afterwards, with a budget.
    tenant.add_project(project_id="proj-new", name="other/new", group_ids=[])
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    new = _limit(db, EntityType.PROJECT, "proj-new")
    cycle.run_cycle(trigger="manual")
    # The unmatched name keeps spending for a while after the project exists.
    for total in (1100, 1200, 1300):
        tenant.set_entity_credits(view="project", name=NAME, credits=total)
        cycle.run_cycle(trigger="manual")
    assert _state(db, new).credits_used == 0
    # Now an admin maps the name to the new project: forward only.
    response = admin_client.post(
        "/api/usage/unmatched-entities/map",
        json={"view": "project", "subject_key": NAME, "entity_id": "proj-new"},
    )
    assert response.status_code == httpx.codes.OK, response.text
    cycle.run_cycle(trigger="manual")  # no new usage
    # Expected 0 (forward only); at most 10 (usage before the project was synced).
    assert _state(db, new).credits_used <= 10, _state(db, new).credits_used
