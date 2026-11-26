"""Fifth review of realfix: table-driven sequences over map/unmap, renames in both orders,
deletion and return, disputes, short listings, roll-down and rollover.

Each step mutates the fake tenant (or maps through the API) and runs a cycle.
Every case states the genuine new usage of the budget's period, and both
invariants are checked: never more than that (I1), never less (I2), unless the
case documents an inherent loss. Synthetic data only."""

from __future__ import annotations

from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.enums import EntityType
from app.services import cycle
from tests.test_real_tenant_usage import connected, live_tenant  # noqa: F401
from tests.test_review_followups import NAME, _limit, _map, _state


def _project(tenant, pid):  # type: ignore[no-untyped-def]
    return next(p for p in tenant.projects if p["id"] == pid)


def _drop(tenant, view, name):  # type: ignore[no-untyped-def]
    tenant.consumption[view] = [r for r in tenant.consumption[view] if r["name"] != name]


def _sync(n=1):  # type: ignore[no-untyped-def]
    for _ in range(n):
        cycle.run_cycle(trigger="manual", force_org_sync=True)


def _read(n=1):  # type: ignore[no-untyped-def]
    for _ in range(n):
        cycle.run_cycle(trigger="manual")


# Each case: (budget (type, id, counts_existing), steps(tenant, client), expected usage)
def feed_first_rename(t, c):  # type: ignore[no-untyped-def]
    t.set_entity_credits(view="project", name="payments/web", credits=1020)  # +20
    _read()
    _drop(t, "project", "payments/web")
    t.set_entity_credits(view="project", name="payments/web2", credits=1020)
    _read(3)
    _project(t, "proj-web")["name"] = "payments/web2"
    _sync()
    t.set_entity_credits(view="project", name="payments/web2", credits=1030)  # +10
    _read(2)


def sync_first_rename(t, c):  # type: ignore[no-untyped-def]
    t.set_entity_credits(view="project", name="payments/web", credits=1020)
    _read()
    _project(t, "proj-web")["name"] = "payments/web2"
    _sync()
    _read(2)
    _drop(t, "project", "payments/web")
    t.set_entity_credits(view="project", name="payments/web2", credits=1030)
    _read(2)


def map_spend_move_within_group(t, c):  # type: ignore[no-untyped-def]
    _map(c, "proj-api")
    t.set_entity_credits(view="project", name=NAME, credits=900)  # +30 on api
    _read()
    _map(c, "proj-web")  # within the group
    t.set_entity_credits(view="project", name=NAME, credits=905)  # +5 on web
    _read(2)


def delete_and_return_plain(t, c):  # type: ignore[no-untyped-def]
    saved = _project(t, "proj-web")
    t.projects.remove(saved)
    _sync(3)
    _read(9)
    t.projects.append(saved)
    _sync()
    t.set_entity_credits(view="project", name="payments/web", credits=1007)  # +7
    _read(2)


def mapped_delete_and_return(t, c):  # type: ignore[no-untyped-def]
    _map(c, "proj-web")
    t.set_entity_credits(view="project", name=NAME, credits=970)  # +100 on web
    _read()
    saved = _project(t, "proj-web")
    t.projects.remove(saved)
    _sync(3)
    _read(9)
    t.projects.append(saved)
    _sync()
    _read(2)


def project_moves_between_groups(t, c):  # type: ignore[no-untyped-def]
    _project(t, "proj-tools")["groups"] = ["grp-payments"]
    _sync()
    _read()


CASES: list[tuple[str, tuple[str, str], Callable, int]] = [
    ("feed-first rename", (EntityType.PROJECT, "proj-web"), feed_first_rename, 30),
    ("sync-first rename", (EntityType.PROJECT, "proj-web"), sync_first_rename, 30),
    ("sync-first rename, group", (EntityType.GROUP, "grp-payments"), sync_first_rename, 30),
    ("move within a group", (EntityType.GROUP, "grp-payments"), map_spend_move_within_group, 35),
    (
        "move within an application",
        (EntityType.APPLICATION, "app-payments"),
        map_spend_move_within_group,
        35,
    ),
    ("delete and return, plain name", (EntityType.PROJECT, "proj-web"), delete_and_return_plain, 7),
    (
        "delete and return, mapped name",
        (EntityType.PROJECT, "proj-web"),
        mapped_delete_and_return,
        100,
    ),
    (
        "project moves between groups",
        (EntityType.GROUP, "grp-payments"),
        project_moves_between_groups,
        0,
    ),
]


@pytest.mark.parametrize(("label", "budget", "steps", "expected"), CASES, ids=[c[0] for c in CASES])
def test_sequence(
    db: Session,
    connected,  # noqa: F811
    admin_client: TestClient,
    label: str,
    budget: tuple[str, str],
    steps: Callable,
    expected: int,
) -> None:
    tenant = live_tenant()
    tenant.consumption["application"] = []  # the application fallback: sum of its projects
    tenant.set_entity_credits(view="project", name="payments/web", credits=1000)
    tenant.set_entity_credits(view="project", name="platform/tools", credits=3000)
    tenant.set_entity_credits(view="project", name=NAME, credits=870)
    connected(tenant)
    _sync()
    limit = _limit(db, *budget)
    _read()
    assert _state(db, limit).credits_used == 0
    steps(tenant, admin_client)
    state = _state(db, limit)
    assert state.credits_used == expected, (label, state.credits_used, state.baseline_credits)
