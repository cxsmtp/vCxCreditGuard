"""Third review of realfix (guard): the cost of attribution at 2,000 projects."""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event
from sqlalchemy.orm import Session

from app.db.session import get_engine
from app.services import cycle, ingestion
from tests.test_real_tenant_usage import connected, live_tenant  # noqa: F401

N = 2000


def test_scale(
    db: Session,
    connected,  # noqa: F811
    admin_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tenant = live_tenant()
    for i in range(N):
        tenant.add_project(project_id=f"p-{i}", name=f"org/repo-{i}", group_ids=["grp-payments"])
        tenant.set_entity_credits(view="project", name=f"org/repo-{i}", credits=i)
    for i in range(300):  # unmatched names
        tenant.set_entity_credits(view="project", name=f"gone/repo-{i}", credits=i)
    connected(tenant)
    timings: list[tuple[str, float, int]] = []
    real = ingestion._store_dimension
    counter = {"n": 0}

    def count(*_a, **_k):  # type: ignore[no-untyped-def]
        counter["n"] += 1

    engine = get_engine()
    event.listen(engine, "before_cursor_execute", count)

    def timed(session, fetched, *, view, **kwargs):  # type: ignore[no-untyped-def]
        counter["n"] = 0
        start = time.perf_counter()
        out = real(session, fetched, view=view, **kwargs)
        session.flush()
        timings.append((str(view), time.perf_counter() - start, counter["n"]))
        return out

    monkeypatch.setattr(ingestion, "_store_dimension", timed)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    for i in range(0, 300, 3):
        tenant.set_entity_credits(view="project", name=f"org/repo-{i}", credits=i + 10)
    cycle.run_cycle(trigger="manual")
    start = time.perf_counter()
    r = admin_client.get("/api/usage/unmatched-entities?limit=200&offset=100")
    listing = time.perf_counter() - start
    assert r.status_code == 200
    start = time.perf_counter()
    r = admin_client.post(
        "/api/usage/unmatched-entities/map",
        json={"view": "project", "subject_key": "gone/repo-299", "entity_id": "p-1"},
    )
    mapping = time.perf_counter() - start
    assert r.status_code == 200, r.text
    event.remove(engine, "before_cursor_execute", count)
    # One statement per row written, plus a handful: no query per name.
    for view, _seconds, statements in timings:
        if view == "project":
            assert statements < (N + 300) + 100, statements
    assert listing < 5 and mapping < 5, (listing, mapping)
