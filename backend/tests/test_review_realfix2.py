"""Second review of realfix: mappings and automatic matches count forward only.

Ported from the reviewer's tests. A mapping no longer shifts any budget
period's baseline (which raced the evaluation, and two mappings raced each
other); the mapped name is anchored at what it had reported, and only what it
reports beyond that counts. Expectations that described baseline shifts are
restated for that design; the race tests are kept as they were.

Synthetic data only (tests/fake_tenant.py).
"""

from __future__ import annotations

import threading
from decimal import Decimal
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import (
    EntityMapping,
    LimitPeriodState,
    Notification,
    UsageAnchor,
    UsageRecord,
    UsageSnapshot,
)
from app.models.enums import EntityType
from app.services import cycle, evaluation, ingestion
from tests.conftest import USING_SQLITE
from tests.test_real_tenant_usage import ACTOR, connected, live_tenant  # noqa: F401
from tests.test_review_followups import NAME, _limit, _map, _state

NAME2 = "example-org/payments-worker"


def _breach(db: Session):
    db.expire_all()
    return db.scalar(
        select(Notification).where(Notification.title.like("%reached its credit limit"))
    )


def _anchor(db: Session, key: str, view: str = "project") -> UsageAnchor | None:
    db.expire_all()
    return db.scalar(
        select(UsageAnchor).where(UsageAnchor.view_by == view, UsageAnchor.subject_key == key)
    )


def test_map_unmap_remap_counts_each_credit_once(
    db: Session,
    connected,  # noqa: F811
    admin_client: TestClient,
) -> None:
    """Usage spent while mapped counts; unmapping takes exactly that away;
    mapping again starts afresh. Nothing is counted twice or brought back."""
    tenant = live_tenant()
    tenant.set_entity_credits(view="project", name=NAME, credits=0)
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    _map(admin_client, "proj-api")  # mapped before the budget exists
    project = _limit(db, EntityType.PROJECT, "proj-api")
    cycle.run_cycle(trigger="manual")  # baseline = 8, the project's own
    tenant.set_entity_credits(view="project", name=NAME, credits=600)  # spent this period
    cycle.run_cycle(trigger="manual")
    assert _state(db, project).credits_used == 600

    body = _map(admin_client, None)
    assert (
        "600 credits it had added to payments/api no longer count there" in (body["confirmation"])
    ), body["confirmation"]
    cycle.run_cycle(trigger="manual")
    assert _state(db, project).credits_used == 0

    body = _map(admin_client, "proj-api")
    assert "from now on count towards payments/api" in body["confirmation"]
    assert "600 credits it has already reported do not" in body["confirmation"]
    cycle.run_cycle(trigger="manual")
    assert _state(db, project).credits_used == 0
    tenant.set_entity_credits(view="project", name=NAME, credits=650)
    cycle.run_cycle(trigger="manual")
    state = _state(db, project)
    assert state.credits_used == 50, (state.credits_used, state.baseline_credits)


def test_mapping_while_a_cycle_evaluates_does_not_lose_the_shift(
    db: Session,
    connected,  # noqa: F811
    admin_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tenant = live_tenant()
    tenant.set_entity_credits(view="project", name=NAME, credits=870)
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    project = _limit(db, EntityType.PROJECT, "proj-api")
    cycle.run_cycle(trigger="manual")  # baseline 8

    real = evaluation.UsageIndex
    fired = {"done": False}

    class Racing(real):  # type: ignore[misc,valid-type]
        def __init__(self, session):  # type: ignore[no-untyped-def]
            super().__init__(session)
            if not fired["done"] and self.projects:
                fired["done"] = True
                # The cycle has read its totals; an admin maps now.
                _map(admin_client, "proj-api")

    monkeypatch.setattr(evaluation, "UsageIndex", Racing)
    cycle.run_cycle(trigger="manual")
    assert fired["done"]
    monkeypatch.setattr(evaluation, "UsageIndex", real)
    cycle.run_cycle(trigger="manual")
    state = _state(db, project)
    assert state.credits_used == 0, (state.credits_used, state.baseline_credits)
    assert _breach(db) is None, _breach(db).body
    # And spending after the mapping counts.
    tenant.set_entity_credits(view="project", name=NAME, credits=900)
    cycle.run_cycle(trigger="manual")
    assert _state(db, project).credits_used == 30


def test_unmapping_while_a_cycle_evaluates_does_not_breach(
    db: Session,
    connected,  # noqa: F811
    admin_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tenant = live_tenant()
    tenant.set_entity_credits(view="project", name=NAME, credits=870)
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    _map(admin_client, "proj-api")
    project = _limit(db, EntityType.PROJECT, "proj-api")
    cycle.run_cycle(trigger="manual")  # baseline 8: the 870 never counted

    real = evaluation.UsageIndex
    fired = {"done": False}

    class Racing(real):  # type: ignore[misc,valid-type]
        def __init__(self, session):  # type: ignore[no-untyped-def]
            super().__init__(session)
            if not fired["done"] and self.projects:
                fired["done"] = True
                _map(admin_client, None)

    monkeypatch.setattr(evaluation, "UsageIndex", Racing)
    cycle.run_cycle(trigger="manual")
    assert fired["done"]
    state = _state(db, project)
    assert state.credits_used == 0, (state.credits_used, state.baseline_credits)
    assert _breach(db) is None, _breach(db).body


def _map_in_threads(names: list[str], target: str, *, gate: bool) -> list:
    """Map each name in its own session and thread, all at once."""
    from app.api.routes import dashboard as routes
    from app.db.session import get_session_factory
    from app.schemas.dashboard import MapEntityRequest

    real = ingestion.attribution_lock
    barrier = threading.Barrier(len(names), timeout=20)

    def gated(session):  # type: ignore[no-untyped-def]
        # Every request has read what it reads before the lock, together.
        barrier.wait()
        return real(session)

    outcomes: list = []

    def run(name: str) -> None:
        session = get_session_factory()()
        try:
            routes.map_unmatched_entity(
                MapEntityRequest(view="project", subject_key=name, entity_id=target),
                SimpleNamespace(actor=ACTOR),
                session,
            )
            outcomes.append("ok")
        except BaseException as exc:  # noqa: BLE001
            outcomes.append(repr(exc))
        finally:
            session.close()

    if gate:
        ingestion.attribution_lock = gated  # type: ignore[assignment]
    try:
        threads = [threading.Thread(target=run, args=(n,)) for n in names]
        for t in threads:
            t.start()
        for t in threads:
            t.join(60)
    finally:
        ingestion.attribution_lock = real  # type: ignore[assignment]
    return outcomes


@pytest.mark.skipif(USING_SQLITE, reason="row-level concurrency, PostgreSQL")
def test_two_names_mapped_to_one_project_at_once_both_count_forward(
    db: Session,
    connected,  # noqa: F811
) -> None:
    tenant = live_tenant()
    tenant.set_entity_credits(view="project", name=NAME, credits=870)
    tenant.set_entity_credits(view="project", name=NAME2, credits=500)
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    project = _limit(db, EntityType.PROJECT, "proj-api")
    cycle.run_cycle(trigger="manual")
    start = _state(db, project).baseline_credits

    assert _map_in_threads([NAME, NAME2], "proj-api", gate=True) == ["ok", "ok"]
    assert _anchor(db, NAME).offset_credits == 870
    assert _anchor(db, NAME2).offset_credits == 500
    assert _state(db, project).baseline_credits == start
    cycle.run_cycle(trigger="manual")
    assert _state(db, project).credits_used == 0
    tenant.set_entity_credits(view="project", name=NAME, credits=880)
    tenant.set_entity_credits(view="project", name=NAME2, credits=505)
    cycle.run_cycle(trigger="manual")
    assert _state(db, project).credits_used == 15
    assert _breach(db) is None


def test_shift_against_a_restricted_period_neither_lifts_nor_breaches(
    db: Session,
    connected,  # noqa: F811
    admin_client: TestClient,
) -> None:
    tenant = live_tenant()
    tenant.set_entity_credits(view="project", name=NAME, credits=870)
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    project = _limit(db, EntityType.PROJECT, "proj-api")
    cycle.run_cycle(trigger="manual")
    tenant.set_entity_credits(
        view="project", name="payments/api", credits=158, entity_id="proj-api"
    )
    cycle.run_cycle(trigger="manual")
    st = _state(db, project)
    assert st.credits_used == 150
    _map(admin_client, "proj-api")
    cycle.run_cycle(trigger="manual")
    st = _state(db, project)
    assert st.credits_used == 150, (st.credits_used, st.baseline_credits)
    _map(admin_client, None)
    cycle.run_cycle(trigger="manual")
    st = _state(db, project)
    assert st.credits_used == 150, (st.credits_used, st.baseline_credits)


def test_budgets_of_every_period_type_and_the_simulation_count_forward_only(
    db: Session,
    connected,  # noqa: F811
    admin_client: TestClient,
) -> None:
    """A lifetime budget counts usage already reported by its own names, but a
    name mapped to it counts only from the mapping: the same for every budget,
    so a mapping never brings history into any of them."""
    from app.models.enums import PeriodType
    from app.services import limits_service

    tenant = live_tenant()
    tenant.set_entity_credits(view="project", name=NAME, credits=870)
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    lifetime = limits_service.create_limit(
        db,
        data=limits_service.LimitInput(
            entity_type=EntityType.PROJECT,
            entity_id="proj-api",
            credit_limit=100000,
            period_type=PeriodType.LIFETIME,
            enforce=False,
        ),
        actor=ACTOR,
    )
    monthly = _limit(db, EntityType.GROUP, "grp-payments")
    db.commit()
    cycle.run_cycle(trigger="manual")
    body = _map(admin_client, "proj-api")
    assert "baseline_shifts" not in body
    dry = admin_client.get("/api/preview/dry-run")
    assert dry.status_code == 200, dry.text
    cycle.run_cycle(trigger="manual")
    assert _state(db, monthly).credits_used == 0
    db.expire_all()
    lt = db.scalar(select(LimitPeriodState).where(LimitPeriodState.limit_id == lifetime.id))
    assert lt.credits_used == 8
    tenant.set_entity_credits(view="project", name=NAME, credits=970)
    cycle.run_cycle(trigger="manual")
    db.expire_all()
    lt = db.scalar(select(LimitPeriodState).where(LimitPeriodState.limit_id == lifetime.id))
    assert lt.credits_used == 108
    assert _state(db, monthly).credits_used == 100


def test_a_user_mapping_after_a_restriction_is_not_usage_after_restriction(
    db: Session,
    connected,  # noqa: F811
    admin_client: TestClient,
) -> None:
    from app.models import EnforcementAction, PolicyViolation, UnresolvedSubject
    from app.models.enums import PeriodType
    from app.services import limits_service

    tenant = live_tenant()
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    limits_service.create_limit(
        db,
        data=limits_service.LimitInput(
            entity_type=EntityType.USER,
            entity_id="user-alice",
            credit_limit=2,
            period_type=PeriodType.LIFETIME,
            enforce=True,
        ),
        actor=ACTOR,
    )
    db.commit()
    cycle.run_cycle(trigger="manual")
    db.expire_all()
    assert db.scalar(select(EnforcementAction)).status == "applied"
    # A departed contractor's history, listed first (the feed is largest first).
    tenant.set_user_credits(name="Former Contractor", credits=500, actions={"remediation": 40})
    rows = tenant.consumption["user"]
    rows.insert(0, rows.pop())
    cycle.run_cycle(trigger="manual")
    subject = db.scalar(
        select(UnresolvedSubject).where(UnresolvedSubject.subject_key == "former contractor")
    )
    r = admin_client.post(f"/api/usage/unresolved/{subject.id}/map", json={"user_id": "user-alice"})
    assert r.status_code == 200, r.text
    cycle.run_cycle(trigger="manual")
    db.expire_all()
    found = list(db.scalars(select(PolicyViolation)))
    assert not [v for v in found if v.kind == "usage_after_restriction"], [
        (v.kind, v.evidence) for v in found
    ]
    # Remediation the mapped name runs after the mapping is usage after it.
    tenant.set_user_credits(name="Former Contractor", credits=520, actions={"remediation": 43})
    rows = tenant.consumption["user"]
    rows.insert(0, rows.pop())
    cycle.run_cycle(trigger="manual")
    db.expire_all()
    found = [v for v in db.scalars(select(PolicyViolation)) if v.kind == "usage_after_restriction"]
    assert len(found) == 1, [(v.kind, v.evidence) for v in found]
    assert found[0].evidence["rise_by_action"] == {"remediation": 3}, found[0].evidence


@pytest.mark.skipif(USING_SQLITE, reason="row-level concurrency, PostgreSQL")
def test_same_name_mapped_twice_at_once_is_applied_once(
    db: Session,
    connected,  # noqa: F811
) -> None:
    """Under the attribution lock the second request sees the first's mapping
    and changes nothing (the old design needed a 409 for the race)."""
    tenant = live_tenant()
    tenant.set_entity_credits(view="project", name=NAME, credits=870)
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    project = _limit(db, EntityType.PROJECT, "proj-api")
    cycle.run_cycle(trigger="manual")
    start = _state(db, project).baseline_credits

    assert _map_in_threads([NAME, NAME], "proj-api", gate=True) == ["ok", "ok"]
    db.expire_all()
    assert len(list(db.scalars(select(EntityMapping)))) == 1
    assert _anchor(db, NAME).offset_credits == 870
    assert _state(db, project).baseline_credits == start
    cycle.run_cycle(trigger="manual")
    assert _state(db, project).credits_used == 0


def test_user_mapping_after_demo_mode_anchors_on_the_live_reading(
    db: Session,
    connected,  # noqa: F811
    admin_client: TestClient,
) -> None:
    from datetime import timedelta

    from app.db.base import utcnow
    from app.models import UnresolvedSubject
    from app.services import settings_store

    tenant = live_tenant()
    tenant.set_user_credits(name="Former Contractor", credits=500)
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    limit = _limit(db, EntityType.USER, "user-alice")
    cycle.run_cycle(trigger="manual")
    start = _state(db, limit).baseline_credits
    live = ingestion.latest_live_snapshot(db, "user")
    # A demo reading left behind (demo mode now off), newer than the live one.
    snap = UsageSnapshot(
        collected_at=utcnow() + timedelta(minutes=1),
        view_by="user",
        period_param=settings_store.DEMO_PERIOD_PARAM,
        total_credits=Decimal("700"),
        pages_fetched=1,
    )
    db.add(snap)
    db.flush()
    db.add(
        UsageRecord(
            snapshot_id=snap.id,
            view_by="user",
            subject_key="former contractor",
            subject_name="Former Contractor",
            credits_used=Decimal("700"),
        )
    )
    db.commit()
    subject = db.scalar(
        select(UnresolvedSubject).where(UnresolvedSubject.subject_key == "former contractor")
    )
    r = admin_client.post(f"/api/usage/unresolved/{subject.id}/map", json={"user_id": "user-alice"})
    assert r.status_code == 200, r.text
    anchor = _anchor(db, "former contractor", view="user")
    assert anchor.offset_credits == 500 and anchor.snapshot_id == live.id
    demo_row = db.scalar(select(UsageRecord).where(UsageRecord.snapshot_id == snap.id))
    assert demo_row.entity_id is None
    live_row = db.scalar(
        select(UsageRecord).where(
            UsageRecord.snapshot_id == live.id, UsageRecord.subject_key == "former contractor"
        )
    )
    assert live_row.entity_id == "user-alice" and live_row.attributed_credits == 0
    assert _state(db, limit).baseline_credits == start
    cycle.run_cycle(trigger="manual")
    assert _state(db, limit).credits_used == 0


def test_a_name_that_starts_to_match_by_itself_is_not_this_periods_usage(
    db: Session,
    connected,  # noqa: F811
) -> None:
    """Same movement as a mapping, but automatic: a project renamed in
    Checkmarx One to the name the feed already reported."""
    tenant = live_tenant()
    tenant.set_entity_credits(view="project", name=NAME, credits=870)
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    project = _limit(db, EntityType.PROJECT, "proj-api")
    cycle.run_cycle(trigger="manual")
    for p in tenant.projects:
        if p["id"] == "proj-api":
            p["name"] = NAME  # renamed in Checkmarx One to the reported name
    tenant.set_entity_credits(view="project", name="payments/api", credits=0)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    cycle.run_cycle(trigger="manual")
    state = _state(db, project)
    assert state.credits_used < 100, (state.credits_used, state.baseline_credits)
    anchor = _anchor(db, NAME)
    assert anchor.reason == ingestion.ANCHOR_FIRST_MATCH and anchor.offset_credits == 870
    tenant.set_entity_credits(view="project", name=NAME, credits=880)
    cycle.run_cycle(trigger="manual")
    assert _state(db, project).credits_used == 10


def test_a_new_name_counts_in_full_and_a_rolled_window_re_anchors(
    db: Session,
    connected,  # noqa: F811
    admin_client: TestClient,
) -> None:
    tenant = live_tenant()
    tenant.set_entity_credits(view="project", name=NAME, credits=870)
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    _map(admin_client, "proj-api")
    project = _limit(db, EntityType.PROJECT, "proj-api")
    cycle.run_cycle(trigger="manual")
    # The lookback window rolls past most of the name's old usage.
    tenant.set_entity_credits(view="project", name=NAME, credits=600)
    cycle.run_cycle(trigger="manual")
    anchor = _anchor(db, NAME)
    assert anchor.offset_credits == 600
    assert _state(db, project).credits_used == 0
    tenant.set_entity_credits(view="project", name=NAME, credits=630)
    cycle.run_cycle(trigger="manual")
    assert _state(db, project).credits_used == 30
    # A name that never reported before and matches at once counts in full.
    tenant.set_entity_credits(view="project", name="payments/web", credits=5)
    cycle.run_cycle(trigger="manual")
    assert _anchor(db, "payments/web") is None
