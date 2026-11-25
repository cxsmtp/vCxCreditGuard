"""Third adversarial review of the activity source (cc87ae7..97ce298).
Synthetic data only."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db import session as db_session
from app.models import EnforcementAction, Notification
from app.models.activity import ProjectBudgetInterval
from app.models.enums import EnforcementStatus, EntityType, LimitStatus, UsageView
from app.services import activity_source, enforcement, ingestion, limits_service, settings_store
from tests.activity_world import (
    ACTOR,
    P_API,
    budget,
    counter,
    install_clock,
    new_tenant,
    seed_org,
    use_source,
)

START = datetime(2026, 11, 20, 12, 0, tzinfo=UTC)


# --------------------------------------------------------------- restriction_started


def test_a_stale_pending_action_lets_summary_totals_start_a_restriction(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``restriction_started`` treats any PENDING action as a restriction in
    force. A PENDING row is committed before anything is read or written
    (enforcement.py, the "Committed, not just flushed" step); a process that
    stops there (a restart mid-cycle) leaves one that took nothing. Lifting
    skips it (``restore_for_limit`` keeps only ``may_be_in_force`` rows), so
    it outlives the lift. From then on, summary-counted usage over the limit
    is no longer held: it restricts.

    Alice goes over 5 on the log; the cycle that restricts her dies before
    the write. The admin raises her budget to 20 (she is under it: nothing
    in force, nothing to lift). The log goes away; the summary then counts her
    over 20. Only 6 of that was counted from the log: held, never restricted."""
    from tests.test_summary_hold import World

    settings_store.set_value(db, settings_store.KEY_USAGE_SOURCE, "activity")
    db.commit()
    world = World(db, monkeypatch, log=True)
    limit = world.budget()
    world.evaluate()
    world.tick()
    world.spend(6)
    world.ingest()

    real_capture = enforcement._capture

    def dies(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise KeyboardInterrupt("process stopped mid-cycle")

    monkeypatch.setattr(enforcement, "_capture", dies)
    with pytest.raises(KeyboardInterrupt):
        world.evaluate()
    db.rollback()
    monkeypatch.setattr(enforcement, "_capture", real_capture)
    pending = db.scalars(
        select(EnforcementAction).where(EnforcementAction.limit_id == limit.id)
    ).all()
    assert [a.status for a in pending] == [EnforcementStatus.PENDING]
    assert not world.restricted()

    limits_service.update_limit(
        db, limit=limit, changes={"credit_limit": 20}, actor=ACTOR, client=world.client
    )
    db.commit()
    world.tick()
    world.evaluate()  # 6 of 20: within budget
    assert not world.restricted()

    world.tenant.activity_status = 404
    for _ in range(7):
        world.tick()
        world.spend(5, log=False)
        world.ingest()
        world.evaluate()
    state = world.state(limit)
    assert state.credits_used >= 20  # over, on summary totals
    db.expire_all()
    statuses = [
        a.status
        for a in db.scalars(select(EnforcementAction).where(EnforcementAction.limit_id == limit.id))
    ]
    assert not world.restricted() and state.status != LimitStatus.RESTRICTED, (
        f"restricted on summary totals (log part 6 of 20): status {state.status}, "
        f"actions {statuses}"
    )


# ------------------------------------------------------------- the REBASE rule


@pytest.fixture
def env(db: Session, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    clock = install_clock(monkeypatch, START)
    seed_org(db)
    tenant = new_tenant()
    world = SimpleNamespace(
        db=db, clock=clock, tenant=tenant, client=tenant.client(), suspect=set()
    )
    original = tenant._consumption_response

    def consumption(params):  # type: ignore[no-untyped-def]
        response = original(params)
        view = params.get("viewBy", ["user"])[0]
        if view not in world.suspect or response.status_code != 200:
            return response
        body = response.json()
        body["totalItems"] = int(body.get("totalItems") or 0) + 1
        return httpx.Response(200, json=body)

    tenant._consumption_response = consumption
    return world


def tick(env: SimpleNamespace, minutes: int = 15) -> None:
    env.clock.value = env.clock.value + timedelta(minutes=minutes)


def ingest(env: SimpleNamespace, views=(UsageView.PROJECT,)):  # type: ignore[no-untyped-def]
    result = ingestion.ingest_usage(env.db, env.client, views=views)
    env.db.commit()
    return result


def _drop_row(env: SimpleNamespace, name: str) -> None:
    env.tenant.consumption["project"] = [
        row for row in env.tenant.consumption["project"] if row["name"] != name
    ]


def test_a_rebase_kept_by_a_doubted_reading_becomes_missing_at_its_glitched_total(
    env: SimpleNamespace,
) -> None:
    """REBASE kept in a doubted reading (new rule) does not keep the name's
    figure: the reading's record holds the glitched total, and when the name
    then leaves the feed the "names that left" step turns the row into
    "missing" at that total (ledger.record_reading: ``row.kind != DIP``).
    Its return counts the recovery. A total of 100 throughout; no usage."""
    use_source(env.db, settings_store.USAGE_SOURCE_ACTIVITY)
    project = budget(env.db, EntityType.PROJECT, P_API, created_at=START - timedelta(days=1))
    env.tenant.set_entity_credits(view="project", name="payments/api", credits=100)
    # A large other project: one name leaving is no collapse of the view.
    env.tenant.set_entity_credits(view="project", name="payments/web", credits=10000)
    assert ingest(env).activity.seeded  # type: ignore[union-attr]
    tick(env)
    ingest(env)
    env.tenant.activity_status = 404
    tick(env)
    ingest(env)  # paused 1
    tick(env)
    env.suspect.add("project")
    env.tenant.set_entity_credits(view="project", name="payments/api", credits=60)
    ingest(env)  # paused 2, doubted fall: dip -> rebase
    tick(env)
    ingest(env)  # fed, still doubted and low: rebase kept, nothing counted
    env.suspect.clear()
    tick(env)
    _drop_row(env, "payments/api")
    ingest(env)  # the name is missing
    tick(env)
    env.tenant.set_entity_credits(view="project", name="payments/api", credits=100)
    ingest(env)
    assert counter(env.db, project) == 0, (
        f"project budget counted {counter(env.db, project)} with no usage at all"
    )


# ------------------------------------------------------- budget identity


def test_a_budgets_interval_is_recognised_on_every_observation(
    env: SimpleNamespace,
) -> None:
    """``_same_budget`` compares the stored creation times. A budget made
    the normal way (created_at from the database default), observed by
    several activity writes and evaluations in fresh sessions, keeps a single
    open interval on either engine."""
    from app.services import evaluation

    use_source(env.db, settings_store.USAGE_SOURCE_ACTIVITY)
    limit = limits_service.create_limit(
        env.db,
        data=limits_service.LimitInput(
            entity_type=EntityType.PROJECT,
            entity_id=P_API,
            credit_limit=100,
            period_type="monthly",
            enforce=False,
        ),
        actor=ACTOR,
    )
    env.db.commit()
    limit_id = limit.id
    ingest(env)
    for _ in range(3):
        tick(env)
        ingest(env)
        other = db_session.get_session_factory()()
        try:
            activity_source.observe_budgets(other, env.clock.value)
            other.commit()
            evaluation.evaluate_all(other, client=None, now=env.clock.value, actor=ACTOR)
            other.commit()
        finally:
            other.close()
    env.db.expire_all()
    rows = env.db.scalars(
        select(ProjectBudgetInterval).where(ProjectBudgetInterval.limit_id == limit_id)
    ).all()
    assert [(r.end_at is None) for r in rows] == [True], [
        (r.start_at, r.end_at, r.budget_created_at) for r in rows
    ]


# ------------------------------------------------------------- the notice


def test_the_source_notice_is_raised_once_across_sessions(env: SimpleNamespace) -> None:
    use_source(env.db, settings_store.USAGE_SOURCE_ACTIVITY)
    env.tenant.set_entity_credits(view="project", name="payments/api", credits=100)
    for _ in range(3):
        ingest(env)
        tick(env)
    # A restart: a fresh session, the source switched away and back.
    other = db_session.get_session_factory()()
    try:
        use_source(other, settings_store.USAGE_SOURCE_SUMMARY)
        ingestion.ingest_usage(other, env.client, views=(UsageView.PROJECT,))
        other.commit()
        use_source(other, settings_store.USAGE_SOURCE_ACTIVITY)
        for _ in range(2):
            tick(env)
            ingestion.ingest_usage(other, env.client, views=(UsageView.PROJECT,))
            other.commit()
    finally:
        other.close()
    env.db.expire_all()
    count = env.db.scalar(
        select(func.count())
        .select_from(Notification)
        .where(Notification.dedupe_key == activity_source.NOTICE_KEY)
    )
    assert count == 1
    assert Decimal(1)  # keep Decimal import used


def test_control_stale_pending_with_applied_only_check(db, monkeypatch):
    """Control: the same sequence with the check counting APPLIED only."""
    from app.services import evaluation

    monkeypatch.setattr(evaluation, "restriction_started", evaluation._has_active_enforcement)
    test_a_stale_pending_action_lets_summary_totals_start_a_restriction(db, monkeypatch)


def test_control_the_same_readings_without_a_handover_count_nothing(env: SimpleNamespace) -> None:
    """Control: the ledger alone holds the dip across doubted readings and
    keeps the held total when the name leaves."""
    use_source(env.db, settings_store.USAGE_SOURCE_SUMMARY)
    project = budget(env.db, EntityType.PROJECT, P_API, created_at=START - timedelta(days=1))
    env.tenant.set_entity_credits(view="project", name="payments/api", credits=100)
    env.tenant.set_entity_credits(view="project", name="payments/web", credits=10000)
    for _ in range(3):
        ingest(env)
        tick(env)
    env.suspect.add("project")
    env.tenant.set_entity_credits(view="project", name="payments/api", credits=60)
    ingest(env)
    tick(env)
    ingest(env)
    env.suspect.clear()
    tick(env)
    _drop_row(env, "payments/api")
    ingest(env)
    tick(env)
    env.tenant.set_entity_credits(view="project", name="payments/api", credits=100)
    ingest(env)
    assert counter(env.db, project) == 0
