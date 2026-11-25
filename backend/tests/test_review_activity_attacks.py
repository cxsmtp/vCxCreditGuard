"""Adversarial review of the activity source. Synthetic data only."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from types import SimpleNamespace

import pytest
from sqlalchemy.orm import Session

from app.models.enums import EntityType, UsageView
from app.services import activity_source, ingestion
from tests.activity_world import (
    G_PAY,
    P_API,
    budget,
    counter,
    install_clock,
    iso,
    new_tenant,
    seed_org,
)

START = datetime(2026, 11, 20, 12, 0, tzinfo=UTC)


@pytest.fixture
def env(db: Session, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    clock = install_clock(monkeypatch, START)
    seed_org(db)
    tenant = new_tenant()
    return SimpleNamespace(db=db, clock=clock, tenant=tenant, client=tenant.client())


def tick(env: SimpleNamespace, minutes: int = 15) -> None:
    env.clock.value = env.clock.value + timedelta(minutes=minutes)


def ingest(env: SimpleNamespace, views=(UsageView.PROJECT, UsageView.GROUP)):  # type: ignore[no-untyped-def]
    result = ingestion.ingest_usage(env.db, env.client, views=views)
    env.db.commit()
    return result


def drop_group_row(env: SimpleNamespace, name: str) -> None:
    env.tenant.consumption["group"] = [
        row for row in env.tenant.consumption.get("group", []) if row["name"] != name
    ]


def test_group_row_leaving_during_a_short_outage_counts_the_backlog_twice(
    env: SimpleNamespace,
) -> None:
    """A plain group budget fed by the group's own summary row. The log fails
    for 30 minutes (under OUTAGE_GRACE, so it stays the source); meanwhile the
    group view counts an event, then the group's row leaves the view. When the
    log answers, the group is no longer 'own', so the log feeds the same event
    to the group budget again."""
    group = budget(env.db, EntityType.GROUP, G_PAY, created_at=START - timedelta(days=1))
    env.tenant.set_entity_credits(view="project", name="payments/api", credits=100)
    env.tenant.set_entity_credits(view="group", name="payments", credits=100)
    env.tenant.set_entity_credits(view="group", name="someone-else", credits=100000)
    r = ingest(env)  # cycle 0: log seeds, summary history
    assert r.activity is not None and r.activity.seeded
    tick(env)
    ingest(env)  # cycle 1: G has its own row; nothing new
    assert counter(env.db, group) == 0

    # Cycle 2: the log fails (503). One event of 50 on a project of G.
    env.tenant.activity_status = 503
    tick(env)
    env.tenant.add_activity(
        date=iso(env.clock.value - timedelta(minutes=2)),
        credits="50",
        project_id=P_API,
        user="jdoe",
    )
    env.tenant.set_entity_credits(view="project", name="payments/api", credits=150)
    env.tenant.set_entity_credits(view="group", name="payments", credits=150)
    r = ingest(env)
    assert r.activity is not None and r.activity.read_failed and r.activity.source_active
    # The group view (not covered by the log) fed it: 50.
    assert counter(env.db, group) == Decimal(50)

    # Cycle 3: still failing; the group's own row leaves the group view.
    tick(env)
    drop_group_row(env, "payments")
    r = ingest(env)
    assert r.activity is not None and r.activity.source_active
    assert counter(env.db, group) == Decimal(50)

    # Cycle 4 (30 minutes into the outage): the log answers.
    env.tenant.activity_status = None
    tick(env)
    r = ingest(env)
    assert r.activity is not None and r.activity.source_active
    # Real usage of the group's projects since the budget: 50.
    assert counter(env.db, group) <= Decimal(50), (
        f"group budget holds {counter(env.db, group)} for one event of 50"
    )


def test_group_row_leaving_before_daily_sweep_counts_a_late_row_twice(
    env: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A row that reaches the log (and the summary) more than OVERLAP late is
    counted by the group's own summary row when it appears, and by the log's
    daily sweep, with the group's 'own' status as of the sweep."""
    group = budget(env.db, EntityType.GROUP, G_PAY, created_at=START - timedelta(days=1))
    env.tenant.set_entity_credits(view="project", name="payments/api", credits=100)
    env.tenant.set_entity_credits(view="group", name="payments", credits=100)
    env.tenant.set_entity_credits(view="group", name="someone-else", credits=100000)
    # Filler so that the log has several pages and the normal read is a tail.
    from app.checkmarx import activity as activity_api

    monkeypatch.setattr(activity_api, "ACTIVITY_PAGE_SIZE", 3)
    for minute in range(0, 600, 10):
        env.tenant.add_activity(
            date=iso(START - timedelta(minutes=minute + 1)),
            credits="0",
            project_id=None,
            user="filler",
        )
    ingest(env)  # seed
    tick(env)
    ingest(env)  # own row established; first sweep happens on this non-seed cycle
    # Four hours of cycles, the log growing with zero-credit rows.
    for _ in range(16):
        tick(env)
        env.tenant.add_activity(
            date=iso(env.clock.value - timedelta(minutes=1)),
            credits="0",
            project_id=None,
            user="filler",
        )
        ingest(env)
    # A late row: dated 3 hours ago (after the seed), appears now (in the
    # summary too).
    tick(env)
    env.tenant.add_activity(
        date=iso(env.clock.value - timedelta(hours=3)),
        credits="40",
        project_id=P_API,
        user="jdoe",
    )
    env.tenant.set_entity_credits(view="project", name="payments/api", credits=140)
    env.tenant.set_entity_credits(view="group", name="payments", credits=140)
    ingest(env)
    after_group_view = counter(env.db, group)
    # The group's row leaves the view.
    tick(env)
    drop_group_row(env, "payments")
    ingest(env)
    # A day later the sweep reads the whole log.
    for _ in range(4):
        tick(env, 6 * 60 + 5)
        ingest(env)
    st = activity_source._state(env.db)
    assert st is not None and st.status == activity_source.ACTIVE
    assert counter(env.db, group) <= Decimal(40), (
        f"group view counted {after_group_view}; now {counter(env.db, group)} for one event of 40"
    )


def test_a_row_whose_application_id_appears_later_is_counted_again(
    env: SimpleNamespace,
) -> None:
    """If the log renders applicationIds (or user/userEmail) from the current
    state rather than storing them with the event, a row read before and
    after a change has two identities, and counts twice."""
    from tests.activity_world import APP_PAY

    project = budget(env.db, EntityType.PROJECT, P_API, created_at=START - timedelta(days=1))
    run_log = lambda: activity_source.ingest_activity(env.db, env.client)  # noqa: E731
    run_log()
    env.db.commit()
    tick(env)
    row = env.tenant.add_activity(
        date=iso(env.clock.value - timedelta(minutes=1)),
        credits="30",
        project_id=P_API,
        user="jdoe",
    )
    run_log()
    env.db.commit()
    assert counter(env.db, project) == Decimal(30)
    # The project is added to an application; the log now shows the same
    # (only) event with that application.
    row["applicationIds"] = [APP_PAY]
    row["applications"] = ["Payments"]
    tick(env)
    run_log()
    env.db.commit()
    assert counter(env.db, project) == Decimal(30), counter(env.db, project)


def test_clock_going_back_after_pruning_recounts_rows_still_in_the_log(
    env: SimpleNamespace,
) -> None:
    """Keys are pruned at our clock minus 31 days. If our clock runs ahead of
    Checkmarx's by more than a day and is then corrected, rows pruned while it
    was ahead and still inside the log's window are counted again."""
    project = budget(env.db, EntityType.PROJECT, P_API, created_at=START - timedelta(days=40))
    run_log = lambda: activity_source.ingest_activity(env.db, env.client)  # noqa: E731
    run_log()
    env.db.commit()
    tick(env)
    env.tenant.add_activity(
        date=iso(env.clock.value - timedelta(minutes=1)), credits="9", project_id=P_API, user="jdoe"
    )
    run_log()
    env.db.commit()
    assert counter(env.db, project) == Decimal(9)
    real = env.clock.value
    # 29.5 days later, our clock jumps 2 days ahead (Checkmarx still holds
    # the row: it is 29.5 days old by its clock).
    env.clock.value = real + timedelta(days=29, hours=12) + timedelta(days=2)
    run_log()
    env.db.commit()
    # The clock is corrected; the daily sweep reads the whole window.
    env.clock.value = real + timedelta(days=29, hours=13)
    st = activity_source._state(env.db)
    st.last_sweep_at = None
    env.db.commit()
    run_log()
    env.db.commit()
    assert counter(env.db, project) == Decimal(9), counter(env.db, project)


def test_deactivating_a_project_budget_charges_its_past_auto_triage_to_users(
    env: SimpleNamespace,
) -> None:
    """The integration-account rule says auto triage on a project that had an
    active project budget at the time counts towards no user budget. The
    skip predicate reads the budgets active *now*: deactivating the project
    budget later charges the earlier auto triage to the initiators (it can
    restrict them); reactivating it removes later charges (it can lift)."""
    from app.services import auto_triage_attribution
    from tests.activity_world import U_ALICE

    project_budget = budget(env.db, EntityType.PROJECT, P_API, created_at=START - timedelta(days=1))
    activity_source.ingest_activity(env.db, env.client)  # the log becomes the source
    env.db.commit()

    part = auto_triage_attribution.AttributedPart(
        user_id=U_ALICE,
        project_id=P_API,
        basis=auto_triage_attribution.BASIS_OBSERVED,
        credits=Decimal(25),
        initiator="alice@example.com",
        observed_at=START + timedelta(minutes=30),
    )
    model = auto_triage_attribution.AttributionModel(
        enabled=True, available=True, parts_by_user={U_ALICE: [part]}
    )

    def alice() -> Decimal:
        return auto_triage_attribution.attributed_usage(
            model,
            user_ids=[U_ALICE],
            counts_existing=True,
            since=None,
            skip=activity_source.initiator_skip(env.db),
        ).counted

    # Observed while the project budget was active: no user budget counts it.
    assert alice() == Decimal(0)
    # An hour later the admin switches the project budget off.
    env.clock.value = START + timedelta(hours=2)
    project_budget.is_active = False
    env.db.commit()
    assert alice() == Decimal(0), (
        f"Alice is now charged {alice()} for auto triage the project budget governed"
    )


def test_member_usage_switched_on_during_a_short_outage_counts_the_backlog_twice(
    env: SimpleNamespace,
) -> None:
    """Same family: a plain group budget fed by its own summary row; during a
    short log outage the group view counts an event; the admin turns on
    'include member usage' (the group view stops feeding it, the log feeds it
    by its projects); the log's backlog then feeds the same event again."""
    group = budget(env.db, EntityType.GROUP, G_PAY, created_at=START - timedelta(days=1))
    env.tenant.set_entity_credits(view="project", name="payments/api", credits=100)
    env.tenant.set_entity_credits(view="group", name="payments", credits=100)
    env.tenant.set_entity_credits(view="group", name="someone-else", credits=100000)
    ingest(env)
    tick(env)
    ingest(env)
    env.tenant.activity_status = 503
    tick(env)
    env.tenant.add_activity(
        date=iso(env.clock.value - timedelta(minutes=2)),
        credits="50",
        project_id=P_API,
        user="jdoe",
    )
    env.tenant.set_entity_credits(view="project", name="payments/api", credits=150)
    env.tenant.set_entity_credits(view="group", name="payments", credits=150)
    ingest(env)
    assert counter(env.db, group) == Decimal(50)
    group.include_member_usage = True
    env.db.commit()
    env.tenant.activity_status = None
    tick(env)
    ingest(env)
    assert counter(env.db, group) <= Decimal(50), counter(env.db, group)


def test_a_name_missing_across_the_handover_returns_with_log_counted_usage(
    env: SimpleNamespace,
) -> None:
    """The summary's first reading after the log stops counts nothing, but a
    name missing from that reading is compared, when it returns, with the
    total it had before the log era (UsageMissingName): its increase spans the
    log era, which the log already counted."""
    from tests.activity_world import P_TOOLS, PROJECT_NAMES

    limit = budget(env.db, EntityType.PROJECT, P_API, created_at=START - timedelta(days=1))
    big = PROJECT_NAMES[P_TOOLS]

    def rows(api: int | None, tools: int) -> None:
        env.tenant.consumption["project"] = [
            {"name": big, "creditsUsed": str(tools), "percentOfTotal": 1.0}
        ] + (
            [{"name": PROJECT_NAMES[P_API], "creditsUsed": str(api), "percentOfTotal": 1.0}]
            if api is not None
            else []
        )

    rows(100, 100000)
    ingest(env, views=(UsageView.PROJECT,))  # seed; summary history
    tick(env)
    ingest(env, views=(UsageView.PROJECT,))
    # P_API spends 40 while the log is the source (counted by the log); the
    # summary's project view leaves it out for a while.
    tick(env)
    env.tenant.add_activity(
        date=iso(env.clock.value - timedelta(minutes=2)),
        credits="40",
        project_id=P_API,
        user="jdoe",
    )
    rows(None, 100000)
    ingest(env, views=(UsageView.PROJECT,))
    assert counter(env.db, limit) == Decimal(40)
    # The log goes away (404): the summary takes over; P_API still missing.
    env.tenant.activity_status = 404
    tick(env)
    r = ingest(env, views=(UsageView.PROJECT,))
    assert r.activity is not None and not r.activity.source_active
    tick(env)
    rows(140, 100000)  # back, with the 40 the log counted
    ingest(env, views=(UsageView.PROJECT,))
    assert counter(env.db, limit) <= Decimal(40), counter(env.db, limit)
