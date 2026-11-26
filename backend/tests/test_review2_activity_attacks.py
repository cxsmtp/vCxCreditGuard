"""Second adversarial review of the activity source (e995f72..cc87ae7).
Synthetic data only."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy.orm import Session

from app.models import CxProject
from app.models.enums import EntityType, UsageView
from app.services import activity_source, ingestion, limits_service, settings_store
from tests.activity_world import (
    ACTOR,
    P_API,
    P_TOOLS,
    P_WEB,
    U_BOB,
    budget,
    counter,
    install_clock,
    iso,
    new_tenant,
    seed_org,
    use_source,
)

START = datetime(2026, 11, 20, 12, 0, tzinfo=UTC)


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
        """A listing the completeness checks doubt: one row fewer than the
        feed says it has (a short page), for the views in ``world.suspect``."""
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


def test_a_dip_held_in_the_last_paused_reading_is_dropped_and_its_recovery_counted(
    env: SimpleNamespace,
) -> None:
    """B3. The summary's second paused reading after a fallback is doubted
    (short listing) and shows a project's total falling 100 -> 60: the ledger
    holds the fall as a dip (it may be a glitch). The rebase that follows in
    after_summary_reading drops every remembered row of a present name,
    including the dip just held in this very reading. The next, fed, reading
    shows the glitch gone (100 again): 40 is counted that nobody used."""
    use_source(env.db, settings_store.USAGE_SOURCE_ACTIVITY)
    project = budget(env.db, EntityType.PROJECT, P_API, created_at=START - timedelta(days=1))
    env.tenant.set_entity_credits(view="project", name="payments/api", credits=100)
    env.tenant.set_entity_credits(view="project", name="payments/web", credits=10)
    r = ingest(env)
    assert r.activity is not None and r.activity.seeded
    tick(env)
    ingest(env)

    env.tenant.activity_status = 404  # the log goes away: the summary takes over
    tick(env)
    r = ingest(env)  # paused reading 1
    assert r.activity is not None and not r.activity.source_active

    tick(env)
    env.suspect.add("project")
    env.tenant.set_entity_credits(view="project", name="payments/api", credits=60)
    ingest(env)  # paused reading 2: doubted, with a fall
    assert counter(env.db, project) == 0

    tick(env)
    env.suspect.clear()
    env.tenant.set_entity_credits(view="project", name="payments/api", credits=100)
    ingest(env)  # first fed reading: the glitch is gone
    assert counter(env.db, project) == 0, (
        f"project budget counted {counter(env.db, project)} with no usage at all"
    )


def test_control_the_same_dip_without_a_handover_counts_nothing(env: SimpleNamespace) -> None:
    """Control for the test above: summary only from the start (no rebase)."""
    use_source(env.db, settings_store.USAGE_SOURCE_SUMMARY)
    project = budget(env.db, EntityType.PROJECT, P_API, created_at=START - timedelta(days=1))
    env.tenant.set_entity_credits(view="project", name="payments/api", credits=100)
    env.tenant.set_entity_credits(view="project", name="payments/web", credits=10)
    for _ in range(3):
        ingest(env)
        tick(env)
    env.suspect.add("project")
    env.tenant.set_entity_credits(view="project", name="payments/api", credits=60)
    ingest(env)
    tick(env)
    env.suspect.clear()
    env.tenant.set_entity_credits(view="project", name="payments/api", credits=100)
    ingest(env)
    assert counter(env.db, project) == 0


def _rename_project(db: Session, project_id: str, name: str) -> None:
    project = db.get(CxProject, project_id)
    assert project is not None
    project.name = name
    db.commit()


def test_a_name_rebased_at_the_handover_is_no_rename_partner_any_more(
    env: SimpleNamespace,
) -> None:
    """B3. A project's row left the summary while the log was the source (the
    ledger remembers it as missing, at 500). The handover's paused readings
    turn that memory into kind "rebase". When the project comes back under a
    new name (renamed in Checkmarx), a "rebase" row is no rename partner
    (``partners`` takes only kind "missing"), so the new name counts its
    whole total, 510, of which 500 is history. Without the handover (control
    below) it counts 10."""
    use_source(env.db, settings_store.USAGE_SOURCE_ACTIVITY)
    tools = budget(env.db, EntityType.PROJECT, P_TOOLS, created_at=START - timedelta(days=1))
    env.tenant.set_entity_credits(view="project", name="payments/api", credits=100)
    env.tenant.set_entity_credits(view="project", name="platform/tools", credits=500)
    r = ingest(env)
    assert r.activity is not None and r.activity.seeded
    tick(env)
    ingest(env)
    tick(env)
    env.tenant.consumption["project"] = [
        row for row in env.tenant.consumption["project"] if row["name"] != "platform/tools"
    ]
    ingest(env)  # log era: platform/tools is remembered as missing

    env.tenant.activity_status = 404
    tick(env)
    ingest(env)  # paused 1
    tick(env)
    ingest(env)  # paused 2
    tick(env)
    _rename_project(env.db, P_TOOLS, "platform/tools-v2")
    env.tenant.set_entity_credits(view="project", name="platform/tools-v2", credits=510)
    ingest(env)
    assert counter(env.db, tools) <= Decimal(10), (
        f"renamed project counted {counter(env.db, tools)} for 10 of new usage"
    )


def test_control_a_rename_after_missing_readings_counts_only_the_increase(
    env: SimpleNamespace,
) -> None:
    use_source(env.db, settings_store.USAGE_SOURCE_SUMMARY)
    tools = budget(env.db, EntityType.PROJECT, P_TOOLS, created_at=START - timedelta(days=1))
    env.tenant.set_entity_credits(view="project", name="payments/api", credits=100)
    env.tenant.set_entity_credits(view="project", name="platform/tools", credits=500)
    ingest(env)
    tick(env)
    ingest(env)
    tick(env)
    env.tenant.consumption["project"] = [
        row for row in env.tenant.consumption["project"] if row["name"] != "platform/tools"
    ]
    for _ in range(3):
        ingest(env)
        tick(env)
    _rename_project(env.db, P_TOOLS, "platform/tools-v2")
    env.tenant.set_entity_credits(view="project", name="platform/tools-v2", credits=510)
    ingest(env)
    assert counter(env.db, tools) == Decimal(10)


def test_a_reused_budget_id_leaves_a_budgeted_project_ungoverned(env: SimpleNamespace) -> None:
    """B2. ``usage_budget_interval`` keys its rows by limit id and has no
    foreign key (on purpose: the history outlives the budget). On SQLite a
    deleted limit's id is handed to the next limit created (INTEGER PRIMARY
    KEY without AUTOINCREMENT). The open interval of the deleted budget (on
    payments/web) is then taken for the new budget (on payments/api): the
    new project never gets an interval, so an integration account's usage on
    a project with an active project budget is charged to the person."""
    use_source(env.db, settings_store.USAGE_SOURCE_ACTIVITY)
    settings_store.set_value(env.db, settings_store.KEY_INTEGRATION_ACCOUNTS, ["jdoe"])
    env.db.commit()
    bob = budget(env.db, EntityType.USER, U_BOB, created_at=START - timedelta(days=1))
    web = budget(env.db, EntityType.PROJECT, P_WEB, created_at=START - timedelta(days=1))
    old_id = web.id
    r = ingest(env)
    assert r.activity is not None and r.activity.seeded  # observes web's interval
    tick(env)
    limits_service.delete_limit(env.db, limit=web, actor=ACTOR)
    env.db.commit()
    api = budget(env.db, EntityType.PROJECT, P_API)
    reused = api.id == old_id
    tick(env)
    env.tenant.add_activity(
        date=iso(env.clock.value - timedelta(minutes=1)),
        credits="30",
        project_id=P_API,
        user="jdoe",
    )
    r = ingest(env)
    assert r.activity is not None and r.activity.events_counted == 1
    assert counter(env.db, api) == Decimal(30)
    assert counter(env.db, bob) == 0, (
        f"integration usage on a project with an active budget charged to a person "
        f"({counter(env.db, bob)}); limit id reused: {reused}"
    )
    # And the history says so.
    history = activity_source.BudgetHistory(env.db, env.clock.value, persist=False)
    assert history.covers(P_API, env.clock.value - timedelta(minutes=1))


def test_the_dropped_dip_restricts_a_person_who_spent_nothing_under_the_summary_opt_in(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same B3 dip, on an install that switched from the log to *Summary
    only* with *Allow restrictions from summary totals* on (the old behaviour,
    which the migration also turns on for an explicit summary choice). Alice
    spends nothing; one doubted reading among the handover's paused ones
    shows her total 10 lower. Her monthly budget of 5 is restricted."""
    from app.models.enums import LimitStatus
    from tests.test_summary_hold import World

    settings_store.set_value(db, settings_store.KEY_USAGE_SOURCE, "activity")
    db.commit()
    world = World(db, monkeypatch, log=True)  # the log is the source (seeded)
    limit = world.budget()  # Alice, monthly, 5, enforcing
    # History in the summary (her usage before the budget): never counted.
    world.alice = 33
    world.tenant.set_user_credits(name="Alice Archer", email="alice.archer@example.com", credits=33)
    world.tick()
    world.ingest()
    world.evaluate()
    assert world.state(limit).credits_used == 0

    settings_store.set_value(db, settings_store.KEY_USAGE_SOURCE, "summary")
    settings_store.set_value(db, settings_store.KEY_SUMMARY_RESTRICTS, True)
    db.commit()
    world.tick()
    world.ingest()  # paused reading 1 (the log stops)
    world.evaluate()

    original = world.tenant._consumption_response

    def short_user_listing(params):  # type: ignore[no-untyped-def]
        response = original(params)
        if params.get("viewBy", [""])[0] != "user":
            return response
        body = response.json()
        body["totalItems"] = int(body["totalItems"]) + 1
        return httpx.Response(200, json=body)

    world.tenant._consumption_response = short_user_listing
    world.tenant.set_user_credits(name="Alice Archer", email="alice.archer@example.com", credits=23)
    world.tick()
    world.ingest()  # paused reading 2: doubted, Alice "fell" by 10
    world.evaluate()
    world.tenant._consumption_response = original
    world.tenant.set_user_credits(name="Alice Archer", email="alice.archer@example.com", credits=33)
    world.tick()
    world.ingest()  # the glitch is gone
    world.evaluate()
    state = world.state(limit)
    assert state.credits_used == 0 and state.status != LimitStatus.RESTRICTED, (
        f"Alice spent nothing: used {state.credits_used}, status {state.status}, "
        f"restricted in Checkmarx: {world.restricted()}"
    )


def test_a_reseed_clears_the_group_views_pause_after_a_hand_back(env: SimpleNamespace) -> None:
    """B1. A plain group budget fed by the log through its projects; the log
    counts an event of 50 and the group's own row appears in the same cycle,
    not showing it yet (the summary lags). The hand-back pauses the group
    view for two readings. The admin switches the source to the summary and
    back within the next cycle, whose group reading fails (a 5xx on that view
    only). The re-seed sets ``summary_paused = None`` for every view,
    the group view's pause included, so the next group reading, which now
    shows the 50, feeds it to the budget again."""
    from tests.activity_world import G_PAY

    use_source(env.db, settings_store.USAGE_SOURCE_ACTIVITY)
    views = (UsageView.PROJECT, UsageView.GROUP)
    group = budget(env.db, EntityType.GROUP, G_PAY, created_at=START - timedelta(days=1))
    env.tenant.set_entity_credits(view="project", name="payments/api", credits=100)
    env.tenant.set_entity_credits(view="group", name="someone-else", credits=1000)
    r = ingest(env, views)
    assert r.activity is not None and r.activity.seeded
    tick(env)
    ingest(env, views)

    tick(env)
    env.tenant.add_activity(
        date=iso(env.clock.value - timedelta(minutes=2)),
        credits="50",
        project_id=P_API,
        user="jdoe",
    )
    env.tenant.set_entity_credits(view="project", name="payments/api", credits=150)
    env.tenant.set_entity_credits(view="group", name="payments", credits=100)  # lags
    ingest(env, views)
    assert counter(env.db, group) == Decimal(50)  # from the log

    tick(env)
    use_source(env.db, settings_store.USAGE_SOURCE_SUMMARY)
    env.tenant.fail_views["group"] = 503
    ingest(env, views)
    use_source(env.db, settings_store.USAGE_SOURCE_ACTIVITY)
    env.tenant.fail_views.pop("group")
    env.tenant.set_entity_credits(view="group", name="payments", credits=150)

    tick(env)
    r = ingest(env, views)
    assert r.activity is not None and r.activity.seeded
    assert counter(env.db, group) == Decimal(50), (
        f"group budget holds {counter(env.db, group)} for one event of 50"
    )


def test_ambiguous_identities_never_charge_a_person_twice(env: SimpleNamespace) -> None:
    """Identity: read 1 holds 2 rows of one identity, both Alice's; read 2
    holds 3 (two Alice, one Cara); read 3 shows Alice's first row re-rendered
    as Cara's. Alice is charged 2 at most, Cara nothing she cannot be shown
    to own, the project 3."""
    from tests.activity_world import U_ALICE, U_CARA

    use_source(env.db, settings_store.USAGE_SOURCE_ACTIVITY)
    alice = budget(env.db, EntityType.USER, U_ALICE, created_at=START - timedelta(days=1))
    cara = budget(env.db, EntityType.USER, U_CARA, created_at=START - timedelta(days=1))
    api = budget(env.db, EntityType.PROJECT, P_API, created_at=START - timedelta(days=1))
    assert ingest(env).activity.seeded  # type: ignore[union-attr]
    tick(env)
    when = iso(env.clock.value - timedelta(minutes=3))
    rows = [
        env.tenant.add_activity(date=when, credits="7", project_id=P_API, email="alice@example.com")
        for _ in range(2)
    ]
    ingest(env)
    assert counter(env.db, alice) == 14 and counter(env.db, api) == 14
    tick(env)
    env.tenant.add_activity(date=when, credits="7", project_id=P_API, email="cara@example.com")
    ingest(env)
    assert counter(env.db, alice) == 14 and counter(env.db, cara) == 0
    assert counter(env.db, api) == 21
    tick(env)
    rows[0]["userEmail"] = "cara@example.com"
    ingest(env)
    tick(env)
    rows[1]["userEmail"] = "cara@example.com"  # now every row names Cara
    ingest(env)
    assert counter(env.db, alice) == 14 and counter(env.db, cara) == 0
    assert counter(env.db, api) == 21
