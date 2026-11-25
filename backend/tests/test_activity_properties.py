"""Property tests for the activity source (app/services/activity_source.py),
next to the summary ledger it hands over to and takes over from.

Random sequences over a small synthetic tenant, on a clock the test controls:
spending (identical rows included, an integration account, Auto-triage, an
unknown person); rows arriving late; rows ageing out of the log's window,
and rows inserted, while it is being read; rows of one date reordered between
requests; the per-cycle page cap; the log failing for a cycle (5xx) or going
away (404); the usage source switched between the activity log and the
summary only; month rollovers; a budget created mid-run. Every step runs the
ingest (activity log first, then the summary's project and user views).

Checked after every step, for every budget:

* I1: what its counters hold never exceeds the real usage of the events that
  belong to it, observed from the step before it was created on (whichever
  source counted them), per month (an event belongs to the month of its date,
  or of the moment it was added, the summary counting what it observes) and
  over all months;
* no event is charged to two user budgets: the user budgets together never
  hold more than all usage.

``CXCG_PROPERTY_SEEDS`` runs more seeds (default 12). Synthetic data only.
"""

from __future__ import annotations

import os
import random
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checkmarx import activity as activity_api
from app.models import BudgetUsage, CreditLimit
from app.models.activity import subject_entity_id
from app.models.enums import EntityType, UsageView
from app.services import ingestion, periods, settings_store
from tests.activity_world import (
    APP_PAY,
    G_PAY,
    P_API,
    P_TOOLS,
    P_WEB,
    PROJECT_NAMES,
    U_ALICE,
    U_BOB,
    budget,
    install_clock,
    iso,
    new_tenant,
    seed_org,
)

SEEDS = int(os.environ.get("CXCG_PROPERTY_SEEDS", "12"))
# The review's moves (a group's own row leaving and coming back, a project
# missing from the summary across a handover) are part of the normal run;
# CXCG_REVIEW_MOVES=0 leaves them out.
REVIEW_MOVES = os.environ.get("CXCG_REVIEW_MOVES", "1") != "0"
STEPS = 25
START = datetime(2026, 11, 20, 12, 0, tzinfo=UTC)
OPS = [
    *["spend"] * 6,
    "duplicate",
    "late",
    "drift_age",
    "drift_insert",
    "ties",
    "cap",
    "fail_transient",
    "fail_404",
    "switch",
    "rollover",
    "budget",
    *(["group_row", "hide_project"] if REVIEW_MOVES else []),
]
PEOPLE = [
    ("Alice E", "alice@example.com"),
    ("jdoe", ""),
    ("tracix[bot]", ""),
    ("Auto-triage", ""),
    ("Unknown Person", ""),
]
PROJECTS = [P_API, P_WEB, P_TOOLS]


@dataclass
class _Event:
    date: datetime
    added: datetime
    project: str
    application: str | None
    user: str
    email: str
    credits: Decimal


def _weight(limit: CreditLimit, event: _Event) -> int:
    """How many times the event may count towards the budget: once, or for a
    group budget that includes member usage, once by its project and once by
    its member (the summary feed reads them as two views and adds both, as
    documented; the activity log counts such an event once)."""
    if str(limit.entity_type) == EntityType.GROUP and limit.include_member_usage:
        return int(event.project in (P_API, P_WEB)) + int(event.email == "alice@example.com")
    return int(_belongs(limit, event))


def _belongs(limit: CreditLimit, event: _Event) -> bool:
    kind, entity = str(limit.entity_type), str(limit.entity_id)
    if kind == EntityType.PROJECT:
        return event.project == entity
    if kind == EntityType.GROUP:
        return event.project in (P_API, P_WEB)
    if kind == EntityType.APPLICATION:
        return event.project == P_API or event.application == entity
    if entity == U_ALICE:
        return event.email == "alice@example.com"
    if entity == U_BOB:
        return event.user == "jdoe"
    if entity == subject_entity_id("tracix[bot]"):
        return event.user == "tracix[bot]"
    return False


class _World:
    def __init__(self, db: Session, rng: random.Random, clock) -> None:  # type: ignore[no-untyped-def]
        self.db = db
        self.rng = rng
        self.clock = clock
        self.tenant = new_tenant()
        self.client = self.tenant.client()
        self.events: list[_Event] = []
        # budget id -> events added after this moment may count towards it.
        self.counted_from: dict[int, datetime] = {}
        self.previous_step = START - timedelta(days=1)
        # The group's own row is missing from the summary's group view.
        self.group_hidden = False
        self.pending_hide = False
        # Readings for which the summary's project view leaves P_API out.
        self.project_hidden_for = 0

    @property
    def now(self) -> datetime:
        return self.clock.value

    def add(
        self, *, date: datetime, person: tuple[str, str] | None = None, project=None, credits=None
    ) -> None:  # type: ignore[no-untyped-def]
        user, email = person or self.rng.choice(PEOPLE)
        project = project or self.rng.choice(PROJECTS)
        application = APP_PAY if self.rng.random() < 0.2 else None
        credits = Decimal(credits or self.rng.choice(["1", "1", "2", "3.5", "5"]))
        row = self.tenant.add_activity(
            date=iso(date),
            credits=str(credits),
            project_id=project,
            application_id=application,
            user=user,
            email=email,
        )
        self.events.append(
            _Event(
                date.replace(microsecond=0), self.now, project, application, user, email, credits
            )
        )
        return row  # type: ignore[return-value]

    def summary(self) -> None:
        """The consumption summary: cumulative totals by name, from every
        event (its window is wider than the log's)."""
        by_project: dict[str, Decimal] = {}
        by_person: dict[tuple[str, str], Decimal] = {}
        for event in self.events:
            by_project[event.project] = by_project.get(event.project, Decimal(0)) + event.credits
            key = (event.user, event.email)
            by_person[key] = by_person.get(key, Decimal(0)) + event.credits
        for project, total in by_project.items():
            self.tenant.set_entity_credits(
                view="project", name=PROJECT_NAMES[project], credits=float(total)
            )
        if REVIEW_MOVES:
            # A large other row, so that a row left out is no collapse.
            self.tenant.set_entity_credits(view="project", name="zz-other", credits=1_000_000)
            if self.project_hidden_for > 0:
                self.project_hidden_for -= 1
                self.tenant.consumption["project"] = [
                    row
                    for row in self.tenant.consumption.get("project", [])
                    if row["name"] != PROJECT_NAMES[P_API]
                ]
        for (user, email), total in by_person.items():
            self.tenant.set_user_credits(name=user, email=email or None, credits=float(total))
        if REVIEW_MOVES:
            group_total = sum(
                (event.credits for event in self.events if event.project in (P_API, P_WEB)),
                Decimal(0),
            )
            rows = [{"name": "someone-else", "creditsUsed": "100000", "percentOfTotal": 1.0}]
            if not self.group_hidden:
                rows.append(
                    {"name": "payments", "creditsUsed": str(group_total), "percentOfTotal": 1.0}
                )
            self.tenant.consumption["group"] = rows

    def age_out(self) -> None:
        """The log holds the last 30 days only."""
        floor = self.now - timedelta(days=30)
        self.tenant.activity = [
            row
            for row in self.tenant.activity or []
            if activity_api.parse_date(row["date"]) >= floor  # type: ignore[operator]
        ]


def _check(world: _World, step: int, op: str) -> None:
    db = world.db
    db.expire_all()
    rows = list(db.scalars(select(BudgetUsage)))
    limits = {limit.id: limit for limit in db.scalars(select(CreditLimit))}
    total = sum((event.credits for event in world.events), Decimal(0))
    users = Decimal(0)
    for limit_id, limit in limits.items():
        start = world.counted_from[limit_id]
        mine = [
            event
            for event in world.events
            for _ in range(_weight(limit, event))
            if event.added > start
        ]
        counted = Decimal(0)
        for row in rows:
            if row.limit_id != limit_id or "-Q" in row.period_key:
                continue
            counted += Decimal(row.credits)
            month = [
                event
                for event in mine
                if periods.month_start(event.date).strftime("%Y-%m") == row.period_key
                or periods.month_start(event.added).strftime("%Y-%m") == row.period_key
            ]
            bound = sum((event.credits for event in month), Decimal(0))
            assert Decimal(row.credits) <= bound, (
                f"step {step} ({op}): {limit.entity_type} {limit.entity_id} counted "
                f"{row.credits} in {row.period_key}, its events add up to {bound}"
            )
        bound = sum((event.credits for event in mine), Decimal(0))
        assert counted <= bound, (
            f"step {step} ({op}): {limit.entity_type} {limit.entity_id} counted {counted}, "
            f"its events add up to {bound}"
        )
        if limit.entity_type == EntityType.USER:
            users += counted
    assert users <= total, f"step {step} ({op}): user budgets hold {users} of {total}"


def _run(db: Session, monkeypatch: pytest.MonkeyPatch, seed: int) -> None:
    rng = random.Random(seed)
    clock = install_clock(monkeypatch, START)
    monkeypatch.setattr(activity_api, "ACTIVITY_PAGE_SIZE", rng.choice([3, 4, 5]))
    seed_org(db)
    world = _World(db, rng, clock)
    created = START - timedelta(days=1)
    for entity_type, entity_id, members in (
        (EntityType.PROJECT, P_API, False),
        (EntityType.PROJECT, P_WEB, False),
        (EntityType.GROUP, G_PAY, rng.random() < 0.5),
        (EntityType.APPLICATION, APP_PAY, False),
        (EntityType.USER, U_ALICE, False),
        (EntityType.USER, U_BOB, False),
        (EntityType.USER, subject_entity_id("tracix[bot]"), False),
    ):
        limit = budget(db, entity_type, entity_id, created_at=created, include_member_usage=members)
        world.counted_from[limit.id] = created - timedelta(days=1)
    if rng.random() < 0.3:
        settings_store.set_value(
            db, settings_store.KEY_USAGE_SOURCE, settings_store.USAGE_SOURCE_SUMMARY
        )
        db.commit()
    tools_budget = False
    for step in range(STEPS):
        op = rng.choice(OPS)
        world.tenant.activity_hook = None
        world.tenant.activity_tie_shuffle = None
        world.tenant.activity_status = None
        settings_store.set_value(db, settings_store.KEY_ACTIVITY_MAX_PAGES, 40)
        db.commit()
        world.previous_step = world.now
        clock.value = world.now + timedelta(minutes=rng.randint(5, 40))
        for _ in range(rng.randint(0, 4)):
            world.add(date=world.now - timedelta(minutes=rng.uniform(0, 4)))
        if op == "duplicate":
            for _ in range(rng.randint(2, 4)):
                world.add(
                    date=world.now - timedelta(minutes=1),
                    person=("Auto-triage", ""),
                    project=P_API,
                )
        elif op == "late":
            world.add(date=world.now - timedelta(minutes=rng.choice([30, 90, 200])))
        elif op == "drift_age":

            def age(page: int) -> None:
                if page > 1 and world.tenant.activity and rng.random() < 0.7:
                    world.tenant.activity.sort(key=lambda row: row["date"])
                    world.tenant.activity.pop(0)

            world.tenant.activity_hook = age
        elif op == "drift_insert":

            def insert(page: int) -> None:
                if page > 1 and rng.random() < 0.6:
                    world.add(date=world.now - timedelta(minutes=rng.uniform(1, 60)))

            world.tenant.activity_hook = insert
        elif op == "ties":
            stamp = world.now - timedelta(minutes=2)
            for _ in range(rng.randint(3, 7)):
                world.add(date=stamp)
            world.tenant.activity_tie_shuffle = random.Random(rng.random())
        elif op == "cap":
            settings_store.set_value(db, settings_store.KEY_ACTIVITY_MAX_PAGES, rng.randint(1, 3))
            db.commit()
        elif op == "fail_transient":
            world.tenant.activity_status = rng.choice([500, 503])
        elif op == "fail_404":
            world.tenant.activity_status = 404
        elif op == "switch":
            current = settings_store.usage_source(db)
            settings_store.set_value(
                db,
                settings_store.KEY_USAGE_SOURCE,
                settings_store.USAGE_SOURCE_SUMMARY
                if current == settings_store.USAGE_SOURCE_ACTIVITY
                else settings_store.USAGE_SOURCE_ACTIVITY,
            )
            db.commit()
        elif op == "rollover":
            following = periods.next_month_start(world.now)
            clock.value = following - timedelta(minutes=rng.randint(1, 20))
            world.add(date=world.now - timedelta(seconds=1))
        elif op == "group_row":
            # The group's own row leaves (or comes back to) the group view.
            # Leaving: sometimes during a short log outage that began a cycle
            # earlier, with a large spend on a group project in that cycle.
            if world.group_hidden or rng.random() < 0.4:
                world.group_hidden = not world.group_hidden
            else:
                world.tenant.activity_status = 503
                world.add(date=world.now - timedelta(minutes=1), project=P_API, credits="500")
                world.pending_hide = True
        elif op == "hide_project":
            world.project_hidden_for = rng.randint(1, 4)
            if rng.random() < 0.5:
                world.add(date=world.now - timedelta(minutes=1), project=P_API, credits="300")
        elif op == "budget" and not tools_budget:
            tools_budget = True
            limit = budget(db, EntityType.PROJECT, P_TOOLS, created_at=world.now)
            world.counted_from[limit.id] = world.previous_step
        if world.pending_hide and op != "group_row":
            # Second cycle of the outage: the group's row has left the view.
            world.pending_hide = False
            world.group_hidden = True
            world.tenant.activity_status = 503
        world.age_out()
        world.summary()
        views = (UsageView.PROJECT, UsageView.USER)
        if REVIEW_MOVES:
            views = (UsageView.PROJECT, UsageView.USER, UsageView.GROUP)
        ingestion.ingest_usage(db, world.client, views=views)
        db.commit()
        _check(world, step, op)


@pytest.mark.parametrize("seed", range(SEEDS))
def test_activity_source_never_over_counts(
    db: Session, monkeypatch: pytest.MonkeyPatch, seed: int
) -> None:
    _run(db, monkeypatch, seed)
