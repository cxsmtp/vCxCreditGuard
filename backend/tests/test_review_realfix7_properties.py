"""Seventh review of realfix: the property tests of the sixth round with one
more move, rename_back (a project renamed back to a name it had). Property
tests for the usage ledger (fifth and sixth reviews of realfix).

Random sequences over a small synthetic tenant, on a clock the test controls:
spending; mapping and unmapping; renames in either order; deletions and
returns; group membership changes; a project synced mid-run whose name was
already spending (claims), mapped to later; group and application rows of
their own appearing and leaving; demo mode on and off; plain, late-read and
skipped-evaluation rollovers; the lookback window rolling past old usage; a
change of lookback window; short org listings; names missing from a reading;
page drift serving a row twice; a dip in a doubted reading and its recovery;
budgets switched to counting existing usage and back. Every step runs an org
sync and a reading, and (unless the step skips it) an evaluation.

The oracle follows each reading: an increase counts towards the period the
reading was taken in, and towards none when the previous reading was taken in
an earlier period. A group or application budget is fed by its own row when
the previous reading of its view had one, by its projects otherwise. Checked
after every evaluation, for every budget and every period with a state:

* I1: usage never exceeds the new usage, observed in that period, of the names
  that belonged to one of the budget's entities (by the readings around the
  increase, or because the name is truly that project's), or of its own row;
* I2: usage is never less than the new usage, observed in that period, of the
  names that counted towards one of its entities in both readings around the
  increase (or of its own row present in both), less what is documented as
  lost (a name moving, appearing or missing, a roll-down, a doubted reading, a
  change of lookback window, an interval spanning a rollover).

And a retried or failed reading never counts anything twice.

``CXCG_PROPERTY_SEEDS`` runs more seeds (default 12). Synthetic data only.
"""

# ruff: noqa: F811 - the connected fixture is imported by name

from __future__ import annotations

import os
import random
from collections import defaultdict
from datetime import datetime, timedelta
from decimal import Decimal

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

import app.db.base as base_module
from app.models import LimitPeriodState, UsageDelta, UsageRecord
from app.models.enums import EntityType
from app.models.org import CxApplicationProject, CxProjectGroup
from app.services import connection as connection_service
from app.services import (
    cycle,
    evaluation,
    ingestion,
    ledger,
    limits_service,
    org_sync,
    settings_store,
)
from tests.conftest import ADMIN_PASSWORD, login
from tests.fake_tenant import FakeTenant
from tests.test_real_tenant_usage import connected, live_tenant  # noqa: F401
from tests.test_review_followups import ACTOR, _limit, _state

SEEDS = int(os.environ.get("CXCG_PROPERTY_SEEDS", "12"))
STEPS = 20
POOL = ["example-org/repo-a", "example-org/repo-b", "example-org/repo-c"]
PROJECTS = {"proj-api": "payments/api", "proj-web": "payments/web", "proj-tools": "platform/tools"}
# A project the sync brings mid-run, under a name the feed already reports.
NEW_PROJECT, NEW_NAME = "proj-new", "example-org/repo-c"
APP_MEMBERS = {"proj-api", "proj-web"}
OPS = [
    *["spend"] * 5,
    "map",
    "unmap",
    "rename_feed",
    "rename_sync",
    "delete",
    "restore",
    "group",
    "demo",
    "rollover",
    "late_read",
    "roll",
    "lookback",
    "short",
    "gap",
    "drift",
    "dip",
    "new_project",
    "group_row",
    "app_row",
    "existing",
    *["rename_back"] * int(os.environ.get("RR7_RENAME_BACK_WEIGHT", "2")),
]


class _Clock(datetime):
    """``app.db.base.utcnow`` (every timestamp the app takes) reads this."""

    value: datetime

    @classmethod
    def now(cls, tz=None):  # type: ignore[no-untyped-def, override]
        return cls.value


class _World:
    def __init__(self, tenant: FakeTenant, rng: random.Random, start: datetime) -> None:
        self.tenant = tenant
        self.rng = rng
        self.totals: dict[str, int] = {}
        self.saved_projects: dict[str, dict] = {}
        self.pending_rename: dict[str, str] = {}
        self.renames = 0
        self.op = ""
        self.period = "last_year"
        self.clock = start
        # The project each project name really belongs to, through renames.
        self.owner: dict[str, str] = {name: pid for pid, name in PROJECTS.items()}
        self.owner[NEW_NAME] = NEW_PROJECT
        # A name left out of one reading, with its total, back (and grown) after.
        self.gap: tuple[str, int] | None = None
        # Names reported lower than they are, in a doubted reading, this step.
        self.dipped: set[str] = set()
        # The group's and the application's own rows (None: not reported).
        self.group_row: int | None = None
        self.app_row: int | None = None
        # Grown since the last reading, while reported.
        self.group_grew = 0
        self.app_grew = 0
        self.after_late = False
        # Names the feed moved this step (old, new): their pending usage moves.
        self.moves: list[tuple[str, str]] = []
        self.skip_evaluation = False
        self.existing = False

    def set(self, name: str, total: int) -> None:
        self.totals[name] = total
        self.tenant.set_entity_credits(view="project", name=name, credits=total)

    def drop(self, name: str) -> None:
        self.totals.pop(name, None)
        self.tenant.consumption["project"] = [
            row for row in self.tenant.consumption["project"] if row["name"] != name
        ]

    def project(self, project_id: str) -> dict | None:
        return next((p for p in self.tenant.projects if p["id"] == project_id), None)

    def any_project(self, project_id: str) -> dict | None:
        return self.project(project_id) or self.saved_projects.get(project_id)

    def spend(self, name: str, amount: int) -> None:
        self.set(name, self.totals[name] + amount)
        # The group's and the application's own rows grow with what their
        # projects spend (as Checkmarx attributes it when it is spent).
        owner = self.owner.get(name)
        project = self.any_project(owner) if owner else None
        if self.group_row is not None and project and "grp-payments" in project["groups"]:
            self.group_row += amount
            self.group_grew += amount
            self._set_row("group", "Payments", "grp-payments", self.group_row)
        if self.app_row is not None and owner in APP_MEMBERS:
            self.app_row += amount
            self.app_grew += amount
            self._set_row("application", "Payments", "app-payments", self.app_row)

    def _set_row(self, view: str, name: str, entity_id: str, total: int | None) -> None:
        rows = [r for r in self.tenant.consumption[view] if r["name"] != name]
        self.tenant.consumption[view] = rows
        if total is not None:
            self.tenant.set_entity_credits(view=view, name=name, credits=total, entity_id=entity_id)


def _api(client: TestClient, path: str, payload: dict | None = None) -> httpx.Response:
    """POST as the admin, signing in again when the clock jumped past the
    session's lifetime."""
    response = client.post(path, json=payload)
    if response.status_code == 401:
        assert login(client, "admin", ADMIN_PASSWORD).status_code == 200
        response = client.post(path, json=payload)
    return response


def _serve(monkeypatch: pytest.MonkeyPatch, rows_of) -> None:  # type: ignore[no-untyped-def]
    """Serve the project view as ``rows_of(rows)`` says, in one page."""
    real = FakeTenant._consumption_response

    def response(self, params):  # type: ignore[no-untyped-def]
        if params.get("viewBy", [""])[0] != "project":
            return real(self, params)
        items, total = rows_of(list(self.consumption["project"]))
        return httpx.Response(
            200, json={"items": items, "totalItems": total, "totalPages": 1, "currentPage": 1}
        )

    monkeypatch.setattr(FakeTenant, "_consumption_response", response)


def _truncate_project_listings(monkeypatch: pytest.MonkeyPatch) -> None:
    real = FakeTenant._paged

    def paged(self, rows, key, params):  # type: ignore[no-untyped-def]
        if key == "projects":
            offset = int(params.get("offset", ["0"])[0])
            return httpx.Response(200, json={"totalCount": len(rows), key: rows[offset:][:1]})
        return real(self, rows, key, params)

    monkeypatch.setattr(FakeTenant, "_paged", paged)


def _step(world: _World, db: Session, client: TestClient, mp: pytest.MonkeyPatch, budgets) -> dict:  # type: ignore[no-untyped-def]
    """One random change. Returns the increase per name, and the names whose
    total really fell (rolled down)."""
    rng, increase, rolled = world.rng, defaultdict(int), set()
    world.dipped = set()
    world.moves = []
    world.skip_evaluation = False
    if world.after_late:
        # The reading after a late one is taken in the next month.
        world.after_late = False
        world.clock = _month_end(world.clock) + timedelta(minutes=10)
    if world.gap is not None:
        name, total = world.gap
        world.gap = None
        if name not in world.totals:
            world.set(name, total)
            amount = rng.randint(0, 40)
            world.spend(name, amount)
            increase[name] += amount
    op = world.op = rng.choice(OPS)
    names = sorted(world.totals)
    if op == "spend":
        for name in rng.sample(names, k=min(len(names), rng.randint(1, 3))):
            amount = rng.randint(1, 40)
            world.spend(name, amount)
            increase[name] += amount
    elif op in ("map", "unmap"):
        targets = [*PROJECTS, NEW_PROJECT]
        target = rng.choice(targets) if op == "map" else None
        response = _api(
            client,
            "/api/usage/unmatched-entities/map",
            {"view": "project", "subject_key": rng.choice(POOL), "entity_id": target},
        )
        # A project not synced (or deleted) cannot be mapped to.
        assert response.status_code in (200, 400, 404), response.text
    elif op == "rename_feed":
        # The feed reports the project's usage under its new name first.
        project_id = rng.choice(list(PROJECTS))
        project = world.project(project_id)
        if (
            project is not None
            and project["name"] in world.totals
            and project_id not in world.pending_rename
        ):
            world.renames += 1
            new = f"{project['name']}-f{world.renames}"
            world.owner[new] = project_id
            total = world.totals[project["name"]]
            world.moves.append((project["name"], new))
            world.drop(project["name"])
            world.set(new, total)
            world.pending_rename[project_id] = new
    elif op == "rename_sync":
        firsts = [k for k in world.pending_rename if not k.startswith("feed:")]
        if firsts:
            project_id = rng.choice(firsts)
            new = world.pending_rename.pop(project_id)
            project = world.any_project(project_id)
            if project is not None:
                project["name"] = new
        else:
            project_id = rng.choice(list(PROJECTS))
            project = world.project(project_id)
            if project is not None and project["name"] in world.totals:
                world.renames += 1
                old, new = project["name"], f"{project['name']}-s{world.renames}"
                project["name"] = new
                world.pending_rename[f"feed:{project_id}"] = f"{old}|{new}"
    elif op == "delete":
        project = world.project(rng.choice([*PROJECTS, NEW_PROJECT]))
        if project is not None:
            world.tenant.projects.remove(project)
            world.saved_projects[project["id"]] = project
    elif op == "restore" and world.saved_projects:
        project_id = rng.choice(sorted(world.saved_projects))
        world.tenant.projects.append(world.saved_projects.pop(project_id))
    elif op == "group":
        groups = world.any_project("proj-tools")["groups"]
        if "grp-payments" in groups:
            groups.remove("grp-payments")
        else:
            groups.append("grp-payments")
    elif op == "demo":
        assert _api(client, "/api/ops/demo/seed").status_code == 200
        name = rng.choice(names)
        amount = rng.randint(1, 40)
        world.spend(name, amount)
        increase[name] += amount
    elif op == "rollover":
        world.clock = (world.clock.replace(day=1) + timedelta(days=32)).replace(day=2)
    elif op == "late_read":
        # Read ten minutes before the month ends, evaluated only after it.
        late = _month_end(world.clock) - timedelta(minutes=10)
        if late > world.clock:
            world.clock = late - timedelta(minutes=5)  # _cycle adds 5
            world.after_late = True
            world.skip_evaluation = True
            name = rng.choice(names)
            amount = rng.randint(1, 40)
            world.spend(name, amount)
            increase[name] += amount
    elif op == "roll":
        name = rng.choice(names)
        world.set(name, max(0, world.totals[name] - rng.randint(1, 60)))
        rolled.add(name)
    elif op == "lookback":
        world.period = "last_90_days" if world.period == "last_year" else "last_year"
    elif op == "short":
        _truncate_project_listings(mp)
    elif op == "gap":
        name = rng.choice(names)
        world.gap = (name, world.totals[name])
        world.drop(name)
    elif op == "drift" and len(names) >= 2:
        # The ranking shifts between page requests: one row is served twice,
        # another not at all.
        twice, lost = rng.sample(names, 2)
        _serve(
            mp,
            lambda rows: (
                [r for r in rows if r["name"] != lost] + [r for r in rows if r["name"] == twice],
                len(rows),
            ),
        )
    elif op == "dip":
        name = rng.choice(names)
        low = str(world.totals[name] // 3)
        world.dipped = {name}
        _serve(
            mp,
            lambda rows: (
                [dict(r, creditsUsed=low) if r["name"] == name else r for r in rows],
                len(rows) + 1,
            ),
        )
    elif op == "new_project":
        if world.any_project(NEW_PROJECT) is None:
            world.tenant.add_project(project_id=NEW_PROJECT, name=NEW_NAME, group_ids=[])
    elif op == "group_row":
        if world.group_row is None:
            # First reported with history in it.
            world.group_row = rng.randint(100, 3000)
        else:
            world.group_row = None
        world.group_grew = 0
        world._set_row("group", "Payments", "grp-payments", world.group_row)
    elif op == "app_row":
        world.app_row = rng.randint(100, 3000) if world.app_row is None else None
        world.app_grew = 0
        world._set_row("application", "Payments", "app-payments", world.app_row)
    elif op == "rename_back":
        # A project renamed back to its original name, feed and sync together.
        for project_id in rng.sample(list(PROJECTS), k=len(PROJECTS)):
            project = world.project(project_id)
            original = PROJECTS[project_id]
            if (
                project is not None
                and project["name"] != original
                and project["name"] in world.totals
                and original not in world.totals
                and project_id not in world.pending_rename
                and f"feed:{project_id}" not in world.pending_rename
            ):
                current = project["name"]
                total = world.totals[current]
                world.owner[original] = project_id
                world.moves.append((current, original))
                world.drop(current)
                world.set(original, total)
                project["name"] = original
                break
    elif op == "existing":
        world.existing = not world.existing
        limits_service.update_limit(
            db,
            limit=budgets["proj-web"],
            changes={"count_existing_usage": world.existing},
            actor=ACTOR,
        )
        db.commit()
    # The feed catching up with a rename the sync learnt first, now or later.
    for key in [k for k in world.pending_rename if k.startswith("feed:")]:
        if rng.random() < 0.5:
            old, new = world.pending_rename.pop(key).split("|")
            if old in world.totals:
                world.owner[new] = world.owner.get(old, "")
                total = world.totals[old]
                world.moves.append((old, new))
                world.drop(old)
                world.set(new, total)
    return {"increase": dict(increase), "rolled": rolled}


def _month_end(moment: datetime) -> datetime:
    return (moment.replace(day=1) + timedelta(days=32)).replace(
        day=1, hour=0, minute=0, second=0, microsecond=0
    )


def _cycle(db: Session, world: _World, client: TestClient) -> bool:
    """What the cycle does, on the world's clock. True when it read usage."""
    world.clock += timedelta(minutes=5)
    _Clock.value = world.clock
    cx = connection_service.get_client(db)
    if settings_store.demo_mode(db):
        evaluation.evaluate_all(db, now=world.clock)
        db.commit()
        assert _api(client, "/api/ops/demo/clear").status_code == 200
        return False
    org_sync.sync_org_model(db, cx)
    db.commit()
    ingestion.ingest_usage(db, cx, period_param=world.period)
    db.commit()
    if not world.skip_evaluation:
        evaluation.evaluate_all(db, now=world.clock)
        db.commit()
    return True


class _Reading:
    def __init__(self, db: Session, view: str) -> None:
        snapshot = ingestion.latest_live_snapshot(db, view)
        self.id = snapshot.id if snapshot else None
        self.at = snapshot.collected_at if snapshot else None
        self.period = snapshot.period_param if snapshot else None
        self.rows: dict[str, str | None] = (
            {
                r.subject_key: r.entity_id
                for r in db.scalars(
                    select(UsageRecord).where(UsageRecord.snapshot_id == snapshot.id)
                )
            }
            if snapshot
            else {}
        )

    def has(self, entity_id: str) -> bool:
        return entity_id in self.rows.values()


def _feeds(db: Session) -> dict[str, set[str]]:
    """Budget -> the projects that feed it now (through the project view)."""
    groups: dict[str, set[str]] = defaultdict(set)
    for link in db.scalars(select(CxProjectGroup)):
        groups[link.group_id].add(link.project_id)
    apps: dict[str, set[str]] = defaultdict(set)
    for link in db.scalars(select(CxApplicationProject)):
        apps[link.application_id].add(link.project_id)
    return {
        "proj-api": {"proj-api"},
        "proj-web": {"proj-web"},
        "proj-tools": {"proj-tools"},
        NEW_PROJECT: {NEW_PROJECT},
        "grp-payments": groups["grp-payments"],
        "app-payments": apps["app-payments"],
    }


def _month(moment: datetime | None) -> str | None:
    return moment.strftime("%Y-%m") if moment else None


@pytest.mark.parametrize("seed", range(SEEDS))
def test_random_sequences_keep_both_invariants(
    db: Session,
    connected,
    admin_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    seed: int,
) -> None:
    rng = random.Random(seed)
    start = base_module.utcnow().replace(day=3, hour=8, minute=0, second=0, microsecond=0)
    _Clock.value = start
    monkeypatch.setattr(base_module, "datetime", _Clock)
    tenant = live_tenant()
    tenant.consumption["project"] = []
    # Other groups and applications with large rows of their own, so that one
    # leaving its view is never a collapse the feed is doubted for.
    tenant.consumption["group"] = []
    tenant.set_entity_credits(view="group", name="AA-Platform", credits=100000)
    tenant.consumption["application"] = []
    tenant.add_application(application_id="app-filler", name="Filler", project_ids=[])
    tenant.set_entity_credits(
        view="application", name="Filler", credits=100000, entity_id="app-filler"
    )
    world = _World(tenant, rng, start)
    # Large totals, so that a roll-down is never a collapse the feed is doubted for.
    for name in [*PROJECTS.values(), *POOL]:
        world.set(name, 1000 + rng.randint(0, 500))
    connected(tenant)
    _cycle(db, world, admin_client)
    budgets = {
        "proj-api": _limit(db, EntityType.PROJECT, "proj-api"),
        "proj-web": _limit(db, EntityType.PROJECT, "proj-web"),
        "proj-tools": _limit(db, EntityType.PROJECT, "proj-tools"),
        NEW_PROJECT: _limit(db, EntityType.PROJECT, NEW_PROJECT),
        "grp-payments": _limit(db, EntityType.GROUP, "grp-payments"),
        "app-payments": _limit(db, EntityType.APPLICATION, "app-payments"),
    }
    _cycle(db, world, admin_client)
    # (period, budget) -> bound
    lower: dict[tuple[str, str], int] = defaultdict(int)
    upper: dict[tuple[str, str], int] = defaultdict(int)
    last = _Reading(db, "project")
    last_group, last_app = _Reading(db, "group"), _Reading(db, "application")
    last2_group: _Reading | None = None
    last2_app: _Reading | None = None
    last_feeds = _feeds(db)
    increases: dict[str, int] = defaultdict(int)
    rolled: set[str] = set()
    history: list[str] = []
    totals_periods: set[str | None] = set()
    for _ in range(STEPS):
        with pytest.MonkeyPatch.context() as mp:
            change = _step(world, db, admin_client, mp, budgets)
            history.append(f"{world.clock:%m-%d %H:%M} {world.op} {change}")
            for name, amount in change["increase"].items():
                increases[name] += amount
            rolled |= change["rolled"]
            for old, new in world.moves:
                # The feed reports the name's usage under its new name now.
                if old in increases:
                    increases[new] += increases.pop(old)
                if old in rolled:
                    rolled.discard(old)
                    rolled.add(new)
            group_grew, app_grew = world.group_grew, world.app_grew
            read = _cycle(db, world, admin_client)
            if world.existing and not world.skip_evaluation:
                # Evaluated from reported totals: that period is not the
                # ledger's, and a closed period is never rewritten later.
                totals_periods.add(_month(world.clock))
        if not read:
            continue
        world.group_grew = world.app_grew = 0
        now = _Reading(db, "project")
        group, app = _Reading(db, "group"), _Reading(db, "application")
        assert now.id != last.id, history
        history.append(f"  reading {now.rows}")
        feeds = _feeds(db)
        period = _month(now.at)
        counts = _month(last.at) == period and last.period == now.period
        seen = {name for name in now.rows if name not in world.dipped}
        own = {
            "grp-payments": ("grp-payments", last_group, group, group_grew, last2_group),
            "app-payments": ("app-payments", last_app, app, app_grew, last2_app),
        }
        for budget, projects in feeds.items():
            if not counts:
                continue
            key = (period, budget)
            if budget in own and own[budget][1].has(own[budget][0]):
                # Fed by its own row: what it grew while in both readings.
                entity, before_view, now_view, grew, before2_view = own[budget]
                if now_view.has(entity) and before_view.period == now_view.period:
                    upper[key] += grew
                    if before2_view is not None and before2_view.has(entity):
                        # A row's second reading counts nothing (eighth
                        # review): only from its third does it.
                        lower[key] += grew
                continue
            members = projects | last_feeds[budget]
            for name, amount in increases.items():
                if name not in seen:
                    continue
                before, after = last.rows.get(name), now.rows.get(name)
                if {before, after, world.owner.get(name)} & members:
                    upper[key] += amount
                if (
                    name in last.rows
                    and before == after
                    and after in projects
                    and name not in rolled
                ):
                    lower[key] += amount
        # What a name absent from this reading (or reported lower than it is)
        # added is still to be observed.
        increases = defaultdict(int, {n: a for n, a in increases.items() if n not in seen})
        rolled = {n for n in rolled if n not in seen}
        last2_group, last2_app = last_group, last_app
        last, last_group, last_app, last_feeds = now, group, app, feeds
        if world.skip_evaluation:
            continue
        db.expire_all()
        for budget, limit in budgets.items():
            if budget == "proj-web" and world.existing:
                continue  # it counts reported totals while switched
            for state in db.scalars(
                select(LimitPeriodState).where(LimitPeriodState.limit_id == limit.id)
            ):
                if budget == "proj-web" and state.period_key in totals_periods:
                    continue
                key = (state.period_key, budget)
                used = state.credits_used
                assert lower[key] <= used <= upper[key], (
                    f"seed {seed}, {budget} {state.period_key}: "
                    f"{lower[key]} <= {used} <= {upper[key]}\n" + "\n".join(history)
                )


def test_a_retried_reading_counts_nothing_twice(
    db: Session,
    connected,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tenant = live_tenant()
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    project = _limit(db, EntityType.PROJECT, "proj-web")
    cycle.run_cycle(trigger="manual")
    tenant.set_entity_credits(view="project", name="payments/web", credits=54, entity_id="proj-web")

    # The reading fails after its increases were counted: nothing is kept.
    real = ledger._feed

    def fail(*args, **kwargs):  # type: ignore[no-untyped-def]
        real(*args, **kwargs)
        raise RuntimeError("the database went away")

    monkeypatch.setattr(ledger, "_feed", fail)
    client = connection_service.get_client(db)
    with pytest.raises(RuntimeError):
        ingestion.ingest_usage(db, client)
    db.rollback()
    monkeypatch.setattr(ledger, "_feed", real)
    assert db.scalar(select(UsageDelta).where(UsageDelta.subject_key == "payments/web")) is None

    # Retried, and then read again with nothing new: counted once.
    ingestion.ingest_usage(db, client)
    db.commit()
    ingestion.ingest_usage(db, client)
    db.commit()
    cycle.run_cycle(trigger="manual")
    cycle.run_cycle(trigger="manual")
    assert _state(db, project).credits_used == Decimal("50")
