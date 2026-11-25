"""Property tests for the usage ledger (fifth review of realfix).

Random sequences of spending, mapping and unmapping, renames in either order,
deletions and returns, group membership changes, demo mode on and off, period
rollovers, the lookback window rolling past old usage, a change of lookback
window and short org listings run over a small synthetic tenant: an org sync, a
reading and an evaluation at every step. After every step, for every budget:

* I1: its usage never exceeds the new usage this period of the names that
  belonged to one of its entities, now or before (by the reading, or because
  the name is truly that project's, through renames);
* I2: its usage is never less than the new usage this period of the names that
  counted towards one of its entities in both readings around the increase
  (what is documented as lost: a name moving or appearing, the lookback window
  rolling past old usage, a change of lookback window).

And a retried or failed reading never counts anything twice.

``CXCG_PROPERTY_SEEDS`` runs more seeds (default 12). Synthetic data only.
"""

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

from app.db.base import utcnow
from app.models import LimitPeriodState, UsageDelta, UsageRecord
from app.models.enums import EntityType
from app.models.org import CxProjectGroup
from app.services import connection as connection_service
from app.services import cycle, evaluation, ingestion, ledger, org_sync, settings_store
from app.services.periods import current_window
from tests.fake_tenant import FakeTenant
from tests.test_real_tenant_usage import connected, live_tenant  # noqa: F401
from tests.test_review_followups import _limit, _state

SEEDS = int(os.environ.get("CXCG_PROPERTY_SEEDS", "12"))
STEPS = 16
POOL = ["example-org/repo-a", "example-org/repo-b", "example-org/repo-c"]
PROJECTS = {"proj-api": "payments/api", "proj-web": "payments/web", "proj-tools": "platform/tools"}
OPS = [
    *["spend"] * 4,
    "map",
    "unmap",
    "rename_feed",
    "rename_sync",
    "delete",
    "restore",
    "group",
    "demo",
    "rollover",
    "roll",
    "lookback",
    "short",
    "gap",
]


class _World:
    def __init__(self, tenant: FakeTenant, rng: random.Random) -> None:
        self.tenant = tenant
        self.rng = rng
        self.totals: dict[str, int] = {}
        self.saved_projects: dict[str, dict] = {}
        self.pending_rename: dict[str, str] = {}
        self.renames = 0
        self.op = ""
        self.period = "last_year"
        self.clock = utcnow()
        # The project each project name really belongs to, through renames.
        self.owner: dict[str, str] = {name: pid for pid, name in PROJECTS.items()}
        # A name left out of one reading, with its total, back (and grown) after.
        self.gap: tuple[str, int] | None = None

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


def _truncate_project_listings(monkeypatch: pytest.MonkeyPatch) -> None:
    real = FakeTenant._paged

    def paged(self, rows, key, params):  # type: ignore[no-untyped-def]
        if key == "projects":
            offset = int(params.get("offset", ["0"])[0])
            return httpx.Response(200, json={"totalCount": len(rows), key: rows[offset:][:1]})
        return real(self, rows, key, params)

    monkeypatch.setattr(FakeTenant, "_paged", paged)


def _step(world: _World, client: TestClient, monkeypatch) -> tuple[dict[str, int], set[str]]:  # type: ignore[no-untyped-def]
    """One random change. Returns (increase per name, names rolled down)."""
    rng, increase, rolled = world.rng, defaultdict(int), set()
    if world.gap is not None:
        name, total = world.gap
        world.gap = None
        amount = rng.randint(0, 40)
        world.set(name, total + amount)
        increase[name] += amount
    op = world.op = rng.choice(OPS)
    names = sorted(world.totals)
    if op == "spend":
        for name in rng.sample(names, k=min(len(names), rng.randint(1, 3))):
            amount = rng.randint(1, 40)
            world.set(name, world.totals[name] + amount)
            increase[name] += amount
    elif op in ("map", "unmap"):
        target = rng.choice(list(PROJECTS)) if op == "map" else None
        response = client.post(
            "/api/usage/unmatched-entities/map",
            json={"view": "project", "subject_key": rng.choice(POOL), "entity_id": target},
        )
        # A deleted project cannot be mapped to; an unmapped name not unmapped.
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
            world.drop(project["name"])
            world.set(new, total)
            world.pending_rename[project_id] = new
    elif op == "rename_sync":
        # The sync learns a rename: one the feed reported first, or a new one
        # the feed reports later.
        firsts = [k for k in world.pending_rename if not k.startswith("feed:")]
        if firsts:
            project_id = rng.choice(firsts)
            new = world.pending_rename.pop(project_id)
            project = world.project(project_id) or world.saved_projects.get(project_id)
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
        project = world.project(rng.choice(list(PROJECTS)))
        if project is not None:
            world.tenant.projects.remove(project)
            world.saved_projects[project["id"]] = project
    elif op == "restore" and world.saved_projects:
        project_id = rng.choice(sorted(world.saved_projects))
        world.tenant.projects.append(world.saved_projects.pop(project_id))
    elif op == "group":
        tools = world.project("proj-tools") or world.saved_projects["proj-tools"]
        groups = tools["groups"]
        if "grp-payments" in groups:
            groups.remove("grp-payments")
        else:
            groups.append("grp-payments")
    elif op == "demo":
        # Demo mode for a step, with spending meanwhile.
        assert client.post("/api/ops/demo/seed").status_code == 200
        name = rng.choice(names)
        amount = rng.randint(1, 40)
        world.set(name, world.totals[name] + amount)
        increase[name] += amount
    elif op == "rollover":
        world.clock = (world.clock.replace(day=1) + timedelta(days=32)).replace(day=2)
    elif op == "roll":
        name = rng.choice(names)
        world.set(name, max(0, world.totals[name] - rng.randint(1, 60)))
        rolled.add(name)
    elif op == "lookback":
        world.period = "last_90_days" if world.period == "last_year" else "last_year"
    elif op == "short":
        _truncate_project_listings(monkeypatch)
    elif op == "gap":
        name = rng.choice(names)
        world.gap = (name, world.totals[name])
        world.drop(name)
    # The feed catching up with a rename the sync learnt first, now or later.
    for key in [k for k in world.pending_rename if k.startswith("feed:")]:
        if rng.random() < 0.5:
            old, new = world.pending_rename.pop(key).split("|")
            if old in world.totals:
                world.owner[new] = world.owner.get(old, "")
                total = world.totals[old]
                world.drop(old)
                world.set(new, total)
    return dict(increase), rolled


def _cycle(db: Session, world: _World, client: TestClient) -> None:
    """What the cycle does, on the world's clock (so periods can roll over)."""
    cx = connection_service.get_client(db)
    world.clock += timedelta(minutes=5)
    if settings_store.demo_mode(db):
        evaluation.evaluate_all(db, now=world.clock)
        db.commit()
        assert client.post("/api/ops/demo/clear").status_code == 200
        return
    org_sync.sync_org_model(db, cx)
    db.commit()
    ingestion.ingest_usage(db, cx, period_param=world.period)
    db.commit()
    evaluation.evaluate_all(db, now=world.clock)
    db.commit()


def _reading(db: Session) -> tuple[int | None, str | None, dict[str, str | None]]:
    snapshot = ingestion.latest_live_snapshot(db, "project")
    if snapshot is None:
        return None, None, {}
    return (
        snapshot.id,
        snapshot.period_param,
        {
            r.subject_key: r.entity_id
            for r in db.scalars(select(UsageRecord).where(UsageRecord.snapshot_id == snapshot.id))
        },
    )


def _feeds(db: Session) -> dict[str, set[str]]:
    """Budget -> the projects that feed it now."""
    groups: dict[str, set[str]] = defaultdict(set)
    for link in db.scalars(select(CxProjectGroup)):
        groups[link.group_id].add(link.project_id)
    return {
        "proj-api": {"proj-api"},
        "proj-web": {"proj-web"},
        "proj-tools": {"proj-tools"},
        "grp-payments": groups["grp-payments"],
    }


def _used(db: Session, limit, moment: datetime) -> Decimal:  # type: ignore[no-untyped-def]
    db.expire_all()
    state = db.scalar(
        select(LimitPeriodState).where(
            LimitPeriodState.limit_id == limit.id,
            LimitPeriodState.period_key == current_window(limit, moment).key,
        )
    )
    assert state is not None
    return state.credits_used


@pytest.mark.parametrize("seed", range(SEEDS))
def test_random_sequences_keep_both_invariants(
    db: Session,
    connected,  # noqa: F811
    admin_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    seed: int,
) -> None:
    rng = random.Random(seed)
    tenant = live_tenant()
    tenant.consumption["project"] = []
    tenant.consumption["application"] = []
    world = _World(tenant, rng)
    # Large totals, so that a roll-down is never a collapse the feed is doubted for.
    for name in [*PROJECTS.values(), *POOL]:
        world.set(name, 1000 + rng.randint(0, 500))
    connected(tenant)
    _cycle(db, world, admin_client)
    budgets = {
        "proj-api": _limit(db, EntityType.PROJECT, "proj-api"),
        "proj-web": _limit(db, EntityType.PROJECT, "proj-web"),
        "proj-tools": _limit(db, EntityType.PROJECT, "proj-tools"),
        "grp-payments": _limit(db, EntityType.GROUP, "grp-payments"),
    }
    _cycle(db, world, admin_client)
    lower = dict.fromkeys(budgets, 0)
    upper = dict.fromkeys(budgets, 0)
    last_id, last_period, last = _reading(db)
    last_feeds = _feeds(db)
    increases: dict[str, int] = defaultdict(int)
    rolled: set[str] = set()
    history: list[str] = []
    for _ in range(STEPS):
        monkeypatch.undo()
        connected(tenant)
        period_key = current_window(budgets["proj-api"], world.clock).key
        step_increase, step_rolled = _step(world, admin_client, monkeypatch)
        history.append(f"{world.op} {step_increase} rolled={sorted(step_rolled)}")
        for name, amount in step_increase.items():
            increases[name] += amount
        rolled |= step_rolled
        if current_window(budgets["proj-api"], world.clock).key != period_key:
            # A new period: its usage starts from nothing. Usage observed by
            # the next reading counts towards the period it is evaluated in.
            lower = dict.fromkeys(budgets, 0)
            upper = dict.fromkeys(budgets, 0)
        _cycle(db, world, admin_client)
        reading_id, period, now = _reading(db)
        if reading_id == last_id:
            continue  # no believed reading (demo mode): the next one carries it
        history.append(f"  reading {now}")
        feeds = _feeds(db)
        for budget, projects in feeds.items():
            members = projects | last_feeds[budget]
            for name, amount in increases.items():
                before, after = last.get(name), now.get(name)
                if {before, after, world.owner.get(name)} & members:
                    upper[budget] += amount
                if (
                    period == last_period
                    and name in last
                    and name in now
                    and before == after
                    and after in projects
                    and name not in rolled
                ):
                    lower[budget] += amount
        # What a name absent from both readings added is still to be observed.
        unseen = {name for name in increases if name not in last and name not in now}
        increases = defaultdict(int, {name: increases[name] for name in unseen})
        rolled = rolled & unseen
        last_id, last_period, last, last_feeds = reading_id, period, now, feeds
        for budget, limit in budgets.items():
            used = _used(db, limit, world.clock)
            assert lower[budget] <= used <= upper[budget], (
                f"seed {seed}, {budget}: {lower[budget]} <= {used} <= {upper[budget]}\n"
                + "\n".join(history)
            )


def test_a_retried_reading_counts_nothing_twice(
    db: Session,
    connected,  # noqa: F811
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
