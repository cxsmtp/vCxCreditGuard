"""A large synthetic Checkmarx One tenant, for load tests and scale regression tests.

Built on :class:`tests.fake_tenant.FakeTenant` (same endpoints, same payload
shapes), with what a load test needs on top:

* a realistic size: by default 2,000 projects (60% with a repository, some
  with a repository Fusion setting, half with Auto Triage on), 1,000 users,
  100 groups (nested two levels, with members and projects, and one large
  group holding half the projects), 30 applications, consumption rows for
  every dimension and scans for a subset of projects;
* a per-call latency (``latency_ms``, real wall time, so concurrency shows)
  and rate limiting (``rate_limit_every``: every Nth call answers 429 with a
  ``Retry-After``), to behave like the real API under load;
* a count of calls by endpoint (``calls``), for reporting;
* ``advance()`` to move the tenant on between cycles: usage grows, new scans
  arrive, and a few restricted settings are switched back on by "someone".

Synthetic data only: every name and address is made up.
"""

from __future__ import annotations

import random
import re
import threading
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlparse

import httpx

from app.checkmarx.client import CheckmarxClient
from app.checkmarx.token import TokenManager
from app.core.config import get_settings
from tests.conftest import make_api_key
from tests.fake_tenant import API_BASE, IAM_BASE, TENANT, FakeTenant, _public_scan

BIG_GROUP_ID = "grp-big"

_ID = re.compile(r"/[0-9a-zA-Z_.@%-]*\d[0-9a-zA-Z_.@%-]*")


def endpoint_label(method: str, path: str) -> str:
    """A request as ``METHOD /path`` with the ids taken out, for counting."""
    if path.endswith("/protocol/openid-connect/token"):
        return "POST token"
    if "/credits/consumption" in path:
        return f"{method} /api/credits/consumption"
    if "/ai-agents-coordinator/projects/" in path:
        return f"{method} /api/ai-agents-coordinator/projects/{{id}}/configuration"
    if "/repos-manager/repo/" in path:
        return f"{method} /api/repos-manager/repo/{{id}}"
    if "/role-mappings/clients/" in path:
        suffix = "/composite" if path.endswith("/composite") else ""
        owner = "groups" if "/groups/" in path else "users"
        return f"{method} iam {owner}/{{id}}/role-mappings/clients/{{id}}{suffix}"
    if "/auth/admin/realms/" in path and path.endswith("/groups") and "/users/" in path:
        return f"{method} iam users/{{id}}/groups"
    if path.rstrip("/").endswith("/api/scans"):
        return f"{method} /api/scans/"
    if "/api/scans/" in path:
        return f"{method} /api/scans/{{id}}"
    return f"{method} {_ID.sub('/{id}', path)}"


@dataclass
class ScaleTenant(FakeTenant):
    # Wall-clock time every call takes, like a round trip to the real API.
    latency_ms: float = 0.0
    # Every Nth call answers 429 (0: never), with this Retry-After.
    rate_limit_every: int = 0
    retry_after_seconds: float = 1.0
    # The tenant's clock: scans are dated from it (the load test moves it on).
    clock: Callable[[], datetime] = field(default=lambda: datetime.now(UTC))
    calls: Counter[str] = field(default_factory=Counter)
    rate_limited: int = 0
    total_calls: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _scan_index: dict[str, dict[str, Any]] = field(default_factory=dict)
    _groups_by_id: dict[str, dict[str, Any]] = field(default_factory=dict)
    _rng: random.Random = field(default_factory=lambda: random.Random(7))  # noqa: S311
    _scan_seq: int = 0
    # Project ids whose consumption rows and scans ``advance`` moves on.
    _project_rows: dict[str, dict[str, Any]] = field(default_factory=dict)
    _user_rows: list[dict[str, Any]] = field(default_factory=list)

    # ------------------------------------------------------------- routing

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = urlparse(str(request.url)).path
        with self._lock:
            self.total_calls += 1
            number = self.total_calls
            self.calls[endpoint_label(request.method, path)] += 1
        if self.latency_ms:
            time.sleep(self.latency_ms / 1000)
        if (
            self.rate_limit_every
            and number % self.rate_limit_every == 0
            and not path.endswith("/protocol/openid-connect/token")
        ):
            with self._lock:
                self.rate_limited += 1
            return httpx.Response(
                429,
                headers={"Retry-After": f"{self.retry_after_seconds:g}"},
                json={"message": "Too many requests"},
            )
        if (
            request.method == "GET"
            and "/api/scans/" in path
            and not path.rstrip("/").endswith("/api/scans")
        ):
            # The base class looks a scan up by walking every project's scans.
            row = self._scan_index.get(path.rstrip("/").rsplit("/", 1)[1])
            if row is None:
                return httpx.Response(404, json={"message": "no such scan"})
            return httpx.Response(200, json=_public_scan(row, detail=True))
        response = super().handler(request)
        # The base class keeps every request for assertions; a load test makes
        # tens of thousands, so only the last few are kept.
        if len(self.requests) > 1000:
            del self.requests[:-100]
        return response

    def _group_by_id(self, group_id: str) -> dict[str, Any] | None:
        if len(self._groups_by_id) != len(self.groups):
            self._groups_by_id = {group["id"]: group for group in self.groups}
        return self._groups_by_id.get(group_id)

    def add_scan(self, **kwargs: Any) -> None:  # type: ignore[override]
        super().add_scan(**kwargs)
        row = self.scans[kwargs["project_id"]][-1]
        self._scan_index[row["id"]] = row

    def client(self) -> CheckmarxClient:  # type: ignore[override]
        """A client over this tenant that really waits (Retry-After, backoff)."""
        http = httpx.Client(transport=httpx.MockTransport(self.handler))
        api_key = make_api_key(iam_base_url=IAM_BASE, tenant=TENANT)
        tokens = TokenManager(
            api_key=api_key,
            token_endpoint=f"{IAM_BASE}/auth/realms/{TENANT}/protocol/openid-connect/token",
            client=http,
            settings=get_settings(),
        )
        return CheckmarxClient(
            api_base_url=API_BASE,
            iam_base_url=IAM_BASE,
            tenant_name=TENANT,
            token_manager=tokens,
            client=http,
            settings=get_settings(),
            sleep=time.sleep,
        )

    def reset_counts(self) -> None:
        with self._lock:
            self.calls.clear()
            self.rate_limited = 0

    # ------------------------------------------------------------- moving on

    def _new_scan(self, project_id: str, *, fusion: bool | None, initiator: str) -> None:
        self._scan_seq += 1
        now = self.clock()
        completed = now - timedelta(minutes=self._rng.randint(1, 10))
        engines = ["sast", "sca"]
        ai = None
        if fusion is not None:
            engines.append("ai")
            ai = {"fusionEnabled": "true" if fusion else "false", "llmModel": "opus-5.5"}
        self.add_scan(
            project_id=project_id,
            scan_id=f"scan-{self._scan_seq:07d}",
            initiator=initiator,
            completed_at=completed,
            created_at=completed - timedelta(minutes=8),
            engines=engines,
            ai=ai,
        )

    def advance(self, *, users: float = 0.05, projects: float = 0.10, scans: int = 40) -> None:
        """One interval passes: some people and projects spend, scans arrive,
        and a few restricted settings are turned back on in the tenant."""
        rng = self._rng
        for row in rng.sample(self._user_rows, int(len(self._user_rows) * users)):
            row["creditsUsed"] = round(float(row["creditsUsed"]) + 1.5, 2)
            actions = row["actionsPerformed"]["actions"]
            actions[0]["transactionCount"] += 1
            row["actionsPerformed"]["total"] += 1
        project_ids = list(self._project_rows)
        for project_id in rng.sample(project_ids, int(len(project_ids) * projects)):
            row = self._project_rows[project_id]
            row["creditsUsed"] = round(float(row["creditsUsed"]) + 2.0, 2)
            for action in row["actionsPerformed"]["actions"]:
                if action["actionType"] == "auto_triage":
                    action["transactionCount"] += 2
            row["actionsPerformed"]["total"] += 2
        scanned = [pid for pid in self.scans if self.scans[pid]]
        emails = [user["email"] for user in self.users[:300]]
        for project_id in rng.sample(scanned, min(scans, len(scanned))):
            self._new_scan(
                project_id,
                fusion=rng.random() < 0.3 if rng.random() < 0.5 else None,
                initiator=rng.choice(emails),
            )
        # Someone switches a few things back on.
        for project_id in rng.sample(project_ids, 3):
            self.auto_triage[project_id]["enabled"] = True


def build_scale_tenant(
    *,
    projects: int = 2000,
    users: int = 1000,
    groups: int = 100,
    applications: int = 30,
    scanned_projects: int = 400,
    latency_ms: float = 0.0,
    rate_limit_every: int = 0,
    retry_after_seconds: float = 1.0,
    clock: Callable[[], datetime] | None = None,
    seed: int = 7,
) -> ScaleTenant:
    """A tenant of the given size (synthetic data, deterministic for a seed)."""
    rng = random.Random(seed)  # noqa: S311 - test data
    tenant = ScaleTenant(
        latency_ms=latency_ms,
        rate_limit_every=rate_limit_every,
        retry_after_seconds=retry_after_seconds,
        clock=clock or (lambda: datetime.now(UTC)),
        _rng=random.Random(seed + 1),  # noqa: S311 - test data
    )
    now = tenant.clock()

    # Groups: one large group, then divisions with teams under them.
    tenant.add_group(group_id=BIG_GROUP_ID, name="Enterprise", path="/Enterprise")
    divisions = max(1, -(-(groups - 1) // 10))
    team_ids: list[str] = []
    team_names: list[str] = []
    made = 1
    for division in range(divisions):
        division_name = f"division-{division:02d}"
        tenant.add_group(
            group_id=f"grp-d{division:02d}", name=division_name, path=f"/{division_name}"
        )
        made += 1
        for team in range(9):
            if made >= groups:
                break
            name = f"team-{division:02d}-{team}"
            group_id = f"grp-t{division:02d}{team}"
            tenant.add_group(group_id=group_id, name=name, path=f"/{division_name}/{name}")
            team_ids.append(group_id)
            team_names.append(name)
            made += 1

    # Users, each in one or two teams (by name, as /users/v2 reports them).
    for index in range(users):
        first = f"Given{index:04d}"
        last = f"Family{index % 97:02d}"
        member_of = rng.sample(team_names, k=1 + (index % 2))
        if index % 3 == 0:
            member_of.append("Enterprise")
        tenant.add_user(
            user_id=f"user-{index:05d}",
            username=f"user{index:05d}@example.com",
            email=f"user{index:05d}@example.com",
            first_name=first,
            last_name=last,
            groups=member_of,
        )
        tenant.set_user_credits(
            name=f"{first} {last}",
            email=f"user{index:05d}@example.com",
            credits=round(rng.uniform(0, 40), 2),
            actions={"triage": rng.randint(1, 20), "remediation": rng.randint(0, 5)},
        )
    tenant._user_rows = list(tenant.consumption["user"])

    # Projects: the first half in the large group, each in one team.
    emails = [f"user{index:05d}@example.com" for index in range(min(users, 300))]
    for index in range(projects):
        project_id = f"proj-{index:05d}"
        name = f"repo-{index:05d}"
        group_ids = [team_ids[index % len(team_ids)]]
        if index < projects // 2:
            group_ids.append(BIG_GROUP_ID)
        has_repo = index % 5 < 3  # 60%
        tenant.add_project(
            project_id=project_id,
            name=name,
            group_ids=group_ids,
            repo_id=f"repo-{index:05d}" if has_repo else None,
            auto_triage_enabled=index % 2 == 0,
        )
        if has_repo and index % 2 == 0:
            tenant.repo_fusion[f"repo-{index:05d}"] = {"enabled": True, "model": "opus-5.5"}
        auto = rng.randint(0, 30) if index % 2 == 0 else 0
        tenant.set_entity_credits(
            view="project",
            name=name,
            entity_id=project_id,
            credits=round(auto * 0.5 + rng.uniform(0, 10), 2),
            actions={
                "auto_triage": auto,
                "triage": rng.randint(0, 10),
                "fusion": rng.randint(0, 3),
            },
        )
    tenant._project_rows = {
        row["id"]: row for row in tenant.consumption["project"] if row.get("id")
    }

    # Applications: consecutive slices of the projects.
    per_app = max(1, int(projects * 0.9) // max(1, applications))
    for index in range(applications):
        project_ids = [
            f"proj-{n:05d}" for n in range(index * per_app, min(projects, (index + 1) * per_app))
        ]
        tenant.add_application(
            application_id=f"app-{index:03d}",
            name=f"Application {index:03d}",
            project_ids=project_ids,
        )
        tenant.set_entity_credits(
            view="application",
            name=f"Application {index:03d}",
            entity_id=f"app-{index:03d}",
            credits=sum(
                float(tenant._project_rows[pid]["creditsUsed"])
                for pid in project_ids
                if pid in tenant._project_rows
            ),
        )
    tenant.consumption["action"] = [
        {
            "name": "auto_triage",
            "actionType": "auto_triage",
            "transactionCount": 1000,
            "creditsUsed": 500,
        },
        {"name": "triage", "actionType": "triage", "transactionCount": 5000, "creditsUsed": 5000},
        {
            "name": "remediation",
            "actionType": "remediation",
            "transactionCount": 900,
            "creditsUsed": 2700,
        },
    ]
    tenant.consumption["group"] = []

    # Scans on a subset of projects, the auto-triage ones and those in the
    # large group first.
    for index in range(min(scanned_projects, projects)):
        project_id = f"proj-{index:05d}"
        for age in (3, 2, 1):
            tenant._scan_seq += 1
            completed = now - timedelta(days=age, minutes=rng.randint(0, 600))
            tenant.add_scan(
                project_id=project_id,
                scan_id=f"scan-{tenant._scan_seq:07d}",
                initiator=rng.choice(emails),
                completed_at=completed,
                created_at=completed - timedelta(minutes=8),
                engines=["sast", "sca", "ai"] if age == 1 else ["sast", "sca"],
                ai={"fusionEnabled": "false", "llmModel": "opus-5.5"} if age == 1 else None,
            )
    return tenant
