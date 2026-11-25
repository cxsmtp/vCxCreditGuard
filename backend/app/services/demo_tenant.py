"""A small in-memory Checkmarx One tenant, for the enforcement self-test in demo mode.

Demo mode never touches a real tenant. To let an admin try the self-test there
anyway, this serves the handful of IAM and platform endpoints a restriction and
its restore use, for the seeded demo users and projects only (``demo_service``),
over an ``httpx.MockTransport``: nothing leaves the process. Its state lives in
memory for the life of the process and starts from the same made-up values
every time (synthetic data only).

One demo user, Grace, also holds ``create-fusion-scan`` through a group's
composite role, so the self-test has a restriction that cannot bite to show.
"""

from __future__ import annotations

import copy
import json
import threading
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

import httpx

from app.checkmarx.client import CheckmarxClient
from app.checkmarx.token import TokenManager
from app.services import demo_service

TENANT = "creditguard-demo"
# Reserved names (RFC 2606): never resolvable, and never called anyway.
IAM_BASE = "https://iam.demo.invalid"
API_BASE = "https://ast.demo.invalid/api"
CLIENT_UUID = "00000000-0000-4000-8000-00000000d3a0"
# Not a credential: the transport below answers every token request itself.
DEMO_KEY = "creditguard-demo-tenant"

_ROLES = (
    "view-projects",
    "view-scans",
    "create-fusion-scan",
    "manage-fusion",
    "update-llm-scan-mode",
    "manage-llm-configuration",
)
# A composite role that contains a Fusion role, as ``scan-fusion`` does on a tenant.
_COMPOSITES = {"scan-fusion": ["create-fusion-scan", "view-scans"]}
_AI = ["create-fusion-scan", "manage-fusion", "update-llm-scan-mode", "manage-llm-configuration"]


def _initial_state() -> dict[str, Any]:
    users = {uid: ["view-projects", "view-scans", *_AI] for uid, *_ in demo_service._USERS}
    # Grace holds create-fusion-scan only through the Platform group's composite.
    users["demo-user-grace"] = ["view-projects", "view-scans", "manage-fusion"]
    projects: dict[str, dict[str, Any]] = {}
    repos: dict[str, dict[str, Any]] = {}
    for project_id, _name, _group, repo_id, _credits in demo_service._PROJECTS:
        projects[project_id] = {
            "auto_triage": {
                "feature": "auto_triage",
                "enabled": True,
                "config": {
                    "branches": ["main"],
                    "scannerTypes": ["SAST", "SCA"],
                    "riskStatuses": ["NEW"],
                    "severityLevels": ["CRITICAL", "HIGH"],
                },
                "allowOverride": {"projects": True, "branches": True},
            },
            "auto_remediation": {
                "feature": "auto_remediation",
                "enabled": True,
                "config": {"branches": ["main"], "severityLevels": ["CRITICAL"]},
            },
            "fusion": {
                "key": "scan.config.ai.fusionEnabled",
                "name": "Fusion Scan",
                "category": "ai",
                "originLevel": "Project",
                "value": "true",
                "valuetype": "Bool",
                "allowOverride": True,
                "isPersisted": True,
            },
        }
        if repo_id:
            repos[repo_id] = {
                "remediationSeverities": {"value": ["CRITICAL", "HIGH"], "isEditable": True},
                "fusionScanConfig": {"enabled": True, "llmModel": "opus-5.5"},
            }
    return {
        "users": users,
        "user_groups": {"demo-user-grace": ["demo-iam-platform"]},
        "groups": {"demo-iam-platform": {"name": "Platform", "roles": ["scan-fusion"]}},
        "projects": projects,
        "repos": repos,
    }


class DemoTenant:
    """The demo tenant's state and its HTTP handler. Thread safe."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.state = _initial_state()

    def reset(self) -> None:
        with self._lock:
            self.state = _initial_state()

    # ----------------------------------------------------------------- payloads

    @staticmethod
    def _role(name: str) -> dict[str, Any]:
        return {
            "id": f"demo-role-{name}",
            "name": name,
            "composite": name in _COMPOSITES,
            "clientRole": True,
            "containerId": CLIENT_UUID,
        }

    def _effective(self, user_id: str) -> set[str]:
        names = list(self.state["users"].get(user_id, []))
        for group_id in self.state["user_groups"].get(user_id, []):
            names.extend(self.state["groups"].get(group_id, {}).get("roles", []))
        found: set[str] = set()
        while names:
            name = names.pop()
            if name not in found:
                found.add(name)
                names.extend(_COMPOSITES.get(name, []))
        return found

    # ------------------------------------------------------------------ routing

    def handle(self, request: httpx.Request) -> httpx.Response:
        with self._lock:
            return self._route(request)

    def _route(self, request: httpx.Request) -> httpx.Response:
        url = urlparse(str(request.url))
        path = url.path
        params = parse_qs(url.query)
        method = request.method
        if path.endswith("/protocol/openid-connect/token"):
            return httpx.Response(200, json={"access_token": "demo-access", "expires_in": 1800})
        try:
            body: Any = json.loads(request.content) if request.content else None
        except ValueError:
            return httpx.Response(400, json={"message": "expected JSON"})
        admin = f"/auth/admin/realms/{TENANT}/"
        realm = f"/auth/realms/{TENANT}/"
        if path.startswith(admin):
            return self._iam(method, path[len(admin) :], body)
        if path.startswith(realm) and path.endswith("/groups"):
            return httpx.Response(200, json={"groups": self._group_list()})
        if path.startswith("/api/"):
            return self._platform(method, path[len("/api/") :].rstrip("/"), params, body)
        return httpx.Response(404, json={"message": "not served by the demo tenant"})

    def _group_list(self) -> list[dict[str, Any]]:
        return [
            {"id": gid, "name": group["name"], "path": f"/{group['name']}", "subGroups": []}
            for gid, group in self.state["groups"].items()
        ]

    def _iam(self, method: str, path: str, body: Any) -> httpx.Response:
        parts = path.split("/")
        if path == "clients":
            return httpx.Response(200, json=[{"id": CLIENT_UUID, "clientId": "ast-app"}])
        if path == "groups":
            return httpx.Response(200, json=self._group_list())
        if path == f"clients/{CLIENT_UUID}/roles":
            names = [*_ROLES, *_COMPOSITES]
            return httpx.Response(200, json=[self._role(name) for name in names])
        if path.startswith(f"clients/{CLIENT_UUID}/roles/") and path.endswith("/composites"):
            name = unquote(parts[3])
            children = _COMPOSITES.get(name, [])
            return httpx.Response(200, json=[self._role(child) for child in children])
        if parts[0] == "groups" and len(parts) >= 5 and parts[2] == "role-mappings":
            roles = self.state["groups"].get(parts[1], {}).get("roles", [])
            return httpx.Response(200, json=[self._role(name) for name in roles])
        if parts[0] != "users" or len(parts) < 3:
            return httpx.Response(404, json={"message": "not served by the demo tenant"})
        user_id = parts[1]
        if user_id not in self.state["users"]:
            return httpx.Response(404, json={"error": "User not found"})
        if parts[2] == "groups":
            return httpx.Response(
                200,
                json=[
                    {"id": gid, "name": group["name"], "path": f"/{group['name']}"}
                    for gid in self.state["user_groups"].get(user_id, [])
                    if (group := self.state["groups"].get(gid)) is not None
                ],
            )
        if parts[-1] == "composite":
            return httpx.Response(
                200, json=[self._role(name) for name in sorted(self._effective(user_id))]
            )
        current: list[str] = self.state["users"][user_id]
        if method == "GET":
            return httpx.Response(200, json=[self._role(name) for name in current])
        names = [entry.get("name") for entry in body or [] if isinstance(entry, dict)]
        if method == "DELETE":
            self.state["users"][user_id] = [name for name in current if name not in names]
        elif method == "POST":
            self.state["users"][user_id] = current + [
                name for name in names if name in _ROLES and name not in current
            ]
        return httpx.Response(204)

    def _platform(
        self, method: str, path: str, params: dict[str, list[str]], body: Any
    ) -> httpx.Response:
        if path == "scans":
            return httpx.Response(200, json={"totalCount": 0, "filteredTotalCount": 0, "scans": []})
        if path.startswith("ai-agents-coordinator/projects/"):
            project = self.state["projects"].get(path.split("/")[2])
            if project is None:
                return httpx.Response(404, json={"message": "no such project"})
            if method == "GET":
                return httpx.Response(
                    200,
                    json={
                        "scope": "project",
                        "allowAiUsage": True,
                        "configurations": copy.deepcopy(
                            [project["auto_triage"], project["auto_remediation"]]
                        ),
                    },
                )
            for entry in (body or {}).get("configurations", []):
                if isinstance(entry, dict) and entry.get("feature") in project:
                    project[entry["feature"]] = copy.deepcopy(entry)
            return httpx.Response(200, json={"status": "ok"})
        if path == "configuration/project":
            project = self.state["projects"].get((params.get("project-id") or [""])[0])
            if project is None:
                return httpx.Response(404, json={"message": "no such project"})
            if method == "GET":
                return httpx.Response(200, json=[copy.deepcopy(project["fusion"])])
            for entry in body or []:
                if isinstance(entry, dict) and entry.get("key") == project["fusion"]["key"]:
                    project["fusion"] = {**project["fusion"], **entry, "isPersisted": True}
            return httpx.Response(204)
        if path.startswith("repos-manager/repo/"):
            repo = self.state["repos"].get(path.split("/")[2])
            if repo is None:
                return httpx.Response(404, json={"message": "no such repository"})
            if method == "GET":
                return httpx.Response(200, json=copy.deepcopy(repo))
            for key in ("remediationSeverities", "fusionScanConfig"):
                if isinstance((body or {}).get(key), dict):
                    repo[key] = copy.deepcopy(body[key])
            return httpx.Response(200, json={"status": "ok"})
        return httpx.Response(404, json={"message": "not served by the demo tenant"})

    # ------------------------------------------------------------------- client

    def client(self) -> CheckmarxClient:
        http = httpx.Client(transport=httpx.MockTransport(self.handle))
        tokens = TokenManager(
            api_key=DEMO_KEY,
            token_endpoint=f"{IAM_BASE}/auth/realms/{TENANT}/protocol/openid-connect/token",
            client=http,
        )
        return CheckmarxClient(
            api_base_url=API_BASE,
            iam_base_url=IAM_BASE,
            tenant_name=TENANT,
            token_manager=tokens,
            client=http,
            sleep=lambda _seconds: None,
        )


_tenant: DemoTenant | None = None
_tenant_guard = threading.Lock()


def tenant() -> DemoTenant:
    """The process's demo tenant (created on first use)."""
    global _tenant
    with _tenant_guard:
        if _tenant is None:
            _tenant = DemoTenant()
        return _tenant


def client() -> CheckmarxClient:
    return tenant().client()
