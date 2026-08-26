"""An in-memory Checkmarx One tenant for tests.

Serves every endpoint the utility calls, over ``httpx.MockTransport``, and holds
mutable state so a test can assert on what enforcement actually changed rather
than only on which calls were made. Response shapes mirror the real payloads,
including their inconsistencies: some consumption rows carry an email in ``name``
and no ``email`` field at all.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx

from app.checkmarx.client import CheckmarxClient
from app.checkmarx.token import TokenManager
from app.checkmarx.usage import FALLBACK_PROBE_VIEW
from app.core.config import get_settings
from tests.conftest import make_api_key

TENANT = "acme-corp"
IAM_BASE = "https://eu.iam.checkmarx.net"
API_BASE = "https://eu.ast.checkmarx.net/api"
CLIENT_UUID = "5770afc3-605f-4a5d-a041-02a139096cd0"

ALL_ROLES: dict[str, str] = {
    "view-risk-management": "62660f23-52cb-4361-9d49-7abae5e520f8",
    "view-risk-management-dashboard": "72660f23-52cb-4361-9d49-7abae5e520f9",
    "view-risk-management-tab": "82660f23-52cb-4361-9d49-7abae5e520fa",
    "view-projects": "92660f23-52cb-4361-9d49-7abae5e520fb",
    "view-scans": "a2660f23-52cb-4361-9d49-7abae5e520fc",
}


@dataclass
class FakeTenant:
    users: list[dict[str, Any]] = field(default_factory=list)
    groups: list[dict[str, Any]] = field(default_factory=list)
    projects: list[dict[str, Any]] = field(default_factory=list)
    applications: list[dict[str, Any]] = field(default_factory=list)
    # viewBy -> list of item dicts, exactly as the API would return them.
    consumption: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    # user id -> role names currently mapped
    role_mappings: dict[str, list[str]] = field(default_factory=dict)
    # project id -> {"enabled": bool, "config": {...}}
    auto_triage: dict[str, dict[str, Any]] = field(default_factory=dict)
    # repo id -> remediation severities
    repo_severities: dict[str, list[str]] = field(default_factory=dict)

    # Test controls
    unsupported_views: set[str] = field(default_factory=set)
    # Mirrors the real endpoint: an unrecognised viewBy answers 200 with this
    # dimension's rows instead of failing. Set to "user" to reproduce that.
    fallback_view: str | None = None
    probe_fails: bool = False
    probe_calls: int = 0
    fail_paths: dict[str, int] = field(default_factory=dict)
    page_size_override: int | None = None
    users_requires_paging: bool = False
    requests: list[tuple[str, str]] = field(default_factory=list)

    # ------------------------------------------------------------- convenience

    def add_user(
        self,
        *,
        user_id: str,
        username: str,
        email: str | None = None,
        first_name: str | None = None,
        last_name: str | None = None,
        groups: list[str] | None = None,
        roles: list[str] | None = None,
        enabled: bool = True,
    ) -> None:
        role_names = roles if roles is not None else list(ALL_ROLES)
        self.users.append(
            {
                "id": user_id,
                "username": username,
                "email": email,
                "firstName": first_name,
                "lastName": last_name,
                "isEnabled": enabled,
                "authProvider": "saml",
                "roles": role_names,
                "groups": groups or [],
            }
        )
        self.role_mappings[user_id] = list(role_names)

    def add_group(self, *, group_id: str, name: str, path: str | None = None) -> None:
        self.groups.append(
            {
                "id": group_id,
                "name": name,
                "path": path or f"/{name}",
                "subGroupCount": 0,
                "subGroups": [],
            }
        )

    def add_project(
        self,
        *,
        project_id: str,
        name: str,
        group_ids: list[str] | None = None,
        repo_id: str | int | None = None,
        auto_triage_enabled: bool = True,
    ) -> None:
        payload: dict[str, Any] = {"id": project_id, "name": name, "groups": group_ids or []}
        if repo_id:
            # Keep the payload value as given so tests can reproduce the real
            # API reporting repoId as an integer, but key the severities store
            # by the string form the repos-manager URL will contain.
            payload["repoId"] = repo_id
            self.repo_severities[str(repo_id)] = ["CRITICAL", "HIGH"]
        self.projects.append(payload)
        self.auto_triage[project_id] = {
            "enabled": auto_triage_enabled,
            "config": {
                "branches": ["main"],
                "scannerTypes": ["SAST", "SCA"],
                "riskStatuses": ["NEW"],
                "severityLevels": ["CRITICAL", "HIGH"],
            },
        }

    def add_application(
        self, *, application_id: str, name: str, project_ids: list[str] | None = None
    ) -> None:
        self.applications.append(
            {"id": application_id, "name": name, "projectIds": project_ids or []}
        )

    def set_user_credits(
        self,
        *,
        name: str,
        credits: int | float,
        email: str | None = None,
        actions: dict[str, int] | None = None,
    ) -> None:
        """Add or replace a viewBy=user consumption row."""
        item: dict[str, Any] = {
            "name": name,
            "creditsUsed": credits,
            "percentOfTotal": 0.1,
            "actionsPerformed": {
                "actions": [
                    {"actionType": action, "transactionCount": count}
                    for action, count in (actions or {"triage": 1}).items()
                ],
                "total": sum((actions or {"triage": 1}).values()),
            },
        }
        if email:
            item["email"] = email
            item["userEmail"] = email
        rows = self.consumption.setdefault("user", [])
        for index, existing in enumerate(rows):
            if existing.get("name") == name:
                rows[index] = item
                return
        rows.append(item)

    def set_entity_credits(
        self, *, view: str, name: str, credits: int | float, entity_id: str | None = None
    ) -> None:
        item: dict[str, Any] = {"name": name, "creditsUsed": credits, "percentOfTotal": 1.0}
        if entity_id:
            item["id"] = entity_id
        rows = self.consumption.setdefault(view, [])
        for index, existing in enumerate(rows):
            if existing.get("name") == name or (entity_id and existing.get("id") == entity_id):
                rows[index] = item
                return
        rows.append(item)

    # ----------------------------------------------------------------- routing

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = urlparse(str(request.url))
        path = url.path
        params = parse_qs(url.query)
        self.requests.append((request.method, path))

        for fragment, status_code in self.fail_paths.items():
            if fragment in path:
                return httpx.Response(status_code, json={"message": "forced failure"})

        if path.endswith("/protocol/openid-connect/token"):
            return httpx.Response(
                200, json={"access_token": "fake-access-token", "expires_in": 1800}
            )

        if path.endswith(f"/auth/realms/{TENANT}/users/v2"):
            return self._users_response(params)

        if path.endswith(f"/auth/realms/{TENANT}/groups"):
            return httpx.Response(
                200,
                json={
                    "count": len(self.groups),
                    "filteredCount": len(self.groups),
                    "groups": self.groups,
                },
            )

        if path.endswith("/api/projects"):
            return self._paged(self.projects, "projects", params)

        if path.endswith("/api/applications"):
            return self._paged(self.applications, "applications", params)

        if path.endswith("/api/credits/consumption"):
            return self._consumption_response(params)

        if path.endswith(f"/auth/admin/realms/{TENANT}/clients"):
            return httpx.Response(200, json=[{"id": CLIENT_UUID, "clientId": "ast-app"}])

        if path.endswith(f"/clients/{CLIENT_UUID}/roles"):
            return httpx.Response(
                200,
                json=[{"id": role_id, "name": name} for name, role_id in ALL_ROLES.items()],
            )

        if "/role-mappings/clients/" in path:
            return self._role_mapping_response(request, path)

        if "/ai-agents-coordinator/projects/" in path:
            return self._auto_triage_response(request, path)

        if "/repos-manager/repo/" in path:
            return self._repo_response(request, path, params)

        return httpx.Response(404, json={"message": f"no fake route for {path}"})

    # ---------------------------------------------------------------- handlers

    def _users_response(self, params: dict[str, list[str]]) -> httpx.Response:
        if not self.users_requires_paging:
            return httpx.Response(200, json={"filteredCount": len(self.users), "users": self.users})
        # Simulate an endpoint that caps its unpaginated response.
        size = int(params.get("size", ["2"])[0])
        page = int(params.get("page", ["0"])[0] or 0)
        if page == 0:
            return httpx.Response(
                200, json={"filteredCount": len(self.users), "users": self.users[:1]}
            )
        start = (page - 1) * size
        return httpx.Response(
            200,
            json={
                "filteredCount": len(self.users),
                "users": self.users[start : start + size],
            },
        )

    def _paged(
        self, rows: list[dict[str, Any]], key: str, params: dict[str, list[str]]
    ) -> httpx.Response:
        limit = int(params.get("limit", ["100"])[0])
        offset = int(params.get("offset", ["0"])[0])
        window = rows[offset : offset + limit]
        return httpx.Response(200, json={"totalCount": len(rows), key: window})

    def _consumption_response(self, params: dict[str, list[str]]) -> httpx.Response:
        view = params.get("viewBy", ["user"])[0]
        if view in self.unsupported_views:
            return httpx.Response(
                400, json={"message": f"viewBy {view} is not supported on this tenant"}
            )

        known = view in self.consumption
        if not known:
            if view == FALLBACK_PROBE_VIEW:
                self.probe_calls += 1
                if self.probe_fails:
                    return httpx.Response(500, json={"message": "probe failed"})
            # The real endpoint does not reject an unknown dimension, it quietly
            # serves the user view.
            rows = self.consumption.get(self.fallback_view, []) if self.fallback_view else []
        else:
            rows = self.consumption.get(view, [])
        size = self.page_size_override or int(params.get("size", ["100"])[0])
        page = int(params.get("page", ["1"])[0])
        start = (page - 1) * size
        window = rows[start : start + size]
        total_pages = max(1, -(-len(rows) // size)) if rows else 1
        return httpx.Response(
            200,
            json={
                "items": window,
                "totalItems": len(rows),
                "totalPages": total_pages,
                "currentPage": page,
            },
        )

    def _role_mapping_response(self, request: httpx.Request, path: str) -> httpx.Response:
        user_id = path.split("/users/")[1].split("/role-mappings")[0]
        current = self.role_mappings.setdefault(user_id, [])

        if request.method == "GET":
            return httpx.Response(
                200,
                json=[
                    {"id": ALL_ROLES[name], "name": name} for name in current if name in ALL_ROLES
                ],
            )

        body = json.loads(request.content or b"[]")
        names = [entry["name"] for entry in body if isinstance(entry, dict)]
        if request.method == "DELETE":
            self.role_mappings[user_id] = [name for name in current if name not in names]
        elif request.method == "POST":
            self.role_mappings[user_id] = current + [name for name in names if name not in current]
        return httpx.Response(204)

    def _auto_triage_response(self, request: httpx.Request, path: str) -> httpx.Response:
        project_id = path.split("/projects/")[1].split("/configuration")[0]
        state = self.auto_triage.setdefault(
            project_id, {"enabled": False, "config": {"branches": ["main"]}}
        )
        if request.method == "GET":
            return httpx.Response(
                200,
                json={
                    "scope": "project",
                    "projectId": project_id,
                    "configurations": [
                        {
                            "feature": "auto_triage",
                            "enabled": state["enabled"],
                            "config": state["config"],
                            "allowOverride": {"branches": True, "projects": True},
                        }
                    ],
                },
            )
        body = json.loads(request.content or b"{}")
        for entry in body.get("configurations", []):
            if entry.get("feature") == "auto_triage":
                state["enabled"] = bool(entry.get("enabled"))
                if entry.get("config"):
                    state["config"] = entry["config"]
        return httpx.Response(200, json={"status": "ok"})

    def _repo_response(
        self, request: httpx.Request, path: str, params: dict[str, list[str]]
    ) -> httpx.Response:
        repo_id = path.split("/repos-manager/repo/")[1]
        if request.method == "GET":
            if "projectId" not in params:
                return httpx.Response(400, json={"message": "projectId is required"})
            return httpx.Response(
                200,
                json={
                    "id": repo_id,
                    "remediationSeverities": self.repo_severities.get(repo_id, []),
                },
            )
        if request.method != "PATCH":
            return httpx.Response(405, json={"message": "only PATCH is implemented"})
        if "projectId" not in params:
            return httpx.Response(400, json={"message": "projectId is required"})
        body = json.loads(request.content or b"{}")
        self.repo_severities[repo_id] = list(body.get("remediationSeverities", []))
        return httpx.Response(200, json={"status": "ok"})

    # ------------------------------------------------------------------ client

    def client(self) -> CheckmarxClient:
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
            sleep=lambda _s: None,
        )


def populated_tenant() -> FakeTenant:
    """A small tenant with the shapes the real one exhibits.

    Deliberately includes an unmatchable consumption row and a user whose only
    identifier is a display name, because both occur in the real feed.
    """
    tenant = FakeTenant()
    tenant.add_group(group_id="grp-platform", name="AA-Platform")
    tenant.add_group(group_id="grp-payments", name="Payments")

    tenant.add_user(
        user_id="user-harsh",
        username="harsh.gokani@checkmarx.com",
        email="harsh.gokani@checkmarx.com",
        first_name="Harsh",
        last_name="Gokani",
        groups=["AA-Platform"],
    )
    tenant.add_user(
        user_id="user-sean",
        username="sean.casey@checkmarx.com",
        email="sean.casey@checkmarx.com",
        first_name="Sean",
        last_name="Casey",
        groups=["Payments"],
    )
    tenant.add_user(
        user_id="user-akash",
        username="akash",
        email="akash.singh@checkmarx.com",
        first_name="Akash",
        last_name="Singh",
        groups=["AA-Platform", "Payments"],
    )

    tenant.add_project(
        project_id="proj-api", name="payments/api", group_ids=["grp-payments"], repo_id="repo-1"
    )
    tenant.add_project(project_id="proj-web", name="payments/web", group_ids=["grp-payments"])
    tenant.add_project(project_id="proj-tools", name="platform/tools", group_ids=["grp-platform"])

    tenant.add_application(
        application_id="app-payments", name="Payments", project_ids=["proj-api", "proj-web"]
    )

    # Resolvable by email, by display name, and not at all.
    tenant.set_user_credits(
        name="Harsh Gokani",
        email="harsh.gokani@checkmarx.com",
        credits=3,
        actions={"remediation": 1},
    )
    tenant.set_user_credits(name="Sean Casey", credits=5, actions={"triage": 5})
    tenant.set_user_credits(name="departed.person@checkmarx.com", credits=7)

    tenant.set_entity_credits(
        view="application", name="Payments", credits=12, entity_id="app-payments"
    )
    tenant.set_entity_credits(view="project", name="payments/api", credits=8, entity_id="proj-api")
    tenant.set_entity_credits(view="project", name="payments/web", credits=4, entity_id="proj-web")
    tenant.set_entity_credits(
        view="project", name="platform/tools", credits=2, entity_id="proj-tools"
    )
    tenant.consumption["action"] = [
        {"name": "triage", "actionType": "triage", "transactionCount": 9, "creditsUsed": 9},
        {
            "name": "remediation",
            "actionType": "remediation",
            "transactionCount": 2,
            "creditsUsed": 6,
        },
    ]
    return tenant
