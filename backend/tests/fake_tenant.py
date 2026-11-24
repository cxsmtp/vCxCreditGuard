"""An in-memory Checkmarx One tenant for tests.

Serves every endpoint the utility calls, over ``httpx.MockTransport``, and holds
mutable state so a test can assert on what enforcement actually changed rather
than only on which calls were made. Response shapes mirror the real payloads,
including their inconsistencies: some consumption rows carry an email in ``name``
and no ``email`` field at all.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
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
    # The tenant AI credit pool returned by GET /api/credits/info. None models a
    # tenant/endpoint that does not report it (the call 404s or errors).
    credit_info: dict[str, Any] | None = field(
        default_factory=lambda: {
            "totalCredits": 1000,
            "usedCredits": 150,
            "availableCredits": 850,
        }
    )
    # user id -> role names currently mapped
    role_mappings: dict[str, list[str]] = field(default_factory=dict)
    # project id -> {"enabled": bool, "config": {...}}
    auto_triage: dict[str, dict[str, Any]] = field(default_factory=dict)
    # repo id -> remediation severities
    repo_severities: dict[str, list[str]] = field(default_factory=dict)
    # project id -> scans, in the shape GET /api/scans/ returns them.
    scans: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    # Every GET /api/scans/ query, as parsed parameters, for assertions.
    scan_queries: list[dict[str, list[str]]] = field(default_factory=list)
    # project id -> entries of GET /api/configuration/project?project-id=...
    project_config: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    # Every PATCH /api/configuration/project body, as (project id, entries).
    config_patches: list[tuple[str, list[dict[str, Any]]]] = field(default_factory=list)
    # Answer a PATCH that locks an entry (allowOverride false) with 400, like a
    # tenant that does not accept the lock.
    reject_config_lock: bool = False
    # Answer 2xx to a lock (allowOverride false) but keep allowOverride as it
    # was, like a tenant that does not support the lock.
    drop_config_lock: bool = False
    # Answer 2xx to a project configuration PATCH but keep nothing.
    drop_config_writes: bool = False
    # Answer 2xx to a fusionScanConfig PATCH but keep nothing.
    drop_repo_fusion_writes: bool = False
    # repo id -> fusionScanConfig. A repo absent here has no fusionScanConfig
    # in its settings (the read does not include it).
    repo_fusion: dict[str, dict[str, Any]] = field(default_factory=dict)
    # GET /api/v1/credits/action-rates. None: the endpoint answers 404.
    action_rates: list[dict[str, Any]] | None = field(
        default_factory=lambda: [
            {
                "action_type": "fusion_scan_-_haiku_4.5",
                "credits_per_action": "1.5",
                "display_name": "Fusion Scan - Haiku 4.5",
                "is_active": True,
            },
            {
                "action_type": "fusion_scan_-_opus_4.7",
                "credits_per_action": "2.5",
                "display_name": "Fusion Scan - Opus 4.7",
                "is_active": True,
            },
            {
                "action_type": "fusion_scan_-_opus_5.5",
                "credits_per_action": "2",
                "display_name": "Fusion Scan - Opus 5.5",
                "is_active": True,
            },
        ]
    )

    # Test controls
    unsupported_views: set[str] = field(default_factory=set)
    # Mirrors the real endpoint: an unrecognised viewBy answers 200 with this
    # dimension's rows instead of failing. Set to "user" to reproduce that.
    fallback_view: str | None = None
    probe_fails: bool = False
    probe_calls: int = 0
    fail_paths: dict[str, int] = field(default_factory=dict)
    # (METHOD, path fragment) -> status code: fail one kind of request only, for
    # example writes to role mappings while reads still work.
    fail_requests: dict[tuple[str, str], int] = field(default_factory=dict)
    # viewBy -> status code: fail consumption for one dimension only.
    fail_views: dict[str, int] = field(default_factory=dict)
    # Serve an empty page from this page number on, while still advertising the
    # full page count: a truncated answer.
    empty_from_page: int | None = None
    page_size_override: int | None = None
    users_requires_paging: bool = False
    requests: list[tuple[str, str]] = field(default_factory=list)
    # What the token endpoint hands out. Opaque by default; access_token_with()
    # builds a JWT-shaped one carrying role claims.
    access_token: str = "fake-access-token"
    # Called with every request before it is answered. Lets a test observe the
    # state of the world at the exact moment the utility is talking to Checkmarx.
    on_request: Callable[[httpx.Request], None] | None = None

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
        self.set_fusion_setting(project_id, value="true", origin="Project", allow_override=True)

    def set_fusion_setting(
        self,
        project_id: str,
        *,
        value: str | None,
        origin: str = "Project",
        allow_override: bool = True,
    ) -> None:
        """The project's scan settings, as GET /api/configuration/project lists them.

        ``value`` None leaves the Fusion entry out altogether.
        """
        entries: list[dict[str, Any]] = [
            {
                "key": "scan.config.ai.llmModel",
                "name": "LLM Model",
                "category": "ai",
                "originLevel": "Tenant",
                "value": "opus-5.5",
                "valuetype": "String",
                "allowOverride": True,
                "isPersisted": True,
            },
            {
                "key": "scan.config.ai.allowAiUsage",
                "name": "Allow AI Usage",
                "category": "ai",
                "originLevel": "Tenant",
                "value": "true",
                "valuetype": "Bool",
                "allowOverride": True,
                "isPersisted": True,
            },
        ]
        if value is not None:
            entries.append(
                {
                    "key": "scan.config.ai.fusionEnabled",
                    "name": "Fusion Scan",
                    "category": "ai",
                    "originLevel": origin,
                    "value": value,
                    "valuetype": "Bool",
                    "allowOverride": allow_override,
                    "isPersisted": True,
                }
            )
        self.project_config[project_id] = entries

    def fusion_setting(self, project_id: str) -> dict[str, Any] | None:
        return next(
            (
                entry
                for entry in self.project_config.get(project_id, [])
                if entry["key"] == "scan.config.ai.fusionEnabled"
            ),
            None,
        )

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
        self,
        *,
        view: str,
        name: str,
        credits: int | float,
        entity_id: str | None = None,
        actions: dict[str, int] | None = None,
    ) -> None:
        """Add or replace a row of a non-user dimension.

        ``actions`` adds the per action transaction breakdown the real project
        rows carry, for example ``{"auto_triage": 4, "triage": 1}``.
        """
        item: dict[str, Any] = {"name": name, "creditsUsed": credits, "percentOfTotal": 1.0}
        if entity_id:
            item["id"] = entity_id
        if actions:
            item["actionsPerformed"] = {
                "actions": [
                    {"actionType": action, "transactionCount": count}
                    for action, count in actions.items()
                ],
                "total": sum(actions.values()),
            }
        rows = self.consumption.setdefault(view, [])
        for index, existing in enumerate(rows):
            if existing.get("name") == name or (entity_id and existing.get("id") == entity_id):
                rows[index] = item
                return
        rows.append(item)

    def set_auto_triage_config(
        self, project_id: str, *, enabled: bool, branches: list[str] | None
    ) -> None:
        """The project's auto triage configuration, as the coordinator reports it."""
        config: dict[str, Any] = {
            "scannerTypes": ["SAST", "SCA"],
            "riskStatuses": ["NEW", "RECURRENT"],
            "severityLevels": ["CRITICAL", "HIGH"],
        }
        if branches is not None:
            config["branches"] = branches
        self.auto_triage[project_id] = {"enabled": enabled, "config": config}

    def add_scan(
        self,
        *,
        project_id: str,
        scan_id: str,
        initiator: str | None,
        completed_at: datetime,
        branch: str = "main",
        status: str = "Completed",
        created_at: datetime | None = None,
        source_origin: str = "webapp",
        engines: list[str] | None = None,
        ai: dict[str, Any] | None = None,
        metadata_in_listing: bool = True,
    ) -> None:
        """A scan in the shape of GET /api/scans/ (synthetic data only).

        ``ai`` is the scan's ``metadata.configs[type=ai].value`` (for example
        ``{"fusionEnabled": "true", "llmModel": "opus-5.5"}``). With
        ``metadata_in_listing`` False only the scan's own read carries it.
        """
        created = created_at or completed_at - timedelta(minutes=10)
        payload: dict[str, Any] = {
            "id": scan_id,
            "status": status,
            "statusDetails": [{"name": "general", "status": status, "details": ""}],
            "branch": branch,
            "createdAt": _iso(created),
            "updatedAt": _iso(completed_at),
            "projectId": project_id,
            "projectName": project_id,
            "userAgent": "test-agent",
            "initiator": initiator,
            "tags": {},
            "engines": engines or ["sast", "sca"],
            "sourceType": "github",
            "sourceOrigin": source_origin,
        }
        configs: list[dict[str, Any]] = [{"type": "sast", "value": {"incremental": "false"}}]
        if ai is not None:
            configs.append({"type": "ai", "value": dict(ai)})
        payload["metadata"] = {"id": scan_id, "type": "upload", "configs": configs}
        if not metadata_in_listing:
            payload["_metadata_only_in_detail"] = True
        self.scans.setdefault(project_id, []).append(payload)

    # ----------------------------------------------------------------- routing

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = urlparse(str(request.url))
        path = url.path
        params = parse_qs(url.query)
        self.requests.append((request.method, path))
        if self.on_request is not None:
            self.on_request(request)

        for fragment, status_code in self.fail_paths.items():
            if fragment in path:
                return httpx.Response(status_code, json={"message": "forced failure"})
        for (method, fragment), status_code in self.fail_requests.items():
            if request.method == method and fragment in path:
                return httpx.Response(status_code, json={"message": "forced failure"})

        if path.endswith("/protocol/openid-connect/token"):
            return httpx.Response(200, json={"access_token": self.access_token, "expires_in": 1800})

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

        if path.endswith("/api/credits/info"):
            if self.credit_info is None:
                return httpx.Response(404, json={"message": "no credit info for this tenant"})
            return httpx.Response(200, json=self.credit_info)

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

        if path.rstrip("/").endswith("/api/scans") and request.method == "GET":
            return self._scans_response(params)

        if "/api/scans/" in path and request.method == "GET":
            scan_id = path.rstrip("/").rsplit("/", 1)[1]
            for rows in self.scans.values():
                for row in rows:
                    if row["id"] == scan_id:
                        return httpx.Response(200, json=_public_scan(row, detail=True))
            return httpx.Response(404, json={"message": "no such scan"})

        if path.rstrip("/").endswith("/api/configuration/project"):
            return self._project_config_response(request, params)

        if path.rstrip("/").endswith("/api/v1/credits/action-rates"):
            if self.action_rates is None:
                return httpx.Response(404, json={"message": "not found"})
            return httpx.Response(
                200, json={"count": len(self.action_rates), "rates": self.action_rates}
            )

        return httpx.Response(404, json={"message": f"no fake route for {path}"})

    # ---------------------------------------------------------------- handlers

    def _users_response(self, params: dict[str, list[str]]) -> httpx.Response:
        if not self.users_requires_paging:
            return httpx.Response(200, json={"filteredCount": len(self.users), "users": self.users})
        # Simulate a Keycloak-style endpoint that caps each page and paginates
        # with `first` (0-based offset) and `max`.
        cap = 2
        first = params.get("first")
        if first is None:
            # Unparameterised call under-reports to force the caller to page.
            window = self.users[:1]
        else:
            offset = int(first[0] or 0)
            size = min(int(params.get("max", [str(cap)])[0]), cap)
            window = self.users[offset : offset + size]
        return httpx.Response(200, json={"filteredCount": len(self.users), "users": window})

    def _paged(
        self, rows: list[dict[str, Any]], key: str, params: dict[str, list[str]]
    ) -> httpx.Response:
        limit = int(params.get("limit", ["100"])[0])
        offset = int(params.get("offset", ["0"])[0])
        window = rows[offset : offset + limit]
        return httpx.Response(200, json={"totalCount": len(rows), key: window})

    def _consumption_response(self, params: dict[str, list[str]]) -> httpx.Response:
        view = params.get("viewBy", ["user"])[0]
        if view in self.fail_views:
            return httpx.Response(self.fail_views[view], json={"message": "forced failure"})
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
        if self.empty_from_page is not None and page >= self.empty_from_page:
            window = []
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

    def _scans_response(self, params: dict[str, list[str]]) -> httpx.Response:
        """GET /api/scans/: newest first, filtered by project, branch and from-date."""
        self.scan_queries.append(params)
        project_id = params.get("project-id", [""])[0]
        rows = list(self.scans.get(project_id, []))
        total = len(rows)
        branch = params.get("branch", [None])[0]
        if branch:
            rows = [row for row in rows if row["branch"] == branch]
        since = params.get("from-date", [None])[0]
        if since:
            floor = _parse(since)
            rows = [row for row in rows if _parse(row["createdAt"]) >= floor]
        rows.sort(key=lambda row: row["createdAt"], reverse=True)
        limit = int(params.get("limit", ["20"])[0])
        offset = int(params.get("offset", ["0"])[0])
        return httpx.Response(
            200,
            json={
                "totalCount": total,
                "filteredTotalCount": len(rows),
                "scans": [_public_scan(row) for row in rows[offset : offset + limit]],
            },
        )

    def _project_config_response(
        self, request: httpx.Request, params: dict[str, list[str]]
    ) -> httpx.Response:
        project_id = params.get("project-id", [""])[0]
        if not project_id:
            return httpx.Response(400, json={"message": "project-id is required"})
        if request.method == "GET":
            return httpx.Response(200, json=self.project_config.get(project_id, []))
        if request.method != "PATCH":
            return httpx.Response(405, json={"message": "only GET and PATCH"})
        body = json.loads(request.content or b"[]")
        if not isinstance(body, list):
            return httpx.Response(400, json={"message": "expected a list"})
        if self.reject_config_lock and any(
            isinstance(entry, dict) and entry.get("allowOverride") is False for entry in body
        ):
            return httpx.Response(400, json={"message": "allowOverride cannot be changed"})
        self.config_patches.append((project_id, body))
        if self.drop_config_writes:
            return httpx.Response(204)
        entries = self.project_config.setdefault(project_id, [])
        for update in body:
            for index, entry in enumerate(entries):
                if entry["key"] == update.get("key"):
                    kept = dict(update)
                    if self.drop_config_lock and kept.get("allowOverride") is False:
                        kept["allowOverride"] = entry.get("allowOverride")
                    entries[index] = {**entry, **kept}
                    break
            else:
                entries.append(dict(update))
        return httpx.Response(204)

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
            settings: dict[str, Any] = {
                "id": repo_id,
                "remediationSeverities": self.repo_severities.get(repo_id, []),
            }
            if repo_id in self.repo_fusion:
                settings["fusionScanConfig"] = dict(self.repo_fusion[repo_id])
            return httpx.Response(200, json=settings)
        if request.method != "PATCH":
            return httpx.Response(405, json={"message": "only PATCH is implemented"})
        if "projectId" not in params:
            return httpx.Response(400, json={"message": "projectId is required"})
        body = json.loads(request.content or b"{}")
        if "remediationSeverities" in body:
            self.repo_severities[repo_id] = list(body.get("remediationSeverities", []))
        if isinstance(body.get("fusionScanConfig"), dict) and not self.drop_repo_fusion_writes:
            self.repo_fusion[repo_id] = dict(body["fusionScanConfig"])
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


def access_token_with(
    *,
    realm_roles: list[str] | None = None,
    client_roles: dict[str, list[str]] | None = None,
    groups: list[str] | None = None,
) -> str:
    """A JWT-shaped access token with role claims (synthetic; never verified)."""
    from tests.conftest import b64url

    payload: dict[str, Any] = {
        "sub": "service-account-creditguard",
        "realm_access": {"roles": realm_roles or []},
        "resource_access": {name: {"roles": roles} for name, roles in (client_roles or {}).items()},
    }
    if groups is not None:
        payload["groups"] = groups
    header = b64url({"alg": "RS256", "typ": "JWT"})
    return f"{header}.{b64url(payload)}.c2lnbmF0dXJl"


def _public_scan(row: dict[str, Any], *, detail: bool = False) -> dict[str, Any]:
    """A stored scan as the API returns it: the listing may leave metadata out."""
    hidden = row.get("_metadata_only_in_detail")
    out = {key: value for key, value in row.items() if not key.startswith("_")}
    if hidden and not detail:
        out.pop("metadata", None)
    return out


def _iso(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _parse(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


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
