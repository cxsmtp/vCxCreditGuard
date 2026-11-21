"""What the stored Checkmarx One API key is actually allowed to do.

A Checkmarx One API key most likely carries only the roles chosen when it was
created, not automatically everything its owner can do. A key created under a
tenant administrator's own account can therefore still be refused calls the
administrator's own browser session makes without trouble. Without this module
that is discovered at the worst moment: the first breach, when a restriction
fails with 403.

So the key is checked up front, with **read-only** calls only:

* one small read per service CreditGuard uses (``limit=1`` style), each reported
  as ok, denied (403), not found, error or skipped (with the reason);
* writes cannot be tried without changing the tenant, so they are reported as
  not tested. When the read on the same service was refused the write is marked
  as one that will fail too, and the access token's own role claims are used as
  a hint where they say something (``realm-management`` without
  ``manage-users``);
* the role and group *names* in the access token are reported so an admin can
  see what the key has. The token itself is never stored, logged or returned.

Refusals seen at run time (a restriction, a restore, a cycle read) are recorded
on the same report, so a write the probes could not test shows up the moment it
is first refused. Each one is tagged with the key it was made with, so a
replaced key's refusals never land on its successor. A refused read is cleared
by the next probe of that read that succeeds; a refused change is cleared only
when CreditGuard later makes the same change successfully (nothing else is
evidence that it works).

How serious a gap is depends on what is configured right now (an enforcing user
limit needs the role mapping calls, an enforcing project, group or application
limit needs the project configuration calls, a group or application limit needs
the groups or applications), so the verdict is worked out again whenever the
report is read, from the stored check results. Only a confirmed gap in something
needed right now asks for everyone's attention (the banner, the admin pop-up,
the top bar light); the rest is shown on the Connection page only.

The report lives in ``app_setting`` as JSON (bookkeeping, never shown as a
setting). Nothing here holds a database write lock across a Checkmarx call, and
a failure here never breaks a sign-in, a connection save or a cycle.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checkmarx import credits as credits_api
from app.checkmarx import iam, platform
from app.checkmarx import scans as scans_api
from app.checkmarx import usage as usage_api
from app.checkmarx.client import (
    CheckmarxClient,
    add_forbidden_listener,
    add_success_listener,
    listeners_paused,
)
from app.checkmarx.errors import (
    CheckmarxAuthError,
    CheckmarxError,
    CheckmarxNotFoundError,
    CheckmarxPermissionError,
    CheckmarxRateLimitError,
    CheckmarxResponseError,
    CheckmarxUnavailableError,
)
from app.db.base import utcnow
from app.models.connection import AppSetting
from app.models.enums import EntityType, Severity
from app.models.limits import CreditLimit
from app.models.org import CxProject, CxUser
from app.services import notifications, settings_store
from app.services.audit import AuditActor, record_audit

logger = logging.getLogger(__name__)

# How often the cycle re-checks on its own. Cheap (a dozen small reads), but
# there is no reason to do it more often: what the key may do changes when an
# admin changes it, and then they press "Check again".
RECHECK_INTERVAL = timedelta(hours=6)

STATUS_OK = "ok"
STATUS_DENIED = "denied"
STATUS_NOT_FOUND = "not_found"
STATUS_ERROR = "error"
STATUS_SKIPPED = "skipped"
STATUS_NOT_TESTED = "not_tested"

# Not tested, but expected to fail.
EXPECT_WILL_FAIL = "will_fail"
EXPECT_PROBABLY_DENIED = "probably_denied"

NEED_CORE = "core"
NEED_GROUP_LIMITS = "group_limits"
NEED_APPLICATION_LIMITS = "application_limits"
NEED_ENFORCE_USERS = "enforce_users"
NEED_ENFORCE_PROJECTS = "enforce_projects"
NEED_AUTO_TRIAGE = "auto_triage_charging"
NEED_OPTIONAL = "optional"

VERDICT_OK = "ok"
VERDICT_LIMITED = "limited"
VERDICT_INSUFFICIENT = "insufficient"
# Nothing could be checked (the key could not be exchanged for a token). The
# connection test already says why; this is not a permission problem.
VERDICT_UNKNOWN = "unknown"
PROBLEM_VERDICTS = frozenset({VERDICT_LIMITED, VERDICT_INSUFFICIENT})

TRIGGER_CONNECTION_SAVED = "connection_saved"
TRIGGER_CONNECTION_TEST = "connection_test"
TRIGGER_MANUAL = "manual"
TRIGGER_CYCLE = "cycle"
TRIGGER_RUNTIME = "runtime"

REPORT_VERSION = 1
_MAX_NAMES = 200
_MAX_RUNTIME_ENTRIES = 50


@dataclass(frozen=True, slots=True)
class CheckSpec:
    id: str
    label: str
    # Plain English: what CreditGuard uses this call for.
    purpose: str
    # Completes "CreditGuard can't ..." for the banner.
    cant: str
    method: str
    # The call as documented, with placeholders instead of tenant values.
    path: str
    kind: str  # "read" or "write"
    needed_for: tuple[str, ...]
    # What stops working without it.
    breaks: str
    # For a write: the reads on the same service. If one of them is refused,
    # the write will be refused too.
    reads: tuple[str, ...] = ()


SPECS: tuple[CheckSpec, ...] = (
    CheckSpec(
        id="iam_users",
        label="IAM users",
        purpose="Read users and their roles",
        cant="read users",
        method="GET",
        path="/auth/realms/<tenant>/users/v2",
        kind="read",
        needed_for=(NEED_CORE,),
        breaks=(
            "Users cannot be synced, so usage cannot be matched to people and user limits "
            "are not evaluated."
        ),
    ),
    CheckSpec(
        id="iam_groups",
        label="IAM groups",
        purpose="Read groups",
        cant="read groups",
        method="GET",
        path="/auth/realms/<tenant>/groups",
        kind="read",
        needed_for=(NEED_GROUP_LIMITS,),
        breaks=(
            "New or changed groups cannot be synced, so group limits work from the groups "
            "synced before (or none). Nothing else uses them."
        ),
    ),
    CheckSpec(
        id="projects",
        label="Projects",
        purpose="Read projects",
        cant="read projects",
        method="GET",
        path="/api/projects",
        kind="read",
        needed_for=(NEED_CORE,),
        breaks=(
            "Projects cannot be synced, so project, group and application limits cannot find "
            "their projects and nothing can be restricted on a project."
        ),
    ),
    CheckSpec(
        id="applications",
        label="Applications",
        purpose="Read applications",
        cant="read applications",
        method="GET",
        path="/api/applications",
        kind="read",
        needed_for=(NEED_APPLICATION_LIMITS,),
        breaks=(
            "Application limits cannot find their projects (they keep what was synced "
            "before). Nothing else uses applications."
        ),
    ),
    CheckSpec(
        id="consumption",
        label="Credit consumption",
        purpose="Count credit usage",
        cant="count credit usage",
        method="GET",
        path="/api/credits/consumption",
        kind="read",
        needed_for=(NEED_CORE,),
        breaks="No credit usage is counted, so no limit is evaluated, warned about or enforced.",
    ),
    CheckSpec(
        id="credit_pool",
        label="Credit pool",
        purpose="Read the tenant's credit pool",
        cant="read the credit pool",
        method="GET",
        path="/api/credits/info",
        kind="read",
        needed_for=(NEED_OPTIONAL,),
        breaks="The tenant's total and available credits are not shown. Nothing else changes.",
    ),
    CheckSpec(
        id="scans",
        label="Scans",
        purpose="Read scans to charge auto triage to the person who started the scan",
        cant="read scans to charge auto triage to the person who started the scan",
        method="GET",
        path="/api/scans/",
        kind="read",
        needed_for=(NEED_AUTO_TRIAGE,),
        breaks=(
            "Auto-triage credits cannot be charged to the person who started the scan; "
            "they stay estimated."
        ),
    ),
    CheckSpec(
        id="ai_config_read",
        label="AI agent project configuration (read)",
        purpose="Read a project's Auto Triage setting",
        cant="read projects' Auto Triage setting",
        method="GET",
        path="/api/ai-agents-coordinator/projects/{projectId}/configuration",
        kind="read",
        needed_for=(NEED_ENFORCE_PROJECTS, NEED_AUTO_TRIAGE),
        breaks=(
            "A project's Auto Triage setting cannot be read before it is changed, so Auto "
            "Triage cannot be restricted (or put back exactly as it was), and auto-triage "
            "charging cannot tell which branches auto triage runs on."
        ),
    ),
    CheckSpec(
        id="repo_read",
        label="Repository settings (read)",
        purpose="Read a repository's PR triage and remediation setting",
        cant="read repositories' PR triage and remediation setting",
        method="GET",
        path="/api/repos-manager/repo/{repoId}?projectId={projectId}",
        kind="read",
        needed_for=(NEED_ENFORCE_PROJECTS,),
        breaks=(
            "The PR triage and remediation setting cannot be read before it is changed; "
            "without a value recorded earlier, that half of a project restriction is left "
            "unchanged, and restrictions in force cannot be verified."
        ),
    ),
    CheckSpec(
        id="iam_clients",
        label="IAM admin: client lookup",
        purpose="Find the ast-app client that owns the AI roles",
        cant="find the client that owns the AI roles",
        method="GET",
        path="/auth/admin/realms/<tenant>/clients?clientId=ast-app",
        kind="read",
        needed_for=(NEED_ENFORCE_USERS,),
        breaks="Users cannot be restricted or restored: their AI roles cannot be looked up.",
    ),
    CheckSpec(
        id="iam_client_roles",
        label="IAM admin: client roles",
        purpose="List the AI roles on the ast-app client",
        cant="list the AI roles",
        method="GET",
        path="/auth/admin/realms/<tenant>/clients/{clientUuid}/roles",
        kind="read",
        needed_for=(NEED_ENFORCE_USERS,),
        breaks="Users cannot be restricted or restored: the AI roles cannot be resolved.",
    ),
    CheckSpec(
        id="iam_user_roles",
        label="IAM admin: user role mappings (read)",
        purpose="Read which AI roles a user holds",
        cant="read users' AI roles",
        method="GET",
        path="/auth/admin/realms/<tenant>/users/{userId}/role-mappings/clients/{clientUuid}",
        kind="read",
        needed_for=(NEED_ENFORCE_USERS,),
        breaks=(
            "A user's roles cannot be read before they are changed, so users cannot be "
            "restricted, verified or restored."
        ),
    ),
    CheckSpec(
        id="role_mapping_write",
        label="IAM admin: user role mappings (change)",
        purpose="Remove a user's AI roles, and give them back",
        cant="remove users' AI roles",
        method="POST/DELETE",
        path="/auth/admin/realms/<tenant>/users/{userId}/role-mappings/clients/{clientUuid}",
        kind="write",
        needed_for=(NEED_ENFORCE_USERS,),
        breaks="User limits cannot restrict anyone, and a restriction cannot be lifted.",
        reads=("iam_clients", "iam_client_roles", "iam_user_roles"),
    ),
    CheckSpec(
        id="ai_config_write",
        label="AI agent project configuration (change)",
        purpose="Restrict a project's Auto Triage, and turn it back on",
        cant="restrict projects' Auto Triage",
        method="PUT",
        path="/api/ai-agents-coordinator/projects/{projectId}/configuration",
        kind="write",
        needed_for=(NEED_ENFORCE_PROJECTS,),
        breaks=(
            "Project, group and application limits cannot turn Auto Triage off, or back on "
            "when a restriction is lifted."
        ),
        reads=("ai_config_read",),
    ),
    CheckSpec(
        id="repo_write",
        label="Repository settings (change)",
        purpose="Restrict a project's PR triage and remediation, and turn it back on",
        cant="restrict projects' PR triage and remediation",
        method="PATCH",
        path="/api/repos-manager/repo/{repoId}?projectId={projectId}",
        kind="write",
        needed_for=(NEED_ENFORCE_PROJECTS,),
        breaks=(
            "Project, group and application limits cannot turn PR triage and remediation "
            "off, or back on when a restriction is lifted."
        ),
        reads=("repo_read",),
    ),
)
SPEC_BY_ID: dict[str, CheckSpec] = {spec.id: spec for spec in SPECS}
_SEVERE_NEEDS = frozenset(
    {
        NEED_CORE,
        NEED_GROUP_LIMITS,
        NEED_APPLICATION_LIMITS,
        NEED_ENFORCE_USERS,
        NEED_ENFORCE_PROJECTS,
    }
)

# A refusal at run time, matched to the check it concerns: (method, path regex).
_RUNTIME_ROUTES: tuple[tuple[frozenset[str], re.Pattern[str], str], ...] = tuple(
    (frozenset(methods.split()), re.compile(pattern), check_id)
    for methods, pattern, check_id in (
        ("GET", r"/auth/realms/[^/]+/users/v2/?$", "iam_users"),
        ("GET", r"/auth/realms/[^/]+/groups/?$", "iam_groups"),
        ("GET", r"/api/projects/?$", "projects"),
        ("GET", r"/api/applications/?$", "applications"),
        ("GET", r"/api/credits/consumption/?$", "consumption"),
        ("GET", r"/api/credits/info/?$", "credit_pool"),
        ("GET POST", r"/api/scans(/byFilters)?/?$", "scans"),
        ("GET", r"/ai-agents-coordinator/projects/[^/]+/configuration/?$", "ai_config_read"),
        (
            "PUT POST PATCH",
            r"/ai-agents-coordinator/projects/[^/]+/configuration/?$",
            "ai_config_write",
        ),
        ("GET", r"/repos-manager/repo/[^/]+/?$", "repo_read"),
        ("PATCH PUT", r"/repos-manager/repo/[^/]+/?$", "repo_write"),
        ("GET", r"/auth/admin/realms/[^/]+/clients/?$", "iam_clients"),
        ("GET", r"/auth/admin/realms/[^/]+/clients/[^/]+/roles/?$", "iam_client_roles"),
        ("GET", r"/users/[^/]+/role-mappings/clients/[^/]+/?$", "iam_user_roles"),
        ("POST DELETE PUT", r"/users/[^/]+/role-mappings/clients/[^/]+/?$", "role_mapping_write"),
    )
)


# ------------------------------------------------------------ token claims


def _names(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    names = sorted({entry.strip()[:128] for entry in value if isinstance(entry, str) and entry})
    return [name for name in names if name][:_MAX_NAMES]


def token_claims(token: str | None) -> dict[str, Any]:
    """Role and group names from an access token's payload. Nothing else.

    Only the middle segment is decoded; the signature is not checked because
    this is the token CreditGuard itself was just given. A token that is not a
    readable JWT (opaque tokens exist) is reported as unreadable, not an error.
    """
    unreadable: dict[str, Any] = {
        "readable": False,
        "realm_roles": [],
        "client_roles": {},
        "roles": [],
        "groups": [],
    }
    if not isinstance(token, str):
        return unreadable
    parts = token.split(".")
    if len(parts) != 3 or not parts[1]:
        return unreadable
    segment = parts[1]
    try:
        raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
        payload = json.loads(raw.decode("utf-8"))
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return unreadable
    if not isinstance(payload, dict):
        return unreadable
    realm_access = payload.get("realm_access")
    resource_access = payload.get("resource_access")
    client_roles: dict[str, list[str]] = {}
    if isinstance(resource_access, dict):
        for client_name, entry in list(resource_access.items())[:_MAX_NAMES]:
            if isinstance(client_name, str) and isinstance(entry, dict):
                client_roles[client_name[:128]] = _names(entry.get("roles"))
    return {
        "readable": True,
        "realm_roles": _names(realm_access.get("roles")) if isinstance(realm_access, dict) else [],
        "client_roles": client_roles,
        "roles": _names(payload.get("roles")),
        "groups": _names(payload.get("groups")),
    }


# --------------------------------------------------------- runtime refusals

_DENIED = "denied"
_ALLOWED = "allowed"
# (what happened, method, url, fingerprint of the key the call was made with or
# None when the client does not say, when). Process wide; flushed onto the
# stored report by the cycle steps and enforcement.
_pending: list[tuple[str, str, str, str | None, datetime]] = []
_pending_lock = threading.Lock()
# (method, path template) of the refused changes on the stored report. A
# successful change is only queued when it answers one of them, so the success
# hook costs one set lookup in the normal case. Replaced whole, never mutated.
_denied_routes: frozenset[tuple[str, str]] = frozenset()


def _queue(kind: str, method: str, url: str, fingerprint: str | None) -> None:
    with _pending_lock:
        if len(_pending) < _MAX_RUNTIME_ENTRIES * 4:
            _pending.append((kind, method, url, fingerprint, utcnow()))


def _on_forbidden(method: str, url: str, fingerprint: str | None) -> None:
    _queue(_DENIED, method, url, fingerprint)


def _on_success(method: str, url: str, fingerprint: str | None) -> None:
    routes = _denied_routes
    if not routes or method == "GET":
        return
    _check_id, path = _classify(method, url)
    if (method, path) in routes:
        _queue(_ALLOWED, method, url, fingerprint)


add_forbidden_listener(_on_forbidden)
add_success_listener(_on_success)

# Refusals seen by the probes are results, not run-time events.
_probing = listeners_paused


def _remember_denied_routes(report: dict[str, Any] | None) -> None:
    global _denied_routes
    routes = frozenset(
        (str(entry.get("method")), str(entry.get("path")))
        for entry in (report or {}).get("runtime_denials") or []
        if isinstance(entry, dict) and entry.get("method") != "GET"
    )
    if routes != _denied_routes:
        _denied_routes = routes


def _classify(method: str, url: str) -> tuple[str | None, str]:
    """(check id or None, the path with tenant values replaced by placeholders)."""
    path = urlparse(url).path or url
    method = method.upper()
    for methods, pattern, check_id in _RUNTIME_ROUTES:
        if method in methods and pattern.search(path):
            return check_id, SPEC_BY_ID[check_id].path
    return None, _template(path)


_ID_SEGMENT = re.compile(r"^(?=.*\d)[A-Za-z0-9_.:-]{6,}$")


def _template(path: str) -> str:
    segments = path.split("/")
    out: list[str] = []
    for index, segment in enumerate(segments):
        previous = segments[index - 1] if index else ""
        if previous == "realms":
            out.append("<tenant>")
        elif _ID_SEGMENT.match(segment):
            out.append("{id}")
        else:
            out.append(segment)
    return "/".join(out)[:300]


def pending_denials() -> int:
    """Run-time events (refusals, and successful retries of refused changes)
    waiting to be recorded."""
    with _pending_lock:
        return len(_pending)


def discard_pending_denials() -> None:
    with _pending_lock:
        _pending.clear()


# -------------------------------------------------------------- the probes


@dataclass
class _ProbeTargets:
    period: str
    project_id: str | None
    repo: tuple[str, str] | None  # (repo id, project id)
    user_id: str | None
    client_uuid: str | None = None


def _outcome(call: Callable[[], Any]) -> tuple[str, str | None]:
    try:
        call()
    except CheckmarxPermissionError:
        return STATUS_DENIED, "Checkmarx answered 403 Forbidden."
    except CheckmarxNotFoundError as exc:
        text = str(exc)
        if "returned 404" in text:
            return STATUS_NOT_FOUND, "Checkmarx answered 404 Not Found."
        return STATUS_NOT_FOUND, text[:300]
    except CheckmarxAuthError:
        raise
    except CheckmarxRateLimitError:
        return STATUS_ERROR, "Checkmarx asked CreditGuard to slow down (429). Check again later."
    except CheckmarxResponseError as exc:
        if exc.status_code is not None:
            return STATUS_ERROR, f"Checkmarx answered {exc.status_code}."
        return STATUS_ERROR, "Checkmarx answered with a body that could not be read."
    except CheckmarxUnavailableError:
        return STATUS_ERROR, "Checkmarx could not be reached, or kept failing. Check again later."
    except CheckmarxError as exc:
        return STATUS_ERROR, str(exc)[:300]
    return STATUS_OK, None


def _run_probes(
    client: CheckmarxClient,
    targets: _ProbeTargets,
    *,
    skip: dict[str, str],
) -> dict[str, tuple[str, str | None]]:
    results: dict[str, tuple[str, str | None]] = {}
    found: dict[str, Any] = {}

    def projects() -> None:
        payload = client.get_json(platform.PROJECTS_PATH, params={"limit": 1, "offset": 0})
        items = payload.get("projects") if isinstance(payload, dict) else payload
        if isinstance(items, list) and items and isinstance(items[0], dict):
            found["project"] = platform.parse_project(items[0])

    def client_lookup() -> None:
        targets.client_uuid = iam.resolve_platform_client_uuid(client)

    probes: list[tuple[str, Callable[[], Any]]] = [
        (
            "iam_users",
            lambda: client.get_json(iam.USERS_PATH, base="realm", params={"first": 0, "max": 1}),
        ),
        (
            "iam_groups",
            lambda: client.get_json(iam.GROUPS_PATH, base="realm", params={"first": 0, "max": 1}),
        ),
        ("projects", projects),
        (
            "applications",
            lambda: client.get_json(platform.APPLICATIONS_PATH, params={"limit": 1, "offset": 0}),
        ),
        (
            "consumption",
            lambda: client.get_json(
                usage_api.CONSUMPTION_PATH,
                params={"viewBy": "user", "period": targets.period, "page": 1, "size": 1},
            ),
        ),
        ("credit_pool", lambda: client.get_json(credits_api.CREDITS_INFO_PATH)),
    ]
    for check_id, call in probes:
        if check_id in skip:
            results[check_id] = (STATUS_SKIPPED, skip[check_id])
        else:
            results[check_id] = _outcome(call)

    # The project used for the per-project reads: a synced one, else the one the
    # projects read just returned.
    project_id = targets.project_id
    repo = targets.repo
    listed = found.get("project")
    if project_id is None and listed is not None:
        project_id = listed.id
    if repo is None and listed is not None and listed.repo_id:
        repo = (listed.repo_id, listed.id)

    if "scans" in skip:
        results["scans"] = (STATUS_SKIPPED, skip["scans"])
    else:
        params: dict[str, Any] = {"limit": 1, "offset": 0}
        if project_id:
            params["project-id"] = project_id
        results["scans"] = _outcome(lambda: client.get_json(scans_api.SCANS_PATH, params=params))

    if project_id is None:
        results["ai_config_read"] = (
            STATUS_SKIPPED,
            "No project is known yet (none synced, and the projects read returned none), so "
            "there was nothing to read the Auto Triage setting of.",
        )
    else:
        results["ai_config_read"] = _outcome(
            lambda: client.get_json(platform.AUTO_TRIAGE_PATH.format(project_id=project_id))
        )

    if repo is None:
        results["repo_read"] = (
            STATUS_SKIPPED,
            "No project linked to a supported repository (with a repository id) is known, so "
            "there was no repository setting to read.",
        )
    else:
        repo_id, repo_project = repo
        results["repo_read"] = _outcome(
            lambda: client.get_json(
                platform.REPO_SETTINGS_PATH.format(repo_id=repo_id),
                params={"projectId": repo_project},
            )
        )

    results["iam_clients"] = _outcome(client_lookup)
    if targets.client_uuid is None:
        reason = "The client lookup above did not succeed, so there is no client to read."
        results["iam_client_roles"] = (STATUS_SKIPPED, reason)
        results["iam_user_roles"] = (STATUS_SKIPPED, reason)
    else:
        uuid = targets.client_uuid
        results["iam_client_roles"] = _outcome(
            lambda: iam.fetch_client_roles(client, client_uuid=uuid)
        )
        if targets.user_id is None:
            results["iam_user_roles"] = (
                STATUS_SKIPPED,
                "No tenant user is known yet, so there was no one whose roles to read.",
            )
        else:
            user_id = targets.user_id
            results["iam_user_roles"] = _outcome(
                lambda: iam.fetch_user_client_roles(client, user_id=user_id, client_uuid=uuid)
            )
    return results


# ----------------------------------------------------------- the report


@dataclass(frozen=True, slots=True)
class Context:
    """What is switched on right now, which decides how serious a gap is."""

    enforce_users: bool
    enforce_projects: bool
    auto_triage_charging: bool
    group_limits: bool = False
    application_limits: bool = False

    def active(self, need: str) -> bool:
        if need == NEED_CORE:
            return True
        if need == NEED_GROUP_LIMITS:
            return self.group_limits
        if need == NEED_APPLICATION_LIMITS:
            return self.application_limits
        if need == NEED_ENFORCE_USERS:
            return self.enforce_users
        if need == NEED_ENFORCE_PROJECTS:
            return self.enforce_projects
        if need == NEED_AUTO_TRIAGE:
            return self.auto_triage_charging
        return False


def current_context(session: Session) -> Context:
    rows = session.execute(
        select(CreditLimit.entity_type, CreditLimit.enforce)
        .where(CreditLimit.is_active.is_(True))
        .distinct()
    ).all()
    present = {str(entity_type) for entity_type, _enforce in rows}
    enforcing = {str(entity_type) for entity_type, enforce in rows if enforce}
    return Context(
        enforce_users=EntityType.USER.value in enforcing,
        enforce_projects=bool(enforcing - {EntityType.USER.value}),
        auto_triage_charging=settings_store.auto_triage_to_initiator(session),
        group_limits=EntityType.GROUP.value in present,
        application_limits=EntityType.APPLICATION.value in present,
    )


_NEED_REASONS: dict[str, tuple[str, str]] = {
    # need -> (when active, when not)
    NEED_CORE: ("Needed all the time.", "Needed all the time."),
    NEED_GROUP_LIMITS: (
        "Needed now: at least one group limit exists.",
        "Only needed once a group limit exists.",
    ),
    NEED_APPLICATION_LIMITS: (
        "Needed now: at least one application limit exists.",
        "Only needed once an application limit exists.",
    ),
    NEED_ENFORCE_USERS: (
        "Needed now: at least one user limit enforces.",
        "Only needed once a user limit enforces.",
    ),
    NEED_ENFORCE_PROJECTS: (
        "Needed now: at least one project, group or application limit enforces.",
        "Only needed once a project, group or application limit enforces.",
    ),
    NEED_AUTO_TRIAGE: (
        "Needed now: auto-triage charging is on.",
        "Only needed when auto-triage charging is on.",
    ),
    NEED_OPTIONAL: ("Optional.", "Optional."),
}


def _required(spec: CheckSpec, ctx: Context) -> tuple[bool, str]:
    active = [need for need in spec.needed_for if ctx.active(need)]
    if active:
        return True, " ".join(_NEED_REASONS[need][0] for need in active)
    return False, " ".join(_NEED_REASONS[need][1] for need in spec.needed_for)


def _empty_check(spec: CheckSpec) -> dict[str, Any]:
    return {
        "id": spec.id,
        "status": STATUS_NOT_TESTED,
        "detail": None,
        "expectation": None,
        "runtime_denied_at": None,
    }


def _skeleton(fingerprint: str | None) -> dict[str, Any]:
    return {
        "version": REPORT_VERSION,
        "checked_at": None,
        "trigger": None,
        "key_fingerprint": fingerprint,
        "token_failed": None,
        "checks": [_empty_check(spec) for spec in SPECS],
        "runtime_denials": [],
        "token": None,
        "last_verdict": None,
        "last_attention": None,
        "problem_since": None,
    }


_WRITE_NOTE = (
    "Cannot be tested without changing the tenant; it is confirmed the first time "
    "CreditGuard uses it."
)


def _infer_writes(checks: dict[str, dict[str, Any]], claims: dict[str, Any] | None) -> None:
    for spec in SPECS:
        if spec.kind != "write":
            continue
        check = checks[spec.id]
        if check["status"] == STATUS_NOT_TESTED:
            check["detail"] = _WRITE_NOTE
        refused = [read for read in spec.reads if checks[read]["status"] == STATUS_DENIED]
        if refused:
            check["expectation"] = EXPECT_WILL_FAIL
            check["detail"] = (
                "Not tested, but it will fail: the read on the same service was refused (403)."
            )
            continue
        if (
            spec.id == "role_mapping_write"
            and claims
            and claims.get("readable")
            and "realm-management" in (claims.get("client_roles") or {})
            and "manage-users" not in claims["client_roles"]["realm-management"]
        ):
            check["expectation"] = EXPECT_PROBABLY_DENIED
            check["detail"] = (
                "Not tested, but probably refused: the key's token lists realm-management "
                "roles without manage-users, which changing role mappings normally needs."
            )


def _confirmed(check: dict[str, Any]) -> bool:
    """Refused, or certain to be: a 403 seen, or the read it depends on refused."""
    return (
        check.get("status") == STATUS_DENIED
        or check.get("expectation") == EXPECT_WILL_FAIL
        or bool(check.get("runtime_denied_at"))
    )


def _is_problem(check: dict[str, Any]) -> bool:
    # "Probably refused" is a guess from the token's role names: shown on the
    # card as a warning, never on its own a reason for the banner or a red verdict.
    return _confirmed(check) or check.get("expectation") == EXPECT_PROBABLY_DENIED


def problem_ids(report: dict[str, Any]) -> list[str]:
    return sorted(check["id"] for check in report.get("checks") or [] if _is_problem(check))


def problem_key(ids: list[str]) -> str | None:
    if not ids:
        return None
    return hashlib.sha256(",".join(sorted(ids)).encode()).hexdigest()[:16]


def _status_phrase(check: dict[str, Any]) -> str:
    if check.get("runtime_denied_at"):
        when = str(check["runtime_denied_at"])[:16].replace("T", " ")
        return f"refused (403) when CreditGuard used it on {when} UTC"
    if check.get("status") == STATUS_DENIED:
        return "refused (403)"
    if check.get("expectation") == EXPECT_WILL_FAIL:
        return "not tested, will fail: the read on the same service was refused"
    if check.get("expectation") == EXPECT_PROBABLY_DENIED:
        return "not tested, probably refused (the token lacks manage-users)"
    return str(check.get("status"))


def _join_or(items: list[str]) -> str:
    if len(items) <= 1:
        return "".join(items)
    return f"{', '.join(items[:-1])} or {items[-1]}"


def _shown(cant: list[str]) -> str:
    shown = cant[:3]
    if len(cant) > 3:
        shown = [*shown[:2], f"{len(cant) - 2} more things"]
    return _join_or(shown)


def assess(report: dict[str, Any] | None, ctx: Context) -> dict[str, Any] | None:
    """The stored report with requirement, verdict and explanation worked out for now."""
    if report is None:
        return None
    by_id = {check.get("id"): check for check in report.get("checks") or []}
    checks: list[dict[str, Any]] = []
    for spec in SPECS:
        stored = by_id.get(spec.id) or _empty_check(spec)
        required, reason = _required(spec, ctx)
        active_needs = [need for need in spec.needed_for if ctx.active(need)]
        problem = _is_problem(stored)
        confirmed = _confirmed(stored)
        checks.append(
            {
                "id": spec.id,
                "label": spec.label,
                "purpose": spec.purpose,
                "method": spec.method,
                "path": spec.path,
                "kind": spec.kind,
                "status": stored.get("status") or STATUS_NOT_TESTED,
                "detail": stored.get("detail"),
                "expectation": stored.get("expectation"),
                "runtime_denied_at": stored.get("runtime_denied_at"),
                "needed_for": list(spec.needed_for),
                "required": required,
                "required_reason": reason,
                "breaks": spec.breaks,
                "problem": problem,
                "severe": confirmed and any(need in _SEVERE_NEEDS for need in active_needs),
                "_confirmed": confirmed,
            }
        )
    problems = [check for check in checks if check["problem"]]
    # Only a confirmed gap in something needed right now is worth everyone's
    # attention (banner, pop-up, top bar light); the rest is for the card.
    attention = any(check["_confirmed"] and check["required"] for check in problems)
    if any(check["severe"] for check in problems):
        verdict = VERDICT_INSUFFICIENT
    elif problems:
        verdict = VERDICT_LIMITED
    elif report.get("token_failed"):
        verdict = VERDICT_UNKNOWN
    else:
        verdict = VERDICT_OK

    ordered = sorted(
        problems,
        key=lambda c: (
            not c["severe"],
            not (c["_confirmed"] and c["required"]),
            not c["required"],
            c["kind"] != "write",
        ),
    )
    cant = [SPEC_BY_ID[check["id"]].cant for check in ordered]
    maybe = [
        SPEC_BY_ID[check["id"]].cant
        for check in ordered
        if check["required"] and not check["_confirmed"]
    ]
    for check in checks:
        del check["_confirmed"]
    if verdict in PROBLEM_VERDICTS and attention:
        summary = f"The Checkmarx API key is missing permissions: CreditGuard can't {_shown(cant)}."
    elif verdict in PROBLEM_VERDICTS and maybe:
        summary = (
            "The Checkmarx API key may be missing a permission CreditGuard needs: it probably "
            f"can't {_shown(maybe)}. This is confirmed the first time CreditGuard tries."
        )
    elif verdict in PROBLEM_VERDICTS:
        summary = (
            "The Checkmarx API key has what CreditGuard needs with the current setup. Not "
            f"allowed, and not needed now: CreditGuard can't {_shown(cant)}."
        )
    elif verdict == VERDICT_UNKNOWN:
        summary = (
            "The API key's permissions could not be checked: the key could not be exchanged "
            "for a token. See the connection test."
        )
    else:
        summary = "The Checkmarx API key has every permission CreditGuard checked."

    claims = report.get("token") or None
    return {
        "verdict": verdict,
        "attention": attention,
        "summary": summary,
        "checked_at": report.get("checked_at"),
        "trigger": report.get("trigger"),
        "key_fingerprint": report.get("key_fingerprint"),
        "enforce_users": ctx.enforce_users,
        "enforce_projects": ctx.enforce_projects,
        "auto_triage_charging": ctx.auto_triage_charging,
        "checks": checks,
        "missing": cant,
        "problem_key": problem_key([check["id"] for check in problems]),
        "runtime_denials": list(report.get("runtime_denials") or []),
        "token": claims,
        "explanation": _explain(verdict, ordered, claims, report, attention=attention),
    }


def _explain(
    verdict: str,
    problems: list[dict[str, Any]],
    claims: dict[str, Any] | None,
    report: dict[str, Any],
    *,
    attention: bool,
) -> dict[str, list[str]]:
    if verdict == VERDICT_UNKNOWN:
        return {
            "why": [
                "The API key could not be exchanged for an access token, so no permission "
                "could be checked. The connection test shows the reason."
            ],
            "missing": [],
            "roles": [],
            "what_to_do": ["Fix the connection on the Connection page, then press Check again."],
        }
    if verdict == VERDICT_OK:
        return {"why": [], "missing": [], "roles": _roles_lines(claims), "what_to_do": []}
    if any(_confirmed(check) for check in problems):
        first = (
            "Checkmarx One refused (403 Forbidden) calls CreditGuard makes with this API key. "
            "The connection itself works, so the address and the key are right: the key is "
            "missing permissions."
        )
    else:
        first = (
            "Nothing has been refused yet, but the roles in the key's access token suggest a "
            "change CreditGuard makes will be. It is confirmed the first time CreditGuard "
            "makes it."
        )
    why = [
        first,
        "The likely reason: a Checkmarx One API key carries only the roles chosen when it was "
        "created, not automatically everything its owner can do. A key created under a tenant "
        "administrator's own account can therefore lack permissions the administrator has in "
        "the browser. A dedicated service account, with a key created for CreditGuard, is "
        "recommended.",
    ]
    missing = [
        f"{SPEC_BY_ID[check['id']].purpose} ({check['method']} {check['path']}): "
        f"{_status_phrase(check)}. {check['breaks']}"
        for check in problems
    ]
    others = [
        entry
        for entry in report.get("runtime_denials") or []
        if isinstance(entry, dict) and not entry.get("check_id")
    ]
    missing.extend(
        f"{entry.get('method')} {entry.get('path')}: refused (403) at run time." for entry in others
    )
    what_to_do = [
        "Create a new API key that includes the permissions for the calls listed as missing "
        "(the README section 'Checkmarx permissions the API key needs' lists every call "
        "CreditGuard makes), or add them to the key's account and key in Checkmarx One "
        "Identity and Access Management.",
        "Paste the new key on the Connection page, or press Check again after changing the "
        "existing key. Check again re-reads everything it can; a change refused at run time "
        "stays listed until CreditGuard next makes that same change successfully, because a "
        "change cannot be tested without making it.",
    ]
    if verdict == VERDICT_LIMITED:
        what_to_do.append(
            "Counting usage and warning are not affected. Only the features listed above stop "
            "working, and only when they are used."
        )
    if not attention:
        what_to_do.append(
            "Nothing CreditGuard needs with the current setup is confirmed missing, so this is "
            "shown here only, not as a banner."
        )
    return {"why": why, "missing": missing, "roles": _roles_lines(claims), "what_to_do": what_to_do}


def _roles_lines(claims: dict[str, Any] | None) -> list[str]:
    if not claims or not claims.get("readable"):
        return ["The key's access token does not list its roles in a readable form."]
    lines: list[str] = []
    if claims.get("realm_roles"):
        lines.append(f"Tenant roles: {', '.join(claims['realm_roles'])}")
    for client_name, roles in sorted((claims.get("client_roles") or {}).items()):
        lines.append(f"{client_name}: {', '.join(roles) if roles else '(none)'}")
    if claims.get("roles"):
        lines.append(f"Roles: {', '.join(claims['roles'])}")
    if claims.get("groups"):
        lines.append(f"Groups: {', '.join(claims['groups'])}")
    return lines or ["The key's access token lists no roles."]


# ------------------------------------------------------------- persistence


def load(session: Session, *, fresh: bool = False) -> dict[str, Any] | None:
    """The stored report. ``fresh`` re-reads the row even if this session has it
    already, so what another process stored meanwhile is not overwritten."""
    if fresh:
        session.get(AppSetting, settings_store.KEY_KEY_PERMISSIONS, populate_existing=True)
    value = settings_store.get_value(session, settings_store.KEY_KEY_PERMISSIONS)
    report = value if isinstance(value, dict) and value.get("version") == REPORT_VERSION else None
    _remember_denied_routes(report)
    return report


def _store(session: Session, report: dict[str, Any]) -> None:
    settings_store.set_value(
        session,
        settings_store.KEY_KEY_PERMISSIONS,
        report,
        description="Latest Checkmarx API key permission report (bookkeeping).",
    )
    _remember_denied_routes(report)


def _current_fingerprint(session: Session) -> str | None:
    from app.services import connection as connection_service

    connection = connection_service.get_connection(session)
    return connection.api_key_fingerprint if connection is not None else None


def current_report(session: Session) -> dict[str, Any] | None:
    """The stored report, assessed for now, if it belongs to the key in use."""
    report = load(session)
    fingerprint = _current_fingerprint(session)
    if report is None or fingerprint is None or report.get("key_fingerprint") != fingerprint:
        return None
    return assess(report, current_context(session))


def summary(session: Session) -> dict[str, Any] | None:
    """The compact form the top bar and banner need, for every signed-in user."""
    try:
        assessed = current_report(session)
    except Exception:  # noqa: BLE001 - a broken report must never break /api/me
        logger.warning("Could not read the API key permission report", exc_info=True)
        return None
    if assessed is None:
        return None
    return {
        "verdict": assessed["verdict"],
        "attention": assessed["attention"],
        "summary": assessed["summary"],
        "missing": assessed["missing"],
        "checked_at": assessed["checked_at"],
        "problem_key": assessed["problem_key"],
    }


def check_due(session: Session, *, now: datetime | None = None) -> bool:
    report = load(session)
    fingerprint = _current_fingerprint(session)
    if fingerprint is None:
        return False
    if report is None or report.get("key_fingerprint") != fingerprint:
        return True
    checked = _parse_time(report.get("checked_at"))
    return checked is None or checked <= (now or utcnow()) - RECHECK_INTERVAL


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


# ------------------------------------------------------------- running it


def run_check(
    session: Session,
    *,
    trigger: str,
    actor: AuditActor,
    client: CheckmarxClient | None = None,
    clear_runtime: bool = False,
) -> dict[str, Any] | None:
    """Probe the key, store the report, and say so if something is missing.

    Commits whatever the caller has pending before the first Checkmarx call, so
    no write lock (the audit chain's included) is held while probing, and
    commits the result. Returns the assessed report, or None if the check could
    not run at all. Never raises.
    """
    try:
        return _run_check(
            session, trigger=trigger, actor=actor, client=client, clear_runtime=clear_runtime
        )
    except Exception:  # noqa: BLE001 - a probe failure must never break its caller
        logger.warning("The API key permission check could not run", exc_info=True)
        try:
            session.rollback()
        except Exception:  # noqa: BLE001
            logger.debug("Rollback after a failed permission check failed", exc_info=True)
        return None


def _run_check(
    session: Session,
    *,
    trigger: str,
    actor: AuditActor,
    client: CheckmarxClient | None,
    clear_runtime: bool,
) -> dict[str, Any] | None:
    from app.services import connection as connection_service

    connection = connection_service.get_connection(session)
    if connection is None:
        return None
    fingerprint = connection.api_key_fingerprint
    cx = client or connection_service.get_client(session)
    ctx = current_context(session)
    # Refusals met before this check go on the report first, so a read the
    # probes now find allowed is not marked refused again afterwards.
    if pending_denials():
        flush_runtime_denials(session, actor=actor)

    targets = _ProbeTargets(
        period=settings_store.usage_period(session),
        project_id=None,
        repo=None,
        user_id=None,
    )
    with_repo = session.scalar(
        select(CxProject)
        .where(CxProject.is_deleted.is_(False), CxProject.repo_id.is_not(None))
        .order_by(CxProject.id)
        .limit(1)
    )
    any_project = with_repo or session.scalar(
        select(CxProject).where(CxProject.is_deleted.is_(False)).order_by(CxProject.id).limit(1)
    )
    if any_project is not None:
        targets.project_id = any_project.id
    if with_repo is not None and with_repo.repo_id:
        targets.repo = (with_repo.repo_id, with_repo.id)
    targets.user_id = session.scalar(
        select(CxUser.id).where(CxUser.is_deleted.is_(False)).order_by(CxUser.id).limit(1)
    ) or connection_service.api_key_subject(session)

    skip: dict[str, str] = {}
    if trigger == TRIGGER_CYCLE and not ctx.auto_triage_charging:
        # With auto-triage charging off nothing in a cycle reads scans, and the
        # automatic re-check keeps it that way. Explicit checks still try it.
        skip["scans"] = (
            "Not read by the automatic check while auto-triage charging is off; "
            "press Check again to test it."
        )

    # Nothing may be held open in the database while Checkmarx is called.
    session.commit()

    report = _skeleton(fingerprint)
    report["trigger"] = trigger
    with _probing():
        try:
            token = cx.tokens.get_access_token()
        except CheckmarxError as exc:
            token = None
            report["token_failed"] = str(exc)[:300]
        if token is not None:
            claims = token_claims(token)
            del token
            results = _run_probes(cx, targets, skip=skip)
        else:
            claims = None
            results = {
                spec.id: (STATUS_NOT_TESTED, "The API key could not be exchanged for a token.")
                for spec in SPECS
                if spec.kind == "read"
            }

    # Read the stored report only now: a refusal recorded while the probes ran
    # (another thread's flush) must be kept, not overwritten.
    previous = load(session, fresh=True)
    if previous is not None and previous.get("key_fingerprint") != fingerprint:
        previous = None

    report["checked_at"] = utcnow().isoformat()
    report["token"] = claims
    checks = {check["id"]: check for check in report["checks"]}
    for check_id, (status, detail) in results.items():
        checks[check_id]["status"] = status
        checks[check_id]["detail"] = detail
    if "scans" in skip:
        carried = next(
            (
                check
                for check in (previous or {}).get("checks") or []
                if check.get("id") == "scans" and check.get("status") != STATUS_NOT_TESTED
            ),
            None,
        )
        if carried is not None:
            checks["scans"]["status"] = carried.get("status", STATUS_NOT_TESTED)
            checks["scans"]["detail"] = (
                f"{carried.get('detail') or ''} (from the last check that read scans)".strip()
            )
    _infer_writes(checks, claims)
    if previous is not None:
        _carry_runtime(report, checks, previous, results, clear_unlisted_reads=clear_runtime)

    _finish(session, report, previous, actor=actor)
    session.commit()
    return assess(report, current_context(session))


def _carry_runtime(
    report: dict[str, Any],
    checks: dict[str, dict[str, Any]],
    previous: dict[str, Any],
    results: dict[str, tuple[str, str | None]],
    *,
    clear_unlisted_reads: bool,
) -> None:
    """Keep the refusals seen at run time that this check cannot disprove.

    A read the probes just made successfully works now, so its refusal goes. A
    refused change stays until the same change goes through at run time: a
    probe cannot test it. ``clear_unlisted_reads`` ("Check again") also forgets
    refused reads that match no check; one that still happens comes back.
    """
    allowed_now = {
        check_id
        for check_id, (status, _detail) in results.items()
        if status == STATUS_OK and SPEC_BY_ID[check_id].kind == "read"
    }
    kept: list[dict[str, Any]] = []
    for entry in previous.get("runtime_denials") or []:
        if not isinstance(entry, dict):
            continue
        check_id = entry.get("check_id")
        if check_id in allowed_now:
            continue
        if check_id is None and clear_unlisted_reads and entry.get("method") == "GET":
            continue
        kept.append(entry)
    report["runtime_denials"] = kept
    for old in previous.get("checks") or []:
        check_id = old.get("id")
        if old.get("runtime_denied_at") and check_id in checks and check_id not in allowed_now:
            checks[check_id]["runtime_denied_at"] = old["runtime_denied_at"]


def flush_runtime_denials(session: Session, *, actor: AuditActor | None = None) -> int:
    """Record the run-time events seen since the last flush on the stored report:
    403s, and successful retries of changes that were refused before.

    Events made with a key other than the one stored now are dropped. Called
    where the caller is about to commit anyway (enforcement's error handlers,
    the end of each cycle step). Never raises, and never disturbs the caller's
    transaction: the work happens in a savepoint.
    """
    with _pending_lock:
        items = list(_pending)
        _pending.clear()
    if not items:
        return 0
    try:
        with session.begin_nested():
            fingerprint = _current_fingerprint(session)
            if fingerprint is None:
                return 0
            items = [item for item in items if item[3] is None or item[3] == fingerprint]
            if not items:
                return 0
            previous = load(session, fresh=True)
            if previous is not None and previous.get("key_fingerprint") != fingerprint:
                previous = None
            report = json.loads(json.dumps(previous)) if previous else _skeleton(fingerprint)
            if _apply_runtime_events(report, items):
                _finish(
                    session,
                    report,
                    previous,
                    actor=actor or AuditActor.system("permission-check"),
                    runtime=True,
                )
        return len(items)
    except Exception:  # noqa: BLE001 - recording a refusal must never break the caller
        logger.warning("Could not record a run-time 403 on the permission report", exc_info=True)
        return 0


def _apply_runtime_events(
    report: dict[str, Any], items: list[tuple[str, str, str, str | None, datetime]]
) -> bool:
    """Apply queued events to ``report`` in place. True when anything changed."""
    checks = {check.get("id"): check for check in report.get("checks") or []}
    for spec in SPECS:
        if spec.id not in checks:
            report["checks"].append(_empty_check(spec))
            checks[spec.id] = report["checks"][-1]
    entries = {
        (entry.get("method"), entry.get("path")): entry
        for entry in report.get("runtime_denials") or []
        if isinstance(entry, dict)
    }
    changed = False
    cleared: set[str] = set()
    for kind, method, url, _fingerprint, moment in items:
        check_id, path = _classify(method, url)
        at = moment.isoformat()
        if kind == _ALLOWED:
            entry = entries.get((method, path))
            if entry is None or str(entry.get("last_seen") or "") > at:
                continue
            logger.info(
                "Checkmarx allowed %s %s, refused earlier: cleared from the API key "
                "permission report.",
                method,
                path,
            )
            del entries[(method, path)]
            changed = True
            if check_id is not None:
                cleared.add(check_id)
            continue
        logger.warning(
            "Checkmarx refused %s %s (403) at run time: the API key is missing a "
            "permission. Recorded on the API key permission report.",
            method,
            path,
        )
        entry = entries.get((method, path))
        if entry is None:
            entry = {
                "method": method,
                "path": path,
                "check_id": check_id,
                "first_seen": at,
                "last_seen": at,
                "count": 0,
            }
            entries[(method, path)] = entry
        entry["last_seen"] = at
        entry["count"] = int(entry.get("count") or 0) + 1
        changed = True
        if check_id is not None:
            checks[check_id]["runtime_denied_at"] = at
    for check_id in cleared:
        remaining = [
            str(entry.get("last_seen"))
            for entry in entries.values()
            if entry.get("check_id") == check_id
        ]
        checks[check_id]["runtime_denied_at"] = max(remaining) if remaining else None
    report["runtime_denials"] = sorted(
        entries.values(), key=lambda entry: str(entry.get("last_seen")), reverse=True
    )[:_MAX_RUNTIME_ENTRIES]
    return changed


_SETUP_LINK = (
    "The Key permissions card on the Connection page shows each call, the key's roles and "
    "what to do."
)


def _finish(
    session: Session,
    report: dict[str, Any],
    previous: dict[str, Any] | None,
    *,
    actor: AuditActor,
    runtime: bool = False,
) -> None:
    """Store the report; log, notify and audit what changed."""
    assessed = assess(report, current_context(session))
    assert assessed is not None
    verdict = assessed["verdict"]
    attention = assessed["attention"]
    before = (previous or {}).get("last_verdict")
    ids = problem_ids(report)
    fingerprint = str(report.get("key_fingerprint") or "")
    now = utcnow()

    if verdict in PROBLEM_VERDICTS:
        if before not in PROBLEM_VERDICTS or not (previous or {}).get("problem_since"):
            report["problem_since"] = now.isoformat()
        else:
            report["problem_since"] = previous["problem_since"]  # type: ignore[index]
        if not runtime:
            log = logger.warning if attention else logger.info
            log(
                "The Checkmarx API key is missing permissions (%s): %s",
                verdict,
                "; ".join(
                    f"{check['purpose']} ({check['method']} {check['path']})"
                    for check in assessed["checks"]
                    if check["problem"]
                ),
            )
        since = str(report["problem_since"]).replace(":", "").replace("-", "")[:15]
        explanation = assessed["explanation"]
        # Readable by every signed-in user: the summary and what stops working
        # (what a viewer sees on the card), never the key's roles.
        body = "\n\n".join(
            [
                assessed["summary"],
                "\n".join(explanation["why"]),
                "What is missing:\n" + "\n".join(f"- {line}" for line in explanation["missing"]),
                "What to do:\n" + "\n".join(f"- {line}" for line in explanation["what_to_do"]),
                _SETUP_LINK,
            ]
        )
        if not attention:
            severity = Severity.INFO
            title = "The Checkmarx API key lacks permissions not needed now"
        else:
            severity = Severity.ERROR if verdict == VERDICT_INSUFFICIENT else Severity.WARNING
            title = "The Checkmarx API key is missing permissions"
        digest = f"{problem_key(ids) or 'none'}:{verdict}:{'a' if attention else 'n'}"
        notifications.notify(
            session,
            category=notifications.CATEGORY_PERMISSIONS,
            severity=severity,
            title=title,
            body=body,
            dedupe_key=notifications.key_permissions_key(fingerprint, since, digest),
        )
    elif verdict == VERDICT_OK:
        report["problem_since"] = None
        if before in PROBLEM_VERDICTS:
            notifications.notify(
                session,
                category=notifications.CATEGORY_PERMISSIONS,
                severity=Severity.INFO,
                title="API key permissions are now sufficient",
                body=(
                    "Every read CreditGuard checks is allowed, and no change CreditGuard "
                    "makes is known to be refused. Changes (removing AI roles, turning Auto "
                    "Triage or PR triage and remediation off and on) cannot be tested without "
                    "making them, so each is confirmed the first time CreditGuard makes it."
                ),
                dedupe_key=notifications.key_permissions_ok_key(fingerprint, now.isoformat()),
            )
    else:
        # Nothing could be checked (the token exchange failed): not the end of
        # a problem, so the episode, and its notification, carry on.
        report["problem_since"] = (previous or {}).get("problem_since")

    if (
        verdict != before
        and verdict != VERDICT_UNKNOWN
        and not (before is None and verdict == VERDICT_OK)
    ):
        record_audit(
            session,
            action="connection.permissions_changed",
            actor=actor,
            target_type="connection",
            target_id="1",
            before={"verdict": before},
            after={"verdict": verdict, "missing": ids},
            detail=assessed["summary"],
        )
    if verdict != VERDICT_UNKNOWN:
        report["last_verdict"] = verdict
        report["last_attention"] = attention
    else:
        report["last_verdict"] = before
        report["last_attention"] = (previous or {}).get("last_attention")
    _store(session, report)
