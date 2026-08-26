"""Platform API reads and the project level AI toggles.

Project enforcement has two independent halves, because Checkmarx exposes them
through two different services:

* **Auto Triage** is a project configuration, read and written through
  ``/api/ai-agents-coordinator/projects/<id>/configuration``. Always available.
* **PR triage and remediation** is a repository setting, written through
  ``/api/repos-manager/repo/<repo_id>?projectId=<id>``. It only exists for
  projects wired to a supported SCM integration, and it needs a ``repo_id`` that
  the projects listing does not always carry. When we do not have one, that half
  is skipped and the enforcement record says so rather than reporting success.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from app.checkmarx.client import CheckmarxClient
from app.checkmarx.errors import CheckmarxError

logger = logging.getLogger(__name__)

PROJECTS_PATH = "/projects"
APPLICATIONS_PATH = "/applications"
AUTO_TRIAGE_PATH = "/ai-agents-coordinator/projects/{project_id}/configuration"
REPO_SETTINGS_PATH = "/repos-manager/repo/{repo_id}"

AUTO_TRIAGE_FEATURE = "auto_triage"
# Used only when a project has never been observed and we have no prior config to
# restore. Mirrors the shape the API documents.
FALLBACK_AUTO_TRIAGE_CONFIG: dict[str, Any] = {
    "branches": ["main"],
    "scannerTypes": ["SAST", "SCA"],
    "severityLevels": ["CRITICAL", "HIGH"],
    "riskStatuses": ["NEW"],
}
DEFAULT_PR_SEVERITIES: tuple[str, ...] = ("CRITICAL", "HIGH")


@dataclass(frozen=True, slots=True)
class PlatformProject:
    id: str
    name: str
    group_ids: tuple[str, ...]
    application_ids: tuple[str, ...]
    repo_url: str | None
    repo_id: str | None
    raw: dict[str, Any]


@dataclass(frozen=True, slots=True)
class PlatformApplication:
    id: str
    name: str
    description: str | None
    project_ids: tuple[str, ...]
    raw: dict[str, Any]


@dataclass(slots=True)
class AutoTriageState:
    """The auto_triage entry of a project's AI agent configuration."""

    enabled: bool | None
    config: dict[str, Any] = field(default_factory=dict)
    scope: str | None = None
    raw: dict[str, Any] | None = None


def _string_tuple(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(entry for entry in value if isinstance(entry, str) and entry)


def _first_repo_id(payload: dict[str, Any]) -> str | None:
    """Best effort read of a supported-SCM repository id from a project payload.

    Checkmarx reports ``repoId`` as an integer (for example ``"repoId": 228481``),
    but older payloads and other fields can carry it as a string. Accept both and
    normalise to a string so the id can be stored and used in the repos-manager
    URL. Booleans and empty/zero-looking values are ignored.
    """
    for key in ("repoId", "repositoryId", "repo_id"):
        value = payload.get(key)
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            continue
        text = str(value).strip()
        if text and text != "0":
            return text
    return None


def parse_project(payload: dict[str, Any]) -> PlatformProject | None:
    project_id = payload.get("id")
    name = payload.get("name")
    if not isinstance(project_id, str) or not isinstance(name, str):
        return None
    return PlatformProject(
        id=project_id,
        name=name,
        group_ids=_string_tuple(payload.get("groups")),
        application_ids=_string_tuple(
            payload.get("applicationIds") or payload.get("applicationIDs")
        ),
        repo_url=payload.get("repoUrl") if isinstance(payload.get("repoUrl"), str) else None,
        # Opportunistic: some project payloads carry the repository id already.
        # The Checkmarx API reports it as an integer, which _first_repo_id
        # normalises to a string for storage and the repos-manager call.
        repo_id=_first_repo_id(payload),
        raw=payload,
    )


def fetch_projects(client: CheckmarxClient, *, page_size: int = 100) -> list[PlatformProject]:
    return [
        parsed
        for item in client.paginate(PROJECTS_PATH, items_key="projects", page_size=page_size)
        if (parsed := parse_project(item)) is not None
    ]


def parse_application(payload: dict[str, Any]) -> PlatformApplication | None:
    application_id = payload.get("id")
    name = payload.get("name")
    if not isinstance(application_id, str) or not isinstance(name, str):
        return None
    return PlatformApplication(
        id=application_id,
        name=name,
        description=(
            payload.get("description") if isinstance(payload.get("description"), str) else None
        ),
        project_ids=_string_tuple(payload.get("projectIds") or payload.get("projects")),
        raw=payload,
    )


def fetch_applications(
    client: CheckmarxClient, *, page_size: int = 100
) -> list[PlatformApplication]:
    return [
        parsed
        for item in client.paginate(
            APPLICATIONS_PATH, items_key="applications", page_size=page_size
        )
        if (parsed := parse_application(item)) is not None
    ]


# ------------------------------------------------------------------ AI toggles


def parse_auto_triage(payload: Any) -> AutoTriageState:
    if not isinstance(payload, dict):
        return AutoTriageState(enabled=None)
    configurations = payload.get("configurations")
    entries = configurations if isinstance(configurations, list) else []
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("feature") != AUTO_TRIAGE_FEATURE:
            continue
        config = entry.get("config")
        return AutoTriageState(
            enabled=bool(entry.get("enabled")) if entry.get("enabled") is not None else None,
            config=config if isinstance(config, dict) else {},
            scope=payload.get("scope") if isinstance(payload.get("scope"), str) else None,
            raw=payload,
        )
    # The feature is simply absent for this project.
    return AutoTriageState(enabled=None, raw=payload)


def get_auto_triage(client: CheckmarxClient, *, project_id: str) -> AutoTriageState:
    payload = client.get_json(AUTO_TRIAGE_PATH.format(project_id=project_id))
    return parse_auto_triage(payload)


def set_auto_triage(
    client: CheckmarxClient,
    *,
    project_id: str,
    enabled: bool,
    config: dict[str, Any] | None = None,
) -> None:
    """Enable or disable Auto Triage, preserving the rest of the configuration.

    The API takes the whole feature entry, so a caller that does not pass the
    existing ``config`` would silently reset branches and severity levels. The
    enforcement service always passes the config it captured before acting.
    """
    body = {
        "configurations": [
            {
                "feature": AUTO_TRIAGE_FEATURE,
                "enabled": enabled,
                "config": config if config else dict(FALLBACK_AUTO_TRIAGE_CONFIG),
            }
        ]
    }
    client.request(
        "PUT",
        AUTO_TRIAGE_PATH.format(project_id=project_id),
        json=body,
        headers={"Content-Type": "application/json"},
    )


def set_pr_remediation_severities(
    client: CheckmarxClient, *, repo_id: str, project_id: str, severities: list[str]
) -> None:
    """Set the severities eligible for PR triage and remediation.

    An empty list disables the feature. Restoring means writing the severities
    that were captured before the change.
    """
    if not repo_id:
        raise CheckmarxError(
            "No repository id is known for this project, so PR triage and remediation "
            "cannot be changed."
        )
    client.request(
        "PATCH",
        REPO_SETTINGS_PATH.format(repo_id=repo_id),
        params={"projectId": project_id},
        json={"remediationSeverities": severities},
        headers={"Content-Type": "application/json"},
    )


def get_pr_remediation_severities(
    client: CheckmarxClient, *, repo_id: str, project_id: str
) -> list[str] | None:
    """Read the severities currently eligible for PR triage and remediation.

    This is what a Restore must reproduce, so capturing it *before* disabling the
    feature (rather than assuming ``CRITICAL``/``HIGH``) is what lets re-enabling
    put back the exact configuration that was in place.

    Returns ``None`` when the value cannot be read - no repository id, the tenant
    does not expose a read for the repo settings, or the payload is unexpected -
    so callers can fall back to a cached or default value rather than guessing.
    An empty list is a real, meaningful answer: the feature is already disabled.
    """
    if not repo_id:
        return None
    try:
        payload = client.get_json(
            REPO_SETTINGS_PATH.format(repo_id=repo_id),
            params={"projectId": project_id},
        )
    except CheckmarxError:
        return None
    if not isinstance(payload, dict):
        return None
    severities = payload.get("remediationSeverities")
    if not isinstance(severities, list):
        return None
    return [entry for entry in severities if isinstance(entry, str) and entry]
