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
* **Fusion** has two halves as well. The project's scan setting
  ``scan.config.ai.fusionEnabled`` is read with
  ``GET /api/configuration/project?project-id=<id>`` (a list of entries) and
  written with ``PATCH`` on the same path, whose body is a list holding the
  whole entry with its new value - exactly what the Checkmarx One UI sends. A
  repository wired to an SCM integration also carries ``fusionScanConfig``
  (``{"enabled": true, "llmModel": "..."}``) in its repos-manager settings.
  That the repos-manager read returns it, and that a ``PATCH`` of it changes
  it, is **not verified**: when the read does not include it, that half is
  skipped and the record says so.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from app.checkmarx.client import CheckmarxClient
from app.checkmarx.errors import CheckmarxError, CheckmarxPermissionError, CheckmarxResponseError

logger = logging.getLogger(__name__)

PROJECTS_PATH = "/projects"
APPLICATIONS_PATH = "/applications"
AUTO_TRIAGE_PATH = "/ai-agents-coordinator/projects/{project_id}/configuration"
REPO_SETTINGS_PATH = "/repos-manager/repo/{repo_id}"
PROJECT_CONFIGURATION_PATH = "/configuration/project"
FUSION_SETTING_KEY = "scan.config.ai.fusionEnabled"
REPO_FUSION_FIELD = "fusionScanConfig"

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
    # The entry's ``allowOverride`` exactly as Checkmarx One sent it (seen as
    # ``{"projects": false, "branches": true, ...}`` on a project-scope read), or
    # None when absent. Recorded verbatim; its meaning is not documented.
    allow_override: Any = None


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
            allow_override=entry.get("allowOverride"),
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
    except CheckmarxPermissionError as exc:
        # The 403 itself is also recorded on the API key permission report by
        # the client's refusal listener, even though it is swallowed here.
        logger.warning(
            "The PR triage and remediation setting of project %s could not be read: %s",
            project_id,
            exc,
        )
        return None
    except CheckmarxError as exc:
        logger.info(
            "The PR triage and remediation setting of project %s could not be read: %s",
            project_id,
            exc,
        )
        return None
    if not isinstance(payload, dict):
        logger.info("Repository %s settings came back in an unexpected shape", repo_id)
        return None
    severities = payload.get("remediationSeverities")
    if not isinstance(severities, list):
        logger.info("Repository %s settings carry no remediationSeverities list", repo_id)
        return None
    return [entry for entry in severities if isinstance(entry, str) and entry]


# ------------------------------------------------------------------ Fusion


@dataclass(slots=True)
class ProjectSetting:
    """One entry of a project's scan configuration, as Checkmarx One reports it."""

    key: str
    value: Any
    origin_level: str | None
    allow_override: bool | None
    entry: dict[str, Any]

    @property
    def enabled(self) -> bool:
        """A Bool setting reads as on only when its value says true."""
        return setting_is_true(self.value)


def setting_is_true(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return isinstance(value, str) and value.strip().lower() == "true"


def parse_project_setting(payload: Any, *, key: str) -> ProjectSetting | None:
    """The entry for ``key`` in a project configuration body, or None if absent.

    Raises ``CheckmarxResponseError`` when the body is not a list of entries:
    an answer that cannot be read is not evidence that the setting is absent.
    """
    entries = payload
    if isinstance(payload, dict):
        # Defensive: an envelope variant would still be readable.
        for envelope in ("configurations", "items", "data"):
            if isinstance(payload.get(envelope), list):
                entries = payload[envelope]
                break
    if not isinstance(entries, list):
        raise CheckmarxResponseError(
            "The project configuration came back in an unexpected shape, so its settings "
            "cannot be read."
        )
    for entry in entries:
        if isinstance(entry, dict) and entry.get("key") == key:
            allow = entry.get("allowOverride")
            origin = entry.get("originLevel")
            return ProjectSetting(
                key=key,
                value=entry.get("value"),
                origin_level=origin if isinstance(origin, str) else None,
                allow_override=allow if isinstance(allow, bool) else None,
                entry=dict(entry),
            )
    return None


def get_project_setting(
    client: CheckmarxClient, *, project_id: str, key: str
) -> ProjectSetting | None:
    payload = client.get_json(PROJECT_CONFIGURATION_PATH, params={"project-id": project_id})
    return parse_project_setting(payload, key=key)


def get_fusion_setting(client: CheckmarxClient, *, project_id: str) -> ProjectSetting | None:
    return get_project_setting(client, project_id=project_id, key=FUSION_SETTING_KEY)


def set_project_setting(client: CheckmarxClient, *, project_id: str, entry: dict[str, Any]) -> None:
    """Write one project configuration entry, as the Checkmarx One UI does.

    The body is a list holding the whole entry (key, name, category, value,
    valuetype, allowOverride, ...) with its new value; the entry is written at
    the project level.
    """
    body = dict(entry)
    body["originLevel"] = "Project"
    client.request(
        "PATCH",
        PROJECT_CONFIGURATION_PATH,
        params={"project-id": project_id},
        json=[body],
        headers={"Content-Type": "application/json"},
    )


def get_repo_settings(
    client: CheckmarxClient, *, repo_id: str, project_id: str
) -> dict[str, Any] | None:
    """A repository's repos-manager settings, or None when they cannot be read.

    Failures are logged and swallowed (a 403 is still recorded on the API key
    permission report by the client's refusal listener).
    """
    if not repo_id:
        return None
    try:
        payload = client.get_json(
            REPO_SETTINGS_PATH.format(repo_id=repo_id),
            params={"projectId": project_id},
        )
    except CheckmarxPermissionError as exc:
        logger.warning("The settings of repository %s could not be read: %s", repo_id, exc)
        return None
    except CheckmarxError as exc:
        logger.info("The settings of repository %s could not be read: %s", repo_id, exc)
        return None
    if not isinstance(payload, dict):
        logger.info("Repository %s settings came back in an unexpected shape", repo_id)
        return None
    return payload


@dataclass(frozen=True, slots=True)
class RepoFusionRead:
    """What a read of a repository's Fusion setting found.

    ``readable`` False: the settings could not be read at all. ``config`` None
    with ``readable`` True: they were read and carry no Fusion setting.
    """

    readable: bool
    config: dict[str, Any] | None = None

    @property
    def enabled(self) -> bool:
        return bool(self.config) and setting_is_true(self.config.get("enabled"))  # type: ignore[union-attr]


def get_repo_fusion(client: CheckmarxClient, *, repo_id: str, project_id: str) -> RepoFusionRead:
    payload = get_repo_settings(client, repo_id=repo_id, project_id=project_id)
    if payload is None:
        return RepoFusionRead(readable=False)
    config = payload.get(REPO_FUSION_FIELD)
    return RepoFusionRead(readable=True, config=dict(config) if isinstance(config, dict) else None)


def set_repo_fusion(
    client: CheckmarxClient, *, repo_id: str, project_id: str, config: dict[str, Any]
) -> None:
    """Write a repository's ``fusionScanConfig`` (unverified that this takes effect)."""
    if not repo_id:
        raise CheckmarxError(
            "No repository id is known for this project, so its repository Fusion setting "
            "cannot be changed."
        )
    client.request(
        "PATCH",
        REPO_SETTINGS_PATH.format(repo_id=repo_id),
        params={"projectId": project_id},
        json={REPO_FUSION_FIELD: config},
        headers={"Content-Type": "application/json"},
    )
