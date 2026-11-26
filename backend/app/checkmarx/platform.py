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

Shapes seen on a live tenant (2026-11), which the code below is written to:

* The repos-manager read wraps ``remediationSeverities`` as
  ``{"value": ["CRITICAL", ...], "isEditable": true}``; older payloads carry a
  bare list. A write sends back the shape that was read, and nothing is
  written when the shape is not one of those two.
* The project Auto Triage read lists more than ``auto_triage``: an
  ``auto_remediation`` feature, each feature's ``allowOverride``, and a top
  level ``allowAiUsage``. A ``PUT`` takes the whole configuration, so the
  payload is sent back as it was read with only the ``auto_triage`` entry's
  ``enabled`` and ``config`` changed.
* An unset project configuration entry still reports ``originLevel``
  ``Project`` (with an empty value); its ``isPersisted`` false is what says the
  project has no value of its own. An inherited entry reports the level it
  comes from (``Tenant``) with that level's ``isPersisted``.
"""

from __future__ import annotations

import copy
import json
import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from app.checkmarx.client import CheckmarxClient, Listing
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
    # The entry's ``allowOverride`` exactly as Checkmarx One sent it, or None
    # when absent. Seen as ``{"projects": false, "branches": true, ...}`` in a
    # captured HAR and as ``{"projects": true, "branches": true, "scannerTypes":
    # true, "riskStatuses": true, "severityLevels": true}`` on a live tenant.
    # Recorded verbatim; its meaning is not documented.
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


def fetch_projects(
    client: CheckmarxClient, *, page_size: int = 100, listing: Listing | None = None
) -> list[PlatformProject]:
    """Every project. ``listing`` is told whether every row could be read."""
    return [
        parsed
        for item in client.paginate(
            PROJECTS_PATH, items_key="projects", page_size=page_size, listing=listing
        )
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
    client: CheckmarxClient, *, page_size: int = 100, listing: Listing | None = None
) -> list[PlatformApplication]:
    """Every application. ``listing`` is told whether every row could be read."""
    return [
        parsed
        for item in client.paginate(
            APPLICATIONS_PATH, items_key="applications", page_size=page_size, listing=listing
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


def auto_triage_put_body(
    payload: Any, *, enabled: bool, config: dict[str, Any] | None
) -> dict[str, Any]:
    """The ``PUT`` body that changes Auto Triage and nothing else.

    ``payload`` is the configuration exactly as it was read. Its
    ``configurations`` are sent back whole - other features
    (``auto_remediation``) and every ``allowOverride`` included - with only the
    ``auto_triage`` entry's ``enabled`` and ``config`` changed, so a tenant
    that treats the ``PUT`` as the whole configuration does not reset what
    CreditGuard does not own. Nothing else at the top level is sent: ``scope``
    and ``projectId`` are named by the path, and ``allowAiUsage`` mirrors the
    tenant's inherited AI switch, which echoing could pin on the project.
    (The exact body the Checkmarx One UI sends is not yet confirmed; see the
    README's Remaining unknowns.)
    """
    if not isinstance(payload, dict) or not isinstance(payload.get("configurations"), list):
        raise CheckmarxResponseError(
            "The project's AI agent configuration could not be read in a known shape, so Auto "
            "Triage was not changed: writing it without the rest of the configuration could "
            "reset the project's other AI features."
        )
    body = {"configurations": copy.deepcopy(payload["configurations"])}
    entries: list[Any] = body["configurations"]
    for entry in entries:
        if isinstance(entry, dict) and entry.get("feature") == AUTO_TRIAGE_FEATURE:
            entry["enabled"] = enabled
            if config:
                entry["config"] = copy.deepcopy(config)
            elif not isinstance(entry.get("config"), dict) or not entry.get("config"):
                entry["config"] = dict(FALLBACK_AUTO_TRIAGE_CONFIG)
            return body
    entries.append(
        {
            "feature": AUTO_TRIAGE_FEATURE,
            "enabled": enabled,
            "config": copy.deepcopy(config) if config else dict(FALLBACK_AUTO_TRIAGE_CONFIG),
        }
    )
    return body


def auto_triage_side_effects(before: Any, after: Any) -> list[str]:
    """What changed, besides ``auto_triage``, between two configuration reads:
    another feature's entry (``auto_remediation``) or ``allowAiUsage``. Empty
    when either read is not in the known shape (nothing to compare)."""
    if not isinstance(before, dict) or not isinstance(after, dict):
        return []

    def others(payload: dict[str, Any]) -> dict[str, str]:
        entries = payload.get("configurations")
        return {
            str(entry.get("feature")): json.dumps(entry, sort_keys=True, default=str)
            for entry in (entries if isinstance(entries, list) else [])
            if isinstance(entry, dict) and entry.get("feature") != AUTO_TRIAGE_FEATURE
        }

    changes: list[str] = []
    was, now = others(before), others(after)
    for feature in sorted(set(was) | set(now)):
        if was.get(feature) != now.get(feature):
            changes.append(
                f"the {feature} feature (was {was.get(feature)}, now {now.get(feature)})"
            )
    if before.get("allowAiUsage") != after.get("allowAiUsage"):
        changes.append(
            f"allowAiUsage (was {before.get('allowAiUsage')!r}, now {after.get('allowAiUsage')!r})"
        )
    return changes


def set_auto_triage(
    client: CheckmarxClient,
    *,
    project_id: str,
    enabled: bool,
    config: dict[str, Any] | None = None,
    current: AutoTriageState | None = None,
) -> None:
    """Enable or disable Auto Triage, preserving the rest of the configuration.

    The API takes the whole configuration, so the body is the configuration as
    read (``current``, or a fresh read when it is not given) with only the
    ``auto_triage`` entry changed: see :func:`auto_triage_put_body`. ``config``
    is the entry's ``config`` to write (the one captured before acting); without
    it the entry keeps the one it was read with.
    """
    if current is None or current.raw is None:
        current = get_auto_triage(client, project_id=project_id)
    body = auto_triage_put_body(current.raw, enabled=enabled, config=config)
    client.request(
        "PUT",
        AUTO_TRIAGE_PATH.format(project_id=project_id),
        json=body,
        headers={"Content-Type": "application/json"},
    )


PR_SEVERITIES_FIELD = "remediationSeverities"
# How ``remediationSeverities`` was read, and so how it is written back.
PR_SHAPE_LIST = "list"  # ["CRITICAL", "HIGH"] (older payloads)
PR_SHAPE_WRAPPED = "wrapped"  # {"value": ["CRITICAL", "HIGH"], "isEditable": true} (live tenant)


class PrSeveritiesShapeError(CheckmarxResponseError):
    """``remediationSeverities`` is in a shape CreditGuard does not know.

    Nothing is written then: a write in the wrong shape could be rejected, or
    worse, accepted and misread.
    """


@dataclass(frozen=True, slots=True)
class PrSeverities:
    """The PR triage and remediation severities of a repository, as read.

    ``shape`` and ``fields`` say how the value was sent, so a write can send it
    back the same way: ``fields`` holds the wrapped form's other keys exactly as
    read (``{"isEditable": true}``), and is empty for a bare list.
    """

    severities: list[str]
    shape: str
    fields: dict[str, Any] = field(default_factory=dict)

    @property
    def editable(self) -> bool:
        """False when the read says the setting may not be changed
        (``"isEditable": false``, set higher up): nothing is written then."""
        return self.fields.get("isEditable") is not False

    def form(self) -> dict[str, Any]:
        """The shape, for an undo snapshot (JSON)."""
        return {"shape": self.shape, "fields": copy.deepcopy(self.fields)}


def parse_pr_severities(value: Any) -> PrSeverities:
    """Read ``remediationSeverities`` in either known shape.

    Raises :class:`PrSeveritiesShapeError` for anything else, a list holding
    something other than strings included.
    """
    if isinstance(value, list) and all(isinstance(entry, str) for entry in value):
        return PrSeverities(severities=[entry for entry in value if entry], shape=PR_SHAPE_LIST)
    if isinstance(value, dict) and "value" in value and value["value"] is None:
        raise PrSeveritiesShapeError(
            f"The repository's {PR_SEVERITIES_FIELD} came back with no value (null). Whether "
            "that means off or not configured is not known, so CreditGuard does not change it."
        )
    if isinstance(value, dict):
        inner = value.get("value")
        if isinstance(inner, list) and all(isinstance(entry, str) for entry in inner):
            return PrSeverities(
                severities=[entry for entry in inner if entry],
                shape=PR_SHAPE_WRAPPED,
                fields={key: copy.deepcopy(item) for key, item in value.items() if key != "value"},
            )
    raise PrSeveritiesShapeError(
        f"The repository's {PR_SEVERITIES_FIELD} came back as {_shape_words(value)}, which is "
        'neither a list of severities nor {"value": [...]}, so CreditGuard does not change it.'
    )


def _shape_words(value: Any) -> str:
    if value is None:
        return "nothing"
    if isinstance(value, dict):
        return "an object with " + (", ".join(sorted(str(key) for key in value)[:6]) or "no keys")
    if isinstance(value, list):
        return "a list holding something other than severity names"
    return f"a {type(value).__name__}"


def pr_severities_body(severities: list[str], *, form: PrSeverities | Mapping[str, Any]) -> Any:
    """``remediationSeverities`` in the shape it was read in.

    ``form`` is the read itself or its :meth:`PrSeverities.form` record.
    Raises :class:`PrSeveritiesShapeError` when the shape is not a known one.
    """
    if isinstance(form, PrSeverities):
        shape, fields = form.shape, form.fields
    else:
        shape = form.get("shape")
        fields = form.get("fields") if isinstance(form.get("fields"), dict) else {}
    values = [entry for entry in severities if isinstance(entry, str) and entry]
    if shape == PR_SHAPE_LIST:
        return values
    if shape == PR_SHAPE_WRAPPED:
        wrapped = copy.deepcopy(dict(fields or {}))
        wrapped["value"] = values
        return wrapped
    raise PrSeveritiesShapeError(
        f"The shape {PR_SEVERITIES_FIELD} was read in is not known, so it is not written."
    )


def set_pr_remediation_severities(
    client: CheckmarxClient,
    *,
    repo_id: str,
    project_id: str,
    severities: list[str],
    form: PrSeverities | Mapping[str, Any] | None,
) -> None:
    """Set the severities eligible for PR triage and remediation.

    An empty list disables the feature. Restoring means writing the severities
    that were captured before the change. ``form`` is how the setting was read
    (see :func:`pr_severities_body`); without a known one nothing is written.
    """
    if not repo_id:
        raise CheckmarxError(
            "No repository id is known for this project, so PR triage and remediation "
            "cannot be changed."
        )
    if form is None:
        raise PrSeveritiesShapeError(
            "The shape of the repository's PR triage and remediation setting is not known "
            "(it has not been read), so it is not written."
        )
    client.request(
        "PATCH",
        REPO_SETTINGS_PATH.format(repo_id=repo_id),
        params={"projectId": project_id},
        json={PR_SEVERITIES_FIELD: pr_severities_body(severities, form=form)},
        headers={"Content-Type": "application/json"},
    )


def read_pr_remediation(
    client: CheckmarxClient, *, repo_id: str, project_id: str
) -> PrSeverities | None:
    """The severities currently eligible for PR triage and remediation, as read.

    This is what a Restore must reproduce, so capturing it *before* disabling the
    feature (rather than assuming ``CRITICAL``/``HIGH``) is what lets re-enabling
    put back the exact configuration that was in place.

    Returns ``None`` when the settings cannot be read (no repository id, a
    refusal, an outage). Raises :class:`PrSeveritiesShapeError` when they were
    read and ``remediationSeverities`` is absent or in an unknown shape. An
    empty list is a real, meaningful answer: the feature is already disabled.
    """
    payload = get_repo_settings(client, repo_id=repo_id, project_id=project_id)
    if payload is None:
        return None
    return parse_pr_severities(payload.get(PR_SEVERITIES_FIELD))


def get_pr_remediation_severities(
    client: CheckmarxClient, *, repo_id: str, project_id: str
) -> list[str] | None:
    """The severities alone, or ``None`` when they cannot be read or understood."""
    try:
        read = read_pr_remediation(client, repo_id=repo_id, project_id=project_id)
    except PrSeveritiesShapeError as exc:
        logger.info("Repository %s: %s", repo_id, exc)
        return None
    return None if read is None else read.severities


# ------------------------------------------------------------------ Fusion


@dataclass(slots=True)
class ProjectSetting:
    """One entry of a project's scan configuration, as Checkmarx One reports it."""

    key: str
    value: Any
    origin_level: str | None
    allow_override: bool | None
    entry: dict[str, Any]
    # ``isPersisted`` as reported: whether the level ``origin_level`` names holds
    # a value (see ``inherited``). None when the entry does not carry it.
    is_persisted: bool | None = None

    @property
    def inherited(self) -> bool:
        """True when the project has no value of its own for this setting.

        ``isPersisted`` belongs to the level ``originLevel`` names: on a live
        tenant an inherited entry reads ``originLevel`` ``Tenant`` with
        ``isPersisted`` true (the tenant's value), and an unset one still reads
        ``originLevel`` ``Project``, with ``isPersisted`` false and an empty
        value. So the project has its own value only when the level is
        ``Project`` and ``isPersisted`` is not false.
        """
        origin = (self.origin_level or "").strip().lower()
        if not origin:
            return False
        if origin != "project":
            return True
        return self.is_persisted is False

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
            persisted = entry.get("isPersisted")
            return ProjectSetting(
                key=key,
                value=entry.get("value"),
                origin_level=origin if isinstance(origin, str) else None,
                allow_override=allow if isinstance(allow, bool) else None,
                entry=dict(entry),
                is_persisted=persisted if isinstance(persisted, bool) else None,
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
