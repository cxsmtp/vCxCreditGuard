"""IAM reads and role mapping writes.

Two different URL spaces are in play, which is easy to trip over:

* ``/auth/realms/<tenant>/users/v2`` and ``/auth/realms/<tenant>/groups`` are
  Checkmarx's own convenience endpoints. They return users with their role and
  group **names**, which is what the org model mirror needs.
* ``/auth/admin/realms/<tenant>/...`` is the Keycloak admin API. Role mappings can
  only be changed there, and it deals in **ids**, so a role name has to be
  resolved to a role id against the ``ast-app`` client first.

Enforcement always re-reads the authoritative mappings from the admin API
immediately before changing them. The names cached on ``cx_user`` are for display
and reporting only: acting on a possibly stale mirror is how you remove a role
somebody never had, and then fail to restore one they did.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

from app.checkmarx.client import CheckmarxClient
from app.checkmarx.errors import CheckmarxNotFoundError, CheckmarxResponseError

logger = logging.getLogger(__name__)

USERS_PATH = "users/v2"
GROUPS_PATH = "groups"
DEFAULT_PAGE_SIZE = 100
MAX_PAGES = 500

# The OAuth client that owns the platform roles. Same client the API key is
# issued for, which is why the default matches CXCG_CX_CLIENT_ID.
PLATFORM_CLIENT_ID = "ast-app"

# The roles a user restriction removes unless an admin chose others (Settings →
# Enforcement, ``enforcement.ai_roles``). They are the general Risk Management
# roles, through which AI Triage and AI Remediation are reached today: a person
# restricted loses the Risk Management pages too. When Checkmarx One ships
# dedicated AI permissions, the setting is changed to name them instead; this
# default stays, so an upgrade never changes what a restriction removes.
#
# The scan-viewing role ("view-scans") is deliberately not here. A credit
# budget governs AI features; whether someone may look at scans is decided by
# the permission they hold in Checkmarx One, and a restriction leaves it alone.
DEFAULT_AI_ROLE_NAMES: tuple[str, ...] = (
    "view-risk-management",
    "view-risk-management-dashboard",
    "view-risk-management-tab",
)
# The name earlier versions used. It is the default list, not the configured one:
# what a restriction removes is ``settings_store.ai_role_names``.
AI_ROLE_NAMES = DEFAULT_AI_ROLE_NAMES

# What the default roles give a person, in words, for the Simulation page. A
# static description (Checkmarx One's own role descriptions are shown as well
# when the tenant provides them).
ROLE_DESCRIPTIONS: dict[str, str] = dict.fromkeys(
    DEFAULT_AI_ROLE_NAMES,
    "Risk Management pages and dashboard; AI Triage/Remediation are reached from here",
)


@dataclass(frozen=True, slots=True)
class IamUser:
    id: str
    username: str | None
    email: str | None
    first_name: str | None
    last_name: str | None
    enabled: bool
    auth_provider: str | None
    role_names: tuple[str, ...]
    group_names: tuple[str, ...]
    raw: dict[str, Any]


@dataclass(frozen=True, slots=True)
class IamGroup:
    id: str
    name: str
    path: str | None
    parent_id: str | None
    raw: dict[str, Any]


@dataclass(frozen=True, slots=True)
class RoleRef:
    """The (id, name) pair the admin role mapping API expects.

    ``composite`` and ``description`` are what a full role representation says
    about it, when it was read with one; they are never sent back.
    """

    id: str
    name: str
    composite: bool = field(default=False, compare=False)
    description: str | None = field(default=None, compare=False)
    # False for a realm role (or another client's) met among a composite's children.
    client_role: bool = field(default=True, compare=False)

    def as_payload(self) -> dict[str, str]:
        return {"id": self.id, "name": self.name}


def _role_ref(entry: Any) -> RoleRef | None:
    if not isinstance(entry, dict):
        return None
    role_id = entry.get("id")
    name = entry.get("name")
    if not isinstance(role_id, str) or not isinstance(name, str):
        return None
    description = entry.get("description")
    return RoleRef(
        id=role_id,
        name=name,
        composite=entry.get("composite") is True,
        description=description if isinstance(description, str) and description else None,
        client_role=entry.get("clientRole") is not False,
    )


def _role_list(payload: Any) -> list[RoleRef]:
    entries = payload if isinstance(payload, list) else []
    return [role for entry in entries if (role := _role_ref(entry)) is not None]


def _string_list(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(entry.strip() for entry in value if isinstance(entry, str) and entry.strip())


def parse_user(payload: dict[str, Any]) -> IamUser | None:
    user_id = payload.get("id")
    if not isinstance(user_id, str) or not user_id:
        logger.warning("Skipping an IAM user record with no id")
        return None
    enabled = payload.get("isEnabled", payload.get("enabled", True))
    return IamUser(
        id=user_id,
        username=payload.get("username") if isinstance(payload.get("username"), str) else None,
        email=payload.get("email") if isinstance(payload.get("email"), str) else None,
        first_name=payload.get("firstName") if isinstance(payload.get("firstName"), str) else None,
        last_name=payload.get("lastName") if isinstance(payload.get("lastName"), str) else None,
        enabled=bool(enabled),
        auth_provider=(
            payload.get("authProvider") if isinstance(payload.get("authProvider"), str) else None
        ),
        role_names=_string_list(payload.get("roles")),
        group_names=_string_list(payload.get("groups")),
        raw=payload,
    )


def fetch_users(
    client: CheckmarxClient, *, page_size: int = DEFAULT_PAGE_SIZE
) -> tuple[list[IamUser], int | None, str | None]:
    """Read every user in the realm.

    Returns the users, the ``filteredCount`` the API reported, and a warning
    string when the two do not agree.

    ``/users/v2`` is Keycloak-backed and paginates with ``first`` (a 0 based row
    offset) and ``max`` (page size), not ``page``/``size``. We ask once with no
    parameters to learn ``filteredCount``, then, when that first page is short,
    page by advancing ``first`` until the whole set is read. If a page yields no
    new users we stop and report the shortfall rather than pretending the partial
    list is complete, because a missing user means missing usage.
    """
    payload = client.get_json(USERS_PATH, base="realm")
    users, reported_total = _parse_users_payload(payload)
    if reported_total is None or len(users) >= reported_total:
        return users, reported_total, None

    logger.info(
        "IAM returned %d of %d users without pagination, paging with first and max",
        len(users),
        reported_total,
    )
    seen: dict[str, IamUser] = {user.id: user for user in users}
    offset = len(users)
    pages = 0
    while pages < MAX_PAGES and len(seen) < reported_total:
        pages += 1
        page_payload = client.get_json(
            USERS_PATH, base="realm", params={"first": offset, "max": page_size}
        )
        page_users, _ = _parse_users_payload(page_payload)
        if not page_users:
            break
        before = len(seen)
        for user in page_users:
            seen[user.id] = user
        # Advance by however many the page returned, so a server that caps the
        # page below ``max`` still makes progress.
        offset += len(page_users)
        if len(seen) == before:
            # Only already-seen users came back: the offset window is not
            # advancing, so stop instead of looping forever.
            break

    collected = list(seen.values())
    if len(collected) < reported_total:
        warning = (
            f"IAM reported {reported_total} users but only {len(collected)} could be read. "
            "Usage for the missing users cannot be attributed, so their limits are not "
            "evaluated. Confirm the pagination parameters for /users/v2."
        )
        logger.warning(warning)
        return collected, reported_total, warning
    return collected, reported_total, None


def _parse_users_payload(payload: Any) -> tuple[list[IamUser], int | None]:
    if isinstance(payload, list):
        entries: list[Any] = payload
        reported_total = None
    elif isinstance(payload, dict):
        raw_users = payload.get("users")
        entries = raw_users if isinstance(raw_users, list) else []
        reported_total = None
        for key in ("filteredCount", "totalCount", "count"):
            value = payload.get(key)
            if isinstance(value, int):
                reported_total = value
                break
    else:
        raise CheckmarxResponseError(f"Unexpected users response of type {type(payload).__name__}.")
    users = [
        parsed
        for entry in entries
        if isinstance(entry, dict) and (parsed := parse_user(entry)) is not None
    ]
    return users, reported_total


def fetch_groups(client: CheckmarxClient) -> list[IamGroup]:
    """Read every group, flattening the nested ``subGroups`` tree."""
    payload = client.get_json(GROUPS_PATH, base="realm")
    if isinstance(payload, dict):
        raw_groups = payload.get("groups")
        entries = raw_groups if isinstance(raw_groups, list) else []
    elif isinstance(payload, list):
        entries = payload
    else:
        raise CheckmarxResponseError(
            f"Unexpected groups response of type {type(payload).__name__}."
        )

    flattened: list[IamGroup] = []
    _flatten_groups(entries, parent_id=None, into=flattened)
    return flattened


def _flatten_groups(entries: list[Any], *, parent_id: str | None, into: list[IamGroup]) -> None:
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        group_id = entry.get("id")
        name = entry.get("name")
        if not isinstance(group_id, str) or not isinstance(name, str):
            continue
        into.append(
            IamGroup(
                id=group_id,
                name=name,
                path=entry.get("path") if isinstance(entry.get("path"), str) else None,
                parent_id=parent_id,
                raw=entry,
            )
        )
        children = entry.get("subGroups")
        if isinstance(children, list) and children:
            _flatten_groups(children, parent_id=group_id, into=into)


# ------------------------------------------------------------- role management


def resolve_platform_client_uuid(
    client: CheckmarxClient, *, client_id: str = PLATFORM_CLIENT_ID
) -> str:
    """Look up the internal UUID of the ``ast-app`` OAuth client.

    Role mapping URLs need this UUID rather than the human readable clientId.
    """
    payload = client.get_json(
        "clients", base="iam", params={"clientId": client_id, "max": 1, "search": "true"}
    )
    entries = payload if isinstance(payload, list) else []
    for entry in entries:
        if isinstance(entry, dict) and entry.get("clientId") == client_id:
            uuid = entry.get("id")
            if isinstance(uuid, str) and uuid:
                return uuid
    # Fall back to the first entry with an id, in case the tenant renamed the client.
    for entry in entries:
        if isinstance(entry, dict) and isinstance(entry.get("id"), str):
            logger.warning(
                "No OAuth client with clientId %r; using %r instead",
                client_id,
                entry.get("clientId"),
            )
            return entry["id"]
    raise CheckmarxNotFoundError(
        f"No OAuth client named {client_id!r} was found in the realm. Role based "
        "enforcement cannot run until this resolves."
    )


def fetch_client_roles(client: CheckmarxClient, *, client_uuid: str) -> dict[str, RoleRef]:
    """All roles defined on the client, keyed by role name."""
    payload = client.get_json(
        f"clients/{client_uuid}/roles", base="iam", params={"briefRepresentation": "false"}
    )
    return {role.name: role for role in _role_list(payload)}


def fetch_user_client_roles(
    client: CheckmarxClient, *, user_id: str, client_uuid: str
) -> list[RoleRef]:
    """The client roles currently mapped directly to one user."""
    payload = client.get_json(f"users/{user_id}/role-mappings/clients/{client_uuid}", base="iam")
    return _role_list(payload)


# ----------------------------------------------- where a user's roles come from
#
# The reads below follow Keycloak's admin REST API (Checkmarx One's IAM is
# Keycloak based). They are NOT verified against a real Checkmarx One tenant:
# callers treat any failure (a 403, a 404) as "source unknown" and never let it
# stop a restriction.


def fetch_user_effective_client_roles(
    client: CheckmarxClient, *, user_id: str, client_uuid: str
) -> list[RoleRef]:
    """Every client role the user holds, however: directly, through a group, or
    as part of a composite role (Keycloak: ``.../clients/{id}/composite``)."""
    payload = client.get_json(
        f"users/{user_id}/role-mappings/clients/{client_uuid}/composite", base="iam"
    )
    return _role_list(payload)


def fetch_user_groups(client: CheckmarxClient, *, user_id: str) -> list[IamGroup]:
    """The groups the user is a direct member of, with their paths
    (``/parent/child``), from which the parent groups are worked out."""
    payload = client.get_json(f"users/{user_id}/groups", base="iam")
    entries = payload if isinstance(payload, list) else []
    groups: list[IamGroup] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        group_id = entry.get("id")
        name = entry.get("name")
        if not isinstance(group_id, str) or not isinstance(name, str):
            continue
        path = entry.get("path") if isinstance(entry.get("path"), str) else None
        groups.append(IamGroup(id=group_id, name=name, path=path, parent_id=None, raw=entry))
    return groups


def fetch_group_client_roles(
    client: CheckmarxClient, *, group_id: str, client_uuid: str, composite: bool = False
) -> list[RoleRef]:
    """The client roles mapped to a group (with ``composite``, also those its
    composite roles contain)."""
    suffix = "/composite" if composite else ""
    payload = client.get_json(
        f"groups/{group_id}/role-mappings/clients/{client_uuid}{suffix}", base="iam"
    )
    return _role_list(payload)


def fetch_client_role_composites(
    client: CheckmarxClient, *, client_uuid: str, role_name: str
) -> list[RoleRef]:
    """The roles a composite client role contains (its direct children)."""
    payload = client.get_json(
        f"clients/{client_uuid}/roles/{quote(role_name, safe='')}/composites", base="iam"
    )
    return _role_list(payload)


def remove_user_client_roles(
    client: CheckmarxClient, *, user_id: str, client_uuid: str, roles: list[RoleRef]
) -> None:
    """Unmap roles from a user. No-op when ``roles`` is empty."""
    if not roles:
        return
    client.request(
        "DELETE",
        f"users/{user_id}/role-mappings/clients/{client_uuid}",
        base="iam",
        json=[role.as_payload() for role in roles],
        headers={"Content-Type": "application/json"},
    )


def add_user_client_roles(
    client: CheckmarxClient, *, user_id: str, client_uuid: str, roles: list[RoleRef]
) -> None:
    """Map roles onto a user. Keycloak treats this as idempotent."""
    if not roles:
        return
    client.request(
        "POST",
        f"users/{user_id}/role-mappings/clients/{client_uuid}",
        base="iam",
        json=[role.as_payload() for role in roles],
        headers={"Content-Type": "application/json"},
    )
