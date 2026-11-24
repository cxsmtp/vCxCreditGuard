"""Where a user's AI roles come from, read best effort.

Removing a role mapping from a user only takes away a role mapped to that user
*directly*. In Keycloak (which Checkmarx One's IAM is built on) a person can also
hold a role through a group they belong to (or a parent of that group), or
because a composite role they hold contains it. Taking away the direct mapping
then changes nothing for that role, and a restriction that says otherwise would
be a false comfort.

So before a user is restricted (and on the Simulation page) CreditGuard reads:

* the user's effective client roles
  (``GET users/{id}/role-mappings/clients/{clientUuid}/composite``);
* the user's groups (``GET users/{id}/groups``) and, through their paths, the
  parent groups, with each group's client role mappings
  (``GET groups/{id}/role-mappings/clients/{clientUuid}``);
* which composite roles contain an AI role
  (``GET clients/{clientUuid}/roles/{roleName}/composites``).

These follow Keycloak's admin REST API and are **not verified** on a real
Checkmarx One tenant. Every one of them is optional: a refusal (403), a 404 or
any other failure only means "source unknown", is never a reason not to
restrict, and is not reported on the API key permission check (these reads are
not part of what the key needs). Nothing here changes a group or a role:
removing a role from a group or a composite role would take it from everyone
else too.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, TypeVar

from sqlalchemy.orm import Session

from app.checkmarx import iam
from app.checkmarx.client import CheckmarxClient, listeners_paused
from app.checkmarx.errors import CheckmarxError

logger = logging.getLogger(__name__)

SOURCE_GROUP = "group"
SOURCE_COMPOSITE = "composite"
SOURCE_UNKNOWN = "unknown"

# Bounds on how much one user's analysis reads.
MAX_GROUPS_PER_USER = 50
MAX_COMPOSITE_DEPTH = 4
MAX_COMPOSITE_READS = 100

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class RoleSource:
    """One way a user holds a role other than a direct mapping."""

    kind: str
    group: str | None = None
    role: str | None = None

    def as_dict(self) -> dict[str, str]:
        out = {"kind": self.kind}
        if self.group:
            out["group"] = self.group
        if self.role:
            out["role"] = self.role
        return out

    @classmethod
    def from_dict(cls, value: Any) -> RoleSource | None:
        if not isinstance(value, dict) or not isinstance(value.get("kind"), str):
            return None
        group = value.get("group")
        role = value.get("role")
        return cls(
            kind=value["kind"],
            group=group if isinstance(group, str) else None,
            role=role if isinstance(role, str) else None,
        )

    def describe(self) -> str:
        if self.kind == SOURCE_GROUP:
            return f"group {self.group}"
        if self.kind == SOURCE_COMPOSITE:
            via = f"role {self.role}"
            return f"{via} (through group {self.group})" if self.group else via
        return "a source CreditGuard cannot see (source unknown)"


def describe_sources(sources: list[RoleSource]) -> str:
    return " and ".join(source.describe() for source in sources) or "source unknown"


@dataclass(slots=True)
class UserRoles:
    """What was read about one user's AI roles."""

    ai_roles: tuple[str, ...]
    # Every client role mapped to the user directly.
    direct: list[iam.RoleRef]
    # Every client role the user holds however; None when it could not be read.
    effective: set[str] | None
    # AI role -> the ways it is held other than directly.
    indirect: dict[str, list[RoleSource]] = field(default_factory=dict)
    # The reads that failed, in words: what is not known.
    unread: list[str] = field(default_factory=list)

    def direct_ai(self) -> list[iam.RoleRef]:
        return [role for role in self.direct if role.name in self.ai_roles]

    def stays_effective(self) -> dict[str, list[RoleSource]]:
        """AI roles the user would still hold once their direct mappings are gone."""
        kept = {name: list(sources) for name, sources in self.indirect.items() if sources}
        if self.effective is not None:
            direct = {role.name for role in self.direct}
            for name in self.ai_roles:
                if name in self.effective and name not in direct and name not in kept:
                    kept[name] = [RoleSource(SOURCE_UNKNOWN)]
        return {name: kept[name] for name in self.ai_roles if name in kept}


def kept_entries(kept: dict[str, list[RoleSource]], *, removed: set[str]) -> list[dict[str, Any]]:
    """The record of roles that stay effective, as stored on the undo snapshot."""
    return [
        {
            "role": name,
            "sources": [source.as_dict() for source in sources],
            # Whether a direct mapping was removed as well (it did not help).
            "direct_removed": name in removed,
        }
        for name, sources in kept.items()
    ]


def kept_from_entries(entries: Any) -> dict[str, list[RoleSource]]:
    kept: dict[str, list[RoleSource]] = {}
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, dict) or not isinstance(entry.get("role"), str):
            continue
        sources = [
            source
            for raw in entry.get("sources") or []
            if (source := RoleSource.from_dict(raw)) is not None
        ]
        kept[entry["role"]] = sources or [RoleSource(SOURCE_UNKNOWN)]
    return kept


class RoleSourceReader:
    """Best-effort reads of where roles come from, cached for one run or request.

    ``client_roles`` and ``client_uuid`` come from the caller's role resolver,
    so the platform client is looked up once per run.
    """

    def __init__(
        self,
        client: CheckmarxClient,
        *,
        client_uuid: Callable[[], str],
        client_roles: Callable[[], dict[str, iam.RoleRef]],
    ) -> None:
        self._client = client
        self._client_uuid = client_uuid
        self._client_roles = client_roles
        self._groups_by_path: dict[str, iam.IamGroup] | None = None
        self._groups_read = False
        self._group_roles: dict[str, list[iam.RoleRef] | None] = {}
        self._children: dict[str, list[iam.RoleRef] | None] = {}
        self._composite_reads = 0

    # ------------------------------------------------------------- plumbing

    def _quiet(self, what: str, call: Callable[[], T]) -> T | None:
        """Run one optional read. Any failure is "not known", logged, and kept
        off the API key permission report."""
        try:
            with listeners_paused():
                return call()
        except CheckmarxError as exc:
            logger.info("Optional IAM read failed (%s): %s", what, exc)
            return None

    def uuid(self) -> str | None:
        return self._quiet("platform client", self._client_uuid)

    def roles(self) -> dict[str, iam.RoleRef]:
        return self._quiet("client roles", self._client_roles) or {}

    # ---------------------------------------------------------------- reads

    def effective(self, user_id: str) -> set[str] | None:
        """The user's effective client roles, read now (never cached)."""
        uuid = self.uuid()
        if uuid is None:
            return None
        roles = self._quiet(
            "effective roles",
            lambda: iam.fetch_user_effective_client_roles(
                self._client, user_id=user_id, client_uuid=uuid
            ),
        )
        return None if roles is None else {role.name for role in roles}

    def _groups(self) -> dict[str, iam.IamGroup] | None:
        if not self._groups_read:
            self._groups_read = True
            groups = self._quiet("groups", lambda: iam.fetch_groups(self._client))
            if groups is not None:
                self._groups_by_path = {group.path: group for group in groups if group.path}
        return self._groups_by_path

    def group_roles(self, group_id: str) -> list[iam.RoleRef] | None:
        if group_id not in self._group_roles:
            uuid = self.uuid()
            self._group_roles[group_id] = (
                None
                if uuid is None
                else self._quiet(
                    "group roles",
                    lambda: iam.fetch_group_client_roles(
                        self._client, group_id=group_id, client_uuid=uuid
                    ),
                )
            )
        return self._group_roles[group_id]

    def children(self, role_name: str) -> list[iam.RoleRef] | None:
        """The roles a composite role contains (direct children); [] when the
        role is not composite, None when that could not be read."""
        if role_name in self._children:
            return self._children[role_name]
        known = self.roles().get(role_name)
        if known is not None and not known.composite:
            self._children[role_name] = []
            return []
        uuid = self.uuid()
        if uuid is None or self._composite_reads >= MAX_COMPOSITE_READS:
            return None
        self._composite_reads += 1
        found = self._quiet(
            "composite role",
            lambda: iam.fetch_client_role_composites(
                self._client, client_uuid=uuid, role_name=role_name
            ),
        )
        self._children[role_name] = found
        return found

    def contained(self, role_name: str) -> set[str] | None:
        """Every client role a composite role contains, however deep (bounded)."""
        found: set[str] = set()
        frontier = [role_name]
        complete = True
        for _depth in range(MAX_COMPOSITE_DEPTH):
            next_frontier: list[str] = []
            for name in frontier:
                children = self.children(name)
                if children is None:
                    complete = False
                    continue
                for child in children:
                    if child.client_role and child.name not in found:
                        found.add(child.name)
                        if child.composite:
                            next_frontier.append(child.name)
            if not next_frontier:
                break
            frontier = next_frontier
        if not found and not complete:
            return None
        return found

    # ------------------------------------------------------------- analysis

    def read_user(
        self,
        user_id: str,
        *,
        ai_roles: tuple[str, ...],
        direct: list[iam.RoleRef] | None = None,
    ) -> UserRoles:
        """Where each AI role the user holds comes from. Never raises a
        Checkmarx error: what could not be read is listed in ``unread``."""
        unread: list[str] = []
        if direct is None:
            uuid = self.uuid()
            direct = (
                self._quiet(
                    "direct roles",
                    lambda: iam.fetch_user_client_roles(
                        self._client, user_id=user_id, client_uuid=uuid
                    ),
                )
                if uuid is not None
                else None
            )
            if direct is None:
                unread.append("the user's direct role mappings")
                direct = []
        effective = self.effective(user_id)
        if effective is None:
            unread.append("the user's effective roles")
        wanted = set(ai_roles)
        indirect: dict[str, list[RoleSource]] = {}

        def add(name: str, source: RoleSource) -> None:
            sources = indirect.setdefault(name, [])
            if source not in sources:
                sources.append(source)

        def through_composites(held: list[iam.RoleRef], group: str | None) -> None:
            known = self.roles()
            for role in held:
                if group is None and role.name in wanted:
                    # Mapped directly and an AI role itself: removed along with
                    # the others, so what it contains does not stay.
                    continue
                if not (role.composite or known.get(role.name, role).composite):
                    continue
                inside = self.contained(role.name)
                if inside is None:
                    unread.append(f"what role {role.name} contains")
                    continue
                for name in sorted(inside & wanted):
                    add(name, RoleSource(SOURCE_COMPOSITE, group=group, role=role.name))

        through_composites(direct, None)

        groups = self._user_groups(user_id, unread)
        for label, group_id in groups:
            mapped = self.group_roles(group_id)
            if mapped is None:
                unread.append(f"the roles of group {label}")
                continue
            for role in mapped:
                if role.name in wanted:
                    add(role.name, RoleSource(SOURCE_GROUP, group=label))
            through_composites(mapped, label)

        return UserRoles(
            ai_roles=tuple(ai_roles),
            direct=list(direct),
            effective=effective,
            indirect={name: indirect[name] for name in ai_roles if name in indirect},
            unread=list(dict.fromkeys(unread)),
        )

    def _user_groups(self, user_id: str, unread: list[str]) -> list[tuple[str, str]]:
        """(label, id) of the user's groups and every parent group above them."""
        groups = self._quiet(
            "user groups", lambda: iam.fetch_user_groups(self._client, user_id=user_id)
        )
        if groups is None:
            unread.append("the user's groups")
            return []
        found: dict[str, str] = {}
        by_path = None
        for group in groups[:MAX_GROUPS_PER_USER]:
            label = group.path or group.name
            found.setdefault(group.id, label)
            path = (group.path or "").strip("/")
            parts = path.split("/") if path else []
            for depth in range(1, len(parts)):
                parent_path = "/" + "/".join(parts[:depth])
                if by_path is None:
                    by_path = self._groups() or {}
                    if self._groups_by_path is None:
                        unread.append("the parent groups")
                parent = by_path.get(parent_path)
                if parent is not None:
                    found.setdefault(parent.id, parent_path)
                elif self._groups_by_path is not None:
                    unread.append(f"parent group {parent_path}")
        return [(label, group_id) for group_id, label in found.items()]


# ------------------------------------------------- the tenant's client roles

# How long the list for the Settings picker is reused. Short: it only saves
# repeated reads while an admin is choosing.
CLIENT_ROLE_CACHE_SECONDS = 60.0

_listing_lock = threading.Lock()
_listing_cache: tuple[tuple[str, ...], float, ClientRoleListing] | None = None


@dataclass(frozen=True, slots=True)
class ClientRoleListing:
    """The roles defined on the platform client, or why they could not be read."""

    available: bool
    roles: tuple[iam.RoleRef, ...] = ()
    message: str | None = None

    def names(self) -> frozenset[str]:
        return frozenset(role.name for role in self.roles)


def reset_client_role_cache() -> None:
    global _listing_cache
    with _listing_lock:
        _listing_cache = None


def tenant_client_roles(session: Session, *, fresh: bool = False) -> ClientRoleListing:
    """The tenant's client roles on ``ast-app``, cached briefly. Never raises:
    a failed read (no connection, a refusal, an outage) says so instead."""
    global _listing_cache
    from app.services import connection as connection_service

    connection = connection_service.get_connection(session)
    if connection is None:
        return ClientRoleListing(
            available=False,
            message="No Checkmarx One connection is configured, so the tenant's roles cannot be "
            "listed.",
        )
    key = (
        str(connection.api_key_fingerprint or ""),
        str(connection.tenant_name or ""),
        str(connection.iam_base_url or ""),
    )
    now = time.monotonic()
    with _listing_lock:
        cached = _listing_cache
    if not fresh and cached is not None and cached[0] == key and cached[1] > now:
        return cached[2]
    try:
        client = connection_service.get_client(session)
        uuid = iam.resolve_platform_client_uuid(client)
        roles = iam.fetch_client_roles(client, client_uuid=uuid)
    except CheckmarxError as exc:
        logger.info("Could not list the tenant's client roles: %s", exc)
        return ClientRoleListing(
            available=False,
            message=f"The tenant's roles could not be read from Checkmarx One: {exc}",
        )
    except Exception as exc:  # noqa: BLE001 - listing roles must never break a page
        logger.warning("Could not list the tenant's client roles", exc_info=True)
        return ClientRoleListing(
            available=False, message=f"The tenant's roles could not be read: {exc}"
        )
    listing = ClientRoleListing(
        available=True, roles=tuple(sorted(roles.values(), key=lambda role: role.name))
    )
    with _listing_lock:
        _listing_cache = (key, now + CLIENT_ROLE_CACHE_SECONDS, listing)
    return listing
