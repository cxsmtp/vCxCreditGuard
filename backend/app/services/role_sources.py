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

Not traversed: realm-level composite roles (such as a realm's default roles)
that contain an ``ast-app`` client role. A role held that way shows as held
through a source CreditGuard cannot see ("source unknown").
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from contextlib import ExitStack
from dataclasses import dataclass, field
from typing import Any, TypeVar

from sqlalchemy.orm import Session

from app.checkmarx import iam
from app.checkmarx.client import CheckmarxClient, listeners_paused, single_attempt
from app.checkmarx.errors import (
    CheckmarxError,
    CheckmarxRateLimitError,
    CheckmarxUnavailableError,
)

logger = logging.getLogger(__name__)

SOURCE_GROUP = "group"
SOURCE_COMPOSITE = "composite"
SOURCE_UNKNOWN = "unknown"

# Bounds on how much one user's analysis reads.
MAX_GROUPS_PER_USER = 50
MAX_COMPOSITE_DEPTH = 4
MAX_COMPOSITE_READS = 100

T = TypeVar("T")

# Why reads stopped under a ReadBudget, in words.
STOPPED_UNAVAILABLE = "Checkmarx IAM did not answer"


@dataclass(slots=True)
class ReadBudget:
    """Bounds on optional reads made while someone waits on a page.

    Each read is tried once with a short timeout (no retry or backoff); the
    first sign that IAM is not answering (unavailable, rate limited, timed out)
    stops every read after it, and so does running out of time. Enforcement
    reads without a budget, with the client's full retry policy.
    """

    seconds: float = 10.0
    call_timeout_seconds: float = 5.0
    # When the first read was made (the clock starts there).
    started: float | None = None
    # Set once reads have stopped: why, in words.
    stopped: str | None = None

    def check(self) -> bool:
        """True while reads may go on."""
        now = time.monotonic()
        if self.started is None:
            self.started = now
        if self.stopped is None and now - self.started >= self.seconds:
            self.stopped = f"the {self.seconds:g} s allowed for reading roles ran out"
        return self.stopped is None


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
    # Every client role the directly mapped AI roles contain (composites): they
    # go with those roles when the restriction removes them.
    removed_contains: set[str] = field(default_factory=set)

    def direct_ai(self) -> list[iam.RoleRef]:
        return [role for role in self.direct if role.name in self.ai_roles]

    def stays_effective(self) -> dict[str, list[RoleSource]]:
        """AI roles the user would still hold once their direct mappings are gone.

        One held through a group or a composite role that is not removed is
        kept. One that is only effective (no source seen) is kept with its
        source unknown, unless a directly mapped AI role contains it: that one
        goes with the composite that is removed.
        """
        kept = {name: list(sources) for name, sources in self.indirect.items() if sources}
        if self.effective is not None:
            direct = {role.name for role in self.direct}
            for name in self.ai_roles:
                if (
                    name in self.effective
                    and name not in direct
                    and name not in kept
                    and name not in self.removed_contains
                ):
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
        budget: ReadBudget | None = None,
    ) -> None:
        self._client = client
        self._client_uuid = client_uuid
        self._client_roles = client_roles
        self.budget = budget
        self._uuid: str | None = None
        self._uuid_read = False
        self._roles: dict[str, iam.RoleRef] | None = None
        self._groups_by_path: dict[str, iam.IamGroup] | None = None
        self._groups_read = False
        self._group_roles: dict[str, list[iam.RoleRef] | None] = {}
        self._children: dict[str, list[iam.RoleRef] | None] = {}
        self._contained: dict[str, set[str] | None] = {}
        # Composite roles whose nesting went deeper than MAX_COMPOSITE_DEPTH.
        self._too_deep: set[str] = set()
        self._composite_reads = 0

    # ------------------------------------------------------------- plumbing

    @property
    def stopped(self) -> str | None:
        """Why reads stopped (under a budget), or None."""
        return self.budget.stopped if self.budget is not None else None

    def _quiet(self, what: str, call: Callable[[], T], *, pause: bool = True) -> T | None:
        """Run one read. Any failure is "not known" and logged.

        ``pause`` keeps an optional read off the API key permission report; a
        read the key is checked for (the platform client, its roles) is left
        on it. Under a budget the read is tried once with a short timeout, and
        nothing is read any more once IAM stopped answering or time ran out.
        """
        budget = self.budget
        if budget is not None and not budget.check():
            return None
        try:
            with ExitStack() as stack:
                if budget is not None:
                    stack.enter_context(single_attempt(budget.call_timeout_seconds))
                if pause:
                    stack.enter_context(listeners_paused())
                return call()
        except (CheckmarxUnavailableError, CheckmarxRateLimitError) as exc:
            logger.info("IAM read failed (%s): %s", what, exc)
            if budget is not None and budget.stopped is None:
                budget.stopped = STOPPED_UNAVAILABLE
            return None
        except CheckmarxError as exc:
            logger.info("IAM read failed (%s): %s", what, exc)
            return None

    def uuid(self) -> str | None:
        """The platform client's uuid; a failed lookup is not tried again."""
        if not self._uuid_read:
            self._uuid = self._quiet("platform client", self._client_uuid, pause=False)
            # Not read because reads had stopped: nothing was tried, nothing to cache.
            self._uuid_read = self._uuid is not None or self.stopped is None
        return self._uuid

    def roles(self) -> dict[str, iam.RoleRef]:
        """The platform client's roles; a failed read is not tried again."""
        if self._roles is None:
            found = self._quiet("client roles", self._client_roles, pause=False)
            if found is not None or self.stopped is None:
                self._roles = found or {}
            return found or {}
        return self._roles

    def _ours(self, role: iam.RoleRef, uuid: str) -> bool:
        """Whether a composite's child is a role of the platform client (by the
        client it belongs to, or by its id; never by its name alone)."""
        if not role.client_role:
            return False
        if role.container_id is not None:
            return role.container_id == uuid
        known = self.roles().get(role.name)
        return known is not None and known.id == role.id

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
        """Every platform client role a composite role contains, however deep
        (bounded by MAX_COMPOSITE_DEPTH: deeper nesting is noted, see
        ``too_deep``). Roles of other clients and realm roles are left out."""
        if role_name in self._contained:
            return self._contained[role_name]
        uuid = self.uuid()
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
                    if uuid is None or not self._ours(child, uuid) or child.name in found:
                        continue
                    found.add(child.name)
                    if child.composite:
                        next_frontier.append(child.name)
            if not next_frontier:
                break
            frontier = next_frontier
        else:
            # Every level was used and there was still more below.
            self._too_deep.add(role_name)
        result = None if not found and not complete else found
        self._contained[role_name] = result
        return result

    def too_deep(self, role_name: str) -> bool:
        """Whether ``contained`` stopped at MAX_COMPOSITE_DEPTH for this role."""
        return role_name in self._too_deep

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

        removed_contains: set[str] = set()

        def inside_of(role: iam.RoleRef) -> set[str] | None:
            known = self.roles()
            if not (role.composite or known.get(role.name, role).composite):
                return set()
            inside = self.contained(role.name)
            if inside is None:
                unread.append(f"what role {role.name} contains")
            elif self.too_deep(role.name):
                unread.append(
                    f"roles nested more than {MAX_COMPOSITE_DEPTH} levels deep inside role "
                    f"{role.name}"
                )
            return inside

        def through_composites(held: list[iam.RoleRef], group: str | None) -> None:
            for role in held:
                if group is None and role.name in wanted:
                    # Mapped directly and an AI role itself: removed along with
                    # the others, so what it contains goes with it.
                    removed_contains.update(inside_of(role) or set())
                    continue
                inside = inside_of(role)
                for name in sorted((inside or set()) & wanted):
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
            removed_contains=removed_contains,
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
        if len(groups) > MAX_GROUPS_PER_USER:
            unread.append(
                f"the roles of the user's groups beyond the first {MAX_GROUPS_PER_USER} "
                f"(the user is in {len(groups)} groups)"
            )
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
