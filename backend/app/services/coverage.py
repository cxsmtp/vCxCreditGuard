"""Enforcement coverage: whether a user restriction can actually bite.

A user restriction removes the configured AI roles where they are mapped to the
user directly. It cannot take away a role the user also holds through a
composite role or a group, and it never touches a user who holds a protected
role. On a live tenant (2026-11) that left almost nobody restrictable:

* ``ast-admin``, held by 274 of 296 users, is a composite role containing all
  three default AI roles (so are ``ast-risk-manager``, ``manage-project`` and
  ``scan-fusion``);
* ``ast-admin`` is also a protected role, so 93% of users are never restricted;
* the tenant had dedicated AI roles (``ai-triage-assist``, ``create-fusion-scan``,
  ``scan-fusion``, ``fusion-manager``, ``manage-fusion``).

This module measures that, so an admin sees it before relying on a user budget.
It works from what the organisation sync already stored (each user's roles and
groups as ``/users/v2`` reports them, which on a live tenant include the roles
held through composites) plus the role-source reads enforcement uses anyway:
the platform client's roles, the composites of the composite roles held, and
the client role mappings of the groups users are in. Those reads are bounded
(``role_sources.ReadBudget`` and the per-run caps) and the result is cached, so
opening a page does not re-read the tenant. It only reads: the role list is
never changed here, only suggestions are made.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checkmarx.client import CheckmarxClient
from app.db.base import utcnow
from app.models.org import CxGroup, CxUser
from app.services import role_sources, settings_store

logger = logging.getLogger(__name__)

# How long a computed report is shown before it is computed again on request.
MAX_AGE = timedelta(hours=6)
# Optional reads for one computation (each read once, short timeout).
READ_SECONDS = 20.0
READ_TIMEOUT_SECONDS = 5.0
MAX_GROUP_READS = 60
# Below this share of AI-role holders a user restriction can reach, the page
# says plainly that user budgets will not bite.
LOW_COVERAGE = 0.5
# Roles a tenant may have for AI features alone (seen on a live tenant), and
# the name fragments that suggest one.
KNOWN_AI_ROLES: tuple[str, ...] = (
    "ai-triage-assist",
    "create-fusion-scan",
    "scan-fusion",
    "fusion-manager",
    "manage-fusion",
)
_AI_FRAGMENTS = ("fusion", "ai-triage", "ai-remediation", "ai-assist")


@dataclass
class Coverage:
    computed_at: datetime
    ai_roles: list[str]
    protected_roles: list[str]
    users: int = 0
    # Users holding at least one configured AI role (by any route).
    ai_holders: int = 0
    # AI holders a user restriction could take AI access from: not protected,
    # and every AI role they hold is lost with its direct mapping.
    restrictable: int = 0
    # AI holders who keep an AI role through a composite role or a group.
    via_composite: int = 0
    via_group: int = 0
    via_composite_or_group: int = 0
    # AI holders never restricted: they hold a protected role (or own the key).
    protected: int = 0
    # AI holders whose sources could not all be read (budget, refusal).
    unknown: int = 0
    # Composite roles found to contain an AI role: {composite: [AI roles]}.
    composites: dict[str, list[str]] = field(default_factory=dict)
    # Composite roles held by AI holders, by how many hold them.
    composite_holders: dict[str, int] = field(default_factory=dict)
    groups_granting: list[str] = field(default_factory=list)
    # Roles on the tenant that look dedicated to AI and are not configured.
    dedicated_roles: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    available: bool = True

    @property
    def share(self) -> float | None:
        return self.restrictable / self.ai_holders if self.ai_holders else None

    @property
    def low(self) -> bool:
        share = self.share
        return share is not None and share < LOW_COVERAGE

    def warning(self) -> str | None:
        """What the admin is told when budgets will not bite, or None."""
        if not self.low:
            return None
        reasons: list[str] = []
        if self.protected:
            reasons.append(
                f"{self.protected} hold a protected role "
                f"({', '.join(self.protected_roles) or 'protected'}), so they are never "
                "restricted"
            )
        if self.via_composite_or_group:
            held = ", ".join(
                name
                for name, _count in sorted(
                    self.composite_holders.items(), key=lambda item: -item[1]
                )[:3]
            )
            reasons.append(
                f"{self.via_composite_or_group} hold an AI role through a composite role"
                f"{f' ({held})' if held else ''} or a group, which removing the role's direct "
                "mapping does not take away"
            )
        share = round((self.share or 0) * 100)
        text = (
            f"User budgets will not bite on this tenant: a user restriction can take AI access "
            f"from only {self.restrictable} of the {self.ai_holders} users who have it "
            f"({share}%). Of those it cannot reach, "
            f"{'; '.join(reasons) or 'the reason is unknown'}."
        )
        if self.dedicated_roles:
            text += (
                " This tenant has roles dedicated to AI features "
                f"({', '.join(self.dedicated_roles)}). If people get AI access through them, "
                "consider making them the roles a restriction removes (Settings → Enforcement "
                "→ AI roles), and keeping them out of broad composite roles. CreditGuard never "
                "changes the list itself."
            )
        text += " Project, group and application limits still turn AI features off on projects."
        return text

    def as_dict(self) -> dict[str, Any]:
        return {
            "computed_at": self.computed_at.isoformat(),
            "ai_roles": self.ai_roles,
            "protected_roles": self.protected_roles,
            "users": self.users,
            "ai_holders": self.ai_holders,
            "restrictable": self.restrictable,
            "share": None if self.share is None else round(self.share, 4),
            "via_composite": self.via_composite,
            "via_group": self.via_group,
            "via_composite_or_group": self.via_composite_or_group,
            "protected": self.protected,
            "unknown": self.unknown,
            "composites": self.composites,
            "composite_holders": self.composite_holders,
            "groups_granting": self.groups_granting,
            "dedicated_roles": self.dedicated_roles,
            "notes": self.notes,
            "available": self.available,
            "low": self.low,
            "warning": self.warning(),
        }


@dataclass(frozen=True, slots=True)
class _User:
    id: str
    roles: frozenset[str]
    groups: tuple[str, ...]


def cached(session: Session) -> dict[str, Any] | None:
    """The last computed report, as stored, or None."""
    value = settings_store.get_value(session, settings_store.KEY_ENFORCEMENT_COVERAGE)
    return value if isinstance(value, dict) and value.get("computed_at") else None


def _fresh(report: dict[str, Any] | None, now: datetime) -> bool:
    if report is None:
        return False
    try:
        at = datetime.fromisoformat(str(report["computed_at"]))
    except (KeyError, ValueError):
        return False
    return now - at < MAX_AGE


def current(
    session: Session, client: CheckmarxClient | None, *, refresh: bool = False
) -> dict[str, Any] | None:
    """The cached report, computed again when it is older than MAX_AGE (or
    ``refresh``) and a client is given. Without a client only the cache is used."""
    report = cached(session)
    if client is None or (not refresh and _fresh(report, utcnow())):
        return report
    try:
        computed = compute(session, client)
    except Exception:  # noqa: BLE001 - a coverage figure must never break a page
        logger.warning("Could not compute the enforcement coverage", exc_info=True)
        return report
    settings_store.set_value(session, settings_store.KEY_ENFORCEMENT_COVERAGE, computed.as_dict())
    session.commit()
    return cached(session)


def compute(session: Session, client: CheckmarxClient | None) -> Coverage:
    """Measure the coverage. Reads the database first, then (with ``client``)
    the role sources, with nothing open in the database meanwhile. Writes
    nothing."""
    from app.services import enforcement

    ai_roles = list(settings_store.ai_role_names(session))
    protected_roles = sorted(settings_store.enforcement_guard(session).protected_roles)
    owners = enforcement.protected_user_ids(session)
    users = [
        _User(
            id=row.id,
            roles=frozenset(str(name) for name in (row.role_names or []) if name),
            groups=tuple(str(name) for name in (row.group_names or []) if name),
        )
        for row in session.scalars(
            select(CxUser).where(CxUser.is_deleted.is_(False), CxUser.enabled.is_(True))
        )
    ]
    groups = {
        key: row.id
        for row in session.scalars(select(CxGroup).where(CxGroup.is_deleted.is_(False)))
        for key in {row.name, row.path or ""}
        if key
    }
    session.commit()  # nothing open while Checkmarx is read

    report = Coverage(computed_at=utcnow(), ai_roles=ai_roles, protected_roles=protected_roles)
    report.users = len(users)
    wanted = set(ai_roles)
    protected_lower = {name.lower() for name in protected_roles}
    holders = [user for user in users if user.roles & wanted]
    report.ai_holders = len(holders)

    reader: role_sources.RoleSourceReader | None = None
    if client is not None:
        resolver = enforcement.RoleResolver(client)
        reader = role_sources.RoleSourceReader(
            client,
            client_uuid=lambda: resolver.client_uuid,
            client_roles=resolver.all_roles,
            budget=role_sources.ReadBudget(
                seconds=READ_SECONDS, call_timeout_seconds=READ_TIMEOUT_SECONDS
            ),
        )
    else:
        report.available = False
        report.notes.append(
            "Checkmarx One is not connected, so composite roles and groups were not read: "
            "only protected roles are counted."
        )

    # Composite roles held by AI holders, and the AI roles they contain.
    client_roles = reader.roles() if reader is not None else {}
    composite_names = sorted(
        {
            name
            for user in holders
            for name in user.roles
            if name not in wanted
            and (client_roles.get(name) is None or client_roles[name].composite)
        }
    )
    if reader is not None and client_roles:
        composite_names = [name for name in composite_names if name in client_roles]
    contains: dict[str, set[str] | None] = {}
    for name in composite_names:
        if reader is None:
            contains[name] = None
            continue
        found = reader.contained(name)
        contains[name] = None if found is None else found & wanted
        if found and found & wanted:
            report.composites[name] = sorted(found & wanted)

    # Groups that grant an AI role (directly or through a composite they map).
    group_grants: dict[str, set[str] | None] = {}
    group_reads = 0
    if reader is not None:
        for name in sorted({group for user in holders for group in user.groups}):
            group_id = groups.get(name) or groups.get(f"/{name}")
            if group_id is None:
                group_grants[name] = None
                continue
            if group_reads >= MAX_GROUP_READS:
                group_grants[name] = None
                continue
            group_reads += 1
            mapped = reader.group_roles(group_id)
            if mapped is None:
                group_grants[name] = None
                continue
            granted: set[str] = set()
            for role in mapped:
                if role.name in wanted:
                    granted.add(role.name)
                elif role.composite:
                    inner = reader.contained(role.name)
                    granted |= (inner or set()) & wanted
            group_grants[name] = granted
            if granted:
                report.groups_granting.append(name)
    if reader is not None and reader.stopped:
        report.notes.append(f"Some roles were not read: {reader.stopped}.")

    for user in holders:
        held_ai = user.roles & wanted
        protected = user.id in owners or bool({r.lower() for r in user.roles} & protected_lower)
        kept: set[str] = set()
        unknown = reader is None
        for name in user.roles:
            if name not in contains:
                continue
            inner = contains[name]
            if inner is None:
                unknown = True
            else:
                kept |= inner & held_ai
            if inner:
                report.composite_holders[name] = report.composite_holders.get(name, 0) + 1
        via_composite = bool(kept)
        via_group = False
        for group in user.groups:
            granted = group_grants.get(group)
            if granted is None:
                if reader is not None and group in group_grants:
                    unknown = True
                continue
            if granted & held_ai:
                via_group = True
                kept |= granted & held_ai
        report.via_composite += via_composite
        report.via_group += via_group
        report.via_composite_or_group += via_composite or via_group
        if protected:
            report.protected += 1
        if not protected and not kept:
            if unknown:
                report.unknown += 1
            else:
                report.restrictable += 1

    report.dedicated_roles = sorted(
        name
        for name in (set(client_roles) if client_roles else set())
        if name not in wanted
        and (name in KNOWN_AI_ROLES or any(fragment in name for fragment in _AI_FRAGMENTS))
    )
    return report
