"""Policy violations: someone acted against a restriction that is in force.

CreditGuard does not rely on Checkmarx One keeping a setting off. Every cycle it
reads each restriction back and re-applies it (``enforcement._reconcile``), so a
setting switched back on holds for one interval at most. What happened in that
interval, and what happened despite the setting, is recorded here for an admin
to follow up:

* ``setting_reenabled`` - a restricted setting was found switched back on (Auto
  Triage, PR triage and remediation, Fusion in the project's scan settings or
  in its repository's, a user's AI roles) and was turned off again. Checkmarx
  One does not say who changed it.
* ``fusion_scan_during_restriction`` - a scan on a project whose Fusion
  restriction is in force, created after it was applied, ran the AI engine with
  Fusion on (a scan started with its own settings can do that). The scan names
  who started it and from where.
* ``ai_scan_during_restriction`` - the same, but the AI engine ran without
  Fusion (LLM-based scanning), or the scan does not say which. That is the
  restriction working: one information row per restriction per day keeps the
  count, with no notification and no audit entry. Whether that costs credits
  is not known.
* ``usage_after_restriction`` - what the restriction is meant to stop (a user's
  AI Triage and AI Remediation; a project's Auto Triage or Fusion) kept rising
  in the consumption feed after it was applied. One record per restriction,
  brought up to date while it keeps rising. Credits can be billed a little
  after the action, so a small rise right after a restriction may predate it.
* ``scans_not_checked`` - more scans were made on a restricted project since
  the last look than one cycle's listing reaches, so some were not looked at.
  Information, once per restriction (brought up to date if it happens again).

The AI-scan counts and scans not checked are information (``INFO_KINDS``):
never counted as open violations, no notification, no audit entry. Every
other new violation raises one notification and an audit entry
(``violation.detected``); acknowledging and resolving are audited too. A
setting switched back on is notified in the ``enforcement`` category, as a
re-applied restriction always was; the scan and usage findings in ``policy``.
Notifications and the audit log are visible to viewers, so they name the
project and what happened, never the person: who started a scan is only on the
violation row, which only admins can read. The scan listing is bounded like the
auto-triage scan reads, nothing here holds a database write lock across a
Checkmarx call, and one project's failure never stops the others.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.checkmarx import scans as scans_api
from app.checkmarx import usage as usage_api
from app.checkmarx.client import CheckmarxClient
from app.checkmarx.errors import CheckmarxAuthError, CheckmarxError, CheckmarxNotFoundError
from app.db.base import utcnow
from app.models.enums import ActionType, EnforcementKind, EnforcementStatus, Severity, UsageView
from app.models.limits import CreditLimit, EnforcementAction
from app.models.usage import UsageRecord, UsageSnapshot
from app.models.violations import (
    INFO_KINDS,
    KIND_AI_SCAN,
    KIND_FUSION_SCAN,
    KIND_SCANS_NOT_CHECKED,
    KIND_SETTING_REENABLED,
    KIND_USAGE_AFTER,
    STATUS_ACKNOWLEDGED,
    STATUS_OPEN,
    STATUS_RESOLVED,
    PolicyViolation,
)
from app.services import ingestion, notifications, settings_store, usage_mix
from app.services.audit import AuditActor, record_audit

logger = logging.getLogger(__name__)

AUDIT_TARGET = "policy_violation"
# Bounded like the auto-triage scan reads: a busy tenant never makes a cycle
# unbounded. A project that does not fit is looked at again next cycle.
MAX_PROJECTS_PER_CYCLE = 50
MAX_PAGES_PER_PROJECT = 2
SCAN_PAGE_SIZE = scans_api.DEFAULT_PAGE_SIZE
MAX_SCAN_READS_PER_CYCLE = 50
# Scans not classified yet (queued, running, or not read for want of budget)
# kept per project by id, so they are found again even once the cursor has
# moved past them.
MAX_PENDING_PER_PROJECT = 100
# Statuses of a scan that never ran its engines (or stopped): never recorded,
# never priced.
_NOT_RUN = frozenset({"failed", "canceled", "cancelled"})
# A scan in any other status (queued, running) is not final yet: it is looked
# at again next cycle, for up to this long, and then taken as it is.
_FINAL = frozenset({*scans_api.COMPLETED_STATUSES, *_NOT_RUN})
MAX_WAIT_FOR_A_SCAN = timedelta(days=1)
# Scan ids kept on an AI-scan information row, so a listing read twice is not
# counted twice.
MAX_AI_SCAN_IDS = 500

KIND_LABELS: dict[str, str] = {
    KIND_SETTING_REENABLED: "Setting switched back on",
    KIND_FUSION_SCAN: "Fusion scan during a restriction",
    KIND_AI_SCAN: "AI scans without Fusion during a restriction (information)",
    KIND_USAGE_AFTER: "Usage kept rising after a restriction",
    KIND_SCANS_NOT_CHECKED: "Scans not checked (information)",
}

_REENABLED_WHAT: dict[str, str] = {
    EnforcementKind.REMOVE_USER_ROLES.value: "the AI roles were given back to the user",
    EnforcementKind.DISABLE_AUTO_TRIAGE.value: "Auto Triage was switched back on",
    EnforcementKind.DISABLE_PR_REMEDIATION.value: "PR triage and remediation was switched back on",
    EnforcementKind.DISABLE_FUSION.value: (
        "Fusion was switched back on in the project's scan settings (or its lock against "
        "per-scan override was removed)"
    ),
    EnforcementKind.DISABLE_REPO_FUSION.value: "Fusion was switched back on in the repository",
}
_FUSION_KINDS = (EnforcementKind.DISABLE_FUSION.value, EnforcementKind.DISABLE_REPO_FUSION.value)


# ------------------------------------------------------------------ recording


def _clip(value: str | None, length: int) -> str | None:
    return value[:length] if isinstance(value, str) else None


def record(
    session: Session,
    *,
    kind: str,
    dedupe_key: str,
    title: str,
    detail: str,
    target_type: str,
    target_id: str,
    target_label: str | None,
    limit: CreditLimit | None = None,
    action_id: int | None = None,
    actor: str | None = None,
    source: str | None = None,
    evidence: dict[str, Any] | None = None,
    credits: Decimal | None = None,
    severity: Severity = Severity.WARNING,
    public_detail: str | None = None,
    notify: bool = True,
    notification_key: str | None = None,
    category: str = notifications.CATEGORY_POLICY,
) -> PolicyViolation | None:
    """Record a violation once (by ``dedupe_key``). None when already recorded.

    Raises the notification and writes the audit entry in the caller's
    transaction; the caller commits. Never called with a Checkmarx call open.

    Only the violation row (admins only) names people. The notification and the
    audit entry are visible to viewers, so they carry ``public_detail`` (the
    project and what happened, never who), and the audit records only whether
    a person was named. ``notify`` False records the row alone: no notification
    and no audit entry. ``notification_key`` lets several rows about one event
    share a single notification; ``category`` is the notification's.
    """
    key = dedupe_key[:200]
    if session.scalar(select(PolicyViolation.id).where(PolicyViolation.dedupe_key == key)):
        return None
    violation = PolicyViolation(
        kind=kind,
        detected_at=utcnow(),
        limit_id=limit.id if limit is not None else None,
        limit_label=_clip(
            (limit.entity_label or limit.entity_id) if limit is not None else None, 512
        ),
        enforcement_action_id=action_id,
        target_type=target_type,
        target_id=target_id[:64],
        target_label=_clip(target_label, 512),
        actor=_clip(actor, 320),
        source=_clip(source, 128),
        detail=detail,
        evidence=evidence,
        credits=credits,
        severity=str(severity),
        status=STATUS_OPEN,
        dedupe_key=key,
    )
    try:
        with session.begin_nested():
            session.add(violation)
            session.flush()
    except IntegrityError:
        # Another writer recorded the same finding in the meantime.
        return None
    if not notify:
        return violation
    public = public_detail if public_detail is not None else detail
    notifications.notify(
        session,
        category=category,
        severity=severity,
        title=title,
        body=_notification_body(public),
        entity_type=limit.entity_type if limit is not None else None,
        entity_id=limit.entity_id if limit is not None else None,
        entity_label=limit.entity_label if limit is not None else None,
        dedupe_key=(notification_key or f"violation:{violation.id}")[:200],
        enforcement_action_id=action_id,
    )
    record_audit(
        session,
        action="violation.detected",
        actor=AuditActor.system("violations"),
        target_type=AUDIT_TARGET,
        target_id=str(violation.id),
        target_label=target_label,
        after={
            "kind": kind,
            "target_type": target_type,
            "target_id": target_id,
            # Who it was is on the violation itself (admins only), not here.
            "actor_recorded": actor is not None,
            "source": source,
            "credits": str(credits) if credits is not None else None,
        },
        detail=public[:1000],
    )
    return violation


def _notification_body(public: str) -> str:
    return (
        public + "\n\nIt is recorded on the Policy violations page, where an admin can see the "
        "details, acknowledge it and resolve it."
    )


def record_reenabled(
    session: Session,
    *,
    action: EnforcementAction,
    limit: CreditLimit,
    found: dict[str, Any],
    title: str | None = None,
    body: str | None = None,
) -> PolicyViolation | None:
    """A restriction read back switched on again, and re-applied (kind a).

    One row per restriction per budget period: each later find adds to its
    ``occurrences`` and moves ``last_seen`` (the restriction is re-applied every
    time all the same). None when an existing row was brought up to date.

    The notification is in the ``enforcement`` category, as a re-applied
    restriction's always was, so e-mail and webhook consumers that follow that
    category still get it. A user's AI roles, Auto Triage and PR triage and
    remediation are notified once per restriction per period (the key the
    re-applied notice always used): an IdP or SCIM sync that puts the roles
    back every day is one notification a period, not one a day. Fusion, whose
    scans cost credits, is notified once a day, and Fusion found back on in
    both the project's scan settings and its repository is one notification.
    """
    what = _REENABLED_WHAT.get(str(action.kind), "a restricted setting was switched back on")
    label = action.target_label or action.target_id
    now = utcnow()
    day = now.strftime("%Y-%m-%d")
    period = action.period_key or day
    fusion = str(action.kind) in _FUSION_KINDS
    notification_key = (
        f"violation:{KIND_SETTING_REENABLED}:{action.target_type}:{action.target_id}:fusion:{day}"
        if fusion
        else notifications.reconcile_key(action.id, period)
    )
    key = f"{KIND_SETTING_REENABLED}:{action.id}:{period}"[:200]
    row = session.scalar(select(PolicyViolation).where(PolicyViolation.dedupe_key == key))
    previous = dict(row.evidence or {}) if row is not None else {}
    occurrences = int(previous.get("occurrences") or 1) + 1 if row is not None else 1
    first_seen = previous.get("first_seen") or (
        row.detected_at.isoformat() if row is not None else now.isoformat()
    )
    detail = (
        f"On {label}, {what} while {limit.entity_type} limit "
        f"{limit.entity_label or limit.entity_id} restricts it. CreditGuard found it in its "
        "regular check and applied the restriction again. Checkmarx One does not say who "
        "changed it; its own audit trail may. One record per restriction per budget period: "
        f"found {occurrences} time{'s' if occurrences != 1 else ''} in {period}, last on "
        f"{now:%Y-%m-%d %H:%M} UTC."
    )
    evidence = {
        "restriction": str(action.kind),
        "found": found.get("found"),
        "origin_level": found.get("origin_level"),
        "reapplied": True,
        "restricted_since": action.applied_at.isoformat() if action.applied_at else None,
        "period": period,
        "occurrences": occurrences,
        "first_seen": first_seen,
        "last_seen": now.isoformat(),
    }
    if row is not None:
        reopened = row.status == STATUS_RESOLVED
        if reopened:
            # Resolved, and then it happened again: that is news, so the row is
            # open again rather than quietly counting a new occurrence.
            evidence["reopened_at"] = now.isoformat()
            row.status = STATUS_OPEN
            row.resolved_by = None
            row.resolved_at = None
        row.evidence = evidence
        row.detail = detail
        row.updated_at = now
        session.flush()
        if reopened:
            record_audit(
                session,
                action="violation.reopened",
                actor=AuditActor.system("violations"),
                target_type=AUDIT_TARGET,
                target_id=str(row.id),
                target_label=label,
                after={"kind": KIND_SETTING_REENABLED, "occurrences": occurrences},
                detail=f"Found again after it was resolved: {what} on {label}.",
            )
        if fusion:
            notifications.notify(
                session,
                category=notifications.CATEGORY_ENFORCEMENT,
                severity=Severity.WARNING,
                title=title or f"{label}: a restriction was undone in Checkmarx One",
                body=_notification_body(body or detail),
                entity_type=limit.entity_type,
                entity_id=limit.entity_id,
                entity_label=limit.entity_label,
                dedupe_key=notification_key,
                enforcement_action_id=action.id,
            )
        return None
    return record(
        session,
        kind=KIND_SETTING_REENABLED,
        dedupe_key=key,
        title=title or f"{label}: a restriction was undone in Checkmarx One",
        detail=detail,
        public_detail=body or detail,
        notification_key=notification_key,
        category=notifications.CATEGORY_ENFORCEMENT,
        target_type=action.target_type,
        target_id=action.target_id,
        target_label=action.target_label,
        limit=limit,
        action_id=action.id,
        evidence=evidence,
    )


# ------------------------------------------------------------- status changes


class ViolationError(ValueError):
    """The requested status change is not possible."""


def acknowledge(
    session: Session, violation: PolicyViolation, *, actor: AuditActor, note: str | None
) -> PolicyViolation:
    if violation.status == STATUS_RESOLVED:
        raise ViolationError("This violation is already resolved.")
    before = {"status": violation.status, "note": violation.note}
    violation.status = STATUS_ACKNOWLEDGED
    violation.acknowledged_by = _clip(actor.actor_name, 128)
    violation.acknowledged_at = utcnow()
    if note:
        violation.note = note
    session.flush()
    record_audit(
        session,
        action="violation.acknowledged",
        actor=actor,
        target_type=AUDIT_TARGET,
        target_id=str(violation.id),
        target_label=violation.target_label,
        before=before,
        after={"status": violation.status, "note": violation.note},
    )
    return violation


def resolve(
    session: Session, violation: PolicyViolation, *, actor: AuditActor, note: str | None
) -> PolicyViolation:
    if violation.status == STATUS_RESOLVED:
        raise ViolationError("This violation is already resolved.")
    before = {"status": violation.status, "note": violation.note}
    now = utcnow()
    if violation.acknowledged_at is None:
        violation.acknowledged_at = now
        violation.acknowledged_by = _clip(actor.actor_name, 128)
    violation.status = STATUS_RESOLVED
    violation.resolved_by = _clip(actor.actor_name, 128)
    violation.resolved_at = now
    if note:
        violation.note = note
    session.flush()
    record_audit(
        session,
        action="violation.resolved",
        actor=actor,
        target_type=AUDIT_TARGET,
        target_id=str(violation.id),
        target_label=violation.target_label,
        before=before,
        after={"status": violation.status, "note": violation.note},
    )
    return violation


def open_count(session: Session) -> int:
    """Open violations to follow up. The information rows (``INFO_KINDS``) are
    nothing to act on and never counted."""
    return int(
        session.scalar(
            select(func.count())
            .select_from(PolicyViolation)
            .where(PolicyViolation.status == STATUS_OPEN, PolicyViolation.kind.not_in(INFO_KINDS))
        )
        or 0
    )


# ------------------------------------------------------------------ detection


@dataclass
class DetectionResult:
    projects_checked: int = 0
    scans_read: int = 0
    detected: int = 0
    updated: int = 0
    skipped_projects: int = 0
    truncated: int = 0
    errors: list[str] = field(default_factory=list)

    def as_stats(self) -> dict[str, Any]:
        return {
            "ok": not self.errors,
            "projects_checked": self.projects_checked,
            "scans_read": self.scans_read,
            "detected": self.detected,
            "updated": self.updated,
            "skipped_projects": self.skipped_projects,
            "truncated": self.truncated,
            "errors": self.errors,
        }


@dataclass(frozen=True, slots=True)
class _FusionWatch:
    project_id: str
    label: str | None
    since: datetime
    action_id: int
    limit_id: int | None


def detect(session: Session, client: CheckmarxClient) -> DetectionResult:
    """Look for violations of the restrictions in force. The cycle's step.

    Commits before every Checkmarx call and after each project's findings.
    """
    result = DetectionResult()
    try:
        _detect_scans(session, client, result)
    except CheckmarxAuthError:
        raise
    _detect_usage(session, result)
    session.commit()
    return result


def _fusion_watches(session: Session) -> list[_FusionWatch]:
    """Projects with a Fusion restriction in force, earliest restriction first."""
    earliest: dict[str, EnforcementAction] = {}
    for action in session.scalars(
        select(EnforcementAction)
        .where(
            EnforcementAction.kind.in_(_FUSION_KINDS),
            EnforcementAction.status == EnforcementStatus.APPLIED,
            EnforcementAction.applied_at.is_not(None),
        )
        .order_by(EnforcementAction.applied_at, EnforcementAction.id)
    ):
        earliest.setdefault(action.target_id, action)
    return [
        _FusionWatch(
            project_id=action.target_id,
            label=action.target_label,
            since=action.applied_at,  # type: ignore[arg-type]
            action_id=action.id,
            limit_id=action.limit_id,
        )
        for action in earliest.values()
    ]


def _cursors(session: Session) -> dict[str, Any]:
    value = settings_store.get_value(session, settings_store.KEY_VIOLATION_SCAN_CURSORS)
    return dict(value) if isinstance(value, dict) else {}


def _scan_state(entry: Any) -> tuple[datetime | None, dict[str, str]]:
    """A project's cursor and its pending scans (id -> created at).

    An entry is ``{"at": ..., "pending": {...}}``; a plain timestamp (as first
    written) is a cursor with nothing pending.
    """
    if isinstance(entry, str):
        return scans_api.parse_time(entry), {}
    if not isinstance(entry, dict):
        return None, {}
    pending = entry.get("pending")
    return (
        scans_api.parse_time(entry.get("at")),
        {
            str(scan_id): str(at)
            for scan_id, at in (pending.items() if isinstance(pending, dict) else ())
            if isinstance(at, str)
        },
    )


def _model_key(name: str | None) -> str | None:
    """A model name as one comparable key: ``opus-5.5`` and ``Opus 5.5`` match."""
    if not isinstance(name, str):
        return None
    words = [word for word in re.split(r"[\s_\-]+", name.strip().lower()) if word]
    return "_".join(words) or None


def _fusion_price(
    model: str | None, rates: dict[str, tuple[Decimal, str | None]]
) -> Decimal | None:
    """Credits per Fusion scan with this model (``opus-5.5``), when the rates say.

    The model must match a Fusion rate's model exactly (by its action type or
    its display name): ``opus-5.5`` never takes the price of ``x-opus-5.5``.
    """
    wanted = _model_key(model)
    if wanted is None:
        return None
    for key, (price, display) in rates.items():
        if usage_api.normalise_action_type(key) != ActionType.FUSION:
            continue
        for name in (key, display):
            if _model_key(usage_api.fusion_model(name)) == wanted:
                return price
    return None


def _scan_day(scan: scans_api.ScanSummary) -> str:
    moment = scan.created_at or utcnow()
    return moment.strftime("%Y-%m-%d")


def _recorded_scan_ids(session: Session, watch: _FusionWatch) -> set[str]:
    """Scans already recorded for this restriction: never read again.

    The Fusion scans of the project (their key names the scan) and the scans
    counted on this restriction's AI-scan information rows.
    """
    prefix = f"{KIND_FUSION_SCAN}:{watch.project_id}:"
    recorded = {
        key[len(prefix) :]
        for key in session.scalars(
            select(PolicyViolation.dedupe_key).where(
                PolicyViolation.kind == KIND_FUSION_SCAN,
                PolicyViolation.target_id == watch.project_id,
            )
        )
        if key.startswith(prefix)
    }
    for evidence in session.scalars(
        select(PolicyViolation.evidence).where(
            PolicyViolation.kind == KIND_AI_SCAN,
            PolicyViolation.enforcement_action_id == watch.action_id,
        )
    ):
        if isinstance(evidence, dict):
            recorded.update(str(scan_id) for scan_id in evidence.get("scan_ids") or [])
    return recorded


@dataclass
class _ProjectScans:
    """One restricted project's scans this cycle, between listing and recording."""

    watch: _FusionWatch
    cursor: datetime | None
    since: datetime
    listing: scans_api.ScanListing
    now: datetime
    found: list[scans_api.ScanSummary] = field(default_factory=list)
    # Scans not yet classified for good (queued or running), by id.
    pending: dict[str, datetime] = field(default_factory=dict)
    # Scans that need their own read (id, created at), earliest first.
    to_read: list[tuple[str, datetime]] = field(default_factory=list)
    reads_granted: int = 0


def _detect_scans(session: Session, client: CheckmarxClient, result: DetectionResult) -> None:
    """Classify the scans made on each project whose Fusion restriction is in force.

    Per project, scans are listed newest first back to its cursor. A scan
    already recorded is never read again, so a scan that holds the cursor back
    (still running) costs nothing for the scans after it. Scans not yet
    classified (queued or running, or whose settings the listing left out with
    no read left) are kept by id as pending and found again next cycle, from the
    listing while the cursor is held before them, and by their own read once it
    has moved on. The cursor stops before the earliest pending scan in the
    listing; a listing cut off by the page cap moves it past what was listed,
    and the scans it could not reach are said once (``scans_not_checked``)
    instead of holding detection still for ever.

    Every project is listed first; the cycle's single-scan reads are then
    handed out one at a time to each project that needs one in turn, so one
    busy project can neither starve the others nor be held back by idle ones.
    """
    watches = _fusion_watches(session)
    if not watches:
        return
    if len(watches) > MAX_PROJECTS_PER_CYCLE:
        result.skipped_projects += len(watches) - MAX_PROJECTS_PER_CYCLE
        watches = watches[:MAX_PROJECTS_PER_CYCLE]
    cursors = _cursors(session)
    rates = usage_mix.rate_table(session)

    # 1. List each project's scans and sort them out, without single-scan reads.
    projects: list[_ProjectScans] = []
    for watch in watches:
        cursor, kept_pending = _scan_state(cursors.get(watch.project_id))
        since = max(watch.since, cursor) if cursor is not None else watch.since
        recorded = _recorded_scan_ids(session, watch)
        session.commit()  # nothing open while Checkmarx is called
        try:
            listing = scans_api.list_project_scans(
                client,
                project_id=watch.project_id,
                since=since,
                page_size=SCAN_PAGE_SIZE,
                max_pages=MAX_PAGES_PER_PROJECT,
            )
        except CheckmarxAuthError:
            raise
        except CheckmarxError as exc:
            session.rollback()
            logger.warning(
                "Could not list the scans of restricted project %s: %s", watch.project_id, exc
            )
            result.errors.append(f"{watch.label or watch.project_id}: {exc}")
            continue
        result.scans_read += len(listing.scans)
        project = _ProjectScans(
            watch=watch, cursor=cursor, since=since, listing=listing, now=utcnow()
        )
        listed = {scan.id for scan in listing.scans}
        for scan in listing.scans:
            if scan.id in recorded:
                continue
            if scan.created_at is None or scan.created_at <= watch.since:
                continue
            if scan.status.strip().lower() in _NOT_RUN or not scan.ran_ai:
                continue
            if _waiting(scan, scan.created_at, project.now):
                project.pending[scan.id] = scan.created_at
            elif scan.has_configs:
                project.found.append(scan)
            else:
                # The listing left the scan's settings out; its own read has them.
                project.to_read.append((scan.id, scan.created_at))
        # Pending scans the listing no longer reaches: read one by one.
        for scan_id, at in kept_pending.items():
            created = scans_api.parse_time(at)
            if scan_id not in listed and scan_id not in recorded and created is not None:
                project.to_read.append((scan_id, created))
        project.to_read.sort(key=lambda item: item[1])
        projects.append(project)

    # 2. Hand out the single-scan reads, one per project in turn.
    reads_left = MAX_SCAN_READS_PER_CYCLE
    while reads_left > 0:
        wanting = [p for p in projects if p.reads_granted < len(p.to_read)]
        if not wanting:
            break
        for project in wanting:
            if reads_left <= 0:
                break
            project.reads_granted += 1
            reads_left -= 1

    # 3. Per project: its reads, then its findings and its cursor, committed.
    for project in projects:
        watch = project.watch
        listed_scans = {scan.id: scan for scan in project.listing.scans}
        session.commit()  # nothing open while Checkmarx is called
        for position, (scan_id, created) in enumerate(project.to_read):
            if position >= project.reads_granted:
                project.pending[scan_id] = created  # no read left: next cycle
                continue
            try:
                scan = scans_api.get_scan(client, scan_id=scan_id)
            except CheckmarxAuthError:
                raise
            except CheckmarxNotFoundError:
                continue  # deleted since: nothing to record
            except CheckmarxError as exc:
                # One scan's read failing stops nothing else: looked at again.
                logger.warning("Could not read scan %s: %s", scan_id, exc)
                project.pending[scan_id] = created
                continue
            scan = scan or listed_scans.get(scan_id)
            if scan is None:
                continue
            if scan.status.strip().lower() in _NOT_RUN or not scan.ran_ai:
                continue
            if _waiting(scan, scan.created_at or created, project.now):
                project.pending[scan_id] = created
                continue
            project.found.append(scan)
        result.projects_checked += 1
        state_before = cursors.get(watch.project_id)
        try:
            _record_project_scans(session, project, cursors=cursors, rates=rates, result=result)
            session.commit()
        except Exception as exc:  # noqa: BLE001 - one project must not stop the others
            session.rollback()
            # Its cursor stays where it was: nothing it moved past was recorded.
            if state_before is None:
                cursors.pop(watch.project_id, None)
            else:
                cursors[watch.project_id] = state_before
            logger.warning(
                "Could not record the scans of project %s", watch.project_id, exc_info=True
            )
            result.errors.append(f"{watch.label or watch.project_id}: {exc}")


def _record_project_scans(
    session: Session,
    project: _ProjectScans,
    *,
    cursors: dict[str, Any],
    rates: dict[str, tuple[Decimal, str | None]],
    result: DetectionResult,
) -> None:
    """Record one project's findings and move its cursor (no commit)."""
    watch = project.watch
    listing = project.listing
    pending = project.pending
    limit = session.get(CreditLimit, watch.limit_id) if watch.limit_id else None
    for scan in project.found:
        if _record_scan(session, watch=watch, scan=scan, limit=limit, rates=rates):
            result.detected += 1
    created_times = [scan.created_at for scan in listing.scans if scan.created_at]
    dropped = 0
    if len(pending) > MAX_PENDING_PER_PROJECT:
        # The newest are kept; the oldest are said not checked.
        ordered = sorted(pending.items(), key=lambda item: item[1], reverse=True)
        pending = dict(ordered[:MAX_PENDING_PER_PROJECT])
        dropped = len(ordered) - MAX_PENDING_PER_PROJECT
    listed = {scan.id for scan in listing.scans}
    cursor_at: datetime | None
    if listing.truncated:
        # More scans since ``since`` than one listing reaches: those behind the
        # ones read cannot be reached, now or later (the listing is newest
        # first). Said once, and the cursor moves on.
        result.truncated += 1
        cursor_at = max(created_times, default=project.cursor)
        _note_not_checked(
            session,
            watch=watch,
            limit=limit,
            after=project.since,
            before=min(created_times, default=None),
            dropped=dropped,
        )
    else:
        if dropped:
            _note_not_checked(
                session, watch=watch, limit=limit, after=None, before=None, dropped=dropped
            )
        held = [at for scan_id, at in pending.items() if scan_id in listed]
        # Listed again from the earliest pending scan in the listing (the
        # listing includes a scan created at ``since``).
        cursor_at = min(held) if held else max(created_times, default=project.cursor)
    state: dict[str, Any] = {
        "at": cursor_at.isoformat() if cursor_at is not None else None,
        "pending": {scan_id: at.isoformat() for scan_id, at in pending.items()},
    }
    if cursors.get(watch.project_id) != state:
        cursors[watch.project_id] = state
        settings_store.set_value(
            session,
            settings_store.KEY_VIOLATION_SCAN_CURSORS,
            _bounded_cursors(session, cursors),
            description=(
                "Newest scan looked at, and scans not classified yet, per restricted project "
                "(bookkeeping)."
            ),
        )


def _waiting(scan: scans_api.ScanSummary, created: datetime, now: datetime) -> bool:
    """Not final yet (queued, running), and not waited for long enough."""
    return scan.status.strip().lower() not in _FINAL and now - created < MAX_WAIT_FOR_A_SCAN


def _note_not_checked(
    session: Session,
    *,
    watch: _FusionWatch,
    limit: CreditLimit | None,
    after: datetime | None,
    before: datetime | None,
    dropped: int,
) -> None:
    """Scans on this project that could not be looked at: said once per restriction.

    Information, not a violation (no notification, no audit entry): a later
    occurrence brings the one row up to date.
    """
    label = watch.label or watch.project_id
    key = f"{KIND_SCANS_NOT_CHECKED}:{watch.action_id}"
    now = utcnow()
    row = session.scalar(select(PolicyViolation).where(PolicyViolation.dedupe_key == key))
    previous = dict(row.evidence or {}) if row is not None else {}
    windows = list(previous.get("windows") or [])
    if after is not None or before is not None:
        window = {
            "after": after.isoformat() if after else None,
            "before": before.isoformat() if before else None,
        }
        if window not in windows:
            windows = [*windows, window][-20:]
    occurrences = int(previous.get("occurrences") or 0) + 1
    pending_dropped = int(previous.get("pending_dropped") or 0) + dropped
    evidence = {
        "occurrences": occurrences,
        "windows": windows,
        "pending_dropped": pending_dropped,
        "first_seen": previous.get("first_seen") or now.isoformat(),
        "last_seen": now.isoformat(),
        "restricted_since": watch.since.isoformat(),
        "max_listed_per_cycle": SCAN_PAGE_SIZE * MAX_PAGES_PER_PROJECT,
    }
    detail = (
        f"More scans were made on {label} since it was last looked at than one cycle lists "
        f"({SCAN_PAGE_SIZE * MAX_PAGES_PER_PROJECT}), so the older ones in between were not "
        "checked for Fusion. The newest were, and detection carries on from them. "
        f"It happened {occurrences} time{'s' if occurrences != 1 else ''} during this "
        "restriction (the windows not checked are in the evidence)."
        + (
            f" {pending_dropped} scan{'s' if pending_dropped != 1 else ''} still running were "
            "also given up on because too many were waiting."
            if pending_dropped
            else ""
        )
        + " Information only: the consumption feed still counts Fusion used there."
    )
    if row is not None:
        row.evidence = evidence
        row.detail = detail
        row.updated_at = now
        session.flush()
        return
    record(
        session,
        kind=KIND_SCANS_NOT_CHECKED,
        dedupe_key=key,
        title=f"{label}: scans not checked",
        detail=detail,
        target_type="cx_project",
        target_id=watch.project_id,
        target_label=watch.label,
        limit=limit,
        action_id=watch.action_id,
        evidence=evidence,
        severity=Severity.INFO,
        notify=False,
    )


def _bounded_cursors(session: Session, cursors: dict[str, Any]) -> dict[str, Any]:
    """Only the projects still restricted keep a cursor."""
    live = {watch.project_id for watch in _fusion_watches(session)}
    return {project: at for project, at in cursors.items() if project in live}


def _record_scan(
    session: Session,
    *,
    watch: _FusionWatch,
    scan: scans_api.ScanSummary,
    limit: CreditLimit | None,
    rates: dict[str, tuple[Decimal, str | None]],
) -> bool:
    if not scan.fusion:
        return _count_ai_scan(session, watch=watch, scan=scan, limit=limit)
    label = watch.label or watch.project_id
    model = scan.llm_model
    # Only a scan that finished is priced: one still running after a day (it
    # was waited for that long) may yet fail or be cancelled, and costs nothing then.
    finished = scan.status.strip().lower() in scans_api.COMPLETED_STATUSES
    price = _fusion_price(model, rates) if finished else None
    source = " / ".join(part for part in (scan.source_origin, scan.source_type) if part) or None
    evidence = {
        "scan_id": scan.id,
        "status": scan.status,
        "branch": scan.branch,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "engines": list(scan.engines),
        "fusion_enabled": scan.fusion,
        "llm_model": model,
        "source_origin": scan.source_origin,
        "source_type": scan.source_type,
        "credits_per_scan": str(price) if price is not None else None,
        "restricted_since": watch.since.isoformat(),
    }
    who = scan.initiator or "someone Checkmarx One does not name"
    cost = (
        f" At the current rate a Fusion scan with {model} costs "
        f"{usage_mix.format_credits(price)} credits."
        if price is not None and model
        else ""
    )
    unfinished = "" if finished else f" It had not finished when it was checked ({scan.status})."
    what = (
        f"Scan {scan.id} on {label} ran Fusion{f' ({model})' if model else ''} although "
        "Fusion is turned off for the project by a restriction in force."
    )
    detail = (
        f"{what} It was started by {who}{f' from {source}' if source else ''}"
        f"{f' on branch {scan.branch}' if scan.branch else ''}: a scan started with its "
        f"own settings can turn Fusion on for itself.{cost}{unfinished}"
    )
    # Seen by viewers too: the project and what happened, not who.
    public = (
        f"{what}{f' It came from {source}.' if source else ''} A scan started with its own "
        f"settings can turn Fusion on for itself.{cost}{unfinished}"
    )
    return (
        record(
            session,
            kind=KIND_FUSION_SCAN,
            dedupe_key=f"{KIND_FUSION_SCAN}:{watch.project_id}:{scan.id}",
            title=f"{label}: a scan ran Fusion during a restriction",
            detail=detail,
            public_detail=public,
            target_type="cx_project",
            target_id=watch.project_id,
            target_label=watch.label,
            limit=limit,
            action_id=watch.action_id,
            actor=scan.initiator,
            source=source,
            evidence=evidence,
            credits=price,
        )
        is not None
    )


def _count_ai_scan(
    session: Session,
    *,
    watch: _FusionWatch,
    scan: scans_api.ScanSummary,
    limit: CreditLimit | None,
) -> bool:
    """An AI scan without Fusion on a project whose Fusion is turned off.

    That is the restriction working, not a violation: no notification and no
    audit entry. One information row per restriction per day keeps the count
    (scans that ran without Fusion, and scans that do not say), for anyone who
    wants to see how much the AI engine still runs there. True when the row was
    created (not when an existing one was added to).
    """
    label = watch.label or watch.project_id
    day = _scan_day(scan)
    key = f"{KIND_AI_SCAN}:{watch.action_id}:{day}"
    row = session.scalar(select(PolicyViolation).where(PolicyViolation.dedupe_key == key))
    previous = dict(row.evidence or {}) if row is not None else {}
    scan_ids = list(previous.get("scan_ids") or [])
    if scan.id in scan_ids:
        return False  # already counted (a listing read again)
    counts = {
        "without_fusion": int(previous.get("without_fusion") or 0),
        "not_said": int(previous.get("not_said") or 0),
    }
    counts["without_fusion" if scan.fusion is False else "not_said"] += 1
    approximate = bool(previous.get("approximate"))
    if len(scan_ids) < MAX_AI_SCAN_IDS:
        scan_ids.append(scan.id)
    else:
        # Past this many, a scan read twice could be counted twice.
        approximate = True
    initiators = list(previous.get("initiators") or [])
    if scan.initiator and scan.initiator not in initiators and len(initiators) < 20:
        initiators.append(scan.initiator)
    total = counts["without_fusion"] + counts["not_said"]
    evidence = {
        "day": day,
        "scans": total,
        **counts,
        "approximate": approximate,
        "scan_ids": scan_ids,
        "initiators": initiators,
        "restricted_since": watch.since.isoformat(),
    }
    detail = (
        f"{'At least ' if approximate else ''}{total} scan{'s' if total != 1 else ''} on "
        f"{label} ran the AI engine on {day} while Fusion is turned off for the project by a "
        f"restriction ({counts['without_fusion']} without Fusion, {counts['not_said']} that "
        "do not say). That is the restriction working; it is recorded for information "
        "only, without a notification. Whether LLM-based scanning without Fusion costs "
        "credits is not known."
    )
    if row is not None:
        row.evidence = evidence
        row.detail = detail
        row.updated_at = utcnow()
        session.flush()
        return False
    return (
        record(
            session,
            kind=KIND_AI_SCAN,
            dedupe_key=key,
            title=f"{label}: AI scans during a Fusion restriction",
            detail=detail,
            target_type="cx_project",
            target_id=watch.project_id,
            target_label=watch.label,
            limit=limit,
            action_id=watch.action_id,
            evidence=evidence,
            severity=Severity.INFO,
            notify=False,
        )
        is not None
    )


# ---------------------------------------------------------------- usage rise


# What each restriction is meant to stop, as consumption action types.
_STOPS: dict[str, tuple[str, ...]] = {
    EnforcementKind.REMOVE_USER_ROLES.value: ("triage", "remediation"),
    EnforcementKind.DISABLE_AUTO_TRIAGE.value: ("auto_triage",),
    EnforcementKind.DISABLE_FUSION.value: ("fusion",),
    EnforcementKind.DISABLE_REPO_FUSION.value: ("fusion",),
}


def _record_for(session: Session, snapshot: UsageSnapshot, entity_id: str) -> UsageRecord | None:
    return session.scalar(
        select(UsageRecord)
        .where(UsageRecord.snapshot_id == snapshot.id, UsageRecord.entity_id == entity_id)
        .limit(1)
    )


def _bucketed(record: UsageRecord | None) -> dict[str, int]:
    totals: dict[str, int] = {}
    for action, count in ((record.actions if record else None) or {}).items():
        if isinstance(count, int) and not isinstance(count, bool):
            key = usage_mix.bucket(action)
            totals[key] = totals.get(key, 0) + count
    return totals


def _detect_usage(session: Session, result: DetectionResult) -> None:
    groups: dict[tuple[str, str], list[EnforcementAction]] = {}
    for action in session.scalars(
        select(EnforcementAction)
        .where(
            EnforcementAction.status == EnforcementStatus.APPLIED,
            EnforcementAction.applied_at.is_not(None),
        )
        .order_by(EnforcementAction.applied_at, EnforcementAction.id)
    ):
        if str(action.kind) in _STOPS:
            groups.setdefault((action.target_type, action.target_id), []).append(action)
    for (target_type, target_id), actions in groups.items():
        try:
            outcome = _usage_for_target(session, target_type, target_id, actions)
            if outcome == "detected":
                result.detected += 1
            elif outcome == "updated":
                result.updated += 1
            session.commit()
        except Exception as exc:  # noqa: BLE001 - one target must not stop the others
            session.rollback()
            logger.warning("Could not check usage after restricting %s", target_id, exc_info=True)
            result.errors.append(f"usage of {target_id}: {exc}")


def _usage_for_target(
    session: Session, target_type: str, target_id: str, actions: list[EnforcementAction]
) -> str | None:
    """ "detected", "updated", or None when there is nothing (new) to say.

    Each action type is measured from its own restriction: Fusion restricted
    after Auto Triage is compared with the reading before *Fusion* was
    restricted, so Fusion used legitimately in between is not reported.
    """
    first = actions[0]
    view = UsageView.USER.value if target_type == "cx_user" else UsageView.PROJECT.value
    latest = ingestion.latest_snapshot(session, view)
    if latest is None:
        return None
    now_record = _record_for(session, latest, target_id)
    if now_record is None:
        return None
    now_counts = _bucketed(now_record)
    # The earliest applied restriction that stops each action type (actions
    # are in applied order).
    since_by_type: dict[str, EnforcementAction] = {}
    for action in actions:
        for stop in _STOPS[str(action.kind)]:
            since_by_type.setdefault(stop, action)
    rises: dict[str, int] = {}
    baselines: dict[str, UsageSnapshot] = {}
    for action_type in sorted(since_by_type):
        restricted = since_by_type[action_type]
        before = usage_mix._snapshot_at(session, view, restricted.applied_at)  # type: ignore[arg-type]
        if before is None or before.id == latest.id:
            continue
        then_counts = _bucketed(_record_for(session, before, target_id))
        rise = now_counts.get(action_type, 0) - then_counts.get(action_type, 0)
        if rise < 0:
            # Older transactions left the lookback window: new ones cannot be
            # told apart from them, so nothing is claimed.
            return None
        if rise > 0:
            rises[action_type] = rise
            baselines[action_type] = before
    if not rises:
        return None
    # The credits rise is measured from the baseline of the earliest restriction
    # whose action type rose (evidence only; priced below for Fusion alone).
    earliest_type = min(rises, key=lambda t: (since_by_type[t].applied_at, since_by_type[t].id))
    before = baselines[earliest_type]
    then_record = _record_for(session, before, target_id)
    credits_rise = Decimal(now_record.credits_used or 0) - Decimal(
        (then_record.credits_used if then_record else 0) or 0
    )
    credits: Decimal | None = None
    if set(rises) == {"fusion"}:
        priced = usage_mix._price_fusion(
            session,
            latest=usage_mix._fusion_models(session, latest, [target_id]),
            baseline=usage_mix._fusion_models(session, before, [target_id]),
            fusion_rise=rises["fusion"],
            own=max(credits_rise, Decimal("0")),
        )
        if priced:
            credits = sum((part[3] for part in priced), Decimal("0"))
    label = first.target_label or target_id
    listed = ", ".join(
        f"{usage_mix.ACTION_LABELS.get(action_type, action_type)} {count} transaction"
        f"{'s' if count != 1 else ''}"
        for action_type, count in rises.items()
    )
    detail = (
        f"After {label} was restricted on "
        f"{since_by_type[earliest_type].applied_at:%Y-%m-%d %H:%M} UTC, the consumption "
        f"feed kept counting what the restriction is meant to stop: {listed}"
        + (f", about {usage_mix.format_credits(credits)} credits" if credits is not None else "")
        + ". Credits can be billed a little after the action, so a small rise straight after "
        "a restriction may come from before it."
    )
    evidence = {
        "rise_by_action": rises,
        "credits_rise": str(credits_rise),
        "restricted_since": first.applied_at.isoformat() if first.applied_at else None,
        "restricted_since_by_action": {
            action_type: since_by_type[action_type].applied_at.isoformat()  # type: ignore[union-attr]
            for action_type in rises
        },
        "baseline_reading_at": before.collected_at.isoformat(),
        "baseline_reading_at_by_action": {
            action_type: baselines[action_type].collected_at.isoformat() for action_type in rises
        },
        "latest_reading_at": latest.collected_at.isoformat(),
        "restrictions": sorted({str(action.kind) for action in actions}),
    }
    key = f"{KIND_USAGE_AFTER}:{target_type}:{target_id}:{first.id}"
    existing = session.scalar(select(PolicyViolation).where(PolicyViolation.dedupe_key == key))
    if existing is not None:
        # One record per restriction, brought up to date while it keeps rising.
        if existing.status != STATUS_RESOLVED and existing.evidence != evidence:
            existing.evidence = evidence
            existing.detail = detail
            existing.credits = credits
            existing.updated_at = utcnow()
            return "updated"
        return None
    limit = session.get(CreditLimit, first.limit_id) if first.limit_id else None
    created = (
        record(
            session,
            kind=KIND_USAGE_AFTER,
            dedupe_key=key,
            title=f"{label}: usage kept rising after a restriction",
            detail=detail,
            target_type=target_type,
            target_id=target_id,
            target_label=first.target_label,
            limit=limit,
            action_id=first.id,
            actor=first.target_label if target_type == "cx_user" else None,
            evidence=evidence,
            credits=credits,
        )
        is not None
    )
    return "detected" if created else None
