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
  Fusion (LLM-based scanning), or the scan does not say which. Information
  only: whether that costs credits is not known.
* ``usage_after_restriction`` - what the restriction is meant to stop (a user's
  AI Triage and AI Remediation; a project's Auto Triage or Fusion) kept rising
  in the consumption feed after it was applied. One record per restriction,
  brought up to date while it keeps rising. Credits can be billed a little
  after the action, so a small rise right after a restriction may predate it.

Each new violation raises one notification (category ``policy``) and an audit
entry (``violation.detected``); acknowledging and resolving are audited too.
The scan listing is bounded like the auto-triage scan reads, nothing here holds
a database write lock across a Checkmarx call, and one project's failure never
stops the others.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.checkmarx import scans as scans_api
from app.checkmarx import usage as usage_api
from app.checkmarx.client import CheckmarxClient
from app.checkmarx.errors import CheckmarxAuthError, CheckmarxError
from app.db.base import utcnow
from app.models.enums import ActionType, EnforcementKind, EnforcementStatus, Severity, UsageView
from app.models.limits import CreditLimit, EnforcementAction
from app.models.usage import UsageRecord, UsageSnapshot
from app.models.violations import (
    KIND_AI_SCAN,
    KIND_FUSION_SCAN,
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
MAX_SCAN_READS_PER_CYCLE = 50
# Statuses of a scan that never ran its engines.
_NOT_RUN = frozenset({"failed", "canceled", "cancelled"})

KIND_LABELS: dict[str, str] = {
    KIND_SETTING_REENABLED: "Setting switched back on",
    KIND_FUSION_SCAN: "Fusion scan during a restriction",
    KIND_AI_SCAN: "AI scan without Fusion during a restriction",
    KIND_USAGE_AFTER: "Usage kept rising after a restriction",
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
) -> PolicyViolation | None:
    """Record a violation once (by ``dedupe_key``). None when already recorded.

    Raises the notification and writes the audit entry in the caller's
    transaction; the caller commits. Never called with a Checkmarx call open.
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
    notifications.notify(
        session,
        category=notifications.CATEGORY_POLICY,
        severity=severity,
        title=title,
        body=detail
        + "\n\nIt is recorded on the Policy violations page, where it can be acknowledged "
        "and resolved.",
        entity_type=limit.entity_type if limit is not None else None,
        entity_id=limit.entity_id if limit is not None else None,
        entity_label=limit.entity_label if limit is not None else None,
        dedupe_key=f"violation:{violation.id}",
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
            "actor": actor,
            "source": source,
            "credits": str(credits) if credits is not None else None,
        },
        detail=detail[:1000],
    )
    return violation


def record_reenabled(
    session: Session,
    *,
    action: EnforcementAction,
    limit: CreditLimit,
    found: dict[str, Any],
) -> PolicyViolation | None:
    """A restriction read back switched on again, and re-applied (kind a)."""
    what = _REENABLED_WHAT.get(str(action.kind), "a restricted setting was switched back on")
    label = action.target_label or action.target_id
    moment = utcnow()
    detail = (
        f"On {label}, {what} while {limit.entity_type} limit "
        f"{limit.entity_label or limit.entity_id} restricts it. CreditGuard found it in its "
        "regular check and applied the restriction again. Checkmarx One does not say who "
        "changed it; its own audit trail may."
    )
    return record(
        session,
        kind=KIND_SETTING_REENABLED,
        dedupe_key=f"{KIND_SETTING_REENABLED}:{action.id}:{moment.isoformat()}",
        title=f"{label}: a restriction was undone in Checkmarx One",
        detail=detail,
        target_type=action.target_type,
        target_id=action.target_id,
        target_label=action.target_label,
        limit=limit,
        action_id=action.id,
        evidence={
            "restriction": str(action.kind),
            "found": found.get("found"),
            "origin_level": found.get("origin_level"),
            "reapplied": True,
            "restricted_since": action.applied_at.isoformat() if action.applied_at else None,
        },
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
    return int(
        session.scalar(
            select(func.count())
            .select_from(PolicyViolation)
            .where(PolicyViolation.status == STATUS_OPEN)
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


def _cursors(session: Session) -> dict[str, str]:
    value = settings_store.get_value(session, settings_store.KEY_VIOLATION_SCAN_CURSORS)
    return dict(value) if isinstance(value, dict) else {}


def _fusion_price(
    model: str | None, rates: dict[str, tuple[Decimal, str | None]]
) -> Decimal | None:
    """Credits per Fusion scan with this model (``opus-5.5``), when the rates say."""
    if not model:
        return None
    suffix = usage_api.action_key(model)
    for key, (price, _display) in rates.items():
        if usage_api.normalise_action_type(key) == ActionType.FUSION and (
            key.endswith(f"_{suffix}")
        ):
            return price
    return None


def _detect_scans(session: Session, client: CheckmarxClient, result: DetectionResult) -> None:
    watches = _fusion_watches(session)
    if not watches:
        return
    cursors = _cursors(session)
    rates = usage_mix.rate_table(session)
    reads_left = MAX_SCAN_READS_PER_CYCLE
    for index, watch in enumerate(watches):
        if index >= MAX_PROJECTS_PER_CYCLE:
            result.skipped_projects += len(watches) - index
            break
        cursor = scans_api.parse_time(cursors.get(watch.project_id))
        since = max(watch.since, cursor) if cursor is not None else watch.since
        session.commit()  # nothing open while Checkmarx is called
        try:
            listing = scans_api.list_project_scans(
                client,
                project_id=watch.project_id,
                since=since,
                max_pages=MAX_PAGES_PER_PROJECT,
            )
            result.scans_read += len(listing.scans)
            found = []
            for scan in listing.scans:
                if scan.created_at is None or scan.created_at <= watch.since:
                    continue
                if scan.status.strip().lower() in _NOT_RUN or not scan.ran_ai:
                    continue
                if not scan.has_configs and reads_left > 0:
                    # The listing left the scan's settings out; its own read has them.
                    reads_left -= 1
                    scan = scans_api.get_scan(client, scan_id=scan.id) or scan
                found.append(scan)
        except CheckmarxAuthError:
            raise
        except CheckmarxError as exc:
            session.rollback()
            logger.warning(
                "Could not list the scans of restricted project %s: %s", watch.project_id, exc
            )
            result.errors.append(f"{watch.label or watch.project_id}: {exc}")
            continue
        result.projects_checked += 1
        try:
            limit = session.get(CreditLimit, watch.limit_id) if watch.limit_id else None
            for scan in found:
                if _record_scan(session, watch=watch, scan=scan, limit=limit, rates=rates):
                    result.detected += 1
            if listing.truncated:
                # Unread scans may lie behind those read: the cursor stays, and
                # the dedupe key keeps the ones read from being reported again.
                result.truncated += 1
            else:
                newest = max(
                    (scan.created_at for scan in listing.scans if scan.created_at), default=None
                )
                if newest is not None:
                    cursors[watch.project_id] = newest.isoformat()
                    settings_store.set_value(
                        session,
                        settings_store.KEY_VIOLATION_SCAN_CURSORS,
                        _bounded_cursors(session, cursors),
                        description="Newest scan looked at per restricted project (bookkeeping).",
                    )
            session.commit()
        except Exception as exc:  # noqa: BLE001 - one project must not stop the others
            session.rollback()
            logger.warning(
                "Could not record the scans of project %s", watch.project_id, exc_info=True
            )
            result.errors.append(f"{watch.label or watch.project_id}: {exc}")


def _bounded_cursors(session: Session, cursors: dict[str, str]) -> dict[str, str]:
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
    label = watch.label or watch.project_id
    model = scan.llm_model
    price = _fusion_price(model, rates) if scan.fusion else None
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
    if scan.fusion:
        cost = (
            f" At the current rate a Fusion scan with {model} costs "
            f"{usage_mix.format_credits(price)} credits."
            if price is not None and model
            else ""
        )
        detail = (
            f"Scan {scan.id} on {label} ran Fusion{f' ({model})' if model else ''} although "
            "Fusion is turned off for the project by a restriction in force. It was started by "
            f"{who}{f' from {source}' if source else ''}"
            f"{f' on branch {scan.branch}' if scan.branch else ''}: a scan started with its "
            f"own settings can turn Fusion on for itself.{cost}"
        )
        return (
            record(
                session,
                kind=KIND_FUSION_SCAN,
                dedupe_key=f"{KIND_FUSION_SCAN}:{watch.project_id}:{scan.id}",
                title=f"{label}: a scan ran Fusion during a restriction",
                detail=detail,
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
    which = (
        "without Fusion (LLM-based scanning)"
        if scan.fusion is False
        else "and does not say whether Fusion was on"
    )
    detail = (
        f"Scan {scan.id} on {label} ran the AI engine {which} while Fusion is turned off for "
        f"the project by a restriction. It was started by {who}"
        f"{f' from {source}' if source else ''}. Whether this costs credits is not known; it "
        "is recorded for information."
    )
    return (
        record(
            session,
            kind=KIND_AI_SCAN,
            dedupe_key=f"{KIND_AI_SCAN}:{watch.project_id}:{scan.id}",
            title=f"{label}: an AI scan ran during a Fusion restriction",
            detail=detail,
            target_type="cx_project",
            target_id=watch.project_id,
            target_label=watch.label,
            limit=limit,
            action_id=watch.action_id,
            actor=scan.initiator,
            source=source,
            evidence=evidence,
            severity=Severity.INFO,
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
    """ "detected", "updated", or None when there is nothing (new) to say."""
    first = actions[0]
    view = UsageView.USER.value if target_type == "cx_user" else UsageView.PROJECT.value
    watched = sorted({stop for action in actions for stop in _STOPS[str(action.kind)]})
    latest = ingestion.latest_snapshot(session, view)
    before = usage_mix._snapshot_at(session, view, first.applied_at)  # type: ignore[arg-type]
    if latest is None or before is None or latest.id == before.id:
        return None
    now_record = _record_for(session, latest, target_id)
    then_record = _record_for(session, before, target_id)
    if now_record is None:
        return None
    now_counts, then_counts = _bucketed(now_record), _bucketed(then_record)
    rises: dict[str, int] = {}
    for action_type in watched:
        rise = now_counts.get(action_type, 0) - then_counts.get(action_type, 0)
        if rise < 0:
            # Older transactions left the lookback window: new ones cannot be
            # told apart from them, so nothing is claimed.
            return None
        if rise > 0:
            rises[action_type] = rise
    if not rises:
        return None
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
        f"After {label} was restricted on {first.applied_at:%Y-%m-%d %H:%M} UTC, the consumption "
        f"feed kept counting what the restriction is meant to stop: {listed}"
        + (f", about {usage_mix.format_credits(credits)} credits" if credits is not None else "")
        + ". Credits can be billed a little after the action, so a small rise straight after "
        "a restriction may come from before it."
    )
    evidence = {
        "rise_by_action": rises,
        "credits_rise": str(credits_rise),
        "restricted_since": first.applied_at.isoformat() if first.applied_at else None,
        "baseline_reading_at": before.collected_at.isoformat(),
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
