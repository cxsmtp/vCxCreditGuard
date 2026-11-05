"""Read-only previews: enforcement blast radius and a dry-run of the next cycle.

Neither function writes anything. They answer two questions an admin wants
settled *before* turning enforcement on:

* **Blast radius** - if this entity's limit were enforced right now, exactly what
  would be restricted, and how much of it? One user's AI roles, or N projects'
  Auto Triage (and PR remediation where a repo is wired up).
* **Dry run** - across every active limit, what would the next cycle decide with
  the usage on hand, and which breaches would actually enforce? The same
  evaluation arithmetic, with the writes left out.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models.enums import EnforcementKind, LimitStatus
from app.models.limits import CreditLimit, LimitPeriodState
from app.services import enforcement, evaluation
from app.services.periods import PeriodError, current_window


@dataclass(frozen=True, slots=True)
class TargetPreview:
    kind: str
    target_type: str
    target_id: str
    target_label: str | None


@dataclass(slots=True)
class BlastRadius:
    entity_type: str
    entity_id: str
    entity_label: str | None
    exempt: bool
    affected_users: int
    affected_projects: int
    remove_user_roles: int
    disable_auto_triage: int
    disable_pr_remediation: int
    total_actions: int
    targets: list[TargetPreview] = field(default_factory=list)


def blast_radius(session: Session, *, entity_type: str, entity_id: str) -> BlastRadius:
    """What enforcing this entity's limit would change, computed read-only."""
    exempt = enforcement.is_exempt(session, entity_type=entity_type, entity_id=entity_id)
    targets = enforcement.plan_targets(session, entity_type=entity_type, entity_id=entity_id)

    projects: set[str] = set()
    users: set[str] = set()
    counts = {
        EnforcementKind.REMOVE_USER_ROLES: 0,
        EnforcementKind.DISABLE_AUTO_TRIAGE: 0,
        EnforcementKind.DISABLE_PR_REMEDIATION: 0,
    }
    previews: list[TargetPreview] = []
    for target in targets:
        counts[target.kind] = counts.get(target.kind, 0) + 1
        if target.kind == EnforcementKind.REMOVE_USER_ROLES:
            users.add(target.target_id)
        else:
            projects.add(target.target_id)
        previews.append(
            TargetPreview(
                kind=str(target.kind),
                target_type=target.target_type,
                target_id=target.target_id,
                target_label=target.target_label,
            )
        )

    label = enforcement_entity_label(session, entity_type=entity_type, entity_id=entity_id)
    return BlastRadius(
        entity_type=entity_type,
        entity_id=entity_id,
        entity_label=label,
        exempt=exempt,
        affected_users=len(users),
        affected_projects=len(projects),
        remove_user_roles=counts[EnforcementKind.REMOVE_USER_ROLES],
        disable_auto_triage=counts[EnforcementKind.DISABLE_AUTO_TRIAGE],
        disable_pr_remediation=counts[EnforcementKind.DISABLE_PR_REMEDIATION],
        total_actions=len(previews),
        targets=previews,
    )


def enforcement_entity_label(session: Session, *, entity_type: str, entity_id: str) -> str | None:
    from app.services import limits_service

    return limits_service.resolve_entity_label(
        session, entity_type=entity_type, entity_id=entity_id
    )


@dataclass(slots=True)
class DryRunRow:
    limit_id: int
    entity_type: str
    entity_id: str
    entity_label: str | None
    credit_limit: int
    enforce: bool
    exempt: bool
    usage_available: bool
    credits_used: Decimal
    percent_used: float | None
    projected_status: str
    would_enforce: bool
    blast: BlastRadius | None
    note: str | None = None


@dataclass(slots=True)
class DryRunResult:
    generated_at: datetime
    rows: list[DryRunRow] = field(default_factory=list)
    would_enforce_count: int = 0
    would_warn_count: int = 0
    affected_projects: int = 0
    affected_users: int = 0


def dry_run(session: Session, *, now: datetime | None = None) -> DryRunResult:
    """Project what the next evaluation cycle would decide, writing nothing."""
    moment = now or utcnow()
    index = evaluation.UsageIndex(session)
    result = DryRunResult(generated_at=moment)
    all_projects: set[str] = set()
    all_users: set[str] = set()

    # The real cycle defers every restriction when no tenant connection is
    # configured, so a dry run should say so rather than promise enforcement that
    # could not run.
    from app.services import connection as connection_service

    connection_configured = connection_service.get_connection(session) is not None

    limits = list(session.scalars(select(CreditLimit).where(CreditLimit.is_active.is_(True))))
    for limit in limits:
        row = _project_one(
            session,
            limit=limit,
            index=index,
            moment=moment,
            connection_configured=connection_configured,
        )
        result.rows.append(row)
        if row.projected_status == LimitStatus.WARNED:
            result.would_warn_count += 1
        if row.would_enforce:
            result.would_enforce_count += 1
            if row.blast is not None:
                for target in row.blast.targets:
                    if target.kind == str(EnforcementKind.REMOVE_USER_ROLES):
                        all_users.add(target.target_id)
                    else:
                        all_projects.add(target.target_id)

    result.affected_projects = len(all_projects)
    result.affected_users = len(all_users)
    result.rows.sort(key=lambda r: (not r.would_enforce, -(r.percent_used or 0.0)))
    return result


def _project_one(
    session: Session,
    *,
    limit: CreditLimit,
    index: evaluation.UsageIndex,
    moment: datetime,
    connection_configured: bool = True,
) -> DryRunRow:
    exempt = enforcement.is_exempt(
        session, entity_type=limit.entity_type, entity_id=limit.entity_id
    )

    try:
        window = current_window(limit, moment)
    except PeriodError as exc:
        return DryRunRow(
            limit_id=limit.id,
            entity_type=limit.entity_type,
            entity_id=limit.entity_id,
            entity_label=limit.entity_label,
            credit_limit=limit.credit_limit,
            enforce=limit.enforce,
            exempt=exempt,
            usage_available=False,
            credits_used=Decimal("0"),
            percent_used=None,
            projected_status=LimitStatus.OK,
            would_enforce=False,
            blast=None,
            note=f"Misconfigured period: {exc}",
        )

    reported_total, available = index.reported_total(limit)
    # Read the stored baseline without creating or mutating any state. When no
    # state exists yet, use the exact baseline the first real cycle would pick
    # (evaluation.baseline_for) rather than assuming the current reading: for a
    # lifetime, custom or count_existing_usage limit that baseline is 0, so the
    # first cycle counts the whole reported total and can breach immediately. A
    # naive "baseline = reported_total" would make the simulation claim such a
    # limit is within budget right up until it restricts someone.
    state = session.scalar(
        select(LimitPeriodState).where(
            LimitPeriodState.limit_id == limit.id, LimitPeriodState.period_key == window.key
        )
    )
    baseline = (
        state.baseline_credits
        if state is not None
        else evaluation.baseline_for(
            limit, window=window, reported_total=reported_total, available=available
        )
    )
    credits_used = max(Decimal("0"), reported_total - baseline) if available else Decimal("0")

    if not available or not window.is_active:
        return DryRunRow(
            limit_id=limit.id,
            entity_type=limit.entity_type,
            entity_id=limit.entity_id,
            entity_label=limit.entity_label,
            credit_limit=limit.credit_limit,
            enforce=limit.enforce,
            exempt=exempt,
            usage_available=available,
            credits_used=Decimal("0"),
            percent_used=None,
            projected_status=LimitStatus.OK,
            would_enforce=False,
            blast=None,
            note=(
                "No consumption reported for this level on this tenant."
                if not available
                else "The custom period is not currently open."
            ),
        )

    percent = float(credits_used) / limit.credit_limit * 100 if limit.credit_limit > 0 else 100.0
    threshold = Decimal(limit.credit_limit) * Decimal(limit.warning_threshold_pct) / 100

    if credits_used >= Decimal(limit.credit_limit):
        projected = LimitStatus.BREACHED
    elif credits_used >= threshold:
        projected = LimitStatus.WARNED
    else:
        projected = LimitStatus.OK

    blast: BlastRadius | None = None
    would_enforce = False
    note: str | None = None
    if projected == LimitStatus.BREACHED:
        if exempt:
            note = "Would breach, but the entity is exempt."
        elif not limit.enforce:
            note = "Would breach, but the limit is monitor only."
        else:
            blast = blast_radius(session, entity_type=limit.entity_type, entity_id=limit.entity_id)
            would_enforce = blast.total_actions > 0
            if not would_enforce:
                note = "Would breach, but there is nothing to restrict (no linked projects)."
            elif not connection_configured:
                note = (
                    "Would breach and enforce, but no Checkmarx connection is configured, "
                    "so the restriction would be deferred until one is."
                )

    return DryRunRow(
        limit_id=limit.id,
        entity_type=limit.entity_type,
        entity_id=limit.entity_id,
        entity_label=limit.entity_label,
        credit_limit=limit.credit_limit,
        enforce=limit.enforce,
        exempt=exempt,
        usage_available=True,
        credits_used=credits_used,
        percent_used=percent,
        projected_status=projected,
        would_enforce=would_enforce,
        blast=blast,
        note=note,
    )
