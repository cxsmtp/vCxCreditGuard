"""Limit evaluation: usage in, warnings and enforcement out.

How usage per period is derived, because it is not a sum of events:

    credits_used = reported_total - baseline_credits

``reported_total`` is what the consumption endpoint currently reports for the
entity over its fixed lookback window. ``baseline_credits`` is that same figure
captured the moment the budget period opened. If the lookback window slides far
enough that the reported total drops below the baseline, the baseline is lowered
to match rather than letting usage go negative or, worse, letting a stale high
baseline mask real consumption.

Usage by entity level:

* **User** comes straight from ``viewBy=user``.
* **Application** prefers ``viewBy=application`` and falls back to summing its
  projects when the tenant does not report that dimension.
* **Project** comes from ``viewBy=project``. If the tenant does not support it,
  project usage is marked unavailable and the limit is never enforced, because
  "unknown" must not be treated as "zero".
* **Group** has no API dimension at all, so it is computed locally as the sum of
  its projects, plus its member users when ``include_member_usage`` is on. That
  flag defaults to off because a group whose projects and members overlap would
  otherwise count the same credits twice.

Precedence: the brief's "most restrictive limit wins" is implemented as "every
breached limit enforces its own action". A user in two groups working on a project
inside an application is restricted the moment any one of those budgets is
exhausted, and each restriction is individually reversible.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checkmarx.client import CheckmarxClient
from app.db.base import utcnow
from app.models.enums import (
    EnforcementStatus,
    EntityType,
    LimitStatus,
    PeriodType,
    Severity,
    UsageView,
)
from app.models.limits import CreditLimit, EnforcementAction, LimitPeriodState
from app.models.org import CxApplicationProject, CxGroupMembership, CxProjectGroup
from app.services import enforcement, ingestion, notifications
from app.services.audit import AuditActor, record_audit
from app.services.periods import PeriodError, PeriodWindow, current_window, describe_window

logger = logging.getLogger(__name__)


@dataclass
class LimitEvaluation:
    limit: CreditLimit
    period: PeriodWindow | None
    state: LimitPeriodState | None
    credits_used: Decimal
    usage_available: bool
    status: str
    percent_used: float | None
    newly_warned: bool = False
    newly_breached: bool = False
    enforced: enforcement.EnforcementOutcome | None = None
    note: str | None = None


@dataclass
class EvaluationResult:
    evaluated: int = 0
    warned: int = 0
    breached: int = 0
    enforced: int = 0
    monitor_only: int = 0
    restored: int = 0
    unavailable: int = 0
    errors: list[str] = field(default_factory=list)
    evaluations: list[LimitEvaluation] = field(default_factory=list)

    def as_stats(self) -> dict[str, object]:
        return {
            "evaluated": self.evaluated,
            "warned": self.warned,
            "breached": self.breached,
            "enforced": self.enforced,
            "monitor_only": self.monitor_only,
            "restored": self.restored,
            "usage_unavailable": self.unavailable,
            "errors": self.errors,
        }


class UsageIndex:
    """Reported totals per entity, read once per evaluation run."""

    def __init__(self, session: Session) -> None:
        self._session = session
        self.users = ingestion.latest_totals(session, UsageView.USER)
        self.applications = ingestion.latest_totals(session, UsageView.APPLICATION)
        self.projects = ingestion.latest_totals(session, UsageView.PROJECT)
        self.groups = ingestion.latest_totals(session, UsageView.GROUP)
        self.project_dimension = ingestion.dimension_supported(session, UsageView.PROJECT)
        self.group_dimension = ingestion.dimension_supported(session, UsageView.GROUP)
        self.application_dimension = ingestion.dimension_supported(session, UsageView.APPLICATION)
        self.user_dimension = ingestion.dimension_supported(session, UsageView.USER)

    def project_total(self, project_id: str) -> tuple[Decimal, bool]:
        if not self.project_dimension:
            return Decimal("0"), False
        return self.projects.get(project_id, Decimal("0")), True

    def user_total(self, user_id: str) -> tuple[Decimal, bool]:
        if not self.user_dimension:
            return Decimal("0"), False
        return self.users.get(user_id, Decimal("0")), True

    def application_total(self, application_id: str) -> tuple[Decimal, bool]:
        if self.application_dimension and application_id in self.applications:
            return self.applications[application_id], True
        # Fall back to the sum of the application's projects.
        project_ids = list(
            self._session.scalars(
                select(CxApplicationProject.project_id).where(
                    CxApplicationProject.application_id == application_id
                )
            )
        )
        if not project_ids or not self.project_dimension:
            if self.application_dimension:
                # The dimension works, this application simply spent nothing.
                return Decimal("0"), True
            return Decimal("0"), False
        return sum(
            (self.projects.get(pid, Decimal("0")) for pid in project_ids), Decimal("0")
        ), True

    def group_total(self, group_id: str, *, include_members: bool) -> tuple[Decimal, bool]:
        # The endpoint does have a group dimension. Prefer its figure when the group
        # actually appears in the snapshot, and roll up the group's projects
        # otherwise: the row shape for that dimension has not been observed with data
        # on any tenant yet, so the rollup remains the dependable path rather than a
        # guess about a payload nobody has seen.
        if not include_members and self.group_dimension and group_id in self.groups:
            return self.groups[group_id], True

        project_ids = list(
            self._session.scalars(
                select(CxProjectGroup.project_id).where(CxProjectGroup.group_id == group_id)
            )
        )
        total = Decimal("0")
        available = False
        if project_ids and self.project_dimension:
            total += sum(
                (self.projects.get(pid, Decimal("0")) for pid in project_ids), Decimal("0")
            )
            available = True
        if include_members:
            member_ids = list(
                self._session.scalars(
                    select(CxGroupMembership.user_id).where(CxGroupMembership.group_id == group_id)
                )
            )
            if member_ids and self.user_dimension:
                total += sum(
                    (self.users.get(uid, Decimal("0")) for uid in member_ids), Decimal("0")
                )
                available = True
        return total, available

    def reported_total(self, limit: CreditLimit) -> tuple[Decimal, bool]:
        if limit.entity_type == EntityType.USER:
            return self.user_total(limit.entity_id)
        if limit.entity_type == EntityType.PROJECT:
            return self.project_total(limit.entity_id)
        if limit.entity_type == EntityType.APPLICATION:
            return self.application_total(limit.entity_id)
        if limit.entity_type == EntityType.GROUP:
            return self.group_total(limit.entity_id, include_members=limit.include_member_usage)
        return Decimal("0"), False


def evaluate_all(
    session: Session,
    *,
    client: CheckmarxClient | None = None,
    now: datetime | None = None,
    actor: AuditActor | None = None,
) -> EvaluationResult:
    """Evaluate every active limit, warn, enforce and handle period rollover.

    ``client`` may be omitted to evaluate without any possibility of a write to
    Checkmarx, which is what the monitor-only path and the tests use.
    """
    moment = now or utcnow()
    actor = actor or AuditActor.system("evaluator")
    result = EvaluationResult()
    index = UsageIndex(session)
    resolver = enforcement.RoleResolver(client) if client is not None else None

    limits = list(session.scalars(select(CreditLimit).where(CreditLimit.is_active.is_(True))))
    for limit in limits:
        try:
            evaluation = _evaluate_one(
                session,
                limit=limit,
                index=index,
                moment=moment,
                client=client,
                actor=actor,
                resolver=resolver,
                result=result,
            )
        except PeriodError as exc:
            result.errors.append(f"limit {limit.id}: {exc}")
            notifications.notify(
                session,
                category=notifications.CATEGORY_SYNC_ERROR,
                severity=Severity.WARNING,
                title=f"Limit on {limit.entity_label or limit.entity_id} is misconfigured",
                body=str(exc),
                entity_type=limit.entity_type,
                entity_id=limit.entity_id,
                entity_label=limit.entity_label,
                dedupe_key=f"badperiod:{limit.id}",
            )
            continue
        result.evaluated += 1
        result.evaluations.append(evaluation)

    session.flush()
    return result


def _evaluate_one(
    session: Session,
    *,
    limit: CreditLimit,
    index: UsageIndex,
    moment: datetime,
    client: CheckmarxClient | None,
    actor: AuditActor,
    resolver: enforcement.RoleResolver | None,
    result: EvaluationResult,
) -> LimitEvaluation:
    window = current_window(limit, moment)
    reported_total, available = index.reported_total(limit)

    _close_stale_periods(
        session,
        limit=limit,
        current_key=window.key,
        client=client,
        actor=actor,
        result=result,
    )

    state = _get_or_create_state(
        session, limit=limit, window=window, reported_total=reported_total, available=available
    )

    # A sliding lookback window can drop old consumption, which would otherwise
    # produce negative usage. Re-baseline instead.
    if reported_total < state.baseline_credits:
        logger.info(
            "Reported total for %s %s fell below the period baseline, re-baselining",
            limit.entity_type,
            limit.entity_id,
        )
        state.baseline_credits = reported_total

    state.reported_total = reported_total
    state.usage_available = available
    state.credits_used = (
        max(Decimal("0"), reported_total - state.baseline_credits) if available else Decimal("0")
    )
    state.last_evaluated_at = moment

    if not available:
        result.unavailable += 1
        state.status = LimitStatus.OK
        session.flush()
        return LimitEvaluation(
            limit=limit,
            period=window,
            state=state,
            credits_used=Decimal("0"),
            usage_available=False,
            status=state.status,
            percent_used=None,
            note=(
                "Checkmarx does not report consumption for this entity level on this "
                "tenant, so the limit is not evaluated."
            ),
        )

    if not window.is_active:
        state.status = LimitStatus.OK
        session.flush()
        return LimitEvaluation(
            limit=limit,
            period=window,
            state=state,
            credits_used=state.credits_used,
            usage_available=True,
            status=state.status,
            percent_used=None,
            note="The custom period for this limit is not currently open.",
        )

    percent = (
        float(state.credits_used) / limit.credit_limit * 100 if limit.credit_limit > 0 else 100.0
    )
    threshold_credits = Decimal(limit.credit_limit) * Decimal(limit.warning_threshold_pct) / 100

    evaluation = LimitEvaluation(
        limit=limit,
        period=window,
        state=state,
        credits_used=state.credits_used,
        usage_available=True,
        status=state.status,
        percent_used=percent,
    )

    exempt = enforcement.is_exempt(
        session, entity_type=limit.entity_type, entity_id=limit.entity_id
    )

    if state.credits_used >= Decimal(limit.credit_limit):
        state.status = LimitStatus.BREACHED
        if state.breached_at is None:
            state.breached_at = moment
            evaluation.newly_breached = True
            result.breached += 1
            _notify_breach(session, limit, state, window, exempt=exempt)
        if exempt:
            evaluation.note = "Exempt from enforcement."
        elif not limit.enforce:
            result.monitor_only += 1
            evaluation.note = "Monitor only, no action taken."
        elif client is None:
            evaluation.note = "No Checkmarx connection available, enforcement deferred."
        else:
            outcome = enforcement.apply_enforcement(
                session,
                client,
                limit=limit,
                period_key=window.key,
                actor=actor,
                resolver=resolver,
            )
            evaluation.enforced = outcome
            if outcome.applied:
                state.status = LimitStatus.RESTRICTED
                state.restricted_at = state.restricted_at or moment
                result.enforced += len(outcome.applied)
    else:
        # Not breaching the limit. If access was previously restricted (e.g. because credit
        # limit was lower or usage was higher), restore the removed access now that
        # consumption is within budget.
        was_restricted = state.status in {
            LimitStatus.RESTRICTED,
            LimitStatus.BREACHED,
        } or _has_active_enforcement(session, limit.id, window.key)
        restored = 0
        if was_restricted:
            if client is not None:
                restored = enforcement.restore_for_limit(
                    session,
                    client,
                    limit_id=limit.id,
                    period_key=window.key,
                    actor=actor,
                    reason="credit_increased",
                )
                if restored > 0:
                    result.restored += restored
                    state.restored_at = moment
                    state.status = LimitStatus.RESTORED
            else:
                evaluation.note = "No Checkmarx connection available, restoration deferred."

        if restored == 0 and state.status != LimitStatus.RESTORED:
            if state.credits_used >= threshold_credits:
                state.status = LimitStatus.WARNED
                if state.warned_at is None:
                    state.warned_at = moment
                    evaluation.newly_warned = True
                    result.warned += 1
                    _notify_warning(session, limit, state, window, percent)
            else:
                state.status = LimitStatus.OK

    evaluation.status = state.status
    session.flush()
    return evaluation


def _has_active_enforcement(session: Session, limit_id: int, period_key: str) -> bool:
    return (
        session.scalar(
            select(EnforcementAction.id).where(
                EnforcementAction.limit_id == limit_id,
                EnforcementAction.period_key == period_key,
                EnforcementAction.status == EnforcementStatus.APPLIED,
            )
        )
        is not None
    )


def baseline_for(
    limit: CreditLimit, *, window: PeriodWindow, reported_total: Decimal, available: bool
) -> Decimal:
    """The starting figure a new period discounts from the reported total.

    Zero means "count everything Checkmarx reports". A non zero baseline means
    "count only what is spent from now on".

    * **Lifetime** always counts everything. A lifetime budget that discounted
      history would silently mean "since the limit was created", and a limit of 10
      against 13 already spent would read as 0 used and within budget, which is the
      opposite of the truth. (Bounded in practice by the API's lookback window, so
      a lifetime limit wants the widest window available.)
    * **Custom** always counts everything, because the admin chose the window
      explicitly and expects consumption inside it to count.
    * **Monthly and quarterly** discount by default. The lookback window is wider
      than the period and the API does not say *when* inside it credits were spent,
      so counting the lot would let a year of history exhaust a fresh monthly budget
      on day one and restrict people for consumption that predates the limit. An
      admin who wants the reported figure counted sets ``count_existing_usage``.
    """
    if not available:
        # A baseline taken from an unreadable dimension would make the first real
        # reading look like a full period of consumption.
        return Decimal("0")
    if window.period_type in {PeriodType.LIFETIME, PeriodType.CUSTOM}:
        return Decimal("0")
    if limit.count_existing_usage:
        return Decimal("0")
    return reported_total


def _get_or_create_state(
    session: Session,
    *,
    limit: CreditLimit,
    window: PeriodWindow,
    reported_total: Decimal,
    available: bool,
) -> LimitPeriodState:
    state = session.scalar(
        select(LimitPeriodState).where(
            LimitPeriodState.limit_id == limit.id,
            LimitPeriodState.period_key == window.key,
        )
    )
    if state is not None:
        return state
    state = LimitPeriodState(
        limit_id=limit.id,
        period_key=window.key,
        period_start=window.start,
        period_end=window.end,
        baseline_credits=baseline_for(
            limit, window=window, reported_total=reported_total, available=available
        ),
        reported_total=reported_total,
        credits_used=Decimal("0"),
        usage_available=available,
        status=LimitStatus.OK,
    )
    session.add(state)
    session.flush()
    return state


def _close_stale_periods(
    session: Session,
    *,
    limit: CreditLimit,
    current_key: str,
    client: CheckmarxClient | None,
    actor: AuditActor,
    result: EvaluationResult,
) -> None:
    """Roll over: restore access granted purely by an expired period's limit.

    ``hold_until_released`` opts out, which is how an admin keeps a restriction in
    place across the boundary until they personally lift it.
    """
    stale = list(
        session.scalars(
            select(LimitPeriodState).where(
                LimitPeriodState.limit_id == limit.id,
                LimitPeriodState.period_key != current_key,
                LimitPeriodState.status.in_(
                    [LimitStatus.RESTRICTED, LimitStatus.BREACHED, LimitStatus.WARNED]
                ),
            )
        )
    )
    if not stale:
        return

    for state in stale:
        if limit.hold_until_released and state.status == LimitStatus.RESTRICTED:
            logger.info(
                "Limit %s is held until manually released, keeping period %s restricted",
                limit.id,
                state.period_key,
            )
            continue
        if state.status == LimitStatus.RESTRICTED and client is not None:
            try:
                restored = enforcement.restore_for_limit(
                    session,
                    client,
                    limit_id=limit.id,
                    period_key=state.period_key,
                    actor=actor,
                    reason="period_rollover",
                )
            except Exception as exc:  # noqa: BLE001 - one failure must not stop the cycle
                result.errors.append(f"limit {limit.id}: could not restore after rollover: {exc}")
                logger.exception("Rollover restore failed for limit %s", limit.id)
                continue
            result.restored += restored
            state.restored_at = utcnow()
        state.status = LimitStatus.RESTORED if state.restricted_at else LimitStatus.OK
    session.flush()


# ------------------------------------------------------------------ notifications


def _notify_warning(
    session: Session,
    limit: CreditLimit,
    state: LimitPeriodState,
    window: PeriodWindow,
    percent: float,
) -> None:
    entity = limit.entity_label or limit.entity_id
    notifications.notify(
        session,
        category=notifications.CATEGORY_WARNING,
        severity=Severity.WARNING,
        title=(
            f"{limit.entity_type.capitalize()} {entity} reached {percent:.0f}% of its credit limit"
        ),
        body=(
            f"{state.credits_used} of {limit.credit_limit} credits used "
            f"{describe_window(window)}. The warning threshold is "
            f"{limit.warning_threshold_pct}%.\n"
            f"{'Enforcement is on' if limit.enforce else 'This limit is monitor only'}, "
            f"so reaching the limit "
            f"{'will restrict access' if limit.enforce else 'will only notify'}."
        ),
        entity_type=limit.entity_type,
        entity_id=limit.entity_id,
        entity_label=limit.entity_label,
        dedupe_key=notifications.warning_key(limit.id, window.key),
    )


def _notify_breach(
    session: Session,
    limit: CreditLimit,
    state: LimitPeriodState,
    window: PeriodWindow,
    *,
    exempt: bool,
) -> None:
    entity = limit.entity_label or limit.entity_id
    if exempt:
        tail = "This entity is on the exemption list, so no action was taken."
        severity = Severity.WARNING
        dedupe = notifications.monitor_only_key(limit.id, window.key)
    elif limit.enforce:
        tail = "Enforcement is on, so access is being restricted now."
        severity = Severity.CRITICAL
        dedupe = notifications.breach_key(limit.id, window.key)
    else:
        tail = "This limit is monitor only, so no action was taken."
        severity = Severity.WARNING
        dedupe = notifications.monitor_only_key(limit.id, window.key)

    notifications.notify(
        session,
        category=notifications.CATEGORY_WARNING
        if not limit.enforce
        else notifications.CATEGORY_ENFORCEMENT,
        severity=severity,
        title=f"{limit.entity_type.capitalize()} {entity} reached its credit limit",
        body=(
            f"{state.credits_used} of {limit.credit_limit} credits used "
            f"{describe_window(window)}.\n{tail}"
        ),
        entity_type=limit.entity_type,
        entity_id=limit.entity_id,
        entity_label=limit.entity_label,
        dedupe_key=dedupe,
    )


# ------------------------------------------------------------------ housekeeping


def restore_on_limit_change(
    session: Session,
    client: CheckmarxClient | None,
    *,
    limit: CreditLimit,
    actor: AuditActor,
    reason: str = "limit_removed",
) -> int:
    """Lift restrictions when a limit is disabled, deleted or switched to monitor only.

    Leaving someone restricted by a limit that no longer applies is the single
    most confusing failure this tool could have, so it is handled at the point the
    limit changes rather than waiting for the next cycle.
    """
    if client is None:
        return 0
    restored = enforcement.restore_for_limit(
        session, client, limit_id=limit.id, actor=actor, reason=reason
    )
    if restored:
        states = list(
            session.scalars(
                select(LimitPeriodState).where(
                    LimitPeriodState.limit_id == limit.id,
                    LimitPeriodState.status.in_([LimitStatus.RESTRICTED, LimitStatus.BREACHED]),
                )
            )
        )
        for st in states:
            st.status = LimitStatus.RESTORED
            st.restored_at = utcnow()
        session.flush()

        record_audit(
            session,
            action="enforcement.reversed_bulk",
            actor=actor,
            target_type="credit_limit",
            target_id=str(limit.id),
            target_label=limit.entity_label,
            detail=f"{restored} restriction(s) lifted because the limit changed ({reason}).",
        )
    return restored


def pending_restore_count(session: Session) -> int:
    from app.models.enums import EnforcementStatus

    return len(
        list(
            session.scalars(
                select(EnforcementAction.id).where(
                    EnforcementAction.status == EnforcementStatus.APPLIED
                )
            )
        )
    )
