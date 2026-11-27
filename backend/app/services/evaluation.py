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

Auto-triage credits charged to the person who started the scan (the setting
``attribution.auto_triage_to_scan_initiator``, see
``app/services/auto_triage_attribution.py``) are a second, dated component of a
user's figure, added on top of ``reported_total - baseline_credits``. They follow
the same period rule as the person's own credits: a limit that counts existing
usage counts all of them inside the consumption window; one that discounts it
counts only charges observed after its baseline was taken (``baseline_at``).
With the setting off nothing here changes.

Precedence: the brief's "most restrictive limit wins" is implemented as "every
breached limit enforces its own action". A user in two groups working on a project
inside an application is restricted the moment any one of those budgets is
exhausted, and each restriction is individually reversible.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal

from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session

from app.checkmarx.client import CheckmarxClient
from app.db.base import utcnow
from app.models.enums import (
    EnforcementKind,
    EnforcementStatus,
    EntityType,
    LimitStatus,
    PeriodType,
    Severity,
    UsageView,
)
from app.models.limits import (
    CreditLimit,
    EnforcementAction,
    Exemption,
    LimitPeriodState,
    effective_project_actions,
)
from app.models.org import (
    CxApplicationProject,
    CxGroupMembership,
    CxProject,
    CxProjectGroup,
    CxUser,
)
from app.models.usage import BudgetUsage
from app.services import (
    auto_triage_attribution,
    enforcement,
    error_text,
    headroom,
    ingestion,
    ledger,
    notifications,
    pacing,
    recount,
    settings_store,
    usage_mix,
)
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
    # Breached, enforcing limits whose restriction was not applied because
    # enforcement is paused (by an admin, or by the safety ceiling).
    deferred: int = 0
    # Breached, enforcing period budgets not restricted because their usage
    # over the limit was counted from the consumption summary (summary_hold).
    summary_held: int = 0
    # Breached, enforcing period budgets whose new restriction was not applied
    # because the independent recount of the activity log did not confirm it
    # (app/services/recount.py).
    recount_held: int = 0
    # Why new restrictions are not being applied this cycle, or None if they are.
    enforcement_paused: str | None = None
    errors: list[str] = field(default_factory=list)
    evaluations: list[LimitEvaluation] = field(default_factory=list)
    # With a connection: what the cycle's budgets allowed (pacing.py) - the
    # verification rotation and the writes - and each limit whose restriction
    # is being spread over several cycles, with its progress.
    pacing: dict[str, object] | None = None
    rollouts: list[dict[str, object]] = field(default_factory=list)
    # Limits whose writes wait for the second pass (large rollouts).
    postponed: list[int] = field(default_factory=list)

    def as_stats(self) -> dict[str, object]:
        stats: dict[str, object] = {
            "evaluated": self.evaluated,
            "warned": self.warned,
            "breached": self.breached,
            "enforced": self.enforced,
            "monitor_only": self.monitor_only,
            "summary_held": self.summary_held,
            "recount_held": self.recount_held,
            "restored": self.restored,
            "usage_unavailable": self.unavailable,
            "deferred": self.deferred,
            "enforcement_paused": self.enforcement_paused,
            "errors": self.errors,
        }
        if self.pacing is not None:
            stats["pacing"] = self.pacing
        if self.rollouts:
            stats["rollouts"] = self.rollouts
        return stats


# During the first pass of a cycle, a limit needing more restriction writes
# than this waits for the second pass, so a large rollout never holds up the
# restrictions of small limits (a single user, a project).
LARGE_ROLLOUT_WRITES = 50


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
        self._attribution: auto_triage_attribution.AttributionModel | None = None
        # The activity source's integration-account rule for auto-triage
        # charges (None: nothing to skip), read on first use.
        self._initiator_skip: object = False
        # Read on first use, once for every limit (reports and previews ask
        # about hundreds of limits in one request).
        self._states: dict[str, dict[int, LimitPeriodState]] = {}
        self._counters: dict[str, dict[int, BudgetUsage]] = {}
        # What the activity log counted, per period (activity_source).
        self._log_counted: dict[str, dict[int, Decimal]] = {}
        self._restriction_hold: object = False
        self._exempt: set[tuple[str, str]] | None = None
        # Each budget's headroom (app/services/headroom.py), read once.
        self.headroom = headroom.Resolver(session)

    def counter(self, limit_id: int, period_key: str) -> tuple[Decimal, dict[str, int]] | None:
        """A limit's ledger counter for a period, read for every limit at once
        (None: there is none yet)."""
        if period_key not in self._counters:
            self._counters[period_key] = {
                row.limit_id: row
                for row in self._session.scalars(
                    select(BudgetUsage).where(BudgetUsage.period_key == period_key)
                )
            }
        row = self._counters[period_key].get(limit_id)
        return (Decimal(row.credits or 0), dict(row.actions or {})) if row is not None else None

    def log_counter(self, limit_id: int, period_key: str) -> Decimal:
        """What the activity log counted towards a budget in a period."""
        if period_key not in self._log_counted:
            from app.services import activity_source

            self._log_counted[period_key] = activity_source.log_counted(self._session, period_key)
        return self._log_counted[period_key].get(limit_id, Decimal("0"))

    @property
    def restriction_hold(self) -> dict[str, object] | None:
        if self._restriction_hold is False:
            from app.services import activity_source

            self._restriction_hold = activity_source.restriction_hold(self._session)
        return self._restriction_hold  # type: ignore[return-value]

    def period_state(self, limit_id: int, period_key: str) -> LimitPeriodState | None:
        """The stored state of a limit's period, read for every limit at once."""
        if period_key not in self._states:
            self._states[period_key] = {
                state.limit_id: state
                for state in self._session.scalars(
                    select(LimitPeriodState).where(LimitPeriodState.period_key == period_key)
                )
            }
        return self._states[period_key].get(limit_id)

    def is_exempt(self, entity_type: str, entity_id: str) -> bool:
        """``enforcement.is_exempt``, from one read of every exemption."""
        if self._exempt is None:
            self._exempt = {
                (kind, eid)
                for kind, eid in self._session.execute(
                    select(Exemption.entity_type, Exemption.entity_id)
                )
            }
        return (str(entity_type), entity_id) in self._exempt

    @property
    def attribution(self) -> auto_triage_attribution.AttributionModel:
        """Auto-triage credits charged to scan initiators, built once per run."""
        if self._attribution is None:
            self._attribution = auto_triage_attribution.build_model(self._session)
        return self._attribution

    def attributed_usage(
        self,
        limit: CreditLimit,
        *,
        window: PeriodWindow,
        state: LimitPeriodState | None,
        moment: datetime,
    ) -> auto_triage_attribution.AttributedUsage | None:
        """The auto-triage credits charged from scans that count towards this limit.

        None when the setting is off or the limit is not one a person's usage
        feeds (a user limit, or a group limit that includes member usage).
        Project, application and plain group figures already contain the
        project's auto-triage credits and are never touched.
        """
        if limit.entity_type != EntityType.USER and not (
            limit.entity_type == EntityType.GROUP and limit.include_member_usage
        ):
            return None
        if not self.user_dimension or not self.attribution.enabled:
            return None
        if limit.entity_type == EntityType.USER:
            user_ids = [limit.entity_id]
            exclude: set[str] = set()
        else:
            user_ids = list(
                self._session.scalars(
                    select(CxGroupMembership.user_id).where(
                        CxGroupMembership.group_id == limit.entity_id
                    )
                )
            )
            # The group's own projects are already counted in full by the
            # project rollup; charging their auto triage to members as well
            # would count it twice.
            exclude = (
                set(
                    self._session.scalars(
                        select(CxProjectGroup.project_id).where(
                            CxProjectGroup.group_id == limit.entity_id
                        )
                    )
                )
                if self.project_dimension
                else set()
            )
        counts_all = counts_existing_usage(limit, window=window)
        if counts_all:
            since = None
        elif state is not None:
            since = state.baseline_at or state.period_start
        else:
            # No period yet: the first evaluation takes its baseline now.
            since = moment
        if self._initiator_skip is False:
            from app.services import activity_source

            self._initiator_skip = activity_source.initiator_skip(self._session)
        return auto_triage_attribution.attributed_usage(
            self.attribution,
            user_ids=user_ids,
            exclude_projects=exclude,
            counts_existing=counts_all,
            since=since,
            skip=self._initiator_skip,  # type: ignore[arg-type]
        )

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
    only: frozenset[int] | None = None,
) -> EvaluationResult:
    """Evaluate every active limit, warn, enforce and handle period rollover.

    ``only``: the fast check (app/services/fastcheck.py) evaluates and
    enforces just these budgets, with every gate of a cycle (the pause and
    the safety ceilings, ``summary_hold``, the recount) and none of its
    housekeeping: no closed-period settling, no sweep of unjustified
    restrictions and no verification pass. The full cycle does those.

    ``client`` may be omitted to evaluate without any possibility of a write to
    Checkmarx, which is what the monitor-only path and the tests use.

    With a client the cycle's write budget (``pacing``) is spent in a fixed
    order, so giving access back and keeping restrictions in force never wait
    behind a rollout:

    1. **Lifts**: restrictions nothing justifies any more (a limit switched
       off, an exemption), then, limit by limit, the period rollover and a
       budget that covers the usage again. Usage is evaluated here too; no new
       restriction is applied yet.
    2. **Verification**: the restrictions in force chosen for this cycle are
       read back, and drift re-asserted (``_plan_verification``).
    3. **New restrictions**, small limits first, then large rollouts with
       whatever is left.
    """
    moment = now or utcnow()
    actor = actor or AuditActor.system("evaluator")
    result = EvaluationResult()
    # Periods already over whose counters grew since they were last evaluated
    # (an increase observed before the rollover, evaluated after it).
    if only is None:
        _settle_closed_periods(session, moment)
    # What the project budgets are now, recorded before any limit is judged:
    # the integration-account rule for auto-triage charges reads it, and a
    # past charge's outcome must never change (app/services/activity_source.py).
    from app.services import activity_source

    activity_source.observe_budgets(session, moment)
    index = UsageIndex(session)
    resolver = enforcement.RoleResolver(client) if client is not None else None
    budget: enforcement.EnforcementBudget | None = None
    config: pacing.Pacing | None = None
    # The independent recount before every new restriction of a period budget
    # (app/services/recount.py): the log is read at most once per cycle.
    recounter = recount.Recounter(client, now=moment) if client is not None else None

    if client is not None:
        config = pacing.pacing(session)
        budget = enforcement.EnforcementBudget(
            writes=config.max_writes_per_cycle or None,
            postpone_large=LARGE_ROLLOUT_WRITES if config.max_writes_per_cycle else None,
        )
        if only is None:
            _lift_unjustified_restrictions(
                session, client, actor=actor, result=result, budget=budget
            )
            try:
                enforcement.return_roles_outside_the_restriction(
                    session, client, actor=actor, resolver=resolver
                )
            except Exception:  # noqa: BLE001 - a housekeeping pass must not stop the cycle
                session.rollback()
                logger.warning("Could not return roles outside the restriction", exc_info=True)
        # Decided once, before anything is restricted: either the whole cycle
        # may apply new restrictions or none of it may. Giving access back is
        # never held up by this.
        try:
            result.enforcement_paused = _enforcement_hold(
                session, moment=moment, actor=actor, recounter=recounter
            )
        except Exception as exc:  # noqa: BLE001 - the safety check failing must fail safe
            session.rollback()
            logger.exception("The enforcement safety check failed")
            result.enforcement_paused = (
                "The safety check could not be completed this cycle, so no new restriction "
                "was applied."
            )
            result.errors.append(f"enforcement safety check: {error_text.public_error(exc)}")

    # Pass 1: usage, warnings, breaches and every lift (rollover, a budget that
    # covers the usage again). Breached limits to enforce are collected.
    to_enforce: list[int] = []
    limit_ids = list(
        session.scalars(
            select(CreditLimit.id).where(CreditLimit.is_active.is_(True)).order_by(CreditLimit.id)
        )
    )
    if only is not None:
        limit_ids = [limit_id for limit_id in limit_ids if limit_id in only]
    for limit_id in limit_ids:
        # Re-read at the start of each limit's own transaction: an admin may have
        # edited, disabled or deleted it while earlier limits were being worked on.
        limit = session.get(CreditLimit, limit_id, populate_existing=True)
        if limit is None or not limit.is_active:
            continue
        if client is not None and result.enforcement_paused is None:
            # An admin can press Pause while a cycle is running. It takes effect
            # from the next limit, not from the next cycle.
            result.enforcement_paused = _manual_pause(session)
        try:
            evaluation = _evaluate_one(
                session,
                limit=limit,
                index=index,
                moment=moment,
                client=client,
                actor=actor,
                result=result,
                hold=result.enforcement_paused,
                budget=budget,
                to_enforce=to_enforce,
            )
        except PeriodError as exc:
            session.rollback()
            result.errors.append(f"limit {limit_id}: {exc}")
            notifications.notify(
                session,
                category=notifications.CATEGORY_SYNC_ERROR,
                severity=Severity.WARNING,
                title=f"Limit on {limit.entity_label or limit.entity_id} is misconfigured",
                body=str(exc),
                entity_type=limit.entity_type,
                entity_id=limit.entity_id,
                entity_label=limit.entity_label,
                dedupe_key=f"badperiod:{limit_id}",
            )
            session.commit()
            continue
        except Exception as exc:  # noqa: BLE001 - one limit must never block the rest
            # A failure on one limit (a restore that Checkmarx rejected, a deleted
            # user, a transient outage) is recorded and the loop moves on. Letting
            # it propagate would leave every later limit unevaluated, cycle after
            # cycle, for as long as the one failure persisted. The rollback clears
            # whatever that limit left half-written so the next one starts clean.
            session.rollback()
            logger.exception("Evaluation of limit %s failed", limit_id)
            result.errors.append(f"limit {limit_id}: {error_text.public_error(exc)}")
            continue
        # One short transaction per limit: its state is durable before the next
        # limit starts talking to Checkmarx, and no lock outlives its own work.
        session.commit()
        result.evaluated += 1
        result.evaluations.append(evaluation)

    if client is None or budget is None or config is None or resolver is None:
        return result

    # Pass 2: read back the restrictions in force chosen for this cycle.
    if result.enforcement_paused is None:
        result.enforcement_paused = _manual_pause(session)
    if only is not None:
        # The fast check: no verification pass (the full cycle's), and no
        # restriction in force is read back by the enforcement below.
        budget.verify_ids = frozenset()
        if result.enforcement_paused is None and to_enforce and recounter is not None:
            _prepare_recount(session, recounter, to_enforce, moment=moment)
        if result.enforcement_paused is None and to_enforce:
            budget.postpone_large = None
            _enforce_pending(
                session,
                client,
                to_enforce,
                moment=moment,
                actor=actor,
                resolver=resolver,
                result=result,
                budget=budget,
                recounter=recounter,
            )
        result.pacing = {"writes": budget.as_stats()}
        return result
    plan = _plan_verification(
        session,
        config,
        moment,
        paused=result.enforcement_paused,
        enforcing=frozenset(to_enforce),
    )
    verification = plan.stats
    result.pacing = {"verification": verification}
    if plan.chosen:
        if config.read_concurrency > 1:
            try:
                verification["read_ahead"] = enforcement.prefetch_verification(
                    session,
                    client,
                    action_ids=plan.chosen,
                    resolver=resolver,
                    workers=config.read_concurrency,
                )
            except Exception:  # noqa: BLE001 - reading ahead is only an optimisation
                session.rollback()
                logger.warning("Could not read the restrictions in force ahead", exc_info=True)
        checked = enforcement.verify_in_force(
            session,
            client,
            action_ids=plan.chosen,
            actor=actor,
            resolver=resolver,
            budget=budget,
        )
    else:
        checked = enforcement.VerificationPass()
    # Whatever is in force and was not chosen is not read back again by the
    # limits' enforcement below.
    budget.verify_ids = frozenset()

    # Pass 3: new restrictions, small limits first, then large rollouts. The
    # activity log is read for the recounts first, with nothing open in the
    # database.
    if result.enforcement_paused is None and to_enforce and recounter is not None:
        _prepare_recount(session, recounter, to_enforce, moment=moment)
    if result.enforcement_paused is None and to_enforce:
        _enforce_pending(
            session,
            client,
            to_enforce,
            moment=moment,
            actor=actor,
            resolver=resolver,
            result=result,
            budget=budget,
            recounter=recounter,
        )
    if result.postponed and result.enforcement_paused is None:
        budget.postpone_large = None
        postponed, result.postponed = result.postponed, []
        _enforce_pending(
            session,
            client,
            postponed,
            moment=moment,
            actor=actor,
            resolver=resolver,
            result=result,
            budget=budget,
            recounter=recounter,
        )

    # Pass 4: restrictions that could not be read back are written again to
    # keep them in force - after the new restrictions, so that never takes
    # the budget a new breach needs. Each is then out of the rotation for an
    # interval: written again at most once per verification interval.
    if checked.postponed and result.enforcement_paused is None:
        late = enforcement.verify_in_force(
            session,
            client,
            action_ids=checked.postponed,
            actor=actor,
            resolver=resolver,
            budget=budget,
            late=True,
        )
        checked.merge(late)
    elif checked.postponed:
        checked.reapply_deferred += checked.postponed
    checked.postponed = []
    verification.update(checked.as_stats())
    result.errors.extend(checked.errors)
    _take_out_of_rotation(session, checked.out_of_rotation, moment)
    _alert_unverified(session, plan, checked.read_back, moment)
    result.pacing["writes"] = budget.as_stats()
    verification["verified"] = budget.verified
    return result


# Who looks after a restriction in force this cycle (_plan_verification).
OWNER_PLAN = "plan"  # its breached limit's enforcement: the target is in its plan
OWNER_KEPT = "kept"  # stays in force outside any plan: verified on its own
OWNER_LIFTING = "lifting"  # being lifted (the sweep, the rollover, a raised budget)
OWNER_GONE = "gone"  # the project or user was deleted in Checkmarx One: nothing to read


@dataclass
class VerificationPlan:
    stats: dict[str, object]
    # The restrictions to read back this cycle, oldest-verified first.
    chosen: list[int]
    # (id, target) unverified for more than ``stale_after`` before the pass,
    # outcome unknown that long, and being lifted with the last lift failed.
    stale: list[tuple[int, str]] = field(default_factory=list)
    stale_unsettled: list[tuple[int, str]] = field(default_factory=list)
    lift_failing: list[tuple[int, str]] = field(default_factory=list)
    stale_after: timedelta = timedelta(hours=2)
    paused: bool = False


def _owners(
    session: Session,
    rows: list,  # type: ignore[type-arg]
    moment: datetime,
    enforcing: frozenset[int],
) -> dict[int, str]:
    """For each restriction in force, who looks after it this cycle.

    Mirrors the cycle itself, so that a restriction is only ever counted as
    "verified in rotation" if something will really read it back.
    ``enforcing``: the limits this cycle found breached and enforces.

    * ``plan``: its limit is enforced this cycle, in its current period, and
      this target is in what its enforcement plans (the project is still in
      the group or application, not exempt, not deleted; the user is not
      exempt or protected);
    * ``kept``: it stays in force although no plan meets it - a project that
      left the group or application (lifted, like every restriction of the
      period, when the period ends), a hold-until-released limit's earlier
      period (until an admin releases it), a period whose usage cannot be read
      or whose custom window is closed. Verified on its own;
    * ``lifting``: the sweep lifts it this cycle (the limit is switched off,
      deleted or no longer turns this off, the entity or target is exempt or
      protected, an admin's restore did not finish), or the rollover does (an
      earlier period of a limit that does not hold), or a budget that covers
      the usage again does. Not verified: it is being given back;
    * ``gone``: the project or user was deleted in Checkmarx One.
    """
    limit_ids = {row.limit_id for row in rows if row.limit_id is not None}
    limits = {
        limit.id: limit
        for limit in session.scalars(select(CreditLimit).where(CreditLimit.id.in_(limit_ids)))
    }
    headrooms = headroom.Resolver(session, moment)
    exempt = {
        (str(kind), eid)
        for kind, eid in session.execute(select(Exemption.entity_type, Exemption.entity_id))
    }
    protected = enforcement.protected_users(
        session, {row.target_id for row in rows if row.target_type == enforcement.TARGET_USER}
    )
    deleted = {
        (enforcement.TARGET_PROJECT, project_id)
        for project_id in session.scalars(
            select(CxProject.id).where(CxProject.is_deleted.is_(True))
        )
    } | {
        (enforcement.TARGET_USER, user_id)
        for user_id in session.scalars(select(CxUser.id).where(CxUser.is_deleted.is_(True)))
    }
    windows: dict[int, PeriodWindow | None] = {}
    for limit in limits.values():
        try:
            windows[limit.id] = current_window(limit, moment)
        except PeriodError:
            windows[limit.id] = None
    states = {
        (state.limit_id, state.period_key): state
        for state in session.scalars(
            select(LimitPeriodState).where(LimitPeriodState.limit_id.in_(limit_ids))
        )
        if windows.get(state.limit_id) is not None
        and state.period_key == windows[state.limit_id].key  # type: ignore[union-attr]
    }
    protected_roles = settings_store.enforcement_guard(session).protected_roles
    planned: set[str] = set()
    for limit in limits.values():
        window = windows.get(limit.id)
        if (
            limit.id not in enforcing
            or not limit.is_active
            or not limit.enforce
            or window is None
            or (str(limit.entity_type), limit.entity_id) in exempt
        ):
            continue
        planned.update(
            enforcement.idempotency_key(
                limit_id=limit.id,
                period_key=window.key,
                kind=str(target.kind),
                target_id=target.target_id,
            )
            for target in enforcement.plan_targets(
                session,
                entity_type=limit.entity_type,
                entity_id=limit.entity_id,
                project_actions=effective_project_actions(limit),
                protected_roles=protected_roles,
            )
        )

    owners: dict[int, str] = {}
    for row in rows:
        limit = limits.get(row.limit_id) if row.limit_id is not None else None
        target_entity = (
            EntityType.USER if row.target_type == enforcement.TARGET_USER else EntityType.PROJECT
        )
        if (
            row.reversal_reason == enforcement.ADMIN_REASON
            or limit is None
            or not limit.is_active
            or not limit.enforce
            or (str(row.entity_type), row.entity_id) in exempt
            or enforcement.deselected_kind(row.kind, row.target_type, limit)
            or (str(target_entity), row.target_id) in exempt
            or row.target_id in protected
        ):
            owners[row.id] = OWNER_LIFTING
            continue
        if row.idempotency_key in planned:
            # A deleted user is still in a user limit's plan (only deleted
            # projects drop out of plans): nothing is there to read back.
            owners[row.id] = (
                OWNER_GONE if (row.target_type, row.target_id) in deleted else OWNER_PLAN
            )
            continue
        window = windows.get(limit.id)
        if window is not None and row.period_key != window.key:
            # An earlier period: the rollover lifts it, unless the limit holds.
            owners[row.id] = OWNER_KEPT if limit.hold_until_released else OWNER_LIFTING
        elif window is not None and row.reversal_reason:
            owners[row.id] = OWNER_LIFTING  # an automatic lift that did not finish
        else:
            # The current period. A target that left its breached limit's plan
            # stays in force (lifted with the period); one whose limit is
            # within budget again is being lifted (a "restricted" period
            # keeps that status until the last one is).
            state = states.get((limit.id, window.key)) if window is not None else None
            within_budget = (
                limit.id not in enforcing
                and window is not None
                and window.is_active
                and state is not None
                and state.usage_available
                and state.credits_used < headrooms.restrict_at(limit)
            )
            owners[row.id] = OWNER_LIFTING if within_budget else OWNER_KEPT
        if owners[row.id] == OWNER_KEPT and ((row.target_type, row.target_id) in deleted):
            owners[row.id] = OWNER_GONE
    return owners


def _plan_verification(
    session: Session,
    config: pacing.Pacing,
    moment: datetime,
    *,
    paused: str | None = None,
    enforcing: frozenset[int] = frozenset(),
) -> VerificationPlan:
    """Which restrictions in force are read back this cycle: the oldest-verified.

    Chosen only from restrictions the cycle will really read back: every one
    a breached limit's enforcement plans, and every one that stays in force
    outside any plan (``_owners``); not the ones being lifted. Each is read
    back at most every ``verify_interval_minutes``, spread over the cycles,
    never more than the per-cycle cap; with the interval at 0, every one,
    every cycle.

    A restriction that could not be read back (an error, or no readable
    answer) moves to the back of the rotation (``last_checked_at``) and is
    not due again for an interval, so a persistent failure never takes the
    slots of the others every cycle; it stays unverified and is counted, and
    the alert decided after the pass (``_alert_unverified``) names it.

    While enforcement is paused nothing is read back or re-asserted (as before
    pacing): restrictions in force are left as they are until it resumes.
    """
    rows = session.execute(
        select(
            EnforcementAction.id,
            EnforcementAction.idempotency_key,
            EnforcementAction.limit_id,
            EnforcementAction.period_key,
            EnforcementAction.kind,
            EnforcementAction.entity_type,
            EnforcementAction.entity_id,
            EnforcementAction.target_type,
            EnforcementAction.target_id,
            EnforcementAction.reversal_reason,
            EnforcementAction.error,
            EnforcementAction.last_verified_at,
            EnforcementAction.last_checked_at,
            EnforcementAction.applied_at,
        ).where(EnforcementAction.status == EnforcementStatus.APPLIED)
    ).all()
    # Attempts whose outcome is unknown and that may have taken something: in
    # force as far as anyone can tell. Not read back by the rotation (the
    # enforcement of their limit completes them, or the sweep lifts them;
    # reading one back as "held" would record an outcome that was never
    # recorded), but counted, and named by the alert if they stay that way.
    unsettled = [
        action
        for action in session.scalars(
            select(EnforcementAction).where(
                EnforcementAction.status.in_(
                    [
                        status
                        for status in enforcement.RESTORABLE_STATUSES
                        if status != EnforcementStatus.APPLIED
                    ]
                )
            )
        )
        if enforcement.may_be_in_force(action)
    ]
    owners = _owners(session, rows, moment, enforcing) if rows else {}
    candidates = [row for row in rows if owners.get(row.id) in (OWNER_PLAN, OWNER_KEPT)]
    by_owner = dict.fromkeys((OWNER_PLAN, OWNER_KEPT, OWNER_LIFTING, OWNER_GONE), 0)
    for owner in owners.values():
        by_owner[owner] += 1
    # Being lifted, and the last attempt failed: it is still in force.
    lift_failing = [
        row
        for row in rows
        if owners.get(row.id) == OWNER_LIFTING and row.error and row.reversal_reason
    ]
    never = datetime.min.replace(tzinfo=UTC)
    interval = config.verify_interval_minutes
    paced = interval > 0
    # Due a little early (a tenth of the interval), so the time the cycles
    # themselves take never pushes a read-back past the interval.
    cutoff = moment - timedelta(minutes=interval - max(1, interval // 10)) if paced else moment

    def due(row) -> bool:  # type: ignore[no-untyped-def]
        verified_due = row.last_verified_at is None or row.last_verified_at <= cutoff
        # One that could not be read back is not due again for an interval.
        checked_due = row.last_checked_at is None or row.last_checked_at <= cutoff
        return verified_due and checked_due

    due_count = sum(1 for row in candidates if due(row))
    ordered = sorted(
        candidates,
        key=lambda row: (
            max(row.last_verified_at or never, row.last_checked_at or never),
            row.id,
        ),
    )
    if paused is not None:
        chosen: list = []  # type: ignore[type-arg]
    elif paced:
        eligible = [
            row for row in ordered if row.last_checked_at is None or row.last_checked_at <= cutoff
        ]
        chosen = eligible[: config.verifications_per_cycle(len(candidates), due_count) or 0]
    else:
        chosen = ordered
    verified_at = [row.last_verified_at for row in candidates if row.last_verified_at is not None]
    oldest = min(verified_at) if verified_at else None
    # Unverified for more than twice the interval (or, at interval 0, two
    # cycles): the rotation is not keeping up, or these cannot be read back.
    # Decided after the pass (those read back this cycle are not named).
    stale_after = timedelta(minutes=2 * (interval if paced else config.interval_minutes))
    stale = [
        row
        for row in candidates
        if (row.last_verified_at or row.applied_at or moment) < moment - stale_after
    ]
    stale_unsettled = [
        action for action in unsettled if (action.created_at or moment) < moment - stale_after
    ]
    stats: dict[str, object] = {
        "in_force": len(rows) + len(unsettled),
        "rotation": len(candidates),
        "in_a_plan": by_owner[OWNER_PLAN],
        "outside_a_plan": by_owner[OWNER_KEPT],
        "being_lifted": by_owner[OWNER_LIFTING],
        "lift_failing": len(lift_failing),
        "target_deleted": by_owner[OWNER_GONE],
        "outcome_unknown": len(unsettled),
        "interval_minutes": interval,
        "due": due_count,
        "selected": len(chosen),
        "oldest_verified_minutes_ago": (
            int((moment - oldest).total_seconds() // 60) if oldest is not None else None
        ),
        "never_verified": sum(1 for row in candidates if row.last_verified_at is None),
        # At this size and these settings, the longest a restriction in force
        # (in a plan or not) goes without being read back.
        "each_verified_within_minutes": config.coverage_minutes(len(candidates)),
    }
    if paused is not None:
        stats["paused"] = True
    return VerificationPlan(
        stats=stats,
        chosen=[row.id for row in chosen],
        stale=[(row.id, row.target_id) for row in stale],
        stale_unsettled=[(action.id, action.target_id) for action in stale_unsettled],
        lift_failing=[(row.id, row.target_id) for row in lift_failing],
        stale_after=stale_after,
        paused=paused is not None,
    )


def _alert_unverified(
    session: Session,
    plan: VerificationPlan,
    read_back: set[int],
    moment: datetime,
) -> None:
    """After the verification pass: name what is still unverified too long.

    Restrictions read back this cycle are not named (after downtime the first
    cycle reads them all back). Attempts whose outcome is still unknown are
    named only if they are still unknown now; so are lifts that keep failing.
    """
    stale = [(aid, target) for aid, target in plan.stale if aid not in read_back]
    unsettled = []
    for action_id, target in plan.stale_unsettled:
        action = session.get(EnforcementAction, action_id, populate_existing=True)
        if (
            action is not None
            and action.status != EnforcementStatus.APPLIED
            and enforcement.may_be_in_force(action)
        ):
            unsettled.append((action_id, target))
    lifting = []
    for action_id, target in plan.lift_failing:
        action = session.get(EnforcementAction, action_id, populate_existing=True)
        if action is not None and enforcement.may_be_in_force(action):
            lifting.append((action_id, target))
    plan.stats["unverified_beyond_twice_the_interval"] = len(stale)
    plan.stats["outcome_unknown_beyond_twice_the_interval"] = len(unsettled)
    plan.stats["lift_failing_still_in_force"] = len(lifting)
    if plan.paused or not (stale or unsettled or lifting):
        return
    _notify_unverified(
        session,
        stale=stale,
        unsettled=unsettled,
        lifting=lifting,
        stale_after=plan.stale_after,
        moment=moment,
    )


def _notify_unverified(
    session: Session,
    *,
    stale: list[tuple[int, str]],
    unsettled: list[tuple[int, str]],
    lifting: list[tuple[int, str]],
    stale_after: timedelta,
    moment: datetime,
) -> None:
    """Say (once a day) that restrictions in force have gone unverified too long."""
    hours = stale_after.total_seconds() / 3600

    def examples(rows: list[tuple[int, str]]) -> str:
        names = sorted({target for _id, target in rows})
        return ", ".join(names[:5]) + ("..." if len(names) > 5 else "")

    parts = []
    if stale:
        parts.append(
            f"{len(stale):,} not read back for more than {hours:g} hours: {examples(stale)}. "
            "Either they cannot be read back (the cycle record lists them: "
            "evaluate.pacing.verification, unverified and failed; they are written again at "
            "most once per interval to keep them in force), or the rotation does not reach "
            "them within the interval at this size: raise the read-backs per cycle, or the "
            "interval."
        )
    if unsettled:
        parts.append(
            f"{len(unsettled):,} whose last attempt's outcome has been unknown for more than "
            f"{hours:g} hours: {examples(unsettled)}. They may be in force; the cycle keeps "
            "trying to complete them (or to lift them, if nothing justifies them)."
        )
    if lifting:
        parts.append(
            f"{len(lifting):,} still in force because lifting them keeps failing: "
            f"{examples(lifting)}. The cycle tries again every time; the Notification Center "
            "has the error of each."
        )
    total = len(stale) + len(unsettled) + len(lifting)
    notifications.notify(
        session,
        category=notifications.CATEGORY_ENFORCEMENT,
        severity=Severity.WARNING,
        title=(
            f"{total:,} restriction(s) in force not confirmed in Checkmarx One for more than "
            f"{hours:g} hours (not read back)"
        ),
        body=(
            "Each restriction in force is read back regularly (Settings → Enforcement, verify "
            "each restriction every), so a change made in Checkmarx One that undoes it is "
            "found and re-asserted.\n\n"
            + "\n\n".join(parts)
            + "\n\nThey are still restricted as far as CreditGuard knows."
        ),
        dedupe_key=f"unverified:{moment.strftime('%Y-%m-%d')}",
    )
    session.commit()


def _take_out_of_rotation(session: Session, action_ids: list[int], moment: datetime) -> None:
    """Restrictions that could not be read back go to the back of the rotation.

    Their last verification is unchanged (they stay unverified, and count
    towards the alert); they move behind the others and are not due again for
    a verification interval, so one that keeps failing (an error, or no
    readable answer) neither takes a slot from the others nor is written
    again every cycle.
    """
    for start in range(0, len(action_ids), 1000):
        session.execute(
            update(EnforcementAction)
            .where(EnforcementAction.id.in_(action_ids[start : start + 1000]))
            .values(last_checked_at=moment)
        )
    session.commit()


def _record_rollout(
    session: Session,
    limit: CreditLimit,
    state: LimitPeriodState,
    outcome: enforcement.EnforcementOutcome,
    result: EvaluationResult,
) -> None:
    """Keep a rollout's progress on the period state, and say when one starts.

    ``rollout_pending`` holds the users or projects still to restrict. Every
    one of them was let through by the safety ceiling (or by an admin's
    resume) when its turn came, so the ceiling does not count them as new
    again; anything outside it (a project added to the group since) still is.
    Identities, not a count: a target that leaves the plan (exempted, out of
    the group) frees no slot for another.
    """
    if outcome.planned_targets == 0:
        return
    remaining = outcome.deferred_targets
    if not remaining and state.rollout_total is None:
        return  # done in one cycle, as every small limit is
    starting = state.rollout_total is None
    state.rollout_total = outcome.planned_targets
    state.rollout_done = outcome.planned_targets - remaining
    state.rollout_pending = sorted({target.target_id for target in outcome.deferred}) or None
    noun = "users" if limit.entity_type == EntityType.USER else "projects"
    progress = {
        "limit_id": limit.id,
        "limit": limit.entity_label or limit.entity_id,
        "done": state.rollout_done,
        "total": state.rollout_total,
        "noun": noun,
    }
    result.rollouts.append(progress)
    if starting and remaining:
        notifications.notify(
            session,
            category=notifications.CATEGORY_ENFORCEMENT,
            severity=Severity.WARNING,
            title=(
                f"Restricting {limit.entity_label or limit.entity_id} over several cycles: "
                f"{state.rollout_done:,} of {state.rollout_total:,} {noun} so far"
            ),
            body=(
                f"This limit restricts {state.rollout_total:,} {noun}, more than one cycle makes "
                "changes for (Settings → Enforcement, restriction changes per cycle). The rest "
                "are restricted by the next cycles, resuming where this one stopped; the "
                "progress is shown on the limit. Pausing enforcement stops it."
            ),
            entity_type=limit.entity_type,
            entity_id=limit.entity_id,
            entity_label=limit.entity_label,
            dedupe_key=f"rollout:{limit.id}:{state.period_key}",
        )


def _clear_rollout(state: LimitPeriodState) -> None:
    """The period stopped being restricted (or a lift began): no rollout runs."""
    state.rollout_total = None
    state.rollout_done = None
    state.rollout_pending = None


def _enforce_pending(
    session: Session,
    client: CheckmarxClient,
    limit_ids: list[int],
    *,
    moment: datetime,
    actor: AuditActor,
    resolver: enforcement.RoleResolver | None,
    result: EvaluationResult,
    budget: enforcement.EnforcementBudget,
    recounter: recount.Recounter | None = None,
) -> None:
    """Apply the restrictions of breached limits, each in its own transaction.

    Called once with ``budget.postpone_large`` set (a limit needing more writes
    than that is postponed, so every small limit goes first), then again for
    the postponed ones with whatever budget is left.

    A new restriction of a monthly or quarterly budget is applied only when
    the independent recount of the activity log is also at or over the limit
    (``recount.gate``); otherwise it stays BREACHED, warned and recorded.
    """
    by_limit = {evaluation.limit.id: evaluation for evaluation in result.evaluations}
    for position, limit_id in enumerate(limit_ids):
        if result.enforcement_paused is None:
            result.enforcement_paused = _manual_pause(session)
        if result.enforcement_paused is not None:
            # Paused part way (an admin pressed Pause): the rest wait, and
            # those that would have started restricting are counted as such.
            _count_deferred(session, limit_ids[position:], moment=moment, result=result)
            break
        limit = session.get(CreditLimit, limit_id, populate_existing=True)
        if limit is None or not limit.is_active or not limit.enforce:
            continue
        try:
            window = current_window(limit, moment)
            state = session.scalar(
                select(LimitPeriodState).where(
                    LimitPeriodState.limit_id == limit.id,
                    LimitPeriodState.period_key == window.key,
                )
            )
            if state is None or state.status not in (LimitStatus.BREACHED, LimitStatus.RESTRICTED):
                continue
            held = (
                recount.gate(
                    session,
                    recounter,
                    limit=limit,
                    window=window,
                    counted=Decimal(state.credits_used or 0),
                    moment=moment,
                )
                if recounter is not None
                else None
            )
            if held is not None:
                result.recount_held += 1
                evaluation = by_limit.get(limit.id)
                if evaluation is not None:
                    evaluation.note = held
                session.commit()
                continue
            outcome = enforcement.apply_enforcement(
                session,
                client,
                limit=limit,
                period_key=window.key,
                actor=actor,
                resolver=resolver,
                budget=budget,
            )
            result.enforced += len(outcome.applied)
            if outcome.postponed:
                # Its writes come with the large rollouts, which record its
                # progress (and say when a rollout starts).
                result.postponed.append(limit.id)
            else:
                _record_rollout(session, limit, state, outcome, result)
            # RESTRICTED means "a restriction from this limit is in force for
            # this period", not "one was newly applied this cycle".
            if _has_active_enforcement(session, limit.id, window.key):
                state.status = LimitStatus.RESTRICTED
                state.restricted_at = state.restricted_at or moment
            evaluation = by_limit.get(limit.id)
            if evaluation is not None:
                evaluation.status = state.status
                earlier = evaluation.enforced
                if earlier is not None:
                    outcome.reconciled = [*earlier.reconciled, *outcome.reconciled]
                    outcome.unverified = [*earlier.unverified, *outcome.unverified]
                    outcome.skipped = [*earlier.skipped, *outcome.skipped]
                    outcome.failed = [*earlier.failed, *outcome.failed]
                    outcome.applied = [*earlier.applied, *outcome.applied]
                evaluation.enforced = outcome
            session.commit()
        except Exception as exc:  # noqa: BLE001 - one limit must never block the rest
            session.rollback()
            logger.exception("Enforcing limit %s failed", limit_id)
            result.errors.append(f"limit {limit_id}: {error_text.public_error(exc)}")


def _prepare_recount(
    session: Session,
    recounter: recount.Recounter,
    limit_ids: list[int],
    *,
    moment: datetime,
) -> None:
    """Read the activity log windows the new restrictions' recounts need,
    once, before any of them (the session's transaction is ended first)."""
    periods: set[str] = set()
    for limit_id in limit_ids:
        limit = session.get(CreditLimit, limit_id)
        if limit is None:
            continue
        try:
            window = current_window(limit, moment)
        except PeriodError:
            continue
        if recount.applies(session, limit, window):
            periods.add(recount.period_for(window, moment))
    recounter.prepare(session, periods)


def _count_deferred(
    session: Session, limit_ids: list[int], *, moment: datetime, result: EvaluationResult
) -> None:
    for limit_id in limit_ids:
        limit = session.get(CreditLimit, limit_id)
        if limit is None:
            continue
        try:
            window = current_window(limit, moment)
        except PeriodError:
            continue
        if _would_start_restricting(session, limit, window.key):
            result.deferred += 1
            evaluation = next((e for e in result.evaluations if e.limit.id == limit_id), None)
            if evaluation is not None:
                evaluation.note = (
                    f"Enforcement is paused, so no restriction was applied. "
                    f"{result.enforcement_paused}"
                )


def _manual_pause(session: Session) -> str | None:
    """The pause reason if enforcement is paused right now, else None.

    Asked before every limit, so it reads the one setting it needs.
    """
    if not settings_store.get_value(session, settings_store.KEY_ENFORCEMENT_PAUSED, False):
        return None
    reason = settings_store.get_value(session, settings_store.KEY_ENFORCEMENT_PAUSE_REASON)
    return reason if isinstance(reason, str) and reason else "Paused by an administrator."


def _enforcement_hold(
    session: Session,
    *,
    moment: datetime,
    actor: AuditActor,
    recounter: recount.Recounter | None = None,
) -> str | None:
    """Why no new restriction may be applied this cycle, or None if they may.

    Two things hold enforcement: an admin pausing it, and the safety ceilings.
    The ceilings are on how much may *start* being restricted in a single cycle,
    counted both in limits and in the users and projects they would restrict.
    People run out of budget one at a time; dozens of limits tipping over in the
    same few minutes, or one limit taking hundreds of projects with it, is what
    a bad usage read, a mis-imported file or a wrong period looks like. When
    that happens nothing at all is restricted, and enforcement stays paused
    until an admin has looked and resumed it. Resuming lets that batch through
    once; the ceilings apply again from the following cycle.
    """
    guard = settings_store.enforcement_guard(session)
    if guard.paused:
        return guard.pause_reason or "Paused by an administrator."
    if guard.ceiling_waived_once:
        settings_store.set_value(session, settings_store.KEY_CEILING_WAIVED_ONCE, False)
        session.commit()
        return None
    if guard.max_new_per_cycle <= 0 and guard.max_new_targets_per_cycle <= 0:
        return None

    limits_starting, targets_starting = _about_to_start_restricting(session, moment)
    over_limits = 0 < guard.max_new_per_cycle < len(limits_starting)
    over_targets = 0 < guard.max_new_targets_per_cycle < len(targets_starting)
    if (over_limits or over_targets) and recounter is not None:
        # Only what the recount would let start counts towards the ceiling
        # (the log is read only when the ceiling would trip without it).
        limits_starting, targets_starting = _about_to_start_restricting(
            session, moment, recounter=recounter
        )
        over_limits = 0 < guard.max_new_per_cycle < len(limits_starting)
        over_targets = 0 < guard.max_new_targets_per_cycle < len(targets_starting)
    if not over_limits and not over_targets:
        return None

    examples = ", ".join(limits_starting[:5]) + ("..." if len(limits_starting) > 5 else "")
    what = (
        f"{len(limits_starting)} limits were about to start restricting in one cycle, more "
        f"than the safety ceiling of {guard.max_new_per_cycle}"
        if over_limits
        else (
            f"{len(targets_starting)} users and projects were about to be restricted in one "
            f"cycle, more than the safety ceiling of {guard.max_new_targets_per_cycle}"
        )
    )
    reason = f"Stopped automatically: {what}. Nothing was restricted."
    settings_store.set_value(session, settings_store.KEY_ENFORCEMENT_PAUSED, True)
    settings_store.set_value(session, settings_store.KEY_ENFORCEMENT_PAUSE_REASON, reason)
    notifications.notify(
        session,
        category=notifications.CATEGORY_ENFORCEMENT,
        severity=Severity.CRITICAL,
        title="Enforcement paused: too much was about to be restricted at once",
        body=(
            f"{reason}\n\nLimits affected: {examples}\n\nCheck the Simulation page: if "
            "the figures are wrong (a bad usage read, a wrong period, a mistaken import), "
            "fix that first. If they are right, resume enforcement under Settings → Enforcement: "
            "that lets this batch through, and the ceilings apply again afterwards. Access "
            "that is already restricted stays restricted, and restrictions that are no "
            "longer justified are still lifted."
        ),
        # Each trip is news: it can only happen again after an admin resumed.
        dedupe_key=f"breaker:{moment.isoformat(timespec='seconds')}",
    )
    record_audit(
        session,
        action="enforcement.paused",
        actor=actor,
        target_type="settings",
        after={
            "limits_about_to_restrict": len(limits_starting),
            "targets_about_to_be_restricted": len(targets_starting),
            "limit_ceiling": guard.max_new_per_cycle,
            "target_ceiling": guard.max_new_targets_per_cycle,
        },
        detail=reason,
    )
    session.commit()
    logger.error(reason)
    return reason


def _starting_targets(
    session: Session, limit_id: int, period_key: str, targets: list[tuple[str, str]]
) -> list[tuple[str, str]]:
    """The (kind, target id) pairs this limit would newly restrict.

    "Newly" means the cycle would really change something for it: there is no
    action yet for this limit, period and target, or the last one was lifted
    automatically and would be re-applied. A target an admin restored this
    period, one that is already restricted, and one that was tried and not
    restricted (protected, refused by Checkmarx, deliberately left alone) are
    not new - counting those would trip the ceiling on every cycle for ever.
    """
    if not targets:
        return []
    existing = {
        row.idempotency_key: row
        for row in session.execute(
            select(
                EnforcementAction.idempotency_key,
                EnforcementAction.status,
                EnforcementAction.reversal_reason,
            ).where(
                EnforcementAction.limit_id == limit_id,
                EnforcementAction.period_key == period_key,
            )
        )
    }
    starting: list[tuple[str, str]] = []
    for kind, target_id in targets:
        action = existing.get(
            enforcement.idempotency_key(
                limit_id=limit_id, period_key=period_key, kind=kind, target_id=target_id
            )
        )
        if action is None or (
            action.status == EnforcementStatus.REVERSED
            and action.reversal_reason != enforcement.ADMIN_REASON
        ):
            starting.append((kind, target_id))
    return starting


def _would_start_restricting(session: Session, limit: CreditLimit, period_key: str) -> bool:
    targets = [
        (str(target.kind), target.target_id)
        for target in enforcement.plan_targets(
            session,
            entity_type=limit.entity_type,
            entity_id=limit.entity_id,
            project_actions=effective_project_actions(limit),
        )
    ]
    return bool(_starting_targets(session, limit.id, period_key, targets))


def _about_to_start_restricting(
    session: Session, moment: datetime, *, recounter: recount.Recounter | None = None
) -> tuple[list[str], set[str]]:
    """What this cycle would newly restrict: limit labels, and distinct targets.

    With a ``recounter``, a row that needs the recount counts only when the
    recount agrees (it is read, silently: the gate itself warns)."""
    from app.services import preview_service

    limits_starting: list[str] = []
    targets_starting: set[str] = set()
    # A rollout spread over several cycles passed the ceiling (or an admin let
    # it through) target by target: the users and projects it still has to
    # restrict are not new. Anything else (projects added to the group since,
    # or a whole new breach after the period was lifted) still is. Kept as
    # identities (_record_rollout), never as a count.
    rollouts: dict[tuple[int, str], set[str]] = {
        (state.limit_id, state.period_key): {
            str(target_id) for target_id in (state.rollout_pending or [])
        }
        for state in session.scalars(
            select(LimitPeriodState).where(LimitPeriodState.rollout_pending.is_not(None))
        )
        if state.status in (LimitStatus.BREACHED, LimitStatus.RESTRICTED)
    }
    rows = preview_service.dry_run(session, now=moment, light=True).rows
    if recounter is not None:
        needed = [row for row in rows if row.would_enforce and row.recount_required]
        limits = {row.limit_id: session.get(CreditLimit, row.limit_id) for row in needed}
        windows = {
            limit_id: current_window(limit, moment)
            for limit_id, limit in limits.items()
            if limit is not None
        }
        recounter.prepare(
            session, {recount.period_for(window, moment) for window in windows.values()}
        )
        refused: set[int] = set()
        for limit_id, window in windows.items():
            limit = session.get(CreditLimit, limit_id)
            if limit is None or not recounter.check(session, limit, window).agrees:
                refused.add(limit_id)
        rows = [row for row in rows if row.limit_id not in refused]
    for row in rows:
        if not row.would_enforce or row.blast is None or row.period_key is None:
            continue
        starting = _starting_targets(
            session,
            row.limit_id,
            row.period_key,
            [(target.kind, target.target_id) for target in row.blast.targets],
        )
        let_through = rollouts.get((row.limit_id, row.period_key), set())
        ids = [
            target_id
            for target_id in dict.fromkeys(target_id for _kind, target_id in starting)
            if target_id not in let_through
        ]
        if ids:
            limits_starting.append(row.entity_label or row.entity_id)
            targets_starting.update(ids)
    return limits_starting, targets_starting


def _lift_unjustified_restrictions(
    session: Session,
    client: CheckmarxClient,
    *,
    actor: AuditActor,
    result: EvaluationResult,
    budget: enforcement.EnforcementBudget | None = None,
) -> None:
    """Give back access that nothing justifies withholding any more.

    A restriction is lifted the moment its limit is disabled, deleted or switched
    to monitor only, or its entity is exempted. If Checkmarx was unreachable at
    that moment the change still stands, and this is what completes it: every
    cycle looks for restrictions whose reason has gone and lifts them. Without it
    such a restriction would stay until someone noticed and pressed Restore.
    """
    # Decided from a few columns and set-based reads (every limit, every
    # exemption, the users concerned), not several queries per restriction:
    # a large tenant has thousands in force, and this runs every cycle.
    rows = session.execute(
        select(
            EnforcementAction.id,
            EnforcementAction.status,
            EnforcementAction.limit_id,
            EnforcementAction.entity_type,
            EnforcementAction.entity_id,
            EnforcementAction.target_type,
            EnforcementAction.target_id,
            EnforcementAction.kind,
            EnforcementAction.reversal_reason,
            EnforcementAction.period_key,
        )
        .where(EnforcementAction.status.in_(enforcement.RESTORABLE_STATUSES))
        .order_by(EnforcementAction.id)
    ).all()
    # A demo self-test's restriction lives in the demo tenant, never this one:
    # the demo retry lifts it (enforcement_selftest.retry_demo_holds).
    rows = [row for row in rows if not _demo_selftest_row(row)]
    unsettled = [row.id for row in rows if row.status != EnforcementStatus.APPLIED]
    in_force_unsettled = {
        action.id
        for start in range(0, len(unsettled), 1000)
        for action in session.scalars(
            select(EnforcementAction).where(
                EnforcementAction.id.in_(unsettled[start : start + 1000])
            )
        )
        if enforcement.may_be_in_force(action)
    }
    rows = [
        row
        for row in rows
        if row.status == EnforcementStatus.APPLIED or row.id in in_force_unsettled
    ]
    if not rows:
        return
    limits = {
        limit.id: limit
        for limit in session.scalars(
            select(CreditLimit).where(
                CreditLimit.id.in_({row.limit_id for row in rows if row.limit_id})
            )
        )
    }
    exempt = {
        (entity_type, entity_id)
        for entity_type, entity_id in session.execute(
            select(Exemption.entity_type, Exemption.entity_id)
        )
    }
    protected = enforcement.protected_users(
        session, {row.target_id for row in rows if row.target_type == enforcement.TARGET_USER}
    )
    resolver = enforcement.RoleResolver(client)
    harmless_limits: dict[int, CreditLimit] = {}
    to_lift: list[tuple[int, str]] = []
    for row in rows:
        limit = limits.get(row.limit_id) if row.limit_id else None
        if limit is not None and (not limit.is_active or not limit.enforce):
            # Handled per limit below, so its period state is updated too.
            harmless_limits[limit.id] = limit
            continue
        if row.reversal_reason == enforcement.ADMIN_REASON:
            # An admin's Restore that did not finish (Checkmarx was unreachable,
            # or the process stopped): complete it.
            reason = enforcement.ADMIN_REASON
        elif limit is None:
            # A self-test's restriction its restore left behind, or a deleted limit's.
            reason = (
                "selftest_cleanup"
                if str(row.period_key or "").startswith(enforcement.SELFTEST_PERIOD_PREFIX)
                else "limit_removed"
            )
        elif (row.entity_type, row.entity_id) in exempt:
            reason = enforcement.EXEMPTED_REASON
        elif enforcement.deselected_kind(row.kind, row.target_type, limit):
            # The limit no longer turns this off (its choice was changed).
            reason = enforcement.DESELECTED_REASON
        else:
            # The target itself has become exempt or protected (rather than the
            # limit's own entity): a project exempted while its application's
            # limit restricts it, a user given an administrator role.
            target_entity = (
                EntityType.USER
                if row.target_type == enforcement.TARGET_USER
                else EntityType.PROJECT
            )
            if (target_entity, row.target_id) in exempt:
                reason = enforcement.EXEMPTED_REASON
            elif row.target_id in protected:
                reason = enforcement.PROTECTED_REASON
            else:
                continue
        to_lift.append((row.id, reason))

    for action_id, reason in to_lift:
        action = session.get(EnforcementAction, action_id)
        if action is None or not enforcement.may_be_in_force(action):
            continue
        action_id = action.id
        if budget is not None and not budget.take_write(enforcement.WRITE_LIFT):
            continue  # lifted by the next cycle, which finds it the same way
        try:
            if enforcement.restore_action(
                session, client, action=action, actor=actor, reason=reason, resolver=resolver
            ):
                result.restored += 1
        except Exception as exc:  # noqa: BLE001 - one stuck restore must not stop the cycle
            session.rollback()
            logger.warning("Could not lift restriction %s", action_id, exc_info=True)
            result.errors.append(f"restore {action_id}: {error_text.public_error(exc)}")

    for limit_id, limit in harmless_limits.items():
        try:
            result.restored += restore_on_limit_change(
                session, client, limit=limit, actor=actor, reason="limit_removed", budget=budget
            )
            session.commit()
        except Exception as exc:  # noqa: BLE001
            session.rollback()
            logger.warning("Could not lift the restrictions of limit %s", limit_id, exc_info=True)
            result.errors.append(f"limit {limit_id}: {error_text.public_error(exc)}")


def _demo_selftest_row(row) -> bool:  # type: ignore[no-untyped-def]
    from app.services import demo_service

    return (
        row.limit_id is None
        and str(row.period_key or "").startswith(enforcement.SELFTEST_PERIOD_PREFIX)
        and str(row.target_id).startswith(demo_service.DEMO_PREFIX)
    )


def _evaluate_one(
    session: Session,
    *,
    limit: CreditLimit,
    index: UsageIndex,
    moment: datetime,
    client: CheckmarxClient | None,
    actor: AuditActor,
    result: EvaluationResult,
    hold: str | None = None,
    budget: enforcement.EnforcementBudget | None = None,
    to_enforce: list[int] | None = None,
) -> LimitEvaluation:
    """Evaluate one limit and give back what its period no longer justifies.

    A breached, enforcing limit is not restricted here: its id is added to
    ``to_enforce`` and the cycle applies the restrictions once every lift of
    the cycle has had its turn (``evaluate_all``).
    """
    window = current_window(limit, moment)
    reported_total, available = index.reported_total(limit)

    _close_stale_periods(
        session,
        limit=limit,
        current_key=window.key,
        client=client,
        actor=actor,
        result=result,
        budget=budget,
    )

    state = _get_or_create_state(
        session,
        limit=limit,
        window=window,
        reported_total=reported_total,
        available=available,
        moment=moment,
    )

    # The period's ledger counter exists from its first evaluation on, so
    # that a closed period is reconciled with it (``_settle_closed_periods``)
    # once the budget counts its counter, whatever it counted meanwhile.
    known = index.counter(limit.id, window.key)
    if known is None:
        known = ledger.ensure_counter(session, limit.id, window.key, moment)
    counter = known[0]
    if counts_from_totals(session, limit, window):
        # A budget that counts usage already reported: the current totals of
        # the names that count towards it. A sliding lookback window can drop
        # old consumption, which would otherwise produce negative usage.
        # Re-baseline instead.
        if reported_total < state.baseline_credits:
            logger.info(
                "Reported total for %s %s fell below the period baseline, re-baselining",
                limit.entity_type,
                limit.entity_id,
            )
            state.baseline_credits = reported_total
        used = max(Decimal("0"), reported_total - state.baseline_credits)
    else:
        # A period budget: what the ledger counted for it in this period.
        used = counter
        # Informational only: what of the reported total was there before.
        state.baseline_credits = max(Decimal("0"), reported_total - used)
        # What the period counted stays counted when nothing reports towards
        # the budget any more (a group whose projects were all deleted).
        available = available or used > 0

    state.reported_total = reported_total
    state.usage_available = available
    state.credits_used = used if available else Decimal("0")
    attributed = (
        index.attributed_usage(limit, window=window, state=state, moment=moment)
        if available
        else None
    )
    if attributed is not None:
        state.credits_used += attributed.counted
        state.attributed_credits = attributed.counted
    elif state.attributed_credits is not None:
        state.attributed_credits = None
    state.last_evaluated_at = moment

    if not available:
        result.unavailable += 1
        state.status = LimitStatus.OK
        _clear_rollout(state)
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
        _clear_rollout(state)
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
    # Restricts at the limit, or earlier with a headroom (app/services/headroom.py).
    held_back = index.headroom.for_limit(limit)
    restrict_at = headroom.restrict_at(limit, held_back)
    state.headroom_credits = held_back.credits if held_back.active else None

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
    on_summary = summary_hold(
        session,
        limit=limit,
        window=window,
        index=index,
        credits_used=state.credits_used,
        attributed=attributed.counted if attributed is not None else None,
    )
    if on_summary is not None and restriction_started(session, limit.id, window.key):
        # A restriction already in force (or started) stays in force.
        on_summary = None

    if state.credits_used >= restrict_at:
        state.status = LimitStatus.BREACHED
        if state.breached_at is None:
            state.breached_at = moment
            evaluation.newly_breached = True
            result.breached += 1
            _notify_breach(
                session,
                limit,
                state,
                window,
                exempt=exempt,
                paused=hold is not None,
                on_summary=on_summary,
            )
        early = headroom.early_phrase(limit, state.credits_used, state.headroom_credits)
        if exempt:
            evaluation.note = "Exempt from enforcement."
        elif not limit.enforce:
            result.monitor_only += 1
            evaluation.note = "Monitor only, no action taken."
        elif on_summary is not None:
            # Over budget on summary totals: warned, never restricted.
            result.summary_held += 1
            evaluation.note = (
                f"Over budget on summary totals; not restricted, because {on_summary}."
            )
        elif client is None:
            evaluation.note = "No Checkmarx connection available, enforcement deferred."
        elif hold is not None:
            # Nothing new is restricted, and existing restrictions are left as
            # they are (not re-asserted) until enforcement resumes.
            evaluation.note = f"Enforcement is paused, so no restriction was applied. {hold}"
            if _would_start_restricting(session, limit, window.key):
                result.deferred += 1
        elif to_enforce is not None:
            # Applied after every lift of the cycle (evaluate_all).
            to_enforce.append(limit.id)
            if early is not None:
                evaluation.note = f"Restricted early: {early}."
            if not evaluation.newly_breached:
                # Breached earlier without a restriction (held on summary
                # totals, say): the restriction now starting is announced.
                # Raised once per period (the notice is deduplicated).
                _notify_breach(session, limit, state, window, exempt=False)
        # RESTRICTED means "a restriction from this limit is in force for this
        # period", not "a restriction was newly applied this cycle". Deriving it
        # from the action rows keeps it true on every later cycle of the period,
        # which is what rollover, hold-until-released and the dashboards rely on.
        if _has_active_enforcement(session, limit.id, window.key):
            state.status = LimitStatus.RESTRICTED
            state.restricted_at = state.restricted_at or moment
    else:
        # Not breaching the limit. If access was previously restricted (e.g. because credit
        # limit was lower or usage was higher), restore the removed access now that
        # consumption is within budget.
        was_restricted = state.status in {
            LimitStatus.RESTRICTED,
            LimitStatus.BREACHED,
        } or _has_active_enforcement(session, limit.id, window.key)
        restored = 0
        lifting = False
        if was_restricted:
            # Whatever happens next, no rollout of this period runs any more.
            _clear_rollout(state)
            if client is not None:
                restored = enforcement.restore_for_limit(
                    session,
                    client,
                    limit_id=limit.id,
                    period_key=window.key,
                    actor=actor,
                    reason="credit_increased",
                    budget=budget,
                )
                result.restored += restored
                left = _in_force_count(session, limit.id, window.key)
                if left:
                    # More to lift than this cycle's write budget: the period
                    # stays restricted (the truth: restrictions are in force)
                    # and the next cycles lift the rest, first thing. Only
                    # then is it restored. The Budgets page shows "Lifting".
                    lifting = True
                    state.status = LimitStatus.RESTRICTED
                    evaluation.note = (
                        f"Within budget again: {restored:,} restriction(s) lifted this cycle, "
                        f"{left:,} left for the next cycles."
                    )
                elif restored > 0:
                    state.restored_at = moment
                    state.status = LimitStatus.RESTORED
            else:
                evaluation.note = "No Checkmarx connection available, restoration deferred."

        if not lifting and restored == 0 and state.status != LimitStatus.RESTORED:
            if state.credits_used >= threshold_credits:
                state.status = LimitStatus.WARNED
                if state.warned_at is None:
                    state.warned_at = moment
                    evaluation.newly_warned = True
                    result.warned += 1
                    _notify_warning(session, limit, state, window, percent)
            else:
                state.status = LimitStatus.OK

    if state.status not in (LimitStatus.BREACHED, LimitStatus.RESTRICTED):
        _clear_rollout(state)
    evaluation.status = state.status
    session.flush()
    return evaluation


def _in_force_count(session: Session, limit_id: int, period_key: str) -> int:
    """How many of this limit's restrictions for the period are, or may be, in force."""
    return sum(
        1
        for action in session.scalars(
            select(EnforcementAction).where(
                EnforcementAction.limit_id == limit_id,
                EnforcementAction.period_key == period_key,
                EnforcementAction.status.in_(enforcement.RESTORABLE_STATUSES),
            )
        )
        if enforcement.may_be_in_force(action)
    )


def restriction_started(session: Session, limit_id: int, period_key: str) -> bool:
    """A restriction of this period is in force, or may be: applied, or
    pending (being rolled out, or written with an unknown outcome). Carrying
    it on is not a new restriction (``summary_hold``); a failed one is not in
    force, and trying it again would be."""
    return any(
        enforcement.may_be_in_force(action)
        for action in session.scalars(
            select(EnforcementAction).where(
                EnforcementAction.limit_id == limit_id,
                EnforcementAction.period_key == period_key,
                EnforcementAction.status.in_(
                    (EnforcementStatus.APPLIED, EnforcementStatus.PENDING)
                ),
            )
        )
    )


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
    if counts_existing_usage(limit, window=window):
        return Decimal("0")
    return reported_total


def counts_from_totals(session: Session, limit: CreditLimit, window: PeriodWindow) -> bool:
    """True for a budget whose usage is read from the current totals rather
    than from the ledger: one that counts usage already reported (lifetime,
    custom, count existing usage), and, in demo mode, a demo budget (demo
    readings never reach the ledger)."""
    if counts_existing_usage(limit, window=window):
        return True
    from app.services import demo_service

    return settings_store.demo_mode(session) and str(limit.entity_id).startswith(
        demo_service.DEMO_PREFIX
    )


def summary_hold(
    session: Session,
    *,
    limit: CreditLimit,
    window: PeriodWindow,
    index: UsageIndex,
    credits_used: Decimal,
    attributed: Decimal | None,
) -> str | None:
    """Why a breach of this budget may not start a restriction, or None.

    A period budget's counter holds what the activity log counted and what
    the summary ledger counted (after a fallback to the summary, or from a
    group's own summary row). From running totals the summary cannot always
    tell a glitch from a real fall, so only the log's part may start a new
    restriction; summary-counted usage warns. So do the auto-triage credits
    charged to the person who started the scan: they always derive from the
    summary's project readings (they still count towards the figure). Not for a
    budget that counts current totals (lifetime, custom, count existing
    usage, a demo budget), and not when the admin chose the summary only and
    allowed restrictions from it (``usage.summary_restricts``). A restriction
    already in force is not affected (the caller checks)."""
    restrict_at = index.headroom.restrict_at(limit)
    if credits_used < restrict_at:
        return None
    if counts_from_totals(session, limit, window):
        return None
    if settings_store.summary_restricts(session):
        return None
    if index.log_counter(limit.id, window.key) >= restrict_at:
        return None
    hold = index.restriction_hold
    if hold is None:
        return (
            "the usage over the limit was counted from the consumption summary, "
            "not the activity log"
        )
    return str(hold["reason"])


def counts_existing_usage(limit: CreditLimit, *, window: PeriodWindow) -> bool:
    """True when the period counts usage already reported when it opened.

    The rule behind ``baseline_for``, shared with the auto-triage credits
    charged to a person from their scans so both follow the same period logic.
    """
    if window.period_type in {PeriodType.LIFETIME, PeriodType.CUSTOM}:
        return True
    return bool(limit.count_existing_usage)


def period_usage(
    session: Session,
    *,
    limit: CreditLimit,
    window: PeriodWindow,
    index: UsageIndex,
    moment: datetime,
) -> tuple[Decimal, bool, auto_triage_attribution.AttributedUsage | None]:
    """What the next evaluation would count for this limit, without writing.

    ``(credits_used, usage_available, attributed)``, using the stored period
    state when there is one and the baseline the first evaluation would take
    when there is not. Shared by the simulation and the reports so they cannot
    drift from the evaluation arithmetic.
    """
    reported_total, available = index.reported_total(limit)
    state = index.period_state(limit.id, window.key)
    if not counts_from_totals(session, limit, window):
        # The period's counter, and what the next evaluation will add to it;
        # kept when nothing reports towards the budget any more.
        known = index.counter(limit.id, window.key)
        used = known[0] if known is not None else Decimal("0")
        if not available and used <= 0:
            return Decimal("0"), False, None
        if available:
            attributed = index.attributed_usage(limit, window=window, state=state, moment=moment)
            if attributed is not None:
                return used + attributed.counted, True, attributed
        return used, True, None
    if not available:
        return Decimal("0"), False, None
    baseline = (
        state.baseline_credits
        if state is not None
        else baseline_for(limit, window=window, reported_total=reported_total, available=available)
    )
    used = max(Decimal("0"), reported_total - baseline)
    attributed = index.attributed_usage(limit, window=window, state=state, moment=moment)
    if attributed is not None:
        used += attributed.counted
    return used, True, attributed


def _settle_closed_periods(session: Session, moment: datetime) -> int:
    """Bring a closed period's usage up to what its counter received after
    the period was last evaluated.

    Counters are kept by the period an increase was observed in, so a reading
    taken just before a rollover and evaluated after it still counts towards
    the period it belongs to. Only what arrived after the last evaluation is
    considered, and a closed period's usage is never lowered: changing a
    budget's settings later never rewrites a period already counted (nor
    pushes a restricted one under its limit)."""
    rows = session.execute(
        select(LimitPeriodState, BudgetUsage, CreditLimit.period_type)
        .join(
            BudgetUsage,
            (BudgetUsage.limit_id == LimitPeriodState.limit_id)
            & (BudgetUsage.period_key == LimitPeriodState.period_key),
        )
        .join(CreditLimit, CreditLimit.id == LimitPeriodState.limit_id)
        .where(
            LimitPeriodState.period_end.is_not(None),
            LimitPeriodState.period_end <= moment,
            or_(
                LimitPeriodState.last_evaluated_at.is_(None),
                BudgetUsage.updated_at > LimitPeriodState.last_evaluated_at,
            ),
        )
    ).all()
    settled = 0
    for state, counter, period_type in rows:
        # Only a period of the budget's own type: the month states of a budget
        # now quarterly (or the reverse) stay as they were last counted.
        quarterly = "-Q" in state.period_key
        if period_type not in (PeriodType.MONTHLY, PeriodType.QUARTERLY) or quarterly != (
            period_type == PeriodType.QUARTERLY
        ):
            state.last_evaluated_at = moment
            continue
        used = Decimal(counter.credits or 0) + Decimal(state.attributed_credits or 0)
        if used > state.credits_used:
            state.credits_used = used
            settled += 1
        state.last_evaluated_at = moment
    if rows:
        session.flush()
    return settled


def _get_or_create_state(
    session: Session,
    *,
    limit: CreditLimit,
    window: PeriodWindow,
    reported_total: Decimal,
    available: bool,
    moment: datetime | None = None,
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
        baseline_at=moment or utcnow(),
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
    budget: enforcement.EnforcementBudget | None = None,
) -> None:
    """Roll over: restore access granted purely by an expired period's limit.

    ``hold_until_released`` opts out, which is how an admin keeps a restriction in
    place across the boundary until they personally lift it.
    """
    # The restrictions still in force from earlier periods are whatever action
    # rows say is APPLIED. The period state's own status is only a label and is
    # never trusted to decide whether someone gets their access back.
    restricted_periods = {
        action.period_key
        for action in session.scalars(
            select(EnforcementAction).where(
                EnforcementAction.limit_id == limit.id,
                EnforcementAction.period_key != current_key,
                EnforcementAction.status.in_(enforcement.RESTORABLE_STATUSES),
            )
        )
        if enforcement.may_be_in_force(action)
    }
    open_statuses = [LimitStatus.RESTRICTED, LimitStatus.BREACHED, LimitStatus.WARNED]
    stale = list(
        session.scalars(
            select(LimitPeriodState).where(
                LimitPeriodState.limit_id == limit.id,
                LimitPeriodState.period_key != current_key,
                or_(
                    LimitPeriodState.status.in_(open_statuses),
                    LimitPeriodState.period_key.in_(restricted_periods),
                ),
            )
        )
    )
    states_by_period = {state.period_key: state for state in stale}

    # Every period with a live restriction is handled, whether or not it still
    # has a state row; then any remaining stale state is simply closed.
    for period_key in sorted(restricted_periods | set(states_by_period)):
        state = states_by_period.get(period_key)
        if period_key not in restricted_periods:
            if state is not None:
                state.status = LimitStatus.RESTORED if state.restricted_at else LimitStatus.OK
            continue

        if limit.hold_until_released:
            logger.info(
                "Limit %s is held until manually released, keeping period %s restricted",
                limit.id,
                period_key,
            )
            if state is not None:
                state.status = LimitStatus.RESTRICTED
            continue
        if client is None:
            # Nothing can be lifted without a connection. Leave the period marked
            # restricted so the next connected cycle picks it up, rather than
            # recording a restore that never happened.
            if state is not None:
                state.status = LimitStatus.RESTRICTED
            continue
        deferred_before = budget.writes_deferred if budget is not None else 0
        try:
            restored = enforcement.restore_for_limit(
                session,
                client,
                limit_id=limit.id,
                period_key=period_key,
                actor=actor,
                reason="period_rollover",
                budget=budget,
            )
        except Exception as exc:  # noqa: BLE001 - one failure must not stop the cycle
            shown = error_text.public_error(exc)
            result.errors.append(f"limit {limit.id}: could not restore after rollover: {shown}")
            logger.exception("Rollover restore failed for limit %s", limit.id)
            if state is not None:
                state.status = LimitStatus.RESTRICTED
            continue
        result.restored += restored
        if budget is not None and budget.writes_deferred > deferred_before:
            # More to lift than this cycle's budget: the rest next cycle.
            if state is not None:
                state.status = LimitStatus.RESTRICTED
            continue
        if state is not None:
            state.restored_at = utcnow()
            state.status = LimitStatus.RESTORED
            _clear_rollout(state)
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
    paused: bool = False,
    on_summary: str | None = None,
) -> None:
    entity = limit.entity_label or limit.entity_id
    if exempt:
        tail = "This entity is on the exemption list, so no action was taken."
        severity = Severity.WARNING
        dedupe = notifications.monitor_only_key(limit.id, window.key)
    elif limit.enforce and on_summary is not None:
        tail = (
            f"Over budget on summary totals; not restricted, because {on_summary}. Only "
            "usage counted from the credit activity log starts a restriction of a monthly "
            "or quarterly budget."
        )
        severity = Severity.WARNING
        dedupe = notifications.monitor_only_key(limit.id, window.key)
    elif limit.enforce and paused:
        tail = (
            "This limit enforces, but enforcement is paused, so nothing has been "
            "restricted. It will be once enforcement is resumed, if still over."
        )
        severity = Severity.CRITICAL
        dedupe = notifications.breach_key(limit.id, window.key)
    elif limit.enforce:
        tail = "Enforcement is on, so access is being restricted now."
        severity = Severity.CRITICAL
        dedupe = notifications.breach_key(limit.id, window.key)
    else:
        tail = "This limit is monitor only, so no action was taken."
        severity = Severity.WARNING
        dedupe = notifications.monitor_only_key(limit.id, window.key)

    if notifications.already_raised(session, dedupe):
        return  # the breakdown below is not worth computing for a duplicate
    when = usage_mix.window_phrase(window)
    mix = usage_mix.mix_for(session, limit, period_key=window.key, state=state)
    if mix is not None:
        # One sentence: the credits against the limit, and what they went on.
        headline = usage_mix.describe(
            mix,
            period_key=window.key,
            entity_type=str(limit.entity_type),
            credit_limit=limit.credit_limit,
            when=when,
        )
    else:
        headline = (
            f"{usage_mix.format_credits(state.credits_used)} of "
            f"{usage_mix.format_credits(limit.credit_limit)} credits used {when}."
        )
    early = headroom.early_phrase(limit, state.credits_used, state.headroom_credits)
    title = f"{limit.entity_type.capitalize()} {entity} reached its credit limit"
    if early is not None:
        # Not over budget: inside the headroom kept before the limit.
        title = f"{limit.entity_type.capitalize()} {entity} is nearly out of credits"
        first = "Restricted early" if limit.enforce and not exempt else "Inside the headroom"
        tail = f"{first}: {early}. {tail}"
    lines = [headline, tail]
    if limit.enforce and not exempt:
        kind = usage_mix.restriction_kind_for(limit.entity_type)
        actions = effective_project_actions(limit)
        lines.append(
            "What the restriction does: "
            + (
                "the AI roles are removed from the user."
                if kind == EnforcementKind.REMOVE_USER_ROLES
                else f"{usage_mix.actions_phrase(actions)} "
                + ("is" if len(actions) == 1 else "are")
                + " turned off on "
                + ("the project." if limit.entity_type == EntityType.PROJECT else "its projects.")
            )
            + " "
            + usage_mix.does_not_stop(kind, mix, actions=actions)
        )
    notifications.notify(
        session,
        category=notifications.CATEGORY_WARNING
        if not limit.enforce
        else notifications.CATEGORY_ENFORCEMENT,
        severity=severity,
        title=title,
        body="\n".join(lines),
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
    budget: enforcement.EnforcementBudget | None = None,
) -> int:
    """Lift restrictions when a limit is disabled, deleted or switched to monitor only.

    Leaving someone restricted by a limit that no longer applies is the single
    most confusing failure this tool could have, so it is handled at the point the
    limit changes rather than waiting for the next cycle.
    """
    if client is None:
        return 0
    deferred_before = budget.writes_deferred if budget is not None else 0
    restored = enforcement.restore_for_limit(
        session, client, limit_id=limit.id, actor=actor, reason=reason, budget=budget
    )
    if budget is not None and budget.writes_deferred > deferred_before:
        # The rest are lifted by the next cycle; the period stays restricted
        # until they are. No rollout of the limit runs any more.
        for st in session.scalars(
            select(LimitPeriodState).where(LimitPeriodState.limit_id == limit.id)
        ):
            _clear_rollout(st)
        if restored:
            record_audit(
                session,
                action="enforcement.reversed_bulk",
                actor=actor,
                target_type="credit_limit",
                target_id=str(limit.id),
                target_label=limit.entity_label,
                detail=(
                    f"{restored} restriction(s) lifted because the limit changed ({reason}); "
                    f"{budget.writes_deferred - deferred_before} more are lifted by the next "
                    "cycles."
                ),
            )
        return restored
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
            _clear_rollout(st)
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
    from sqlalchemy import func

    return int(
        session.scalar(
            select(func.count()).where(EnforcementAction.status == EnforcementStatus.APPLIED)
        )
        or 0
    )
