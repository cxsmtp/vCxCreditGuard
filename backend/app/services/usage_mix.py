"""What a limit's credits in the current period went on, in words.

Used by the "reached its credit limit" and "restricted" notifications, so an
admin reading one can tell whether the restriction will actually stop the
spending. Turning off Auto Triage does nothing about Fusion scans, and saying so
next to the numbers is the difference between a useful alert and a puzzling one.

The consumption feed reports **credits per entity** and **transactions per
action type**, not credits per action type. So:

* all of the period's credits are attributed to one action type only when no
  other action type has any transaction in the feed, neither now nor in the
  reading the period's baseline came from ("4 credits used in 2026-11: Fusion
  scan 4"). The feed's lookback window slides, so a count that stayed the same
  (or rose by less than happened) can hide older transactions leaving it while
  new ones arrive; with one action type alone in the feed every credit is that
  action's however the window slid, and with more than one nothing says how the
  credits split;
* otherwise the credits are given as a total and the actions behind them as
  transaction counts, and the message says why. A count that fell means older
  transactions left the feed's sliding lookback window, while the credit figure
  was re-based on the window as well: the two do not line up, so neither the
  credits per action nor the period's counts can be told, and the window's
  counts are given instead. When other action types were in the window already
  the counts that rose are given, with a note that a slide can hide new ones.

Period figures come from the same arithmetic as evaluation: the latest reading
minus the reading the period's baseline was taken from (or everything, for a
limit that counts existing usage). Nothing here calls Checkmarx.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checkmarx import usage as usage_api
from app.models.enums import (
    LEGACY_PROJECT_ACTIONS,
    ActionType,
    EnforcementKind,
    EntityType,
    PeriodType,
    ProjectAction,
    UsageView,
)
from app.models.limits import CreditLimit, LimitPeriodState
from app.models.org import CxApplicationProject, CxGroupMembership, CxProjectGroup
from app.models.usage import UsageRecord, UsageSnapshot
from app.services import ingestion, settings_store
from app.services.periods import PeriodWindow, describe_window

logger = logging.getLogger(__name__)

OTHER = "other"
# The order the breakdown is written in, and the backend twin of the labels in
# frontend/src/lib/format.ts.
ACTION_LABELS: dict[str, str] = {
    ActionType.TRIAGE.value: "AI Triage",
    ActionType.AUTO_TRIAGE.value: "Auto Triage",
    ActionType.REMEDIATION.value: "AI Remediation",
    ActionType.DAST_CORRELATION.value: "DAST correlation",
    ActionType.FUSION.value: "Fusion scan",
    OTHER: "Other",
}
FUSION = ActionType.FUSION.value
# From this share on, Fusion is called out as most of the spending.
LARGE_SHARE = 0.5


def bucket(action_type: str | None) -> str:
    normalised = usage_api.normalise_action_type(action_type)
    return normalised if normalised in ACTION_LABELS and normalised != OTHER else OTHER


@dataclass
class UsageMix:
    credits_used: Decimal
    # Auto-triage credits charged to a person from scans they started.
    attributed: Decimal = Decimal("0")
    # Transactions in the period per action type (bucketed).
    transactions: dict[str, int] = field(default_factory=dict)
    # Credits per action type, when the feed allows saying so; None otherwise.
    credits_by_action: dict[str, Decimal] | None = None
    # True when the counts are the whole lookback window: no reading from when
    # the period's baseline was taken survives, or the window slid (a count fell).
    from_window: bool = False
    # True when action types other than those that rose were in the window: a
    # slide there could hide new transactions, so the counts are a floor.
    masked: bool = False
    # The most transactions such a slide could hide: no more can have left the
    # window than were in it when the period's baseline was read.
    may_hide: int = 0
    # Fusion priced per model from GET /api/v1/credits/action-rates, when the
    # period's rise of every Fusion model is known and priced:
    # [(model label, scans, credits per scan, credits)]. None otherwise.
    fusion_priced: list[tuple[str, int, Decimal, Decimal]] | None = None

    @property
    def fusion_credits(self) -> Decimal | None:
        if not self.fusion_priced:
            return None
        return sum((credits for _m, _n, _r, credits in self.fusion_priced), Decimal("0"))

    def fusion_share(self) -> float:
        priced = self.fusion_credits
        if priced is not None and self.credits_used > 0:
            return float(priced / self.credits_used)
        if self.credits_by_action:
            total = sum(self.credits_by_action.values(), Decimal("0"))
            fusion = self.credits_by_action.get(FUSION, Decimal("0"))
            return float(fusion / total) if total > 0 else 0.0
        total_tx = sum(self.transactions.values())
        return self.transactions.get(FUSION, 0) / total_tx if total_tx else 0.0

    def fusion_is_most(self) -> bool:
        """Fusion is most of the spending, as far as the figures can say.

        Credits per action say it outright. Transaction counts only for the
        period itself; the whole window's counts are no basis for that.
        """
        if not self.has_fusion():
            return False
        if self.fusion_credits is not None or self.credits_by_action:
            return self.fusion_share() >= LARGE_SHARE
        if self.from_window:
            return False
        if self.masked:
            # Worst case: every hidden transaction was something else.
            total_tx = sum(self.transactions.values()) + self.may_hide
            return self.transactions.get(FUSION, 0) / total_tx >= LARGE_SHARE
        return self.fusion_share() >= LARGE_SHARE

    def has_fusion(self) -> bool:
        if self.credits_by_action is not None:
            return self.credits_by_action.get(FUSION, Decimal("0")) > 0
        return self.transactions.get(FUSION, 0) > 0


# ------------------------------------------------------------------ reading


def _sources(session: Session, limit: CreditLimit) -> list[tuple[str, list[str]]]:
    """Which dimension rows make up this limit's figure (mirrors UsageIndex)."""
    entity_id = limit.entity_id
    if limit.entity_type == EntityType.USER:
        return [(UsageView.USER.value, [entity_id])]
    if limit.entity_type == EntityType.PROJECT:
        return [(UsageView.PROJECT.value, [entity_id])]
    if limit.entity_type == EntityType.APPLICATION:
        if _present(session, UsageView.APPLICATION.value, entity_id):
            return [(UsageView.APPLICATION.value, [entity_id])]
        projects = list(
            session.scalars(
                select(CxApplicationProject.project_id).where(
                    CxApplicationProject.application_id == entity_id
                )
            )
        )
        return [(UsageView.PROJECT.value, projects)]
    if limit.entity_type == EntityType.GROUP:
        if not limit.include_member_usage and _present(session, UsageView.GROUP.value, entity_id):
            return [(UsageView.GROUP.value, [entity_id])]
        sources = [
            (
                UsageView.PROJECT.value,
                list(
                    session.scalars(
                        select(CxProjectGroup.project_id).where(
                            CxProjectGroup.group_id == entity_id
                        )
                    )
                ),
            )
        ]
        if limit.include_member_usage:
            sources.append(
                (
                    UsageView.USER.value,
                    list(
                        session.scalars(
                            select(CxGroupMembership.user_id).where(
                                CxGroupMembership.group_id == entity_id
                            )
                        )
                    ),
                )
            )
        return sources
    return []


def _present(session: Session, view: str, entity_id: str) -> bool:
    snapshot = ingestion.latest_snapshot(session, view)
    if snapshot is None:
        return False
    return (
        session.scalar(
            select(UsageRecord.id).where(
                UsageRecord.snapshot_id == snapshot.id, UsageRecord.entity_id == entity_id
            )
        )
        is not None
    )


def _snapshot_at(session: Session, view: str, moment: datetime) -> UsageSnapshot | None:
    query = select(UsageSnapshot).where(
        UsageSnapshot.view_by == view,
        UsageSnapshot.held_reason.is_(None),
        UsageSnapshot.collected_at <= moment,
    )
    if not settings_store.demo_mode(session):
        query = query.where(
            UsageSnapshot.period_param.is_distinct_from(settings_store.DEMO_PERIOD_PARAM)
        )
    return session.scalar(
        query.order_by(UsageSnapshot.collected_at.desc(), UsageSnapshot.id.desc()).limit(1)
    )


def _actions(session: Session, snapshot: UsageSnapshot | None, ids: list[str]) -> dict[str, int]:
    totals: dict[str, int] = {}
    if snapshot is None or not ids:
        return totals
    for actions in session.scalars(
        select(UsageRecord.actions).where(
            UsageRecord.snapshot_id == snapshot.id, UsageRecord.entity_id.in_(ids)
        )
    ):
        for action, count in (actions or {}).items():
            if isinstance(count, int | float):
                key = bucket(action)
                totals[key] = totals.get(key, 0) + int(count)
    return totals


def _fusion_models(
    session: Session, snapshot: UsageSnapshot | None, ids: list[str]
) -> dict[str, int]:
    """Fusion transactions per raw action type (one per model), from the raw rows.

    The stored breakdown files every Fusion model under "fusion"; the model is
    kept in the raw row the feed sent, which is what a price needs.
    """
    totals: dict[str, int] = {}
    if snapshot is None or not ids:
        return totals
    for raw in session.scalars(
        select(UsageRecord.raw).where(
            UsageRecord.snapshot_id == snapshot.id, UsageRecord.entity_id.in_(ids)
        )
    ):
        performed = raw.get("actionsPerformed") if isinstance(raw, dict) else None
        entries = performed.get("actions") if isinstance(performed, dict) else None
        for entry in entries if isinstance(entries, list) else []:
            if not isinstance(entry, dict):
                continue
            action = entry.get("actionType")
            count = entry.get("transactionCount")
            if (
                not isinstance(action, str)
                or usage_api.normalise_action_type(action) != FUSION
                or not isinstance(count, int)
                or isinstance(count, bool)
            ):
                continue
            key = usage_api.action_key(action)
            totals[key] = totals.get(key, 0) + count
    return totals


def rate_table(session: Session) -> dict[str, tuple[Decimal, str | None]]:
    """Credits per action by comparable action key, from the stored action rates.

    Indexed by the rate's ``action_type`` and by its ``display_name``, both as
    :func:`usage_api.action_key`, so either spelling the feed uses matches.
    """
    stored = settings_store.action_rates(session)
    table: dict[str, tuple[Decimal, str | None]] = {}
    for entry in (stored or {}).get("rates") or []:
        if not isinstance(entry, dict):
            continue
        try:
            price = Decimal(str(entry.get("credits_per_action")))
        except (ArithmeticError, ValueError):
            continue
        if not price.is_finite() or price < 0:
            continue
        display = entry.get("display_name") if isinstance(entry.get("display_name"), str) else None
        for name in (entry.get("action_type"), display):
            if isinstance(name, str) and name.strip():
                table.setdefault(usage_api.action_key(name), (price, display))
    return table


def _price_fusion(
    session: Session,
    *,
    latest: dict[str, int],
    baseline: dict[str, int],
    fusion_rise: int,
    own: Decimal,
) -> list[tuple[str, int, Decimal, Decimal]] | None:
    """The period's Fusion scans per model at their price, or None when unsure.

    Only when every model's count is known not to have fallen, the per-model
    rises add up to the Fusion rise, each rising model has a price, and the
    priced credits fit in the period's own credits.
    """
    if fusion_rise <= 0:
        return None
    rises = {key: latest.get(key, 0) - baseline.get(key, 0) for key in set(latest) | set(baseline)}
    if any(rise < 0 for rise in rises.values()):
        return None
    rising = {key: rise for key, rise in rises.items() if rise > 0}
    if sum(rising.values()) != fusion_rise:
        return None
    rates = rate_table(session)
    priced: list[tuple[str, int, Decimal, Decimal]] = []
    for key in sorted(rising):
        rate = rates.get(key)
        if rate is None:
            return None
        price, display = rate
        model = usage_api.fusion_model(display) or usage_api.fusion_model(key)
        if model is None:
            return None
        priced.append((model, rising[key], price, price * rising[key]))
    if sum((credits for *_rest, credits in priced), Decimal("0")) > own:
        # The prices do not fit the credits the feed reports (a price changed,
        # say): say nothing rather than something wrong.
        return None
    return priced


def _counts_everything(limit: CreditLimit) -> bool:
    return limit.period_type in {PeriodType.LIFETIME, PeriodType.CUSTOM} or bool(
        limit.count_existing_usage
    )


def compute(session: Session, limit: CreditLimit, state: LimitPeriodState) -> UsageMix | None:
    """The period's usage for this limit, by action type, as far as the feed says."""
    if not state.usage_available:
        return None
    latest: dict[str, int] = {}
    baseline: dict[str, int] = {}
    latest_models: dict[str, int] = {}
    baseline_models: dict[str, int] = {}
    from_window = False
    since = state.baseline_at or state.period_start
    everything = _counts_everything(limit)
    for view, ids in _sources(session, limit):
        newest = ingestion.latest_snapshot(session, view)
        for action, count in _actions(session, newest, ids).items():
            latest[action] = latest.get(action, 0) + count
        for key, count in _fusion_models(session, newest, ids).items():
            latest_models[key] = latest_models.get(key, 0) + count
        if everything:
            continue
        earlier = _snapshot_at(session, view, since)
        if earlier is None:
            from_window = True
            continue
        for action, count in _actions(session, earlier, ids).items():
            baseline[action] = baseline.get(action, 0) + count
        for key, count in _fusion_models(session, earlier, ids).items():
            baseline_models[key] = baseline_models.get(key, 0) + count
    if from_window:
        baseline = {}
    deltas = {
        action: latest.get(action, 0) - baseline.get(action, 0)
        for action in set(latest) | set(baseline)
    }
    if any(delta < 0 for delta in deltas.values()):
        # The window slid: what left it and what is new cannot be told apart.
        from_window = True
        deltas = dict(latest)
    transactions = {action: count for action, count in deltas.items() if count > 0}
    # Every action type with transactions in the feed, now or at the baseline.
    # Only when that is the one action that rose are all credits provably its:
    # otherwise older transactions of another type may have left the sliding
    # window while as many new ones arrived, leaving its count unchanged.
    in_feed = {action for action, count in latest.items() if count > 0} | {
        action for action, count in baseline.items() if count > 0
    }
    masked = not from_window and bool(in_feed - set(transactions))

    attributed = state.attributed_credits or Decimal("0")
    own = max(Decimal("0"), state.credits_used - attributed)
    credits_by_action: dict[str, Decimal] | None = None
    if own == 0:
        credits_by_action = {}
    elif len(transactions) == 1 and not from_window and in_feed == set(transactions):
        credits_by_action = {next(iter(transactions)): own}
    if credits_by_action is not None and attributed > 0:
        auto = ActionType.AUTO_TRIAGE.value
        credits_by_action[auto] = credits_by_action.get(auto, Decimal("0")) + attributed
    fusion_priced = None
    if not from_window and not masked and transactions.get(FUSION, 0) > 0:
        # Exact only where the counts are: the period's own rise, nothing in the
        # window that a slide could have hidden behind it.
        fusion_priced = _price_fusion(
            session,
            latest=latest_models,
            baseline={} if everything else baseline_models,
            fusion_rise=transactions[FUSION],
            own=own,
        )
    return UsageMix(
        credits_used=state.credits_used,
        attributed=attributed,
        transactions=transactions,
        credits_by_action=credits_by_action,
        from_window=from_window,
        masked=masked,
        may_hide=sum(count for count in baseline.values() if count > 0) if masked else 0,
        fusion_priced=fusion_priced,
    )


def for_period(session: Session, limit: CreditLimit, period_key: str) -> UsageMix | None:
    state = session.scalar(
        select(LimitPeriodState).where(
            LimitPeriodState.limit_id == limit.id, LimitPeriodState.period_key == period_key
        )
    )
    return compute(session, limit, state) if state is not None else None


# ------------------------------------------------------------------ wording


def format_credits(value: Decimal | int | float) -> str:
    """4, 2.5, 0.25: no trailing zeros, no exponent."""
    if isinstance(value, int):
        return str(value)
    text = f"{Decimal(str(value)).normalize():f}"
    return text.rstrip("0").rstrip(".") if "." in text else text


_number = format_credits


def _ordered(mapping: dict[str, object]) -> list[str]:
    return [action for action in ACTION_LABELS if action in mapping]


def period_phrase(period_key: str) -> str:
    """ "in 2026-11" for a month or quarter, "in this budget period" otherwise.

    A lifetime limit counts everything the consumption feed reports, which is
    bounded by its lookback window (see evaluation.baseline_for), not
    everything since the limit was created.
    """
    if len(period_key) <= 8 and period_key[:4].isdigit():
        return f"in {period_key}"
    if period_key == "lifetime":
        return "in the reporting window"
    return "in this budget period"


def window_phrase(window: PeriodWindow) -> str:
    """ "in November 2026", "in Q4 2026", "in the reporting window", or the dates."""
    if window.period_type == PeriodType.LIFETIME:
        return period_phrase("lifetime")
    if window.period_type in (PeriodType.MONTHLY, PeriodType.QUARTERLY):
        return f"in {describe_window(window)}"
    return describe_window(window)


def describe(
    mix: UsageMix,
    *,
    period_key: str,
    entity_type: str,
    credit_limit: Decimal | int | None = None,
    when: str | None = None,
) -> str:
    """One or two sentences: the credits (of the limit, when given), and what
    they were spent on. ``when`` overrides the period wording."""
    of = f" of {_number(credit_limit)}" if credit_limit is not None else ""
    used = f"{_number(mix.credits_used)}{of} credits used {when or period_phrase(period_key)}"
    charged = " (charged from scans they started)"
    if mix.fusion_priced:
        return _describe_priced(mix, used=used)
    if mix.credits_by_action:
        parts = []
        for action in _ordered(mix.credits_by_action):
            amount = mix.credits_by_action[action]
            if amount <= 0:
                continue
            label = ACTION_LABELS[action]
            if action == ActionType.AUTO_TRIAGE.value and mix.attributed > 0:
                label += charged
            parts.append(f"{label} {_number(amount)}")
        return f"{used}: {', '.join(parts)}." if parts else f"{used}."
    if mix.transactions:
        actions = ", ".join(
            f"{ACTION_LABELS[action]} {count} transaction{'s' if count != 1 else ''}"
            for action in _ordered(mix.transactions)
            for count in [mix.transactions[action]]
        )
        if mix.from_window:
            text = (
                f"{used}. Checkmarx reports credits per {entity_type}, not per action, and the "
                "period's transactions cannot be told apart from older ones, so these are the "
                f"actions in its whole lookback window: {actions}."
            )
        elif mix.masked:
            text = (
                f"{used}. Checkmarx reports credits per {entity_type}, not per action, so "
                f"these are the transactions that rose: {actions}. Other actions were already "
                "in its lookback window, and older transactions leaving that window can hide "
                "new ones, so they may be behind some of these credits too."
            )
        else:
            text = (
                f"{used}. Checkmarx reports credits per {entity_type}, not per action, so "
                f"these are the actions behind them: {actions}."
            )
        if mix.attributed > 0:
            text += (
                f" Auto Triage charged from scans they started: {_number(mix.attributed)} credits."
            )
        return text
    return f"{used}."


def _describe_priced(mix: UsageMix, *, used: str) -> str:
    """Fusion scans priced per model, and whatever else the credits went on."""
    priced = mix.fusion_priced or []
    parts = [
        f"Fusion scan ({model}) {count} scan{'s' if count != 1 else ''} = "
        f"{_number(credits)} credit{'s' if credits != 1 else ''}"
        for model, count, _rate, credits in priced
    ]
    own = max(Decimal("0"), mix.credits_used - mix.attributed)
    rest = own - (mix.fusion_credits or Decimal("0"))
    others = {action: count for action, count in mix.transactions.items() if action != FUSION}
    text = f"{used}: {', '.join(parts)}"
    if others:
        listed = ", ".join(
            f"{ACTION_LABELS[action]} {count} transaction{'s' if count != 1 else ''}"
            for action in _ordered(others)
            for count in [others[action]]
        )
        text += (
            f"; the other {_number(rest)} credits went on {listed}"
            if rest > 0
            else f"; also {listed}"
        )
    elif rest > 0:
        text += (
            f"; the other {_number(rest)} credit{'s' if rest != 1 else ''} cannot be placed "
            "on an action"
        )
    text += "."
    if mix.attributed > 0:
        text += f" Auto Triage charged from scans they started: {_number(mix.attributed)} credits."
    return text


_ACTION_NAMES: dict[str, str] = {
    ProjectAction.AUTO_TRIAGE.value: "Auto Triage",
    ProjectAction.PR_REMEDIATION.value: "PR triage and remediation",
    ProjectAction.FUSION.value: "Fusion",
}


def actions_phrase(actions: tuple[str, ...] | list[str]) -> str:
    """ "Auto Triage, PR triage and remediation and Fusion" for a limit's actions."""
    names = [_ACTION_NAMES[action] for action in _ACTION_NAMES if action in actions]
    if len(names) <= 1:
        return "".join(names) or "nothing"
    return f"{', '.join(names[:-1])} and {names[-1]}"


def does_not_stop(
    kind: str, mix: UsageMix | None, *, actions: tuple[str, ...] | list[str] | None = None
) -> str:
    """What the restriction leaves running, in plain words.

    Only what the README states about the enforcement actions: a user
    restriction removes the AI roles and nothing else; a project restriction
    turns off what its limit chose (``actions``; the legacy pair when None).
    """
    fusion_first = ""
    if mix is not None and mix.fusion_is_most():
        fusion_first = (
            "Most of these credits were Fusion scans. "
            if mix.credits_by_action or mix.fusion_priced
            else "Most of the actions behind them were Fusion scans. "
        )
    if kind == EnforcementKind.REMOVE_USER_ROLES:
        return (
            f"{fusion_first}Removing the AI roles changes no project setting, so Auto Triage, "
            "PR triage and remediation and Fusion scans keep running on projects; a project, "
            "group or application limit can turn those off."
        )
    chosen = tuple(actions) if actions is not None else LEGACY_PROJECT_ACTIONS
    sentences = [fusion_first.strip()] if fusion_first else []
    if ProjectAction.FUSION.value not in chosen:
        sentences.append(
            f"Turning off {actions_phrase(chosen)} does not stop Fusion scans: this limit does "
            "not turn Fusion off (edit the limit and choose Turn off Fusion to add it)."
        )
    else:
        sentences.append(
            "Turning Fusion off in the project's settings may not stop a scan started with its "
            "own settings from turning Fusion on for that one scan (the lock against that is "
            "not verified), and the AI engine can still run without Fusion (LLM-based "
            "scanning, whose credit cost is not known). CreditGuard re-applies the setting "
            "every cycle and records any scan that ran Fusion as a policy violation."
        )
    left = [
        _ACTION_NAMES[action]
        for action in (ProjectAction.AUTO_TRIAGE.value, ProjectAction.PR_REMEDIATION.value)
        if action not in chosen
    ]
    if left:
        sentences.append(f"This limit leaves {' and '.join(left)} running.")
    sentences.append(
        "It leaves people's AI roles alone, so AI Triage and AI Remediation they start "
        "themselves keep working (and keep counting here); only a user limit can stop those."
    )
    return " ".join(sentences)


def restriction_kind_for(entity_type: str) -> str:
    """The kind of restriction a limit on this entity level applies."""
    if entity_type == EntityType.USER:
        return EnforcementKind.REMOVE_USER_ROLES
    return EnforcementKind.DISABLE_AUTO_TRIAGE


def mix_for(
    session: Session, limit: CreditLimit, *, period_key: str, state: LimitPeriodState | None = None
) -> UsageMix | None:
    try:
        return (
            compute(session, limit, state)
            if state is not None
            else for_period(session, limit, period_key)
        )
    except Exception:  # noqa: BLE001 - a message detail must never break enforcement
        logger.warning("Could not break down the usage of limit %s", limit.id, exc_info=True)
        return None
