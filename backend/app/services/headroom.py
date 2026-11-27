"""Headroom: restrict a budget before it runs out.

Credits appear in Checkmarx One only once an action is billed, which for a
scan is usually when it finishes. So the scan that takes a budget over its
limit normally completes, whatever CreditGuard does: by the time its credits
are visible, they are spent. A headroom restricts *before* that: once no more
than ``headroom`` credits are left, so the next scan, the one that would
overrun, is not started.

The rule, one place for every caller (evaluation, the recount gate, the
simulation and dry run, the safety ceiling, lifting on a credit increase)::

    restrict_at = credit_limit - headroom
    restricted when credits_used >= restrict_at   (remaining <= headroom)
    lifted when credits_used < restrict_at        (remaining > headroom)

With no headroom (the default) ``restrict_at`` is the limit itself: exactly
the behaviour before headroom existed. Remaining exactly equal to the headroom
counts as inside it, as usage exactly equal to the limit always counted as
over it.

A headroom is either fixed (``headroom_credits``) or automatic
(``headroom_auto``): the median credits of the budget's entity's Fusion scans
over the last 30 days (``FusionScanCost``, filled from the activity log as it
counts), falling back to the tenant-wide median when the entity has fewer than
``MIN_SAMPLES`` scans, and to no headroom when the tenant has too few as well.
Bounds, so a headroom can never restrict a budget nobody has used: a fixed
headroom holds back at most ``credit_limit - 1`` credits; an automatic one at
most half the limit.
"""

from __future__ import annotations

import statistics
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal

from sqlalchemy import delete, or_, select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models.enums import ActionType, EntityType
from app.models.fastpath import FusionScanCost
from app.models.limits import CreditLimit
from app.models.org import CxApplicationProject, CxProjectGroup
from app.services import credits_text, wording

ZERO = Decimal("0")
CENT = Decimal("0.01")
WINDOW = timedelta(days=30)
# Fewer of the entity's scans than this: the tenant-wide median is used.
MIN_SAMPLES = 3
# At most this many recent scans are read for one median.
MAX_SAMPLES = 2000
AUTO_CAP_SHARE = Decimal("0.5")

OFF = "off"
FIXED = "fixed"
AUTO_ENTITY = "auto_entity"
AUTO_TENANT = "auto_tenant"
AUTO_NONE = "auto_none"


@dataclass(frozen=True, slots=True)
class Headroom:
    """The headroom a budget is judged with right now."""

    credits: Decimal
    source: str
    # Fusion scans the automatic median was taken from.
    samples: int = 0
    # The median before the bound (automatic), or the stored value (fixed).
    chosen: Decimal | None = None

    @property
    def active(self) -> bool:
        return self.credits > 0

    def describe(self) -> str:
        if self.source == OFF:
            return "No headroom: restricts at the limit."
        if self.source == FIXED:
            return f"{_fmt(self.credits)} credits (fixed)."
        if self.source == AUTO_NONE:
            return (
                "Automatic: not enough Fusion scans in the last 30 days yet, so no headroom "
                "for now."
            )
        whose = "this budget's" if self.source == AUTO_ENTITY else "the whole tenant's"
        text = (
            f"Automatic: {_fmt(self.credits)} credits, the median cost of {whose} "
            f"{wording.plural(self.samples, 'Fusion scan')} in the last 30 days"
        )
        if self.chosen is not None and self.chosen != self.credits:
            text += f" ({_fmt(self.chosen)}, held to half the limit)"
        return text + "."


def _fmt(value: Decimal) -> str:
    return credits_text.credits(value)


def restrict_at(limit: CreditLimit, headroom: Headroom) -> Decimal:
    """The usage at which this budget starts restricting."""
    return Decimal(limit.credit_limit) - headroom.credits


def configured(limit: CreditLimit) -> bool:
    return bool(limit.headroom_auto) or bool(limit.headroom_credits)


class Resolver:
    """The headroom of each budget, for one pass (medians read once)."""

    def __init__(self, session: Session, now: datetime | None = None) -> None:
        self.session = session
        self.now = now or utcnow()
        self._tenant: tuple[Decimal | None, int] | None = None
        self._cache: dict[int, Headroom] = {}

    def for_limit(self, limit: CreditLimit) -> Headroom:
        if not configured(limit):
            return Headroom(credits=ZERO, source=OFF)
        key = int(limit.id) if limit.id is not None else -1
        cached = self._cache.get(key)
        if cached is not None and key >= 0:
            return cached
        found = self._compute(limit)
        if key >= 0:
            self._cache[key] = found
        return found

    def restrict_at(self, limit: CreditLimit) -> Decimal:
        return restrict_at(limit, self.for_limit(limit))

    def _compute(self, limit: CreditLimit) -> Headroom:
        cap_limit = Decimal(max(0, int(limit.credit_limit)))
        if not limit.headroom_auto:
            stored = Decimal(max(0, int(limit.headroom_credits or 0)))
            bounded = min(stored, max(ZERO, cap_limit - 1))
            if bounded <= 0:
                return Headroom(credits=ZERO, source=OFF)
            return Headroom(credits=bounded, source=FIXED, chosen=stored)
        median, samples = self._entity_median(limit)
        source = AUTO_ENTITY
        if median is None:
            median, samples = self._tenant_median()
            source = AUTO_TENANT
        if median is None or median <= 0:
            return Headroom(credits=ZERO, source=AUTO_NONE, samples=samples)
        bounded = min(median, (cap_limit * AUTO_CAP_SHARE).quantize(CENT))
        return Headroom(credits=max(ZERO, bounded), source=source, samples=samples, chosen=median)

    # ----------------------------------------------------------- medians

    def _recent(self):  # type: ignore[no-untyped-def]
        return select(FusionScanCost.credits).where(
            FusionScanCost.event_at >= self.now - WINDOW, FusionScanCost.credits > 0
        )

    def _median_of(self, query) -> tuple[Decimal | None, int]:  # type: ignore[no-untyped-def]
        values = [
            Decimal(value)
            for value in self.session.scalars(
                query.order_by(FusionScanCost.event_at.desc()).limit(MAX_SAMPLES)
            )
        ]
        if len(values) < MIN_SAMPLES:
            return None, len(values)
        return Decimal(statistics.median(values)).quantize(CENT), len(values)

    def _tenant_median(self) -> tuple[Decimal | None, int]:
        if self._tenant is None:
            self._tenant = self._median_of(self._recent())
        return self._tenant

    def _entity_median(self, limit: CreditLimit) -> tuple[Decimal | None, int]:
        entity_type = str(limit.entity_type)
        entity_id = str(limit.entity_id)
        query = self._recent()
        if entity_type == EntityType.PROJECT.value:
            query = query.where(FusionScanCost.project_id == entity_id)
        elif entity_type == EntityType.USER.value:
            query = query.where(FusionScanCost.user_id == entity_id)
        elif entity_type == EntityType.APPLICATION.value:
            projects = select(CxApplicationProject.project_id).where(
                CxApplicationProject.application_id == entity_id
            )
            query = query.where(
                or_(
                    FusionScanCost.application_id == entity_id,
                    FusionScanCost.project_id.in_(projects),
                )
            )
        elif entity_type == EntityType.GROUP.value:
            projects = select(CxProjectGroup.project_id).where(CxProjectGroup.group_id == entity_id)
            query = query.where(FusionScanCost.project_id.in_(projects))
        else:
            return None, 0
        return self._median_of(query)


def for_limit(session: Session, limit: CreditLimit) -> Headroom:
    return Resolver(session).for_limit(limit)


# --------------------------------------------------------------- observing


def observe(
    session: Session,
    resolved: Iterable[tuple[object, int, str | None, str | None]],
    now: datetime,
) -> int:
    """Add the new Fusion events the activity log just counted to their
    scan's cost (``activity_source._count``: each new event exactly once).
    Writes nothing when there is no Fusion event among them."""
    from app.checkmarx import usage as usage_api

    adds: dict[str, tuple[Decimal, object, str | None, str | None]] = {}
    for event, count, user_id, application_id in resolved:
        action = usage_api.normalise_action_type(getattr(event, "action", None))
        if action != ActionType.FUSION or count <= 0:
            continue
        scan_ids = getattr(event, "scan_ids", ()) or ()
        scan_key = (str(scan_ids[0]) if scan_ids else f"row:{event.key}")[:128]  # type: ignore[attr-defined]
        credits = Decimal(event.credits) * count  # type: ignore[attr-defined]
        before = adds.get(scan_key)
        total = credits + (before[0] if before is not None else ZERO)
        adds[scan_key] = (total, event, user_id, application_id)
    if not adds:
        return 0
    existing = {
        row.scan_key: row
        for row in session.scalars(
            select(FusionScanCost).where(FusionScanCost.scan_key.in_(sorted(adds)))
        )
    }
    for scan_key, (credits, event, user_id, application_id) in adds.items():
        row = existing.get(scan_key)
        if row is None:
            session.add(
                FusionScanCost(
                    scan_key=scan_key,
                    event_at=event.date,  # type: ignore[attr-defined]
                    project_id=(event.project_id or None),  # type: ignore[attr-defined]
                    application_id=application_id,
                    user_id=user_id,
                    credits=credits,
                )
            )
        else:
            row.credits = Decimal(row.credits or 0) + credits
            row.event_at = min(row.event_at, event.date)  # type: ignore[attr-defined]
    session.execute(delete(FusionScanCost).where(FusionScanCost.event_at < now - WINDOW))
    return len(adds)


# ---------------------------------------------------------------- display


def early_phrase(limit: CreditLimit, credits_used: Decimal, headroom: Decimal | None) -> str | None:
    """ "Restricted early: X credits left, below the headroom of Y" when a
    breached budget is still under its limit; None when it is over budget."""
    if not headroom or headroom <= 0:
        return None
    left = Decimal(limit.credit_limit) - Decimal(credits_used)
    if left <= 0:
        return None
    where = "at" if left == Decimal(headroom) else "below"
    return f"{_fmt(left)} credits left, {where} the headroom of {_fmt(Decimal(headroom))}"
