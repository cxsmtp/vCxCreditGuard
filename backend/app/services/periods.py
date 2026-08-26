"""Budget period arithmetic.

All windows are half open, ``[start, end)``, in UTC. A period key is the stable
label that identifies one window for one limit, and is what makes "notify once per
period" and "reset counters at rollover" possible without extra state.

    monthly    2026-08
    quarterly  2026-Q3
    custom     custom:20260101:20260630
    lifetime   lifetime
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from app.models.enums import PeriodType
from app.models.limits import CreditLimit

QUARTER_MONTHS = 3


@dataclass(frozen=True, slots=True)
class PeriodWindow:
    key: str
    start: datetime
    # None for lifetime, which never rolls over.
    end: datetime | None
    period_type: str
    # False when a custom range has not started yet or has already finished.
    is_active: bool = True

    def contains(self, moment: datetime) -> bool:
        if moment < self.start:
            return False
        return self.end is None or moment < self.end


class PeriodError(ValueError):
    """The limit's period configuration cannot produce a window."""


def month_start(moment: datetime) -> datetime:
    return moment.astimezone(UTC).replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def next_month_start(moment: datetime) -> datetime:
    start = month_start(moment)
    return (
        start.replace(year=start.year + 1, month=1)
        if start.month == 12
        else start.replace(month=start.month + 1)
    )


def quarter_of(moment: datetime) -> int:
    return (moment.astimezone(UTC).month - 1) // QUARTER_MONTHS + 1


def quarter_start(moment: datetime) -> datetime:
    first_month = (quarter_of(moment) - 1) * QUARTER_MONTHS + 1
    return moment.astimezone(UTC).replace(
        month=first_month, day=1, hour=0, minute=0, second=0, microsecond=0
    )


def next_quarter_start(moment: datetime) -> datetime:
    start = quarter_start(moment)
    if start.month + QUARTER_MONTHS > 12:
        return start.replace(year=start.year + 1, month=1)
    return start.replace(month=start.month + QUARTER_MONTHS)


def _custom_key(start: datetime, end: datetime | None) -> str:
    tail = end.astimezone(UTC).strftime("%Y%m%d") if end else "open"
    return f"custom:{start.astimezone(UTC).strftime('%Y%m%d')}:{tail}"


def current_window(limit: CreditLimit, now: datetime | None = None) -> PeriodWindow:
    """The window that ``now`` falls into for this limit.

    Raises PeriodError for a custom limit with no start date, which is a
    configuration mistake rather than a runtime condition: evaluating it against
    an invented window could restrict someone on the strength of a guess.
    """
    moment = (now or datetime.now(UTC)).astimezone(UTC)
    period_type = limit.period_type

    if period_type == PeriodType.MONTHLY:
        start = month_start(moment)
        return PeriodWindow(
            key=start.strftime("%Y-%m"),
            start=start,
            end=next_month_start(moment),
            period_type=period_type,
        )

    if period_type == PeriodType.QUARTERLY:
        start = quarter_start(moment)
        return PeriodWindow(
            key=f"{start.year}-Q{quarter_of(moment)}",
            start=start,
            end=next_quarter_start(moment),
            period_type=period_type,
        )

    if period_type == PeriodType.LIFETIME:
        # Anchored at creation so the baseline is captured when the limit is made,
        # not at some arbitrary epoch.
        start = (limit.created_at or moment).astimezone(UTC)
        return PeriodWindow(key="lifetime", start=start, end=None, period_type=period_type)

    if period_type == PeriodType.CUSTOM:
        if limit.custom_period_start is None:
            raise PeriodError(
                "This limit uses a custom period but has no start date. Set a start and "
                "end date, or switch it to monthly."
            )
        start = limit.custom_period_start.astimezone(UTC)
        end = limit.custom_period_end.astimezone(UTC) if limit.custom_period_end else None
        if end is not None and end <= start:
            raise PeriodError("The custom period's end date is not after its start date.")
        window = PeriodWindow(
            key=_custom_key(start, end),
            start=start,
            end=end,
            period_type=period_type,
            is_active=start <= moment and (end is None or moment < end),
        )
        return window

    raise PeriodError(f"Unknown period type {period_type!r}.")


def describe_window(window: PeriodWindow) -> str:
    """Human readable label for notifications and the GUI."""
    if window.period_type == PeriodType.LIFETIME:
        return "since the limit was created"
    if window.period_type == PeriodType.MONTHLY:
        return window.start.strftime("%B %Y")
    if window.period_type == PeriodType.QUARTERLY:
        return f"Q{quarter_of(window.start)} {window.start.year}"
    end = window.end - timedelta(days=1) if window.end else None
    if end is None:
        return f"from {window.start:%d %b %Y}"
    return f"{window.start:%d %b %Y} to {end:%d %b %Y}"
