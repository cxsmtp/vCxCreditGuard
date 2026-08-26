"""Budget period windows and keys."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.models.enums import PeriodType
from app.models.limits import CreditLimit
from app.services.periods import (
    PeriodError,
    current_window,
    describe_window,
    next_month_start,
    next_quarter_start,
)


def limit(period_type: str, **kwargs) -> CreditLimit:
    return CreditLimit(
        id=1,
        entity_type="user",
        entity_id="u1",
        credit_limit=100,
        period_type=period_type,
        created_at=datetime(2026, 1, 15, tzinfo=UTC),
        **kwargs,
    )


class TestMonthly:
    def test_key_and_bounds(self) -> None:
        window = current_window(
            limit(PeriodType.MONTHLY), datetime(2026, 8, 11, 14, 30, tzinfo=UTC)
        )
        assert window.key == "2026-08"
        assert window.start == datetime(2026, 8, 1, tzinfo=UTC)
        assert window.end == datetime(2026, 9, 1, tzinfo=UTC)

    def test_last_instant_of_the_month_stays_in_it(self) -> None:
        window = current_window(
            limit(PeriodType.MONTHLY), datetime(2026, 8, 31, 23, 59, 59, tzinfo=UTC)
        )
        assert window.key == "2026-08"

    def test_first_instant_of_the_next_month_rolls_over(self) -> None:
        window = current_window(limit(PeriodType.MONTHLY), datetime(2026, 9, 1, 0, 0, tzinfo=UTC))
        assert window.key == "2026-09"

    def test_december_rolls_into_january(self) -> None:
        assert next_month_start(datetime(2026, 12, 5, tzinfo=UTC)) == datetime(
            2027, 1, 1, tzinfo=UTC
        )

    def test_windows_are_half_open(self) -> None:
        window = current_window(limit(PeriodType.MONTHLY), datetime(2026, 8, 11, tzinfo=UTC))
        assert window.contains(window.start)
        assert not window.contains(window.end)


class TestQuarterly:
    @pytest.mark.parametrize(
        ("month", "key", "start_month"),
        [
            (1, "2026-Q1", 1),
            (3, "2026-Q1", 1),
            (4, "2026-Q2", 4),
            (8, "2026-Q3", 7),
            (12, "2026-Q4", 10),
        ],
    )
    def test_quarter_boundaries(self, month: int, key: str, start_month: int) -> None:
        window = current_window(limit(PeriodType.QUARTERLY), datetime(2026, month, 15, tzinfo=UTC))
        assert window.key == key
        assert window.start == datetime(2026, start_month, 1, tzinfo=UTC)

    def test_q4_rolls_into_the_next_year(self) -> None:
        assert next_quarter_start(datetime(2026, 11, 1, tzinfo=UTC)) == datetime(
            2027, 1, 1, tzinfo=UTC
        )


class TestLifetime:
    def test_anchored_at_creation_and_never_ends(self) -> None:
        window = current_window(limit(PeriodType.LIFETIME), datetime(2026, 8, 11, tzinfo=UTC))
        assert window.key == "lifetime"
        assert window.start == datetime(2026, 1, 15, tzinfo=UTC)
        assert window.end is None

    def test_contains_any_later_moment(self) -> None:
        window = current_window(limit(PeriodType.LIFETIME), datetime(2026, 8, 11, tzinfo=UTC))
        assert window.contains(datetime(2099, 1, 1, tzinfo=UTC))


class TestCustom:
    def test_key_encodes_both_dates(self) -> None:
        window = current_window(
            limit(
                PeriodType.CUSTOM,
                custom_period_start=datetime(2026, 1, 1, tzinfo=UTC),
                custom_period_end=datetime(2026, 6, 30, tzinfo=UTC),
            ),
            datetime(2026, 3, 1, tzinfo=UTC),
        )
        assert window.key == "custom:20260101:20260630"
        assert window.is_active is True

    def test_open_ended_custom_period(self) -> None:
        window = current_window(
            limit(PeriodType.CUSTOM, custom_period_start=datetime(2026, 1, 1, tzinfo=UTC)),
            datetime(2026, 3, 1, tzinfo=UTC),
        )
        assert window.key == "custom:20260101:open"
        assert window.end is None

    def test_a_future_period_is_not_active(self) -> None:
        window = current_window(
            limit(PeriodType.CUSTOM, custom_period_start=datetime(2027, 1, 1, tzinfo=UTC)),
            datetime(2026, 3, 1, tzinfo=UTC),
        )
        assert window.is_active is False

    def test_a_finished_period_is_not_active(self) -> None:
        window = current_window(
            limit(
                PeriodType.CUSTOM,
                custom_period_start=datetime(2026, 1, 1, tzinfo=UTC),
                custom_period_end=datetime(2026, 2, 1, tzinfo=UTC),
            ),
            datetime(2026, 3, 1, tzinfo=UTC),
        )
        assert window.is_active is False

    def test_missing_start_is_a_configuration_error(self) -> None:
        with pytest.raises(PeriodError, match="no start date"):
            current_window(limit(PeriodType.CUSTOM), datetime(2026, 3, 1, tzinfo=UTC))

    def test_end_before_start_is_rejected(self) -> None:
        with pytest.raises(PeriodError, match="not after its start"):
            current_window(
                limit(
                    PeriodType.CUSTOM,
                    custom_period_start=datetime(2026, 6, 1, tzinfo=UTC),
                    custom_period_end=datetime(2026, 1, 1, tzinfo=UTC),
                ),
                datetime(2026, 3, 1, tzinfo=UTC),
            )


def test_unknown_period_type_is_rejected() -> None:
    with pytest.raises(PeriodError, match="Unknown period type"):
        current_window(limit("fortnightly"), datetime(2026, 3, 1, tzinfo=UTC))


class TestDescriptions:
    def test_monthly_reads_naturally(self) -> None:
        window = current_window(limit(PeriodType.MONTHLY), datetime(2026, 8, 11, tzinfo=UTC))
        assert describe_window(window) == "August 2026"

    def test_quarterly_reads_naturally(self) -> None:
        window = current_window(limit(PeriodType.QUARTERLY), datetime(2026, 8, 11, tzinfo=UTC))
        assert describe_window(window) == "Q3 2026"

    def test_lifetime_reads_naturally(self) -> None:
        window = current_window(limit(PeriodType.LIFETIME), datetime(2026, 8, 11, tzinfo=UTC))
        assert describe_window(window) == "since the limit was created"

    def test_custom_shows_an_inclusive_end_date(self) -> None:
        window = current_window(
            limit(
                PeriodType.CUSTOM,
                custom_period_start=datetime(2026, 1, 1, tzinfo=UTC),
                custom_period_end=datetime(2026, 7, 1, tzinfo=UTC),
            ),
            datetime(2026, 3, 1, tzinfo=UTC),
        )
        assert describe_window(window) == "01 Jan 2026 to 30 Jun 2026"
