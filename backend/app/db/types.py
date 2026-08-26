"""Portable column types shared by SQLite and PostgreSQL."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import DateTime, Dialect, TypeDecorator
from sqlalchemy.types import JSON


class UTCDateTime(TypeDecorator[datetime]):
    """Timezone aware datetimes that survive a round trip through SQLite.

    SQLite has no timezone support, so naive local datetimes are a common source
    of off by hours bugs in budget period maths. Everything is normalised to UTC
    on the way in and re-tagged as UTC on the way out.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetime passed to a UTCDateTime column")
        return value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


# JSON works natively on both backends. Kept as an alias so a future switch to
# JSONB on PostgreSQL happens in one place.
JSONColumn: Any = JSON
