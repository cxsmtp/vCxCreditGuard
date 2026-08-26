"""CSV import and export of limits.

The import is deliberately strict and offers a dry run. A CSV that half applies is
worse than one that is rejected: this tool can restrict people, and an admin
pasting a spreadsheet needs to know exactly what will happen before it does.

Rules:
* Rows are validated first. With ``dry_run`` nothing is written at all.
* ``enforce`` defaults to false when the column is absent, matching the API. An
  import cannot switch a tenant into enforcement by omission.
* An unknown entity id is reported as an error rather than creating a limit that
  can never be evaluated.
"""

from __future__ import annotations

import csv
import io
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checkmarx.client import CheckmarxClient
from app.models.enums import EntityType, PeriodType
from app.models.limits import CreditLimit
from app.services import limits_service
from app.services.audit import AuditActor, record_audit
from app.services.periods import PeriodError, current_window

logger = logging.getLogger(__name__)

COLUMNS = (
    "entity_type",
    "entity_id",
    "entity_label",
    "credit_limit",
    "period_type",
    "warning_threshold_pct",
    "enforce",
    "is_active",
    "include_member_usage",
    "hold_until_released",
    "count_existing_usage",
    "custom_period_start",
    "custom_period_end",
    "notes",
)

# Columns produced by the export for context. They are ignored on import, because
# usage is derived and cannot be set.
EXPORT_ONLY_COLUMNS = ("credits_used", "period_key", "status")

MAX_ROWS = 5000
_TRUE = {"true", "1", "yes", "y", "on"}
_FALSE = {"false", "0", "no", "n", "off", ""}

# Leading characters that make a spreadsheet treat a cell as a formula.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _neutralise(value: object) -> object:
    """Stop a spreadsheet from executing exported text as a formula.

    Entity labels and notes come from the Checkmarx tenant and from admins, so a
    project named ``=HYPERLINK(...)`` or a note starting with ``@`` would otherwise
    be evaluated when the export is opened in Excel or Sheets. Prefixing with an
    apostrophe is the standard mitigation: the text still reads correctly in the
    spreadsheet, and re-importing the file strips it again.

    Numbers are passed through untouched, so the numeric columns stay numeric.
    """
    if not isinstance(value, str) or not value:
        return value
    return f"'{value}" if value.startswith(_FORMULA_PREFIXES) else value


@dataclass
class RowOutcome:
    row: int
    entity_type: str | None
    entity_id: str | None
    action: str
    detail: str | None = None


@dataclass
class ImportResult:
    created: int = 0
    updated: int = 0
    skipped: int = 0
    errors: list[str] = field(default_factory=list)
    rows: list[RowOutcome] = field(default_factory=list)
    dry_run: bool = False

    @property
    def ok(self) -> bool:
        return not self.errors


def export_limits(session: Session) -> str:
    """Every limit as CSV, with current period usage for context."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow([*COLUMNS, *EXPORT_ONLY_COLUMNS])

    limits = session.scalars(
        select(CreditLimit).order_by(CreditLimit.entity_type, CreditLimit.entity_label)
    )
    for limit in limits:
        credits_used = ""
        period_key = ""
        status = ""
        try:
            window = current_window(limit)
        except PeriodError:
            window = None
        if window is not None:
            period_key = window.key
            state = limits_service.current_state(session, limit_id=limit.id, period_key=window.key)
            if state is not None:
                credits_used = str(state.credits_used)
                status = state.status
        writer.writerow(
            [
                _neutralise(cell)
                for cell in (
                    limit.entity_type,
                    limit.entity_id,
                    limit.entity_label or "",
                    limit.credit_limit,
                    limit.period_type,
                    limit.warning_threshold_pct,
                    str(limit.enforce).lower(),
                    str(limit.is_active).lower(),
                    str(limit.include_member_usage).lower(),
                    str(limit.hold_until_released).lower(),
                    str(limit.count_existing_usage).lower(),
                    limit.custom_period_start.isoformat() if limit.custom_period_start else "",
                    limit.custom_period_end.isoformat() if limit.custom_period_end else "",
                    limit.notes or "",
                    credits_used,
                    period_key,
                    status,
                )
            ]
        )
    return buffer.getvalue()


def _parse_bool(value: str | None, *, default: bool = False) -> bool:
    if value is None:
        return default
    text = value.strip().lower()
    if text in _TRUE:
        return True
    if text in _FALSE:
        return default if text == "" else False
    raise ValueError(f"{value!r} is not a true or false value")


def _parse_int(value: str | None, name: str) -> int:
    if value is None or not value.strip():
        raise ValueError(f"{name} is required")
    try:
        return int(value.strip())
    except ValueError as exc:
        raise ValueError(f"{name} must be a whole number, got {value!r}") from exc


def _parse_datetime(value: str | None, name: str) -> datetime | None:
    if value is None or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"{name} must be an ISO 8601 date, got {value!r}") from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def import_limits(
    session: Session,
    *,
    content: str,
    actor: AuditActor,
    dry_run: bool = True,
    client: CheckmarxClient | None = None,
) -> ImportResult:
    """Validate and optionally apply a CSV of limits.

    Existing limits for an entity are updated in place, so the same file can be
    re-imported to adjust budgets.
    """
    result = ImportResult(dry_run=dry_run)
    try:
        reader = csv.DictReader(io.StringIO(content))
    except csv.Error as exc:
        result.errors.append(f"Could not read the CSV: {exc}")
        return result

    if reader.fieldnames is None:
        result.errors.append("The file has no header row.")
        return result

    headers = {name.strip().lower() for name in reader.fieldnames if name}
    missing = {"entity_type", "entity_id", "credit_limit"} - headers
    if missing:
        result.errors.append(
            f"Missing required column(s): {', '.join(sorted(missing))}. "
            f"Expected header: {', '.join(COLUMNS)}"
        )
        return result

    # Parse every row before writing anything.
    parsed: list[tuple[int, limits_service.LimitInput]] = []
    seen: set[tuple[str, str]] = set()

    for index, raw in enumerate(reader, start=2):
        if index - 1 > MAX_ROWS:
            result.errors.append(f"Refusing to import more than {MAX_ROWS} rows.")
            return result
        row = {(key or "").strip().lower(): (value or "") for key, value in raw.items()}
        if not any(row.values()):
            continue
        try:
            data = _row_to_input(row)
        except ValueError as exc:
            result.errors.append(f"Row {index}: {exc}")
            result.rows.append(
                RowOutcome(
                    row=index,
                    entity_type=row.get("entity_type"),
                    entity_id=row.get("entity_id"),
                    action="error",
                    detail=str(exc),
                )
            )
            continue

        key = (str(data.entity_type), data.entity_id)
        if key in seen:
            message = f"duplicate row for {data.entity_type} {data.entity_id}"
            result.errors.append(f"Row {index}: {message}")
            result.rows.append(
                RowOutcome(
                    row=index,
                    entity_type=str(data.entity_type),
                    entity_id=data.entity_id,
                    action="error",
                    detail=message,
                )
            )
            continue
        seen.add(key)

        label = limits_service.resolve_entity_label(
            session, entity_type=data.entity_type, entity_id=data.entity_id
        )
        if label is None:
            message = (
                f"{data.entity_type} {data.entity_id} is not in the synced organisation "
                "model. Run a sync, or check the id."
            )
            result.errors.append(f"Row {index}: {message}")
            result.rows.append(
                RowOutcome(
                    row=index,
                    entity_type=str(data.entity_type),
                    entity_id=data.entity_id,
                    action="error",
                    detail=message,
                )
            )
            continue

        parsed.append((index, data))

    if result.errors:
        # All or nothing: a partially applied import of restriction rules is worse
        # than one that is rejected outright.
        result.skipped = len(parsed)
        return result

    for index, data in parsed:
        existing = session.scalar(
            select(CreditLimit).where(
                CreditLimit.entity_type == data.entity_type,
                CreditLimit.entity_id == data.entity_id,
            )
        )
        action = "update" if existing is not None else "create"
        result.rows.append(
            RowOutcome(
                row=index,
                entity_type=str(data.entity_type),
                entity_id=data.entity_id,
                action=action,
                detail=(
                    f"{data.credit_limit} credits per {data.period_type}, "
                    f"{'enforcing' if data.enforce else 'monitor only'}"
                ),
            )
        )
        if action == "create":
            result.created += 1
        else:
            result.updated += 1

        if dry_run:
            continue

        if existing is None:
            limits_service.create_limit(session, data=data, actor=actor)
        else:
            limits_service.update_limit(
                session,
                limit=existing,
                changes={
                    "credit_limit": data.credit_limit,
                    "period_type": data.period_type,
                    "warning_threshold_pct": data.warning_threshold_pct,
                    "enforce": data.enforce,
                    "include_member_usage": data.include_member_usage,
                    "hold_until_released": data.hold_until_released,
                    "custom_period_start": data.custom_period_start,
                    "custom_period_end": data.custom_period_end,
                    "notes": data.notes,
                },
                actor=actor,
                client=client,
            )

    if not dry_run:
        record_audit(
            session,
            action="limit.imported",
            actor=actor,
            target_type="credit_limit",
            after={"created": result.created, "updated": result.updated},
            detail=f"CSV import applied {result.created + result.updated} limit(s).",
        )
    return result


def _unneutralise(value: str) -> str:
    """Undo the export's formula guard, so a round trip is lossless.

    Only one leading apostrophe is removed, and only because the export may have
    added it. A note that genuinely began with an apostrophe and a formula
    character loses that apostrophe, which is a fair trade for not shipping
    executable spreadsheet cells.
    """
    if value.startswith("'") and value[1:2].startswith(_FORMULA_PREFIXES):
        return value[1:]
    return value


def _row_to_input(row: dict[str, str]) -> limits_service.LimitInput:
    raw_type = (row.get("entity_type") or "").strip().lower()
    try:
        entity_type = EntityType(raw_type)
    except ValueError as exc:
        raise ValueError(
            f"entity_type must be one of user, group, project, application, got {raw_type!r}"
        ) from exc

    entity_id = _unneutralise((row.get("entity_id") or "").strip())
    if not entity_id:
        raise ValueError("entity_id is required")

    credit_limit = _parse_int(row.get("credit_limit"), "credit_limit")
    if credit_limit < 0:
        raise ValueError("credit_limit cannot be negative")

    raw_period = (row.get("period_type") or "monthly").strip().lower()
    try:
        period_type = PeriodType(raw_period)
    except ValueError as exc:
        raise ValueError(
            f"period_type must be one of monthly, quarterly, custom, lifetime, got {raw_period!r}"
        ) from exc

    threshold_raw = (row.get("warning_threshold_pct") or "").strip()
    threshold = int(threshold_raw) if threshold_raw else 80
    if not 1 <= threshold <= 100:
        raise ValueError("warning_threshold_pct must be between 1 and 100")

    include_member_usage = _parse_bool(row.get("include_member_usage"))
    if include_member_usage and entity_type != EntityType.GROUP:
        raise ValueError("include_member_usage is only valid for group limits")

    start = _parse_datetime(row.get("custom_period_start"), "custom_period_start")
    end = _parse_datetime(row.get("custom_period_end"), "custom_period_end")
    if period_type == PeriodType.CUSTOM and start is None:
        raise ValueError("custom_period_start is required when period_type is custom")
    if start and end and end <= start:
        raise ValueError("custom_period_end must be after custom_period_start")

    return limits_service.LimitInput(
        entity_type=entity_type,
        entity_id=entity_id,
        credit_limit=credit_limit,
        period_type=period_type,
        warning_threshold_pct=threshold,
        # Absent column means monitor only, never enforcement.
        enforce=_parse_bool(row.get("enforce"), default=False),
        include_member_usage=include_member_usage,
        hold_until_released=_parse_bool(row.get("hold_until_released")),
        count_existing_usage=_parse_bool(row.get("count_existing_usage")),
        custom_period_start=start,
        custom_period_end=end,
        notes=_unneutralise((row.get("notes") or "").strip()) or None,
    )
