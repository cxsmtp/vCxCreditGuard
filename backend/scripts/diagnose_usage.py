"""Explain why a given entity's usage reads the way it does.

Answers one question: is a zero on screen an attribution failure (Checkmarx
reported credits and we could not match them to this entity) or a baseline effect
(we matched them, but the budget period opened after they were spent)?

    python -m scripts.diagnose_usage --project "singakash/CxHybrid"
    python -m scripts.diagnose_usage --user "someone@example.com"

Read only. It touches nothing and calls no API.
"""

from __future__ import annotations

import argparse
import json
import sys
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import select  # noqa: E402

from app.db.session import session_scope  # noqa: E402
from app.models.enums import UsageView  # noqa: E402
from app.models.limits import CreditLimit, LimitPeriodState  # noqa: E402
from app.models.org import CxApplication, CxProject, CxUser  # noqa: E402
from app.models.usage import DimensionState, UnresolvedSubject, UsageRecord  # noqa: E402
from app.services import ingestion  # noqa: E402
from app.services.periods import PeriodError, current_window  # noqa: E402

RULE = "-" * 78


def heading(text: str) -> None:
    print(f"\n{text}\n{RULE}")


def diagnose(*, needle: str, view: UsageView) -> None:
    with session_scope() as session:
        heading(f"1. Is {needle!r} in the synced organisation model?")
        model = {
            UsageView.PROJECT: CxProject,
            UsageView.APPLICATION: CxApplication,
            UsageView.USER: CxUser,
        }[view]
        rows = list(session.scalars(select(model)))
        matches = [
            row
            for row in rows
            if needle.lower() in (getattr(row, "name", "") or "").lower()
            or needle.lower() == row.id.lower()
            or needle.lower() in (getattr(row, "username", "") or "").lower()
            or needle.lower() in (getattr(row, "email", "") or "").lower()
        ]
        if not matches:
            print(f"  NO. {len(rows)} {view} rows are synced, none matching.")
            print("  Fix: run an organisation sync. Until it is synced, usage for it")
            print("  cannot be attributed and no limit on it can be evaluated.")
            return
        for row in matches:
            label = getattr(row, "name", None) or getattr(row, "display_name", row.id)
            print(f"  YES  id={row.id}  name={label!r}  deleted={row.is_deleted}")
        target = matches[0]

        heading(f"2. Does this tenant report consumption by {view}?")
        state = session.get(DimensionState, str(view))
        if state is None:
            print("  UNKNOWN. This dimension has never been polled.")
            print("  Fix: run a cycle.")
        elif state.supported is False:
            print(f"  NO. Marked unsupported at {state.last_checked_at}.")
            print(f"  Reason recorded: {state.last_error}")
            print("  Consequence: usage is unavailable, NOT zero, and limits at this")
            print("  level are never enforced.")
            return
        else:
            print(f"  YES. Last checked {state.last_checked_at}.")

        heading(f"3. What did the newest {view} snapshot actually contain?")
        snapshot = ingestion.latest_snapshot(session, view)
        if snapshot is None:
            print("  Nothing. No snapshot has been collected for this dimension.")
            return
        records = list(
            session.scalars(select(UsageRecord).where(UsageRecord.snapshot_id == snapshot.id))
        )
        print(f"  snapshot id={snapshot.id} collected_at={snapshot.collected_at}")
        print(f"  reported total={snapshot.total_credits}  rows={len(records)}")

        mine = [record for record in records if record.entity_id == target.id]
        by_name = [
            record
            for record in records
            if record.entity_id is None
            and needle.lower() in (record.subject_name or record.subject_key or "").lower()
        ]

        if mine:
            for record in mine:
                print(f"\n  MATCHED to this entity: credits={record.credits_used}")
                print(f"    reported name  : {record.subject_name!r}")
                print(f"    reported email : {record.subject_email!r}")
                print(f"    subject key    : {record.subject_key!r}")
                print(f"    actions        : {record.actions}")
                print(f"    raw row        : {json.dumps(record.raw, default=str)[:400]}")
        elif by_name:
            print("\n  *** ATTRIBUTION FAILURE ***")
            print("  Checkmarx reported credits under a name that looks like this entity,")
            print("  but they were not matched to it, so they count towards nothing.")
            for record in by_name:
                print(f"    credits={record.credits_used} name={record.subject_name!r}")
                print(f"    subject key={record.subject_key!r}")
                print(f"    raw row={json.dumps(record.raw, default=str)[:400]}")
            print("\n  The reported identifier does not equal the synced name or id above.")
            return
        else:
            print("\n  This entity does not appear in the snapshot at all.")
            print("  Either it spent no credits in the reported window, or the")
            print("  dimension reports a different set of entities than expected.")
            print("  Every row in the snapshot, for comparison:")
            for record in sorted(records, key=lambda item: -Decimal(item.credits_used))[:25]:
                marker = "  " if record.entity_id else " ?"
                print(
                    f"   {marker} {str(record.credits_used):>10}  "
                    f"id={record.entity_id or '(unmatched)'}  name={record.subject_name!r}"
                )
            return

        heading("4. How does that become the number on screen?")
        totals = ingestion.latest_totals(session, view)
        print(f"  reported total for this entity : {totals.get(target.id, Decimal('0'))}")

        limits = list(
            session.scalars(
                select(CreditLimit).where(
                    CreditLimit.entity_type == str(view), CreditLimit.entity_id == target.id
                )
            )
        )
        if not limits:
            print("\n  No limit is configured for this entity, so there is no period")
            print("  figure to show. The dashboard shows the reported total above.")
            return

        for limit in limits:
            print(f"\n  limit id={limit.id} budget={limit.credit_limit} period={limit.period_type}")
            try:
                window = current_window(limit)
            except PeriodError as exc:
                print(f"    MISCONFIGURED: {exc}")
                continue
            period = session.scalar(
                select(LimitPeriodState).where(
                    LimitPeriodState.limit_id == limit.id,
                    LimitPeriodState.period_key == window.key,
                )
            )
            if period is None:
                print(f"    period {window.key} has not been evaluated yet. Run a cycle.")
                continue
            print(f"    period          : {period.period_key}  opened {period.period_start}")
            print(f"    reported_total  : {period.reported_total}")
            print(f"    baseline_credits: {period.baseline_credits}")
            print(f"    credits_used    : {period.credits_used}   <-- the number on screen")
            print(f"    usage_available : {period.usage_available}")
            print(f"    status          : {period.status}")
            if period.credits_used == 0 and period.reported_total > 0:
                print("\n    *** BASELINE EFFECT, NOT A BUG ***")
                print(f"    Checkmarx reports {period.reported_total} credits over its lookback")
                print(
                    f"    window. {period.baseline_credits} of those were already spent when this"
                )
                print(f"    budget period opened at {period.period_start}, so they do not count")
                print("    against it. Only new consumption from that moment counts.")
                print("    If you want the historical figure to count, that is a design")
                print("    question, not a defect. See the README section on how usage is")
                print("    measured.")

        heading("5. Unmatched subjects overall")
        unresolved = list(
            session.scalars(
                select(UnresolvedSubject).where(UnresolvedSubject.mapped_user_id.is_(None))
            )
        )
        if not unresolved:
            print("  None. Every consumption row matched a synced entity.")
        for row in unresolved:
            print(f"  {row.credits_used:>10}  {row.subject_key!r} seen {row.times_seen} times")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--project", help="Project name or id")
    group.add_argument("--user", help="Username, email or id")
    group.add_argument("--application", help="Application name or id")
    args = parser.parse_args()

    if args.project:
        diagnose(needle=args.project, view=UsageView.PROJECT)
    elif args.user:
        diagnose(needle=args.user, view=UsageView.USER)
    else:
        diagnose(needle=args.application, view=UsageView.APPLICATION)


if __name__ == "__main__":
    main()
