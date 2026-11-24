"""Database growth: no raw pages on believed snapshots, raw rows cleared after
a week (except where a reader needs them), pinned baselines, and thinning of
whole snapshots in the retention job."""

from __future__ import annotations

from datetime import datetime, timedelta
from decimal import Decimal

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models.audit import AuditLogEntry
from app.models.enums import EnforcementKind, EnforcementStatus, EntityType, PeriodType, UsageView
from app.models.limits import CreditLimit, EnforcementAction, LimitPeriodState
from app.models.usage import AutoTriageCharge, UsageRecord, UsageSnapshot
from app.services import evaluation, retention, settings_store
from app.services.audit import AuditActor
from tests.test_scale_pacing import (
    ACTOR,
    connected,  # noqa: F401 - fixture
    group_limit,
    tenant_with_projects,
)

DAYS = 45
STEP = timedelta(minutes=30)


def _timeline(db: Session, now: datetime, *, view: str = UsageView.PROJECT.value) -> list[int]:
    """A snapshot every 30 minutes for 45 days, each with a matched and an unmatched row."""
    ids: list[int] = []
    moment = now - timedelta(days=DAYS)
    while moment <= now:
        snapshot = UsageSnapshot(
            collected_at=moment,
            view_by=view,
            period_param="last_year",
            total_credits=Decimal("10"),
            total_items=2,
            pages_fetched=1,
            raw=[{"page": 1}],
        )
        db.add(snapshot)
        db.flush()
        db.add_all(
            [
                UsageRecord(
                    snapshot_id=snapshot.id,
                    view_by=view,
                    subject_key="matched",
                    entity_type=EntityType.PROJECT,
                    entity_id="proj-1",
                    credits_used=Decimal("5"),
                    raw={"projectId": "proj-1", "big": "x" * 50},
                ),
                UsageRecord(
                    snapshot_id=snapshot.id,
                    view_by=view,
                    subject_key="unmatched",
                    credits_used=Decimal("5"),
                    raw={"projectId": "gone", "big": "y" * 50},
                ),
            ]
        )
        ids.append(snapshot.id)
        moment += STEP
    db.commit()
    return ids


def _ids_between(db: Session, start: datetime, end: datetime) -> list[int]:
    return list(
        db.scalars(
            select(UsageSnapshot.id).where(
                UsageSnapshot.collected_at >= start, UsageSnapshot.collected_at < end
            )
        )
    )


def _at_or_before(db: Session, moment: datetime) -> int:
    return db.scalar(
        select(UsageSnapshot.id)
        .where(UsageSnapshot.collected_at <= moment)
        .order_by(UsageSnapshot.collected_at.desc())
        .limit(1)
    )


class TestThinning:
    def test_tiers_pins_raw_rows_and_idempotence(self, db: Session) -> None:
        now = utcnow()
        ids = _timeline(db, now)
        total_before = len(ids)

        # Things that refer to snapshots, mid-hour and mid-day so a plain
        # "one per period" would drop them.
        baseline = _at_or_before(db, now - timedelta(days=20, minutes=50))
        charge_snapshot = _at_or_before(db, now - timedelta(days=30, minutes=20))
        legacy_moment = now - timedelta(days=10, minutes=40)
        limit = CreditLimit(
            entity_type=EntityType.PROJECT,
            entity_id="proj-1",
            credit_limit=1,
            period_type=PeriodType.MONTHLY,
            enforce=True,
        )
        db.add(limit)
        db.flush()
        db.add_all(
            [
                EnforcementAction(
                    idempotency_key="k1",
                    kind=EnforcementKind.DISABLE_AUTO_TRIAGE,
                    status=EnforcementStatus.APPLIED,
                    entity_type=EntityType.PROJECT,
                    entity_id="proj-1",
                    target_type="cx_project",
                    target_id="proj-1",
                    limit_id=limit.id,
                    created_at=now,
                    applied_at=now - timedelta(days=20, minutes=50),
                    baseline_snapshot_id=baseline,
                    attempts=1,
                ),
                # Applied before baselines were pinned: given one, then kept.
                EnforcementAction(
                    idempotency_key="k2",
                    kind=EnforcementKind.DISABLE_FUSION,
                    status=EnforcementStatus.APPLIED,
                    entity_type=EntityType.PROJECT,
                    entity_id="proj-1",
                    target_type="cx_project",
                    target_id="proj-1",
                    limit_id=limit.id,
                    created_at=now,
                    applied_at=legacy_moment,
                    attempts=1,
                ),
                AutoTriageCharge(
                    project_id="proj-1",
                    basis="observed",
                    credits=Decimal("1"),
                    window_start=now - timedelta(days=31),
                    window_end=now - timedelta(days=30),
                    snapshot_id=charge_snapshot,
                    created_at=now,
                ),
            ]
        )
        # An open budget period whose usage breakdown starts 25 days ago.
        period_start = now - timedelta(days=25, minutes=10)
        db.add(
            LimitPeriodState(
                limit_id=limit.id,
                period_key="open",
                period_start=period_start,
                period_end=now + timedelta(days=5),
                baseline_at=period_start,
                status="warned",
            )
        )
        db.commit()
        mix_snapshot = _at_or_before(db, period_start)
        legacy_snapshot = _at_or_before(db, legacy_moment)

        result = retention.prune(db, retention_days=365, actor=ACTOR)
        db.commit()
        stats = result.as_stats()
        assert stats["thinning"] is True and result.baselines_recorded == 1

        # Everything younger than 3 days stays.
        recent = _ids_between(db, now - timedelta(days=3) + STEP, now + STEP)
        assert len(recent) == 3 * 48 - 1 + 1
        # One an hour up to 40 days (plus the pinned ones), one a day beyond.
        hourly = _ids_between(db, now - timedelta(days=39), now - timedelta(days=4))
        assert 35 * 24 - 2 <= len(hourly) <= 35 * 24 + 4
        daily = _ids_between(db, now - timedelta(days=DAYS) - STEP, now - timedelta(days=41))
        assert 3 <= len(daily) <= 6
        for pinned in (baseline, mix_snapshot, legacy_snapshot, ids[-1]):
            assert db.get(UsageSnapshot, pinned) is not None, pinned
        # A charge's snapshot is not pinned (nothing reads it); the charge stays.
        keep, _keep_raw = retention.pinned_snapshots(db, utcnow())
        assert charge_snapshot not in keep
        charge = db.scalar(select(AutoTriageCharge))
        assert charge is not None and charge.snapshot_id == charge_snapshot
        legacy = db.scalar(
            select(EnforcementAction).where(EnforcementAction.idempotency_key == "k2")
        )
        assert legacy.baseline_snapshot_id == legacy_snapshot
        # Whole snapshots only: no orphan rows, no half snapshot.
        remaining = db.scalar(select(func.count()).select_from(UsageSnapshot))
        assert result.thinned_snapshots == total_before - remaining
        assert db.scalar(select(func.count()).select_from(UsageRecord)) == 2 * remaining

        # Raw rows: cleared after a week, except pinned snapshots and rows
        # that matched no entity; snapshot pages never kept on a believed read.
        week = now - timedelta(days=7)

        def raw_rows(*conditions) -> int:  # type: ignore[no-untyped-def]
            return int(
                db.scalar(
                    select(func.count())
                    .select_from(UsageRecord)
                    .join(UsageSnapshot, UsageRecord.snapshot_id == UsageSnapshot.id)
                    .where(UsageRecord.raw.is_not(None), *conditions)
                )
                or 0
            )

        old_matched = raw_rows(
            UsageSnapshot.collected_at < week, UsageRecord.entity_id.is_not(None)
        )
        kept_raw = {baseline, mix_snapshot, legacy_snapshot}
        assert old_matched == len(kept_raw)
        assert raw_rows(UsageSnapshot.collected_at < week, UsageRecord.entity_id.is_(None)) > 0
        assert raw_rows(UsageSnapshot.collected_at >= week, UsageRecord.entity_id.is_not(None)) > 0
        charge_row = db.scalar(
            select(UsageRecord).where(
                UsageRecord.snapshot_id == charge_snapshot, UsageRecord.entity_id.is_not(None)
            )
        )
        assert charge_row is None or charge_row.raw is None
        assert result.raw_cleared_records > 0

        # Audited, with the summary.
        entry = db.scalar(select(AuditLogEntry).where(AuditLogEntry.action == "retention.pruned"))
        assert entry is not None and entry.after["thinned_snapshots"] == result.thinned_snapshots

        # Idempotent.
        again = retention.prune(db, retention_days=365, actor=ACTOR)
        db.commit()
        assert again.thinned_snapshots == 0 and again.raw_cleared_records == 0

    def test_switched_off_keeps_every_snapshot(self, db: Session) -> None:
        now = utcnow()
        ids = _timeline(db, now)
        settings_store.set_value(db, settings_store.KEY_RETENTION_THIN_SNAPSHOTS, False)
        db.commit()
        result = retention.prune(db, retention_days=365, actor=AuditActor.system("t"))
        db.commit()
        assert result.thinned_snapshots == 0 and result.thinning is False
        assert db.scalar(select(func.count()).select_from(UsageSnapshot)) == len(ids)

    def test_held_snapshots_are_never_thinned(self, db: Session) -> None:
        now = utcnow()
        for index in range(4):
            db.add(
                UsageSnapshot(
                    collected_at=now - timedelta(days=10, minutes=index * 5),
                    view_by=UsageView.PROJECT.value,
                    period_param="last_year",
                    total_credits=Decimal("0"),
                    held_reason="collapsed",
                    raw=[{"page": index}],
                )
            )
        db.commit()
        retention.prune(db, retention_days=365, actor=ACTOR)
        db.commit()
        held = list(db.scalars(select(UsageSnapshot).where(UsageSnapshot.held_reason.is_not(None))))
        assert len(held) == 4 and all(row.raw is not None for row in held)


class TestIngestionAndBaselines:
    def test_no_raw_pages_and_the_baseline_is_pinned(self, db: Session, connected) -> None:  # noqa: F811
        tenant = tenant_with_projects(3)
        client = connected(tenant)
        assert all(
            raw is None
            for raw in db.scalars(
                select(UsageSnapshot.raw).where(UsageSnapshot.held_reason.is_(None))
            )
        )
        # Raw rows are still stored, for the week.
        assert db.scalar(
            select(func.count()).select_from(UsageRecord).where(UsageRecord.raw.is_not(None))
        )
        group_limit(db)
        evaluation.evaluate_all(db, client=client, actor=ACTOR)
        latest = db.scalar(
            select(UsageSnapshot.id)
            .where(UsageSnapshot.view_by == UsageView.PROJECT.value)
            .order_by(UsageSnapshot.collected_at.desc())
            .limit(1)
        )
        baselines = set(db.scalars(select(EnforcementAction.baseline_snapshot_id)))
        assert baselines == {latest}
