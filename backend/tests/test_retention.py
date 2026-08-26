"""Data retention pruning."""

from __future__ import annotations

from datetime import timedelta
from decimal import Decimal

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models.audit import AuditLogEntry, Notification
from app.models.enums import EnforcementKind, EnforcementStatus, EntityType, Severity, UsageView
from app.models.limits import CreditLimit, EnforcementAction
from app.models.usage import SchedulerRun, UsageRecord, UsageSnapshot
from app.services import retention
from app.services.audit import AuditActor

ACTOR = AuditActor.system("test")


def add_snapshot(db: Session, *, days_old: int, view: str = UsageView.ACTION) -> UsageSnapshot:
    snapshot = UsageSnapshot(
        collected_at=utcnow() - timedelta(days=days_old),
        view_by=view,
        period_param="last_year",
        total_credits=Decimal("10"),
        total_items=1,
        pages_fetched=1,
    )
    db.add(snapshot)
    db.flush()
    db.add(
        UsageRecord(
            snapshot_id=snapshot.id,
            view_by=view,
            subject_key="triage",
            credits_used=Decimal("10"),
        )
    )
    db.flush()
    return snapshot


def add_notification(db: Session, *, days_old: int, action_id: int | None = None) -> Notification:
    notification = Notification(
        created_at=utcnow() - timedelta(days=days_old),
        severity=Severity.WARNING,
        category="warning",
        title=f"Old notification {days_old} days",
        enforcement_action_id=action_id,
    )
    db.add(notification)
    db.flush()
    return notification


def add_audit(db: Session, *, days_old: int) -> AuditLogEntry:
    entry = AuditLogEntry(
        occurred_at=utcnow() - timedelta(days=days_old),
        actor_type="system",
        actor_name="test",
        action="test.event",
    )
    db.add(entry)
    db.flush()
    return entry


def add_enforcement(db: Session, *, days_old: int, status: str) -> EnforcementAction:
    limit = CreditLimit(
        entity_type=EntityType.PROJECT,
        entity_id=f"proj-{days_old}-{status}",
        credit_limit=10,
        period_type="monthly",
    )
    db.add(limit)
    db.flush()
    action = EnforcementAction(
        idempotency_key=f"key-{days_old}-{status}",
        kind=EnforcementKind.DISABLE_AUTO_TRIAGE,
        status=status,
        entity_type=EntityType.PROJECT,
        entity_id=limit.entity_id,
        target_type="cx_project",
        target_id=limit.entity_id,
        limit_id=limit.id,
        created_at=utcnow() - timedelta(days=days_old),
        undo_snapshot={"enabled_before": True},
        attempts=1,
    )
    db.add(action)
    db.flush()
    return action


class TestBasicPruning:
    def test_snapshots_within_the_recent_tail_survive_even_when_old(self, db: Session) -> None:
        """The tail protects period baselines, so a handful of old snapshots stay."""
        old = add_snapshot(db, days_old=400)
        recent = add_snapshot(db, days_old=1)
        db.commit()

        result = retention.prune(db, retention_days=90, actor=ACTOR)
        db.commit()

        assert result.usage_snapshots == 0
        assert db.get(UsageSnapshot, old.id) is not None
        assert db.get(UsageSnapshot, recent.id) is not None

    def test_old_snapshots_beyond_the_tail_go_with_their_records(self, db: Session) -> None:
        for index in range(retention.KEEP_RECENT_SNAPSHOTS + 3):
            add_snapshot(db, days_old=400 + index)
        db.commit()

        result = retention.prune(db, retention_days=90, actor=ACTOR)
        db.commit()

        assert result.usage_snapshots == 3
        # One record per snapshot, and no orphans left behind.
        assert result.usage_records == 3
        assert (
            db.scalar(select(func.count()).select_from(UsageRecord))
            == retention.KEEP_RECENT_SNAPSHOTS
        )

    def test_old_notifications_go(self, db: Session) -> None:
        old = add_notification(db, days_old=400)
        recent = add_notification(db, days_old=2)
        db.commit()

        result = retention.prune(db, retention_days=90, actor=ACTOR)
        db.commit()
        assert result.notifications == 1
        assert db.get(Notification, old.id) is None
        assert db.get(Notification, recent.id) is not None

    def test_old_scheduler_runs_go(self, db: Session) -> None:
        db.add(
            SchedulerRun(
                kind="cycle",
                trigger="schedule",
                started_at=utcnow() - timedelta(days=400),
                status="success",
            )
        )
        db.commit()
        result = retention.prune(db, retention_days=90, actor=ACTOR)
        db.commit()
        assert result.scheduler_runs == 1

    def test_nothing_recent_is_touched(self, db: Session) -> None:
        add_snapshot(db, days_old=1)
        add_notification(db, days_old=1)
        add_audit(db, days_old=1)
        db.commit()

        result = retention.prune(db, retention_days=90, actor=ACTOR)
        db.commit()
        assert result.total == 0


class TestAuditIntegrity:
    def test_the_prune_of_audit_rows_is_itself_audited(self, db: Session) -> None:
        """The log has to explain its own gaps."""
        add_audit(db, days_old=400)
        add_audit(db, days_old=500)
        db.commit()

        result = retention.prune(db, retention_days=90, actor=ACTOR)
        db.commit()

        assert result.audit_entries == 2
        entry = db.scalar(select(AuditLogEntry).where(AuditLogEntry.action == "retention.pruned"))
        assert entry is not None
        assert entry.after["audit_entries"] == 2
        assert "audit entries were included" in (entry.detail or "")

    def test_no_audit_entry_is_written_when_nothing_was_pruned(self, db: Session) -> None:
        retention.prune(db, retention_days=90, actor=ACTOR)
        db.commit()
        assert (
            db.scalar(select(AuditLogEntry).where(AuditLogEntry.action == "retention.pruned"))
            is None
        )

    def test_recent_audit_entries_survive(self, db: Session) -> None:
        recent = add_audit(db, days_old=5)
        add_audit(db, days_old=400)
        db.commit()
        retention.prune(db, retention_days=90, actor=ACTOR)
        db.commit()
        assert db.get(AuditLogEntry, recent.id) is not None


class TestSafeguards:
    def test_a_live_restriction_keeps_its_notification(self, db: Session) -> None:
        """The notification carries the Restore access button, so it must not be
        pruned while the restriction is still in force."""
        action = add_enforcement(db, days_old=400, status=EnforcementStatus.APPLIED)
        attached = add_notification(db, days_old=400, action_id=action.id)
        unattached = add_notification(db, days_old=400)
        db.commit()

        retention.prune(db, retention_days=90, actor=ACTOR)
        db.commit()

        assert db.get(Notification, attached.id) is not None
        assert db.get(Notification, unattached.id) is None

    def test_applied_enforcement_actions_are_never_pruned(self, db: Session) -> None:
        """Their undo snapshot is the only way to give access back."""
        applied = add_enforcement(db, days_old=900, status=EnforcementStatus.APPLIED)
        db.commit()
        result = retention.prune(db, retention_days=30, actor=ACTOR)
        db.commit()
        assert result.enforcement_actions == 0
        survivor = db.get(EnforcementAction, applied.id)
        assert survivor is not None
        assert survivor.undo_snapshot == {"enabled_before": True}

    def test_reversed_and_failed_actions_are_pruned(self, db: Session) -> None:
        reversed_action = add_enforcement(db, days_old=400, status=EnforcementStatus.REVERSED)
        failed_action = add_enforcement(db, days_old=400, status=EnforcementStatus.FAILED)
        db.commit()
        result = retention.prune(db, retention_days=90, actor=ACTOR)
        db.commit()
        assert result.enforcement_actions == 2
        assert db.get(EnforcementAction, reversed_action.id) is None
        assert db.get(EnforcementAction, failed_action.id) is None

    def test_a_recent_tail_of_snapshots_is_always_kept(self, db: Session) -> None:
        """Period baselines and the trend chart need recent history even when the
        retention window is very short."""
        for days in range(1, 6):
            add_snapshot(db, days_old=days)
        db.commit()

        result = retention.prune(db, retention_days=retention.MINIMUM_RETENTION_DAYS, actor=ACTOR)
        db.commit()
        assert result.usage_snapshots == 0
        assert db.scalar(select(func.count()).select_from(UsageSnapshot)) == 5

    @pytest.mark.parametrize("requested", [0, 1, 3, 6])
    def test_retention_below_the_floor_is_raised(self, db: Session, requested: int) -> None:
        add_audit(db, days_old=5)
        db.commit()
        result = retention.prune(db, retention_days=requested, actor=ACTOR)
        db.commit()
        assert any("raised to the" in note for note in result.skipped)
        # The five day old entry survives, because the floor is seven days.
        assert db.scalar(select(func.count()).select_from(AuditLogEntry)) >= 1

    def test_the_keep_recent_cap_still_allows_old_snapshots_to_go(self, db: Session) -> None:
        for index in range(retention.KEEP_RECENT_SNAPSHOTS + 5):
            add_snapshot(db, days_old=400 + index)
        db.commit()
        result = retention.prune(db, retention_days=90, actor=ACTOR)
        db.commit()
        assert result.usage_snapshots == 5
        assert (
            db.scalar(select(func.count()).select_from(UsageSnapshot))
            == retention.KEEP_RECENT_SNAPSHOTS
        )


class TestCycleIntegration:
    def test_retention_runs_at_most_once_a_day(self, db: Session) -> None:
        from app.services.cycle import _retention_due

        assert _retention_due(db) is True

        add_audit(db, days_old=400)
        db.commit()
        retention.prune(db, retention_days=90, actor=ACTOR)
        db.commit()

        assert _retention_due(db) is False

    def test_it_becomes_due_again_after_a_day(self, db: Session) -> None:
        from app.services.cycle import _retention_due

        entry = AuditLogEntry(
            occurred_at=utcnow() - timedelta(hours=25),
            actor_type="system",
            actor_name="retention",
            action="retention.pruned",
        )
        db.add(entry)
        db.commit()
        assert _retention_due(db) is True
