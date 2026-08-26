"""Cycle orchestration: locking, step isolation and run records."""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.db.session import session_scope
from app.models import Notification, SchedulerLock, SchedulerRun
from app.models.enums import RunStatus
from app.services import connection as connection_service
from app.services import cycle
from app.services.audit import AuditActor
from tests.conftest import make_api_key
from tests.fake_tenant import FakeTenant, populated_tenant


@pytest.fixture
def configured_tenant(db: Session, monkeypatch: pytest.MonkeyPatch) -> FakeTenant:
    """A saved connection whose client is the fake tenant."""
    tenant = populated_tenant()
    connection_service.save_connection(
        db, api_key=make_api_key(tenant="acme-corp"), actor=AuditActor.system("test")
    )
    db.commit()
    monkeypatch.setattr(connection_service, "get_client", lambda _session: tenant.client())
    return tenant


class TestLocking:
    def test_the_lock_is_taken_and_released(self, db: Session) -> None:
        with session_scope() as session:
            assert cycle.acquire_lock(session, holder="holder-a") is True
        with session_scope() as session:
            assert cycle.acquire_lock(session, holder="holder-b") is False
        with session_scope() as session:
            cycle.release_lock(session, holder="holder-a")
        with session_scope() as session:
            assert cycle.acquire_lock(session, holder="holder-b") is True

    def test_a_stale_lock_is_reclaimed(self, db: Session) -> None:
        """A container replaced mid cycle must not block the loop forever."""
        with session_scope() as session:
            cycle.acquire_lock(session, holder="dead-process")
        with session_scope() as session:
            lock = session.get(SchedulerLock, cycle.LOCK_NAME)
            lock.heartbeat_at = utcnow() - cycle.LOCK_STALE_AFTER - timedelta(minutes=1)
        with session_scope() as session:
            assert cycle.acquire_lock(session, holder="new-process") is True

    def test_a_fresh_heartbeat_keeps_the_lock(self, db: Session) -> None:
        with session_scope() as session:
            cycle.acquire_lock(session, holder="live-process")
        with session_scope() as session:
            lock = session.get(SchedulerLock, cycle.LOCK_NAME)
            lock.heartbeat_at = utcnow() - timedelta(minutes=29)
        with session_scope() as session:
            cycle.heartbeat(session, holder="live-process")
        with session_scope() as session:
            assert cycle.acquire_lock(session, holder="other-process") is False

    def test_an_overlapping_cycle_is_skipped_and_recorded(self, db: Session) -> None:
        with session_scope() as session:
            cycle.acquire_lock(session, holder="someone-else")

        result = cycle.run_cycle(trigger="manual")
        assert result.status == RunStatus.SKIPPED
        assert result.skipped_reason is not None

        with session_scope() as session:
            run = session.get(SchedulerRun, result.run_id)
            assert run is not None
            assert run.status == RunStatus.SKIPPED

    def test_release_only_affects_your_own_lock(self, db: Session) -> None:
        with session_scope() as session:
            cycle.acquire_lock(session, holder="holder-a")
        with session_scope() as session:
            cycle.release_lock(session, holder="holder-b")
        with session_scope() as session:
            assert cycle.acquire_lock(session, holder="holder-c") is False


class TestFullCycle:
    def test_a_healthy_cycle_runs_every_step(self, configured_tenant: FakeTenant) -> None:
        result = cycle.run_cycle(trigger="manual", force_org_sync=True)
        assert result.status == RunStatus.SUCCESS, result.errors
        assert result.steps["org_sync"]["users"] == 3
        assert result.steps["ingest"]["user"]["records"] == 3
        assert "evaluate" in result.steps

    def test_the_run_is_recorded_with_stats(self, configured_tenant: FakeTenant) -> None:
        result = cycle.run_cycle(trigger="manual", force_org_sync=True)
        with session_scope() as session:
            run = session.get(SchedulerRun, result.run_id)
            assert run is not None
            assert run.finished_at is not None
            assert run.status == RunStatus.SUCCESS
            assert run.stats["ingest"]

    def test_the_lock_is_released_afterwards(self, configured_tenant: FakeTenant) -> None:
        cycle.run_cycle(trigger="manual")
        with session_scope() as session:
            lock = session.get(SchedulerLock, cycle.LOCK_NAME)
            assert lock is not None
            assert lock.holder is None

    def test_org_sync_is_skipped_when_not_due(self, configured_tenant: FakeTenant) -> None:
        cycle.run_cycle(trigger="manual", force_org_sync=True)
        second = cycle.run_cycle(trigger="schedule")
        assert second.steps["org_sync"] == {"skipped": "not due"}

    def test_no_connection_skips_rather_than_fails(self, db: Session) -> None:
        result = cycle.run_cycle(trigger="manual")
        assert result.status == RunStatus.SKIPPED
        assert "No Checkmarx One connection configured" in (result.skipped_reason or "")


class TestResilience:
    def test_an_ingestion_outage_leaves_the_cycle_partial_not_dead(
        self, configured_tenant: FakeTenant
    ) -> None:
        configured_tenant.fail_paths["/credits/consumption"] = 500
        result = cycle.run_cycle(trigger="manual", force_org_sync=True)

        assert result.status == RunStatus.PARTIAL
        # Org sync still succeeded, and evaluation still ran.
        assert result.steps["org_sync"]["users"] == 3
        assert "evaluate" in result.steps

    def test_an_org_sync_outage_does_not_stop_ingestion(
        self, configured_tenant: FakeTenant
    ) -> None:
        configured_tenant.fail_paths["/users/v2"] = 500
        result = cycle.run_cycle(trigger="manual", force_org_sync=True)
        assert result.status == RunStatus.PARTIAL
        assert result.steps["org_sync"]["ok"] is False
        assert result.steps["ingest"]["user"]["records"] == 3

    def test_a_failure_raises_one_notification_per_day_not_per_cycle(
        self, configured_tenant: FakeTenant
    ) -> None:
        configured_tenant.fail_paths["/credits/consumption"] = 500
        for _ in range(4):
            cycle.run_cycle(trigger="schedule", force_org_sync=False)

        with session_scope() as session:
            errors = list(
                session.scalars(select(Notification).where(Notification.category == "sync_error"))
            )
        assert len(errors) == 1

    def test_the_cycle_recovers_once_the_api_returns(self, configured_tenant: FakeTenant) -> None:
        configured_tenant.fail_paths["/credits/consumption"] = 500
        assert cycle.run_cycle(trigger="manual").status == RunStatus.PARTIAL
        configured_tenant.fail_paths.clear()
        assert cycle.run_cycle(trigger="manual").status == RunStatus.SUCCESS

    def test_unattributable_usage_is_notified(self, configured_tenant: FakeTenant) -> None:
        cycle.run_cycle(trigger="manual", force_org_sync=True)
        with session_scope() as session:
            notification = session.scalar(
                select(Notification).where(Notification.category == "attribution")
            )
        assert notification is not None
        assert "departed.person@checkmarx.com" in notification.title


class TestScheduler:
    def test_the_schedule_description_reflects_settings(self, db: Session) -> None:
        from app import scheduler as scheduler_module
        from app.services import settings_store

        assert scheduler_module.describe_schedule() == "every 15 minute(s)"

        settings_store.set_value(db, settings_store.KEY_SCHEDULE_INTERVAL_MINUTES, 5)
        db.commit()
        assert scheduler_module.describe_schedule() == "every 5 minute(s)"

    def test_cron_mode_is_described(self, db: Session) -> None:
        from app import scheduler as scheduler_module
        from app.services import settings_store

        settings_store.set_value(db, settings_store.KEY_SCHEDULE_MODE, "cron")
        settings_store.set_value(db, settings_store.KEY_SCHEDULE_CRON, "*/10 * * * *")
        db.commit()
        assert "cron */10 * * * *" in scheduler_module.describe_schedule()

    def test_disabling_the_scheduler_is_reflected(self, db: Session) -> None:
        from app import scheduler as scheduler_module
        from app.services import settings_store

        settings_store.set_value(db, settings_store.KEY_SCHEDULER_ENABLED, False)
        db.commit()
        assert scheduler_module.describe_schedule() == "disabled"

    def test_next_run_time_is_none_when_the_scheduler_is_not_running(self, db: Session) -> None:
        """A pending job has no next_run_time attribute, which must not raise."""
        from app import scheduler as scheduler_module

        scheduler_module.shutdown()
        assert scheduler_module.next_run_time() is None
        scheduler_module.reconfigure()
        assert scheduler_module.next_run_time() is None
        scheduler_module.shutdown()

    def test_reconfigure_replaces_the_job_without_a_restart(self, db: Session) -> None:
        from app import scheduler as scheduler_module
        from app.services import settings_store

        scheduler_module.shutdown()
        try:
            scheduler_module.start()
            assert scheduler_module.next_run_time() is not None

            settings_store.set_value(db, settings_store.KEY_SCHEDULE_INTERVAL_MINUTES, 2)
            db.commit()
            assert scheduler_module.reconfigure() == "every 2 minute(s)"
            job = scheduler_module.get_scheduler().get_job(scheduler_module.JOB_ID)
            assert job is not None
            assert job.trigger.interval == timedelta(minutes=2)
        finally:
            scheduler_module.shutdown()

    def test_an_invalid_cron_falls_back_to_the_interval(self, db: Session) -> None:
        from app import scheduler as scheduler_module
        from app.services import settings_store

        settings_store.set_value(db, settings_store.KEY_SCHEDULE_MODE, "cron")
        settings_store.set_value(db, settings_store.KEY_SCHEDULE_CRON, "not a cron expression")
        db.commit()
        scheduler_module.shutdown()
        try:
            scheduler_module.start()
            job = scheduler_module.get_scheduler().get_job(scheduler_module.JOB_ID)
            assert job is not None
            assert job.trigger.interval == timedelta(minutes=15)
        finally:
            scheduler_module.shutdown()

    def test_disabled_scheduler_schedules_no_job(self, db: Session) -> None:
        from app import scheduler as scheduler_module
        from app.services import settings_store

        settings_store.set_value(db, settings_store.KEY_SCHEDULER_ENABLED, False)
        db.commit()
        scheduler_module.shutdown()
        try:
            scheduler_module.start()
            assert scheduler_module.get_scheduler().get_job(scheduler_module.JOB_ID) is None
        finally:
            scheduler_module.shutdown()
