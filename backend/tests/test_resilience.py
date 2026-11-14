"""Behaviour under failure: outages, bad answers, crashes and races.

These are the guarantees an unattended enforcement loop has to keep when the
remote API or the process itself misbehaves.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.checkmarx.iam import AI_ROLE_NAMES
from app.db.base import utcnow
from app.db.session import get_session_factory, session_scope
from app.models import (
    AuditLogEntry,
    CreditLimit,
    DimensionState,
    EnforcementAction,
    Exemption,
    Notification,
    SchedulerLock,
    SchedulerRun,
    UsageRecord,
    UsageSnapshot,
)
from app.models.enums import (
    EnforcementStatus,
    EntityType,
    LimitStatus,
    PeriodType,
    RunStatus,
    Severity,
    UsageView,
)
from app.models.limits import LimitPeriodState
from app.services import connection as connection_service
from app.services import (
    cycle,
    enforcement,
    evaluation,
    ingestion,
    limits_service,
    notifications,
    ops_hardening,
    org_sync,
)
from app.services.audit import AuditActor, record_audit
from tests.conftest import make_api_key, sqlite_only
from tests.fake_tenant import FakeTenant, populated_tenant

ACTOR = AuditActor.system("test")
AUGUST = datetime(2026, 8, 11, 12, 0, tzinfo=UTC)
PERIOD = "2026-08"


def synced(db: Session, tenant: FakeTenant | None = None):
    tenant = tenant or populated_tenant()
    client = tenant.client()
    org_sync.sync_org_model(db, client)
    db.commit()
    return tenant, client


def harsh_limit(db: Session, *, credit_limit: int = 1, enforce: bool = True) -> CreditLimit:
    limit = CreditLimit(
        entity_type=EntityType.USER,
        entity_id="user-harsh",
        entity_label="Harsh Gokani",
        credit_limit=credit_limit,
        period_type=PeriodType.MONTHLY,
        enforce=enforce,
        created_at=datetime(2026, 8, 1, tzinfo=UTC),
    )
    db.add(limit)
    db.commit()
    return limit


def harsh_has_ai_roles(tenant: FakeTenant) -> bool:
    return all(role in tenant.role_mappings["user-harsh"] for role in AI_ROLE_NAMES)


def snapshots(db: Session, view: str = "user") -> list[UsageSnapshot]:
    return list(
        db.scalars(
            select(UsageSnapshot).where(UsageSnapshot.view_by == view).order_by(UsageSnapshot.id)
        )
    )


# ------------------------------------------------------------------ ingestion


class TestFailedReadsLeaveNothingBehind:
    def test_a_failed_read_stores_no_snapshot(self, db: Session) -> None:
        tenant, client = synced(db)
        ingestion.ingest_usage(db, client)
        before = db.scalar(select(func.count()).select_from(UsageSnapshot))

        tenant.fail_paths["/credits/consumption"] = 500
        result = ingestion.ingest_usage(db, client)

        assert result.errors
        assert result.fresh is False
        assert db.scalar(select(func.count()).select_from(UsageSnapshot)) == before

    def test_one_failing_dimension_does_not_discard_the_others(self, db: Session) -> None:
        tenant, client = synced(db)
        tenant.fail_views["project"] = 500
        result = ingestion.ingest_usage(db, client)

        assert result.dimensions["user"].records == 3
        assert result.dimensions["project"].error
        assert any("project" in error for error in result.errors)
        assert ingestion.latest_snapshot(db, UsageView.USER) is not None
        assert ingestion.latest_snapshot(db, UsageView.PROJECT) is None
        # An outage is not "this tenant has no such dimension".
        state = db.get(DimensionState, "project")
        assert state is None or state.supported is not False

    def test_a_truncated_answer_is_rejected_not_stored_as_the_whole_picture(
        self, db: Session
    ) -> None:
        tenant, client = synced(db)
        tenant.page_size_override = 1
        tenant.empty_from_page = 2
        result = ingestion.ingest_usage(db, client, views=(UsageView.USER,))

        assert any("pages" in error for error in result.errors)
        assert snapshots(db) == []

    def test_the_user_dimension_is_never_written_off(self, db: Session) -> None:
        tenant, client = synced(db)
        tenant.unsupported_views.add("user")
        result = ingestion.ingest_usage(db, client, views=(UsageView.USER,))
        assert result.errors
        assert db.get(DimensionState, "user").supported is None

        # It is asked for again on the very next cycle, and recovers.
        tenant.unsupported_views.clear()
        result = ingestion.ingest_usage(db, client, views=(UsageView.USER,))
        assert result.errors == []
        assert result.dimensions["user"].records == 3

    def test_an_unsupported_dimension_is_asked_for_again_after_a_day(self, db: Session) -> None:
        tenant, client = synced(db)
        tenant.unsupported_views.add("project")
        ingestion.ingest_usage(db, client)
        assert db.get(DimensionState, "project").supported is False

        # The tenant gains the dimension. Not noticed straight away...
        tenant.unsupported_views.clear()
        result = ingestion.ingest_usage(db, client)
        assert result.dimensions["project"].supported is False

        # ...but it is once the last check is a day old.
        state = db.get(DimensionState, "project")
        state.last_checked_at = (
            utcnow() - ingestion.REPROBE_UNSUPPORTED_AFTER - timedelta(minutes=1)
        )
        db.commit()
        result = ingestion.ingest_usage(db, client)
        assert result.dimensions["project"].supported is True
        assert db.get(DimensionState, "project").supported is True


class TestReprobeIsQuiet:
    def test_a_dimension_that_stays_unavailable_does_not_degrade_the_run_every_day(
        self, db: Session
    ) -> None:
        tenant, client = synced(db)
        tenant.unsupported_views.add("project")
        first = ingestion.ingest_usage(db, client)
        assert any("project" in warning for warning in first.warnings)  # news, once

        state = db.get(DimensionState, "project")
        state.last_checked_at = utcnow() - ingestion.REPROBE_UNSUPPORTED_AFTER - timedelta(hours=1)
        db.commit()
        calls_before = len(tenant.requests)
        again = ingestion.ingest_usage(db, client)

        assert len(tenant.requests) > calls_before  # it was asked for again...
        assert again.warnings == [] and again.errors == []  # ...and is still not news
        assert again.fresh is True
        refreshed = db.get(DimensionState, "project")
        assert refreshed.supported is False
        assert utcnow() - refreshed.last_checked_at < timedelta(minutes=1)

    def test_a_problem_with_the_action_breakdown_does_not_make_limits_stale(
        self, db: Session
    ) -> None:
        tenant, client = synced(db)
        ingestion.ingest_usage(db, client)
        tenant.fail_views["action"] = 503
        result = ingestion.ingest_usage(db, client)
        assert result.errors  # still reported
        assert result.fresh is True

    def test_a_permission_problem_on_the_user_dimension_is_stale_usage(self, db: Session) -> None:
        tenant, client = synced(db)
        tenant.fail_views["user"] = 403
        result = ingestion.ingest_usage(db, client)
        assert result.fresh is False


class TestCollapsedReadsAreHeld:
    def _collapse(self, tenant: FakeTenant) -> None:
        tenant.consumption["user"] = []

    def test_a_collapsed_read_is_kept_as_evidence_but_not_believed(self, db: Session) -> None:
        tenant, client = synced(db)
        ingestion.ingest_usage(db, client, views=(UsageView.USER,))
        believed = ingestion.latest_snapshot(db, UsageView.USER)

        self._collapse(tenant)
        result = ingestion.ingest_usage(db, client, views=(UsageView.USER,))

        assert result.dimensions["user"].held is True
        assert result.fresh is False
        assert result.warnings
        rows = snapshots(db)
        assert len(rows) == 2 and rows[-1].held_reason
        # The held read carries no records and is never "the latest".
        assert (
            db.scalar(
                select(func.count())
                .select_from(UsageRecord)
                .where(UsageRecord.snapshot_id == rows[-1].id)
            )
            == 0
        )
        assert ingestion.latest_snapshot(db, UsageView.USER).id == believed.id

    def _age_held_reads(self, db: Session, by: timedelta) -> None:
        for row in db.scalars(select(UsageSnapshot).where(UsageSnapshot.held_reason.is_not(None))):
            row.collected_at = row.collected_at - by
        db.commit()

    def test_a_collapse_is_accepted_once_it_has_persisted(self, db: Session) -> None:
        tenant, client = synced(db)
        ingestion.ingest_usage(db, client, views=(UsageView.USER,))
        self._collapse(tenant)

        def read() -> bool:
            return (
                ingestion.ingest_usage(db, client, views=(UsageView.USER,)).dimensions["user"].held
            )

        # Enough reads, but all within minutes: still not believed.
        assert [read() for _ in range(ingestion.HOLD_CONFIRMATIONS + 2)] == [True] * (
            ingestion.HOLD_CONFIRMATIONS + 2
        )
        # The same answer, hours later: accepted.
        self._age_held_reads(db, ingestion.HOLD_MIN_DURATION + timedelta(minutes=1))
        assert read() is False
        assert ingestion.latest_snapshot(db, UsageView.USER).total_credits == Decimal("0")

    def test_reads_that_disagree_with_each_other_are_not_accepted(self, db: Session) -> None:
        tenant, client = synced(db)
        tenant.set_user_credits(name="Sean Casey", credits=1000)
        ingestion.ingest_usage(db, client, views=(UsageView.USER,))
        real_rows = list(tenant.consumption["user"])

        def read() -> bool:
            return (
                ingestion.ingest_usage(db, client, views=(UsageView.USER,)).dimensions["user"].held
            )

        # Nothing, then a third of the real figure, then nothing: a feed that is
        # still misbehaving, not a reset that has settled.
        tenant.consumption["user"] = []
        assert read() is True
        tenant.consumption["user"] = [dict(real_rows[1], creditsUsed=300)]
        assert read() is True
        self._age_held_reads(db, ingestion.HOLD_MIN_DURATION + timedelta(minutes=1))
        tenant.consumption["user"] = []
        assert read() is True

    def test_a_glitch_that_passes_leaves_no_trace_in_the_figures(self, db: Session) -> None:
        tenant, client = synced(db)
        ingestion.ingest_usage(db, client, views=(UsageView.USER,))
        real_rows = list(tenant.consumption["user"])

        self._collapse(tenant)
        ingestion.ingest_usage(db, client, views=(UsageView.USER,))
        tenant.consumption["user"] = real_rows
        result = ingestion.ingest_usage(db, client, views=(UsageView.USER,))

        assert result.dimensions["user"].held is False
        assert ingestion.latest_snapshot(db, UsageView.USER).total_credits == Decimal("15")

    def test_an_ordinary_fall_is_believed(self, db: Session) -> None:
        tenant, client = synced(db)
        ingestion.ingest_usage(db, client, views=(UsageView.USER,))
        # 15 -> 12 credits: old usage ageing out of the window, not a collapse.
        tenant.set_user_credits(name="departed.person@checkmarx.com", credits=4)
        result = ingestion.ingest_usage(db, client, views=(UsageView.USER,))
        assert result.dimensions["user"].held is False

    def test_a_change_of_lookback_window_is_not_a_collapse(self, db: Session) -> None:
        tenant, client = synced(db)
        ingestion.ingest_usage(db, client, views=(UsageView.USER,), period_param="last_year")
        self._collapse(tenant)
        result = ingestion.ingest_usage(
            db, client, views=(UsageView.USER,), period_param="last_month"
        )
        assert result.dimensions["user"].held is False

    def test_a_collapsed_read_does_not_lift_and_then_reapply_restrictions(
        self, db: Session
    ) -> None:
        """The failure this exists to prevent, end to end."""
        tenant, client = synced(db)
        ingestion.ingest_usage(db, client)
        limit = harsh_limit(db)
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        tenant.set_user_credits(name="Harsh Gokani", email="harsh.gokani@checkmarx.com", credits=50)
        ingestion.ingest_usage(db, client)
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        assert not harsh_has_ai_roles(tenant)

        # Checkmarx answers 200 with nothing for one cycle.
        real_rows = list(tenant.consumption["user"])
        tenant.consumption["user"] = []
        ingestion.ingest_usage(db, client)
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)

        # Still restricted, on the same single action: nothing was lifted.
        assert not harsh_has_ai_roles(tenant)
        actions = list(db.scalars(select(EnforcementAction)))
        assert [a.status for a in actions] == [EnforcementStatus.APPLIED]
        state = db.scalar(select(LimitPeriodState).where(LimitPeriodState.limit_id == limit.id))
        assert state.status == LimitStatus.RESTRICTED

        tenant.consumption["user"] = real_rows
        ingestion.ingest_usage(db, client)
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        assert [a.status for a in db.scalars(select(EnforcementAction))] == [
            EnforcementStatus.APPLIED
        ]


# ---------------------------------------------------------------- enforcement


class TestUndoSnapshotIsDurableBeforeTheTenantIsChanged:
    def test_the_snapshot_is_committed_before_roles_are_removed(self, db: Session) -> None:
        tenant, client = synced(db)
        limit = harsh_limit(db)
        seen: list[dict | None] = []

        def at_request(request: httpx.Request) -> None:
            if request.method == "DELETE" and "/role-mappings/" in request.url.path:
                # A different session sees only what has been committed.
                with session_scope() as other:
                    action = other.scalar(select(EnforcementAction))
                    seen.append(
                        None
                        if action is None
                        else {"status": action.status, "snapshot": action.undo_snapshot}
                    )

        tenant.on_request = at_request
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)

        assert len(seen) == 1 and seen[0] is not None
        assert seen[0]["status"] == EnforcementStatus.PENDING
        removed = {entry["name"] for entry in seen[0]["snapshot"]["removed_roles"]}
        assert removed == set(AI_ROLE_NAMES)

    def test_a_crash_after_the_tenant_write_can_still_be_undone(self, db: Session) -> None:
        """The process dies after Checkmarx was changed but before it was recorded."""
        tenant, client = synced(db)
        limit = harsh_limit(db)

        class Crash(BaseException):
            pass

        original = tenant.handler

        def handler(request: httpx.Request) -> httpx.Response:
            response = original(request)
            if request.method == "DELETE" and "/role-mappings/" in request.url.path:
                raise Crash
            return response

        tenant.handler = handler  # type: ignore[method-assign]
        crashing_client = tenant.client()
        with pytest.raises(Crash):
            enforcement.apply_enforcement(
                db, crashing_client, limit=limit, period_key=PERIOD, actor=ACTOR
            )
        db.rollback()
        assert not harsh_has_ai_roles(tenant)

        # A fresh process finds the intent and what was taken.
        tenant.handler = original  # type: ignore[method-assign]
        with session_scope() as session:
            action = session.scalar(select(EnforcementAction))
            assert action.status == EnforcementStatus.PENDING
            assert {e["name"] for e in action.undo_snapshot["removed_roles"]} == set(AI_ROLE_NAMES)

        # The next cycle completes it without losing what must be given back...
        with session_scope() as session:
            fresh_limit = session.get(CreditLimit, limit.id)
            outcome = enforcement.apply_enforcement(
                session, client, limit=fresh_limit, period_key=PERIOD, actor=ACTOR
            )
            assert len(outcome.applied) == 1
            action = session.scalar(select(EnforcementAction))
            assert {e["name"] for e in action.undo_snapshot["removed_roles"]} == set(AI_ROLE_NAMES)
            # ...and Restore returns exactly those roles.
            assert enforcement.restore_action(
                session, client, action=action, actor=ACTOR, reason="admin"
            )
        assert harsh_has_ai_roles(tenant)


class TestUnrecordedRestrictionsAreStillLifted:
    """A restriction Checkmarx applied but the utility never got to record."""

    def _crash_mid_enforcement(self, db: Session):
        tenant, client = synced(db)
        limit = harsh_limit(db)

        class Crash(BaseException):
            pass

        original = tenant.handler

        def handler(request: httpx.Request) -> httpx.Response:
            response = original(request)
            if request.method == "DELETE" and "/role-mappings/" in request.url.path:
                raise Crash
            return response

        tenant.handler = handler  # type: ignore[method-assign]
        with pytest.raises(Crash):
            enforcement.apply_enforcement(
                db, tenant.client(), limit=limit, period_key=PERIOD, actor=ACTOR
            )
        db.rollback()
        tenant.handler = original  # type: ignore[method-assign]
        assert not harsh_has_ai_roles(tenant)
        action = db.scalar(select(EnforcementAction))
        db.refresh(action)
        assert action.status == EnforcementStatus.PENDING
        return tenant, client, limit, action

    def test_an_admin_can_restore_it(self, db: Session) -> None:
        tenant, client, _limit, action = self._crash_mid_enforcement(db)
        assert enforcement.restore_action(db, client, action=action, actor=ACTOR, reason="admin")
        assert harsh_has_ai_roles(tenant)
        assert action.status == EnforcementStatus.REVERSED

    def test_the_cycle_lifts_it_when_the_limit_stops_enforcing(self, db: Session) -> None:
        tenant, client, limit, _action = self._crash_mid_enforcement(db)
        limits_service.update_limit(
            db, limit=limit, changes={"enforce": False}, actor=ACTOR, client=None
        )
        db.commit()
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        assert harsh_has_ai_roles(tenant)

    def test_rollover_lifts_it(self, db: Session) -> None:
        tenant, client, _limit, _action = self._crash_mid_enforcement(db)
        ingestion.ingest_usage(db, client)
        september = datetime(2026, 9, 2, 12, 0, tzinfo=UTC)
        evaluation.evaluate_all(db, client=client, now=september, actor=ACTOR)
        assert harsh_has_ai_roles(tenant)

    def test_a_write_checkmarx_refused_is_not_treated_as_a_restriction(self, db: Session) -> None:
        """The key can read roles but not change them: nothing was taken."""
        tenant, client = synced(db)
        limit = harsh_limit(db)
        tenant.fail_requests[("DELETE", "/role-mappings/")] = 403
        outcome = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        assert outcome.failed
        action = db.scalar(select(EnforcementAction))
        assert action.status == EnforcementStatus.FAILED
        # The read succeeded, so there is a snapshot - but the outcome is known.
        assert action.undo_snapshot["removed_roles"]
        assert enforcement.may_be_in_force(action) is False
        assert harsh_has_ai_roles(tenant)

        # So nothing tries to "restore" it, cycle after cycle, once the limit
        # stops enforcing.
        limits_service.update_limit(
            db, limit=limit, changes={"enforce": False}, actor=ACTOR, client=None
        )
        db.commit()
        before = len(tenant.requests)
        for _ in range(3):
            result = evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
            assert result.restored == 0 and result.errors == []
        assert not [r for r in tenant.requests[before:] if r[0] != "GET"]
        assert (
            db.scalar(
                select(func.count())
                .select_from(Notification)
                .where(Notification.category == notifications.CATEGORY_RESTORATION)
            )
            == 0
        )

    def test_a_refused_write_is_simply_retried_on_the_next_breach(self, db: Session) -> None:
        tenant, client = synced(db)
        limit = harsh_limit(db)
        tenant.fail_requests[("DELETE", "/role-mappings/")] = 403
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        tenant.fail_requests.clear()

        outcome = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        assert len(outcome.applied) == 1
        assert not harsh_has_ai_roles(tenant)
        action = db.scalar(select(EnforcementAction))
        assert enforcement.OUTCOME_UNKNOWN not in action.undo_snapshot

    def test_an_outcome_in_doubt_is_undone_and_can_be_enforced_again(self, db: Session) -> None:
        """A 5xx on the write: Checkmarx may or may not have made the change."""
        tenant, client = synced(db)
        ingestion.ingest_usage(db, client)
        limit = harsh_limit(db)
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        tenant.set_user_credits(name="Harsh Gokani", email="harsh.gokani@checkmarx.com", credits=50)
        ingestion.ingest_usage(db, client)
        tenant.fail_requests[("DELETE", "/role-mappings/")] = 500
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        action = db.scalar(select(EnforcementAction))
        db.refresh(action)
        assert action.status == EnforcementStatus.FAILED
        assert enforcement.may_be_in_force(action) is True
        tenant.fail_requests.clear()

        # The budget is raised: the doubtful restriction is undone to be safe...
        limits_service.update_limit(
            db, limit=limit, changes={"credit_limit": 1000}, actor=ACTOR, client=client
        )
        db.commit()
        db.refresh(action)
        assert action.status == EnforcementStatus.REVERSED
        assert harsh_has_ai_roles(tenant)

        # ...and that automatic lift does not stop a later breach being enforced.
        limits_service.update_limit(
            db, limit=limit, changes={"credit_limit": 1}, actor=ACTOR, client=client
        )
        db.commit()
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        assert not harsh_has_ai_roles(tenant)

    def test_the_admin_api_lists_and_restores_it(
        self, admin_client: TestClient, db: Session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tenant, client, _limit, action = self._crash_mid_enforcement(db)
        monkeypatch.setattr(connection_service, "get_client", lambda _session: client)

        listed = admin_client.get("/api/notifications/enforcements").json()
        assert [row["id"] for row in listed] == [action.id]

        response = admin_client.post(f"/api/notifications/enforcements/{action.id}/restore")
        assert response.status_code == httpx.codes.OK, response.text
        assert response.json()["restored"] is True
        assert harsh_has_ai_roles(tenant)


class TestPersistentFailuresAreNotNoisy:
    def test_a_restriction_that_keeps_failing_alerts_once_a_day_not_every_cycle(
        self, db: Session
    ) -> None:
        tenant, client = synced(db)
        limit = harsh_limit(db)
        tenant.fail_requests[("DELETE", "/role-mappings/")] = 403
        for _ in range(4):
            outcome = enforcement.apply_enforcement(
                db, client, limit=limit, period_key=PERIOD, actor=ACTOR
            )
            assert outcome.failed  # it is still attempted, and still reported, each time

        alerts = db.scalar(
            select(func.count())
            .select_from(Notification)
            .where(Notification.title.like("Could not restrict%"))
        )
        audits = db.scalar(
            select(func.count())
            .select_from(AuditLogEntry)
            .where(AuditLogEntry.action == "enforcement.failed")
        )
        assert alerts == 1 and audits == 1
        assert db.scalar(select(EnforcementAction)).attempts == 4


class TestRestoreIsDurable:
    def test_a_failed_admin_restore_is_completed_by_the_cycle_not_undone(self, db: Session) -> None:
        tenant, client = synced(db)
        ingestion.ingest_usage(db, client)
        harsh_limit(db)
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        tenant.set_user_credits(name="Harsh Gokani", email="harsh.gokani@checkmarx.com", credits=50)
        ingestion.ingest_usage(db, client)
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        action = db.scalar(select(EnforcementAction))
        assert not harsh_has_ai_roles(tenant)

        # The admin presses Restore while Checkmarx is refusing writes.
        tenant.fail_requests[("POST", "/role-mappings/")] = 503
        with pytest.raises(Exception, match="."):
            enforcement.restore_action(db, client, action=action, actor=ACTOR, reason="admin")
        db.refresh(action)
        assert action.status == EnforcementStatus.APPLIED
        assert action.reversal_reason == enforcement.ADMIN_REASON

        # Checkmarx recovers. The limit is still breached, but the cycle finishes
        # the admin's restore rather than treating the roles as its own to keep.
        tenant.fail_requests.clear()
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.refresh(action)
        assert action.status == EnforcementStatus.REVERSED
        assert harsh_has_ai_roles(tenant)
        # And, being an admin's decision, it holds for the rest of the period.
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        assert harsh_has_ai_roles(tenant)

    def test_a_restore_that_keeps_failing_alerts_once_a_day_not_every_cycle(
        self, db: Session
    ) -> None:
        tenant, client, limit = _restricted(db)
        limits_service.update_limit(
            db, limit=limit, changes={"enforce": False}, actor=ACTOR, client=None
        )
        db.commit()
        tenant.fail_requests[("POST", "/role-mappings/")] = 503
        for _ in range(4):
            evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)

        alerts = db.scalar(
            select(func.count())
            .select_from(Notification)
            .where(Notification.title.like("Could not restore%"))
        )
        audits = db.scalar(
            select(func.count())
            .select_from(AuditLogEntry)
            .where(AuditLogEntry.action == "enforcement.restore_failed")
        )
        assert alerts == 1 and audits == 1


@sqlite_only
class TestLockOrder:
    def test_an_admin_lift_during_enforcement_does_not_stall_either_side(self, db: Session) -> None:
        """The cycle is mid-way through restricting a user when an admin switches
        the limit to monitor only. Neither may hold the database while waiting
        for the other."""
        import sqlite3
        import threading
        import time

        from app.core.config import get_settings

        tenant, client = synced(db)
        limit = harsh_limit(db)
        limit_id = limit.id
        path = get_settings().database_url.removeprefix("sqlite:///")
        observed: list[str] = []
        admin_outcome: dict[str, object] = {}

        def admin() -> None:
            try:
                with session_scope() as session:
                    limits_service.update_limit(
                        session,
                        limit=session.get(CreditLimit, limit_id),
                        changes={"enforce": False},
                        actor=ACTOR,
                        client=tenant.client(),
                    )
                admin_outcome["ok"] = True
            except Exception as exc:  # noqa: BLE001
                admin_outcome["error"] = repr(exc)

        thread: list[threading.Thread] = []

        def at_request(request: httpx.Request) -> None:
            if request.method == "DELETE" and "/role-mappings/" in request.url.path and not thread:
                thread.append(threading.Thread(target=admin))
                thread[0].start()
                time.sleep(0.8)  # the admin thread is now waiting for this target
                connection = sqlite3.connect(path, timeout=0)
                try:
                    connection.execute("BEGIN IMMEDIATE")
                    connection.execute("ROLLBACK")
                    observed.append("free")
                except sqlite3.OperationalError:
                    observed.append("write lock held")
                finally:
                    connection.close()

        tenant.on_request = at_request
        started = time.monotonic()
        outcome = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        thread[0].join(30)

        assert observed == ["free"]
        assert time.monotonic() - started < 10
        assert len(outcome.applied) == 1
        assert admin_outcome == {"ok": True}
        # The admin's change came second and wins: the restriction is lifted, and
        # both halves are in the audit trail in the order they happened.
        assert harsh_has_ai_roles(tenant)
        with session_scope() as session:
            actions = [
                row.action
                for row in session.scalars(select(AuditLogEntry).order_by(AuditLogEntry.id))
                if row.action in ("enforcement.applied", "enforcement.reversed")
            ]
        assert actions == ["enforcement.applied", "enforcement.reversed"]


class TestRestoreRace:
    def test_restore_acts_on_the_committed_state_not_a_stale_copy(self, db: Session) -> None:
        tenant, client = synced(db)
        limit = harsh_limit(db)
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        action = db.scalar(select(EnforcementAction))
        assert action.status == EnforcementStatus.APPLIED

        # Another session (the cycle, or a second admin) restores it first.
        with session_scope() as other:
            theirs = other.get(EnforcementAction, action.id)
            assert enforcement.restore_action(
                other, client, action=theirs, actor=ACTOR, reason="admin"
            )
        assert harsh_has_ai_roles(tenant)
        writes_before = [r for r in tenant.requests if r[0] != "GET"]

        # This session still holds the row as APPLIED. It must notice, not replay.
        assert action.status == EnforcementStatus.APPLIED
        assert (
            enforcement.restore_action(db, client, action=action, actor=ACTOR, reason="admin")
            is False
        )
        assert [r for r in tenant.requests if r[0] != "GET"] == writes_before

    def test_enforcement_respects_a_restore_committed_by_another_session(self, db: Session) -> None:
        tenant, client = synced(db)
        limit = harsh_limit(db)
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        action = db.scalar(select(EnforcementAction))

        with session_scope() as other:
            enforcement.restore_action(
                other,
                client,
                action=other.get(EnforcementAction, action.id),
                actor=ACTOR,
                reason="admin",
            )

        # The cycle's session has a stale APPLIED copy; re-verifying must not
        # remove the roles the admin just gave back.
        outcome = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        assert outcome.applied == [] and outcome.reconciled == []
        assert harsh_has_ai_roles(tenant)


# ------------------------------------------------------- lifting restrictions


def _restricted(db: Session):
    tenant, client = synced(db)
    limit = harsh_limit(db)
    enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
    assert not harsh_has_ai_roles(tenant)
    return tenant, client, limit


class TestAFailedLiftIsCompletedLater:
    def test_disabling_a_limit_stands_even_if_checkmarx_is_down(self, db: Session) -> None:
        tenant, client, limit = _restricted(db)
        tenant.fail_paths["/role-mappings/"] = 500

        limits_service.update_limit(
            db, limit=limit, changes={"enforce": False}, actor=ACTOR, client=client
        )
        db.commit()

        with session_scope() as session:
            assert session.get(CreditLimit, limit.id).enforce is False
            # The change is audited even though the lift failed.
            assert session.scalar(
                select(AuditLogEntry).where(AuditLogEntry.action == "limit.updated")
            )
            assert session.scalar(select(EnforcementAction.status)) == EnforcementStatus.APPLIED
        assert not harsh_has_ai_roles(tenant)

        # Checkmarx comes back: the next cycle finishes the job.
        tenant.fail_paths.clear()
        ingestion.ingest_usage(db, client)
        result = evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        assert result.restored == 1
        assert harsh_has_ai_roles(tenant)

    def test_an_exemption_stands_and_its_lift_is_retried(self, db: Session) -> None:
        tenant, client, _limit = _restricted(db)
        tenant.fail_paths["/role-mappings/"] = 500
        limits_service.add_exemption(
            db,
            entity_type=EntityType.USER,
            entity_id="user-harsh",
            reason="lead",
            actor=ACTOR,
            client=client,
        )
        db.commit()
        assert db.scalar(select(Exemption)) is not None
        assert not harsh_has_ai_roles(tenant)

        tenant.fail_paths.clear()
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        assert harsh_has_ai_roles(tenant)
        action = db.scalar(select(EnforcementAction))
        db.refresh(action)
        assert action.reversal_reason == enforcement.EXEMPTED_REASON

    def test_a_limit_is_not_deleted_while_its_restriction_cannot_be_lifted(
        self, db: Session
    ) -> None:
        tenant, client, limit = _restricted(db)
        tenant.fail_paths["/role-mappings/"] = 500
        with pytest.raises(limits_service.LimitRestoreError):
            limits_service.delete_limit(db, limit=limit, actor=ACTOR, client=client)
        db.rollback()
        with session_scope() as session:
            assert session.get(CreditLimit, limit.id) is not None

    def test_a_restriction_whose_limit_is_gone_is_lifted_by_the_cycle(self, db: Session) -> None:
        tenant, client, limit = _restricted(db)
        # The limit was deleted while no connection was available.
        limits_service.delete_limit(db, limit=limit, actor=ACTOR, client=None)
        db.commit()
        assert not harsh_has_ai_roles(tenant)

        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        assert harsh_has_ai_roles(tenant)


class TestApprovalIsOneUnitOfWork:
    def test_nothing_of_an_approval_is_committed_before_all_of_it_is_written(
        self, db: Session
    ) -> None:
        """Approving lifts a restriction, and lifting commits. The commit must
        come after the request is marked approved, not half way through."""
        from app.models import CreditRequest
        from app.models.enums import RequestStatus
        from app.services import requests_service

        tenant, client = synced(db)
        ingestion.ingest_usage(db, client)
        limit = harsh_limit(db)
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        tenant.set_user_credits(name="Harsh Gokani", email="harsh.gokani@checkmarx.com", credits=50)
        ingestion.ingest_usage(db, client)
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        assert not harsh_has_ai_roles(tenant)

        request = requests_service.create_request(
            db,
            data=requests_service.RequestInput(
                entity_type=EntityType.USER,
                entity_id="user-harsh",
                requested_limit=1000,
                reason="release week",
            ),
            actor=ACTOR,
        )
        db.commit()

        seen: list[tuple[str, int]] = []

        def at_request(http_request: httpx.Request) -> None:
            if http_request.method == "POST" and "/role-mappings/" in http_request.url.path:
                # What another session can see at the moment access is given back.
                with session_scope() as other:
                    committed = other.get(CreditRequest, request.id)
                    seen.append((committed.status, other.get(CreditLimit, limit.id).credit_limit))

        tenant.on_request = at_request
        requests_service.approve_request(db, request=request, actor=ACTOR, client=client)
        db.commit()

        assert seen == [(RequestStatus.APPROVED, 1000)]
        assert harsh_has_ai_roles(tenant)
        with session_scope() as session:
            assert session.get(CreditLimit, limit.id).granted_by_request_id == request.id


class TestBulkEditKeepsRejectedValuesOut:
    def test_a_rejected_change_is_not_committed_by_a_later_commit(self, db: Session) -> None:
        synced(db)
        limit = harsh_limit(db, credit_limit=10)
        with pytest.raises(limits_service.LimitError):
            limits_service.update_limit(db, limit=limit, changes={"credit_limit": -5}, actor=ACTOR)
        db.commit()  # what the bulk endpoint does after collecting the error
        with session_scope() as session:
            assert session.get(CreditLimit, limit.id).credit_limit == 10


# ---------------------------------------------------------------------- cycle


@pytest.fixture
def configured_tenant(db: Session, monkeypatch: pytest.MonkeyPatch) -> FakeTenant:
    tenant = populated_tenant()
    connection_service.save_connection(
        db, api_key=make_api_key(tenant="acme-corp"), actor=AuditActor.system("test")
    )
    db.commit()
    client = tenant.client()
    monkeypatch.setattr(connection_service, "get_client", lambda _session: client)
    return tenant


class TestStepIsolation:
    def test_an_unexpected_error_in_one_step_does_not_stop_the_rest(
        self, configured_tenant: FakeTenant, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def boom(*_args, **_kwargs):
            raise RuntimeError("org sync blew up")

        monkeypatch.setattr(org_sync, "sync_org_model", boom)
        result = cycle.run_cycle(trigger="manual", force_org_sync=True)

        assert result.status == RunStatus.PARTIAL
        assert result.steps["org_sync"] == {"ok": False, "error": "org sync blew up"}
        assert result.steps["ingest"]["user"]["supported"] is True
        assert "evaluate" in result.steps and "deliver" in result.steps

    def test_a_failed_step_discards_its_own_half_written_work_only(
        self, configured_tenant: FakeTenant, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cycle.run_cycle(trigger="manual", force_org_sync=True)

        def half_done(session: Session, **_kwargs):
            session.add(
                Notification(
                    category="automation",
                    severity=Severity.INFO,
                    title="half written",
                    created_at=utcnow(),
                )
            )
            session.flush()
            raise RuntimeError("automation failed half way")

        from app.services import requests_service

        monkeypatch.setattr(requests_service, "auto_decide_pending", half_done)
        result = cycle.run_cycle(trigger="manual")

        assert result.status == RunStatus.PARTIAL
        with session_scope() as session:
            assert (
                session.scalar(select(Notification).where(Notification.title == "half written"))
                is None
            )
            # Work from the steps before it was kept.
            assert session.scalar(select(func.count()).select_from(UsageSnapshot)) > 5

    def test_a_partly_failed_ingestion_marks_usage_as_stale(
        self, configured_tenant: FakeTenant
    ) -> None:
        configured_tenant.fail_views["user"] = 503
        result = cycle.run_cycle(trigger="manual", force_org_sync=True)
        assert result.status == RunStatus.PARTIAL
        assert result.steps["evaluate"]["used_stale_usage"] is True
        assert any(error.startswith("ingest:") for error in result.errors)


class TestLockHeartbeat:
    def test_every_run_has_its_own_holder_id(self) -> None:
        assert cycle.new_holder_id() != cycle.new_holder_id()
        assert len(cycle.new_holder_id()) <= 128

    def test_the_keeper_refreshes_the_heartbeat(self, db: Session) -> None:
        with session_scope() as session:
            cycle.acquire_lock(session, holder="run-a")
        with session_scope() as session:
            lock = session.get(SchedulerLock, cycle.LOCK_NAME)
            lock.heartbeat_at = utcnow() - cycle.LOCK_STALE_AFTER + timedelta(seconds=5)

        cycle._LockKeeper("run-a").beat()

        with session_scope() as session:
            lock = session.get(SchedulerLock, cycle.LOCK_NAME)
            assert utcnow() - lock.heartbeat_at < timedelta(seconds=30)
            assert cycle.acquire_lock(session, holder="run-b") is False

    def test_the_keeper_cannot_refresh_someone_elses_lock(self, db: Session) -> None:
        with session_scope() as session:
            cycle.acquire_lock(session, holder="run-a")
        stale = utcnow() - cycle.LOCK_STALE_AFTER - timedelta(minutes=1)
        with session_scope() as session:
            session.get(SchedulerLock, cycle.LOCK_NAME).heartbeat_at = stale

        cycle._LockKeeper("run-b").beat()

        with session_scope() as session:
            assert session.get(SchedulerLock, cycle.LOCK_NAME).heartbeat_at == stale

    def test_the_keeper_thread_beats_while_the_cycle_runs(self, db: Session) -> None:
        with session_scope() as session:
            cycle.acquire_lock(session, holder="run-a")
        old = utcnow() - timedelta(minutes=5)
        with session_scope() as session:
            session.get(SchedulerLock, cycle.LOCK_NAME).heartbeat_at = old

        with cycle._LockKeeper("run-a", interval=0.05) as keeper:
            for _ in range(100):
                keeper._stop.wait(0.05)
                with session_scope() as session:
                    if session.get(SchedulerLock, cycle.LOCK_NAME).heartbeat_at > old:
                        break
        with session_scope() as session:
            assert session.get(SchedulerLock, cycle.LOCK_NAME).heartbeat_at > old
        assert not keeper._thread.is_alive()


class TestHungCycle:
    def test_the_heartbeat_stops_for_a_cycle_that_has_run_far_too_long(self, db: Session) -> None:
        with session_scope() as session:
            cycle.acquire_lock(session, holder="run-a")
        old = utcnow() - timedelta(minutes=5)
        with session_scope() as session:
            session.get(SchedulerLock, cycle.LOCK_NAME).heartbeat_at = old

        keeper = cycle._LockKeeper("run-a", interval=0.02, max_duration=timedelta(seconds=-1))
        with keeper:
            keeper._thread.join(5)
            assert not keeper._thread.is_alive()
        with session_scope() as session:
            assert session.get(SchedulerLock, cycle.LOCK_NAME).heartbeat_at == old


class TestBusyDatabase:
    def test_a_lock_timeout_is_a_retryable_503_not_an_opaque_500(
        self, admin_client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from sqlalchemy.exc import OperationalError

        from app.api.routes import limits as limits_routes

        def busy(*_args, **_kwargs):
            raise OperationalError("SELECT 1", {}, Exception("canceling statement: lock timeout"))

        monkeypatch.setattr(limits_routes.limits_service, "create_limit", busy)
        response = admin_client.post(
            "/api/limits",
            json={"entity_type": "user", "entity_id": "user-harsh", "credit_limit": 5},
        )
        assert response.status_code == httpx.codes.SERVICE_UNAVAILABLE
        assert response.headers["Retry-After"] == "5"
        assert response.json()["detail"]["code"] == "database_busy"


class TestWatchdogIgnoresLockSkips:
    def _run(self, db: Session, *, status: str, when: datetime, stats: dict | None = None) -> None:
        db.add(
            SchedulerRun(
                kind="cycle",
                trigger="schedule",
                started_at=when,
                finished_at=when,
                status=status,
                stats=stats,
            )
        )
        db.flush()

    def test_a_stuck_lock_is_not_reported_as_healthy(self, db: Session) -> None:
        now = utcnow()
        self._run(db, status=RunStatus.SUCCESS, when=now - timedelta(days=2))
        # The timer keeps firing, but every run bounces off a stuck lock.
        for minutes in (45, 30, 15, 0):
            self._run(
                db,
                status=RunStatus.SKIPPED,
                when=now - timedelta(minutes=minutes),
                stats={"reason": cycle.LOCK_BUSY_REASON},
            )
        assert ops_hardening.watchdog_status(db, now=now).state == "down"
        assert ops_hardening.scheduler_alive(db, now=now) is False

    def test_a_run_skipped_for_another_reason_still_counts(self, db: Session) -> None:
        now = utcnow()
        self._run(
            db,
            status=RunStatus.SKIPPED,
            when=now,
            stats={"connection": {"ok": False, "reason": "not configured"}},
        )
        assert ops_hardening.watchdog_status(db, now=now).state == "ok"


# -------------------------------------------------------------- notifications


class TestNotifyDedupe:
    def test_losing_a_race_on_the_dedupe_key_keeps_the_callers_other_work(
        self, db: Session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Another writer inserts the same notification between this writer's
        check and its insert. Only the duplicate insert may be undone."""
        record_audit(db, action="test.kept", actor=ACTOR, detail="must survive")
        db.flush()

        real_scalar = Session.scalar
        raced: list[bool] = []

        def scalar_then_lose_the_race(self, statement, *args, **kwargs):
            found = real_scalar(self, statement, *args, **kwargs)
            if self is db and not raced and "notification" in str(statement).lower():
                raced.append(True)
                # The other writer, landing the same key just after our check.
                db.execute(
                    Notification.__table__.insert().values(
                        created_at=utcnow(),
                        severity=Severity.ERROR,
                        category="sync_error",
                        title="first",
                        dedupe_key="k",
                    )
                )
            return found

        monkeypatch.setattr(Session, "scalar", scalar_then_lose_the_race)
        assert (
            notifications.notify(
                db, category="sync_error", severity=Severity.ERROR, title="again", dedupe_key="k"
            )
            is None
        )
        monkeypatch.undo()
        assert raced == [True]
        db.commit()

        other = get_session_factory()()
        try:
            assert other.scalar(select(AuditLogEntry).where(AuditLogEntry.action == "test.kept"))
            assert other.scalar(select(func.count()).select_from(Notification)) == 1
        finally:
            other.close()

    def test_a_savepoint_does_not_commit_the_callers_transaction(self, db: Session) -> None:
        """On SQLite a savepoint used to start, and then commit, its own
        transaction when it was the first write: the notification outlived the
        caller's rollback."""
        notifications.notify(
            db, category="sync_error", severity=Severity.ERROR, title="rolled back", dedupe_key="r"
        )
        db.rollback()
        other = get_session_factory()()
        try:
            assert other.scalar(select(func.count()).select_from(Notification)) == 0
        finally:
            other.close()


# ------------------------------------------------------------------------ API


class TestDeleteLimitApi:
    def test_a_failed_lift_is_reported_and_the_limit_kept(
        self, admin_client: TestClient, db: Session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tenant, client, limit = _restricted(db)
        from app.api.routes import limits as limits_routes

        monkeypatch.setattr(limits_routes, "_optional_client", lambda _db: client)
        tenant.fail_paths["/role-mappings/"] = 500

        response = admin_client.delete(f"/api/limits/{limit.id}")
        assert response.status_code == httpx.codes.BAD_GATEWAY
        assert response.json()["detail"]["code"] == "restore_failed"
        with session_scope() as session:
            assert session.get(CreditLimit, limit.id) is not None
