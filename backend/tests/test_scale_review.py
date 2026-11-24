"""Findings of the independent review of the 2,000-project scale work, each
with the test that failed before the fix, and a test per further fix.

B1 the verification rotation chooses only restrictions the cycle reads back;
   those outside any plan are verified on their own; failures move back.
S1 the cycle's time budget is the cycle's, never an API request's.
S2 a restore spread over cycles stays "restricted" (lifting) until done.
S3 a rollout's progress is kept as identities and cleared with the period.
S4 lifts go before re-asserts, re-asserts before new restrictions.
S5 a read-back made ahead is read again before anything is written on it.
M1 deleting a limit counts restrictions whose outcome is unknown.
M3 the restrictions page escapes LIKE wildcards and pages in the database.
M5 the pacing settings are part of the configuration backup.
M6 re-asserts count against the write budget, and still happen.
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models import CreditLimit, EnforcementAction, Notification
from app.models.enums import EnforcementStatus, EntityType, LimitStatus, PeriodType
from app.services import (
    enforcement,
    evaluation,
    limits_service,
    ops_hardening,
    org_sync,
    pacing,
    settings_store,
)
from tests.test_scale_pacing import (
    ACTOR,
    applied,
    connected,  # noqa: F401 - fixture
    group_limit,
    setting,
    state_of,
    tenant_with_projects,
)


def _solo_limit(db: Session, project_id: str = "proj-x") -> CreditLimit:
    limit = CreditLimit(
        entity_type=EntityType.PROJECT,
        entity_id=project_id,
        entity_label=f"solo/{project_id}",
        credit_limit=1,
        period_type=PeriodType.MONTHLY,
        enforce=True,
        count_existing_usage=True,
        project_actions=["auto_triage"],
    )
    db.add(limit)
    db.commit()
    return limit


def _next_month(now: datetime) -> datetime:
    return datetime(now.year + (now.month == 12), now.month % 12 + 1, 2, tzinfo=now.tzinfo)


def _writes_to(tenant, project_id: str) -> int:  # type: ignore[no-untyped-def]
    return sum(
        1
        for method, path in tenant.requests
        if method != "GET" and f"/ai-agents-coordinator/projects/{project_id}" in path
    )


# ------------------------------------------------------------------ B1


class TestVerificationOwners:
    def test_restrictions_outside_the_plan_starve_the_verification_rotation(
        self,
        db: Session,
        connected,  # noqa: F811
    ) -> None:
        """Two projects leave the group: their restrictions stay in force (as
        before pacing) but apply_enforcement never meets them, so they were
        never marked verified, stayed 'oldest' and took the per-cycle read-back
        slots for ever. A drift on a project still in the group was then never
        found."""
        tenant = tenant_with_projects(8)
        client = connected(tenant)
        setting(db, settings_store.KEY_SCHEDULE_INTERVAL_MINUTES, 15)
        setting(db, settings_store.KEY_VERIFY_INTERVAL_MINUTES, 60)
        setting(db, settings_store.KEY_MAX_VERIFICATIONS, 2)
        limit = group_limit(db)
        evaluation.evaluate_all(db, client=client, actor=ACTOR)
        assert applied(db, limit.id) == 8

        for project in tenant.projects:
            if project["id"] in ("proj-m00", "proj-m01"):
                project["groups"] = []
        org_sync.sync_org_model(db, client)
        db.commit()
        assert applied(db, limit.id) == 8  # still in force, as before pacing

        tenant.auto_triage["proj-m05"]["enabled"] = True  # drift
        now = utcnow()
        verified = []
        for step in range(1, 13):  # three hours of 15-minute cycles
            result = evaluation.evaluate_all(
                db, client=client, actor=ACTOR, now=now + timedelta(minutes=15 * step)
            )
            verified.append(result.pacing["verification"]["verified"])
        # Each restriction is read back within the hour.
        assert tenant.auto_triage["proj-m05"]["enabled"] is False, (
            f"drift never fixed; read-backs per cycle: {verified}"
        )

    def test_a_restriction_outside_the_plan_is_verified_on_its_own(
        self,
        db: Session,
        connected,  # noqa: F811
    ) -> None:
        tenant = tenant_with_projects(4)
        client = connected(tenant)
        setting(db, settings_store.KEY_SCHEDULE_INTERVAL_MINUTES, 15)
        setting(db, settings_store.KEY_VERIFY_INTERVAL_MINUTES, 60)
        limit = group_limit(db)
        evaluation.evaluate_all(db, client=client, actor=ACTOR)
        for project in tenant.projects:
            if project["id"] == "proj-m00":
                project["groups"] = []
        org_sync.sync_org_model(db, client)
        db.commit()
        # Kept in force until the period ends (as before), so its drift is
        # still found and re-asserted.
        tenant.auto_triage["proj-m00"]["enabled"] = True
        now = utcnow()
        stats = []
        for step in range(1, 5):
            result = evaluation.evaluate_all(
                db, client=client, actor=ACTOR, now=now + timedelta(minutes=15 * step)
            )
            stats.append(result.pacing["verification"])
        assert tenant.auto_triage["proj-m00"]["enabled"] is False
        assert applied(db, limit.id) == 4
        first = stats[0]
        assert first["in_a_plan"] == 3 and first["outside_a_plan"] == 1
        assert first["rotation"] == 4 and first["each_verified_within_minutes"] == 60
        assert sum(stat["reasserted"] for stat in stats) == 1

    def test_held_restrictions_from_last_period_starve_the_rotation(
        self,
        db: Session,
        connected,  # noqa: F811
    ) -> None:
        """A hold-until-released limit keeps last period's restrictions in force
        after the rollover. They are verified on their own, in the rotation,
        without taking every slot."""
        tenant = tenant_with_projects(4)
        tenant.add_project(project_id="proj-x", name="solo/x", group_ids=[])
        tenant.set_entity_credits(view="project", name="solo/x", credits=5, entity_id="proj-x")
        client = connected(tenant)
        setting(db, settings_store.KEY_SCHEDULE_INTERVAL_MINUTES, 15)
        setting(db, settings_store.KEY_VERIFY_INTERVAL_MINUTES, 60)
        held = group_limit(db)
        held.hold_until_released = True
        db.commit()
        solo = _solo_limit(db)
        now = utcnow()
        evaluation.evaluate_all(db, client=client, actor=ACTOR, now=now)
        assert applied(db, held.id) == 4 and applied(db, solo.id) == 1

        setting(db, settings_store.KEY_MAX_VERIFICATIONS, 4)
        next_month = _next_month(now)
        evaluation.evaluate_all(db, client=client, actor=ACTOR, now=next_month)
        tenant.auto_triage["proj-x"]["enabled"] = True  # drift on the new period's restriction
        tenant.auto_triage["proj-m02"]["enabled"] = True  # and on a held one
        for step in range(1, 13):
            evaluation.evaluate_all(
                db, client=client, actor=ACTOR, now=next_month + timedelta(minutes=15 * step)
            )
        assert tenant.auto_triage["proj-x"]["enabled"] is False, "drift never fixed in 3 hours"
        assert tenant.auto_triage["proj-m02"]["enabled"] is False, "held one never verified"

    def test_control_held_with_a_large_cap_finds_the_drift(
        self,
        db: Session,
        connected,  # noqa: F811
    ) -> None:
        tenant = tenant_with_projects(4)
        tenant.add_project(project_id="proj-x", name="solo/x", group_ids=[])
        tenant.set_entity_credits(view="project", name="solo/x", credits=5, entity_id="proj-x")
        client = connected(tenant)
        setting(db, settings_store.KEY_SCHEDULE_INTERVAL_MINUTES, 15)
        setting(db, settings_store.KEY_VERIFY_INTERVAL_MINUTES, 60)
        held = group_limit(db)
        held.hold_until_released = True
        db.commit()
        solo = _solo_limit(db)
        now = utcnow()
        evaluation.evaluate_all(db, client=client, actor=ACTOR, now=now)
        assert applied(db, held.id) == 4 and applied(db, solo.id) == 1

        setting(db, settings_store.KEY_MAX_VERIFICATIONS, 100)
        next_month = _next_month(now)
        evaluation.evaluate_all(db, client=client, actor=ACTOR, now=next_month)
        tenant.auto_triage["proj-x"]["enabled"] = True
        for step in range(1, 13):
            evaluation.evaluate_all(
                db, client=client, actor=ACTOR, now=next_month + timedelta(minutes=15 * step)
            )
        assert tenant.auto_triage["proj-x"]["enabled"] is False, "drift never fixed in 3 hours"

    def test_verify_ids_stats(self, db: Session, connected) -> None:  # noqa: F811
        """Sanity: after the upgrade every row is null and all are due."""
        tenant = tenant_with_projects(3)
        client = connected(tenant)
        group_limit(db)
        evaluation.evaluate_all(db, client=client, actor=ACTOR)
        db.execute(
            EnforcementAction.__table__.update().values(last_verified_at=None)  # type: ignore[attr-defined]
        )
        db.commit()
        result = evaluation.evaluate_all(db, client=client, actor=ACTOR)
        assert result.pacing["verification"]["verified"] == 3
        assert all(
            row is not None
            for row in db.scalars(
                select(EnforcementAction.last_verified_at).where(
                    EnforcementAction.status == EnforcementStatus.APPLIED
                )
            )
        )

    def test_one_that_cannot_be_read_moves_back_and_is_reported(
        self,
        db: Session,
        connected,  # noqa: F811
    ) -> None:
        tenant = tenant_with_projects(4)
        client = connected(tenant)
        setting(db, settings_store.KEY_SCHEDULE_INTERVAL_MINUTES, 15)
        setting(db, settings_store.KEY_VERIFY_INTERVAL_MINUTES, 60)
        setting(db, settings_store.KEY_MAX_VERIFICATIONS, 1)
        group_limit(db)
        now = utcnow()
        evaluation.evaluate_all(db, client=client, actor=ACTOR, now=now)
        tenant.fail_requests[("GET", "/ai-agents-coordinator/projects/proj-m00")] = 500
        db.execute(
            EnforcementAction.__table__.update()  # type: ignore[attr-defined]
            .where(EnforcementAction.target_id == "proj-m00")
            .values(last_verified_at=now - timedelta(hours=5))
        )
        db.commit()
        first = evaluation.evaluate_all(
            db, client=client, actor=ACTOR, now=now + timedelta(minutes=15)
        )
        stats = first.pacing["verification"]
        assert stats["failed"] == 1 and stats["unverified_beyond_twice_the_interval"] == 1
        db.expire_all()
        failing = db.scalar(
            select(EnforcementAction).where(EnforcementAction.target_id == "proj-m00")
        )
        assert failing.last_checked_at is not None  # behind the others now
        # The next cycle reads another one, not the failing one again.
        tenant.requests.clear()
        evaluation.evaluate_all(db, client=client, actor=ACTOR, now=now + timedelta(minutes=30))
        assert not any("proj-m00" in path for _method, path in tenant.requests)
        [alert] = db.scalars(
            select(Notification).where(Notification.title.like("%not read back%"))
        ).all()
        assert "proj-m00" in (alert.body or "")

    def test_restrictions_being_lifted_are_not_chosen(
        self,
        db: Session,
        connected,  # noqa: F811
    ) -> None:
        tenant = tenant_with_projects(4)
        client = connected(tenant)
        limit = group_limit(db)
        evaluation.evaluate_all(db, client=client, actor=ACTOR)
        setting(db, settings_store.KEY_MAX_WRITES, 1)
        row = db.get(CreditLimit, limit.id)
        row.credit_limit = 1_000_000
        db.commit()
        result = evaluation.evaluate_all(db, client=client, actor=ACTOR)
        stats = result.pacing["verification"]
        assert stats["being_lifted"] == 3 and stats["rotation"] == 0
        assert stats["selected"] == 0


# ------------------------------------------------------------------ S1


class TestTimeBudgetIsTheCycles:
    def test_gui_switch_off_is_blocked_by_the_cycles_time_budget(
        self,
        db: Session,
        connected,  # noqa: F811
    ) -> None:
        """An API thread that switches a limit off while a cycle is past its
        time budget still lifts (respect_deadline=False), within its cap."""
        tenant = tenant_with_projects(3)
        client = connected(tenant)
        limit = group_limit(db)
        evaluation.evaluate_all(db, client=client, actor=ACTOR)
        assert applied(db, limit.id) == 3

        with pacing.cycle_deadline(0.001):  # as set by a running scheduler cycle
            time.sleep(0.01)
            limits_service.update_limit(
                db,
                limit=db.get(CreditLimit, limit.id),
                changes={"enforce": False},
                actor=ACTOR,
                client=client,
            )
            db.commit()
        assert applied(db, limit.id) == 0

    def test_the_deadline_belongs_to_the_cycle_and_its_read_workers(self) -> None:
        seen: dict[str, bool] = {}
        with pacing.cycle_deadline(0.001):
            time.sleep(0.01)
            assert pacing.out_of_time()
            # A request served on another thread meanwhile has no deadline.
            other = threading.Thread(target=lambda: seen.update(api=pacing.out_of_time()))
            other.start()
            other.join()
            # The cycle's own read workers do.
            [(_item, worker, _exc)] = pacing.parallel_map(
                lambda _item: pacing.out_of_time(), [1], workers=2
            )
            results = pacing.parallel_map(lambda _item: pacing.out_of_time(), [1, 2], workers=2)
        assert seen == {"api": False}
        assert worker is True and all(value for _i, value, _e in results)
        assert not pacing.out_of_time()

    def test_a_gui_lift_still_honours_its_cap(
        self,
        db: Session,
        connected,  # noqa: F811
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        tenant = tenant_with_projects(4)
        client = connected(tenant)
        monkeypatch.setattr(limits_service, "API_RESTORE_BATCH", 3)
        limit = group_limit(db)
        evaluation.evaluate_all(db, client=client, actor=ACTOR)
        with pacing.cycle_deadline(0.001):
            time.sleep(0.01)
            limits_service.update_limit(
                db,
                limit=db.get(CreditLimit, limit.id),
                changes={"enforce": False},
                actor=ACTOR,
                client=client,
            )
            db.commit()
        assert applied(db, limit.id) == 1


# ------------------------------------------------------------------ S2


class TestLiftingIsNotRestored:
    def test_a_partly_lifted_restore_is_not_shown_as_restored(
        self,
        db: Session,
        connected,  # noqa: F811
        admin_client: TestClient,
    ) -> None:
        tenant = tenant_with_projects(5)
        client = connected(tenant)
        limit = group_limit(db)
        evaluation.evaluate_all(db, client=client, actor=ACTOR)
        setting(db, settings_store.KEY_MAX_WRITES, 2)
        row = db.get(CreditLimit, limit.id)
        row.credit_limit = 1_000_000
        db.commit()
        evaluation.evaluate_all(db, client=client, actor=ACTOR)
        assert applied(db, limit.id) == 3
        assert state_of(db, limit.id).status == LimitStatus.RESTRICTED
        [shown] = [r for r in admin_client.get("/api/limits").json() if r["id"] == limit.id]
        assert shown["current_period"]["lifting_remaining"] == 3

        evaluation.evaluate_all(db, client=client, actor=ACTOR)
        assert state_of(db, limit.id).status == LimitStatus.RESTRICTED
        evaluation.evaluate_all(db, client=client, actor=ACTOR)
        assert applied(db, limit.id) == 0
        assert state_of(db, limit.id).status == LimitStatus.RESTORED
        [shown] = [r for r in admin_client.get("/api/limits").json() if r["id"] == limit.id]
        assert shown["current_period"]["lifting_remaining"] is None


# ------------------------------------------------------------------ S3


class TestRolloutIdentities:
    def test_rollout_progress_survives_a_lift_and_discounts_the_ceiling(
        self,
        db: Session,
        connected,  # noqa: F811
    ) -> None:
        """A rollout waived once (6 targets, ceiling 3) is lifted part way (the
        budget is raised), then breached again in the same period: all 6
        restarting are judged again by the ceiling."""
        tenant = tenant_with_projects(6)
        client = connected(tenant)
        setting(db, settings_store.KEY_MAX_WRITES, 2)
        setting(db, settings_store.KEY_MAX_NEW_TARGETS, 3)
        limit = group_limit(db)
        evaluation.evaluate_all(db, client=client, actor=ACTOR)  # trips
        setting(db, settings_store.KEY_ENFORCEMENT_PAUSED, False)
        setting(db, settings_store.KEY_CEILING_WAIVED_ONCE, True)
        evaluation.evaluate_all(db, client=client, actor=ACTOR)
        assert applied(db, limit.id) == 2
        row = db.get(CreditLimit, limit.id)
        row.credit_limit = 1_000_000
        db.commit()
        evaluation.evaluate_all(db, client=client, actor=ACTOR)
        assert applied(db, limit.id) == 0
        state = state_of(db, limit.id)
        assert (state.rollout_total, state.rollout_done, state.rollout_pending) == (
            None,
            None,
            None,
        )
        row = db.get(CreditLimit, limit.id)
        row.credit_limit = 1
        db.commit()
        again = evaluation.evaluate_all(db, client=client, actor=ACTOR)
        assert again.enforcement_paused is not None, (
            f"6 targets restarted with a ceiling of 3; applied={applied(db, limit.id)}"
        )

    def test_a_target_leaving_the_rollout_frees_no_slot(
        self,
        db: Session,
        connected,  # noqa: F811
    ) -> None:
        tenant = tenant_with_projects(6)
        client = connected(tenant)
        setting(db, settings_store.KEY_MAX_WRITES, 2)
        setting(db, settings_store.KEY_MAX_NEW_TARGETS, 3)
        limit = group_limit(db)
        evaluation.evaluate_all(db, client=client, actor=ACTOR)  # trips
        setting(db, settings_store.KEY_ENFORCEMENT_PAUSED, False)
        setting(db, settings_store.KEY_CEILING_WAIVED_ONCE, True)
        evaluation.evaluate_all(db, client=client, actor=ACTOR)
        state = state_of(db, limit.id)
        pending = list(state.rollout_pending or [])
        assert len(pending) == 4
        # Three of the four still to restrict are exempted, four new projects
        # join: a count of "4 remaining" would let three of them through.
        for project_id in pending[:3]:
            limits_service.add_exemption(
                db, entity_type=EntityType.PROJECT, entity_id=project_id, reason="t", actor=ACTOR
            )
        db.commit()
        for index in range(6, 10):
            tenant.add_project(
                project_id=f"proj-m{index:02d}", name=f"many/{index:02d}", group_ids=["grp-many"]
            )
        org_sync.sync_org_model(db, client)
        db.commit()
        result = evaluation.evaluate_all(db, client=client, actor=ACTOR)
        assert result.enforcement_paused is not None


# ------------------------------------------------------------------ S4


class TestLiftsGoFirst:
    def test_a_lift_is_not_starved_by_a_new_restriction(
        self,
        db: Session,
        connected,  # noqa: F811
    ) -> None:
        tenant = tenant_with_projects(2)
        tenant.add_project(project_id="proj-x", name="solo/x", group_ids=[])
        tenant.add_project(project_id="proj-y", name="solo/y", group_ids=[])
        for name, pid in (("solo/x", "proj-x"), ("solo/y", "proj-y")):
            tenant.set_entity_credits(view="project", name=name, credits=5, entity_id=pid)
        client = connected(tenant)
        # Lower ids: evaluated first, and both new breaches.
        first = _solo_limit(db, "proj-x")
        second = _solo_limit(db, "proj-y")
        for limit in (first, second):
            limit.credit_limit = 1_000_000
        db.commit()
        group = group_limit(db)
        evaluation.evaluate_all(db, client=client, actor=ACTOR)
        assert applied(db, group.id) == 2

        setting(db, settings_store.KEY_MAX_WRITES, 2)
        for limit_id in (first.id, second.id):
            db.get(CreditLimit, limit_id).credit_limit = 1
        db.get(CreditLimit, group.id).credit_limit = 1_000_000
        db.commit()
        result = evaluation.evaluate_all(db, client=client, actor=ACTOR)
        # The group's two lifts went first; the new restrictions wait.
        assert applied(db, group.id) == 0
        assert applied(db, first.id) + applied(db, second.id) == 0
        assert result.pacing["writes"]["lifts"] == 2
        evaluation.evaluate_all(db, client=client, actor=ACTOR)
        assert applied(db, first.id) + applied(db, second.id) == 2


# ------------------------------------------------------------------ S5


class TestReadAheadIsReadAgain:
    def _setup(self, db: Session, connected, monkeypatch: pytest.MonkeyPatch, fixed: bool):  # type: ignore[no-untyped-def]  # noqa: F811
        tenant = tenant_with_projects(3)
        client = connected(tenant)
        setting(db, settings_store.KEY_VERIFY_INTERVAL_MINUTES, 0)
        setting(db, settings_store.KEY_READ_CONCURRENCY, 4)
        group_limit(db)
        evaluation.evaluate_all(db, client=client, actor=ACTOR)
        tenant.auto_triage["proj-m01"]["enabled"] = True  # drift, seen by the read ahead
        original = enforcement.prefetch_verification

        def prefetch(*args, **kwargs):  # type: ignore[no-untyped-def]
            made = original(*args, **kwargs)
            if fixed:
                # Someone puts it back in the minutes between the read ahead
                # and the drift check.
                tenant.auto_triage["proj-m01"]["enabled"] = False
            return made

        monkeypatch.setattr(enforcement, "prefetch_verification", prefetch)
        tenant.requests.clear()
        result = evaluation.evaluate_all(db, client=client, actor=ACTOR)
        assert result.pacing["verification"]["read_ahead"] == 3
        return tenant, result

    def test_a_stale_read_ahead_writes_nothing(
        self,
        db: Session,
        connected,  # noqa: F811
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        tenant, result = self._setup(db, connected, monkeypatch, fixed=True)
        assert _writes_to(tenant, "proj-m01") == 0
        assert result.pacing["verification"]["reasserted"] == 0
        # Read twice: ahead, and again before acting on it.
        reads = [
            path
            for method, path in tenant.requests
            if method == "GET" and "/ai-agents-coordinator/projects/proj-m01" in path
        ]
        assert len(reads) == 2

    def test_a_drift_read_ahead_and_confirmed_is_reasserted(
        self,
        db: Session,
        connected,  # noqa: F811
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        tenant, result = self._setup(db, connected, monkeypatch, fixed=False)
        assert tenant.auto_triage["proj-m01"]["enabled"] is False
        assert result.pacing["verification"]["reasserted"] == 1


# ------------------------------------------------------------------ M6


class TestReassertsCountAgainstTheBudget:
    def test_reasserts_are_budgeted_and_carried_over(
        self,
        db: Session,
        connected,  # noqa: F811
    ) -> None:
        tenant = tenant_with_projects(3)
        client = connected(tenant)
        setting(db, settings_store.KEY_VERIFY_INTERVAL_MINUTES, 0)
        limit = group_limit(db)
        evaluation.evaluate_all(db, client=client, actor=ACTOR)
        setting(db, settings_store.KEY_MAX_WRITES, 1)
        for index in range(3):
            tenant.auto_triage[f"proj-m{index:02d}"]["enabled"] = True
        drifted: list[int] = []
        for _ in range(3):
            result = evaluation.evaluate_all(db, client=client, actor=ACTOR)
            writes = result.pacing["writes"]
            assert writes["writes_used"] <= 1
            drifted.append(
                sum(tenant.auto_triage[f"proj-m{index:02d}"]["enabled"] for index in range(3))
            )
        assert drifted == [2, 1, 0]
        assert applied(db, limit.id) == 3


# ------------------------------------------------------------------ M1


def test_deleting_counts_restrictions_whose_outcome_is_unknown(
    db: Session,
    connected,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tenant = tenant_with_projects(2)
    client = connected(tenant)
    monkeypatch.setattr(limits_service, "API_RESTORE_BATCH", 1)
    limit = group_limit(db)
    evaluation.evaluate_all(db, client=client, actor=ACTOR)
    doubtful = db.scalars(
        select(EnforcementAction).where(EnforcementAction.limit_id == limit.id)
    ).first()
    doubtful.status = EnforcementStatus.PENDING
    doubtful.undo_snapshot = {
        **(doubtful.undo_snapshot or {}),
        enforcement.OUTCOME_UNKNOWN: True,
        "enabled_before": True,
    }
    db.commit()
    assert applied(db, limit.id) == 1
    with pytest.raises(limits_service.LimitRestoreError, match="2 restrictions in force"):
        limits_service.delete_limit(
            db, limit=db.get(CreditLimit, limit.id), actor=ACTOR, client=client
        )


# ------------------------------------------------------------------ M3


def test_the_restrictions_page_treats_wildcards_literally(
    db: Session,
    connected,  # noqa: F811
    admin_client: TestClient,
) -> None:
    tenant = tenant_with_projects(4)
    client = connected(tenant)
    group_limit(db)
    evaluation.evaluate_all(db, client=client, actor=ACTOR)
    page = "/api/notifications/enforcements/page"
    assert admin_client.get(page, params={"q": "many"}).json()["total"] == 4
    for wildcard in ("%", "_", "many_0", "\\", "many/0%"):
        body = admin_client.get(page, params={"q": wildcard}).json()
        assert body["total"] == 0, wildcard
        assert body["items"] == [] and body["by_kind"] == {}
    found = admin_client.get(page, params={"q": "many/0", "limit": 3, "offset": 2}).json()
    assert found["total"] == 4 and len(found["items"]) == 2
    assert found["by_kind"] == {"disable_auto_triage": 4}


# ------------------------------------------------------------------ M5


def test_the_pacing_settings_round_trip_through_a_backup(db: Session) -> None:
    changed = {
        settings_store.KEY_VERIFY_INTERVAL_MINUTES: 30,
        settings_store.KEY_MAX_VERIFICATIONS: 900,
        settings_store.KEY_MAX_WRITES: 400,
        settings_store.KEY_VIOLATION_PROJECTS: 70,
        settings_store.KEY_ATTRIBUTION_PROJECTS: 80,
        settings_store.KEY_ATTRIBUTION_REQUESTS: 300,
        settings_store.KEY_READ_CONCURRENCY: 2,
        settings_store.KEY_CYCLE_TIME_BUDGET_PCT: 60,
    }
    for key, value in changed.items():
        settings_store.set_value(db, key, value)
    db.commit()
    backup = ops_hardening.export_config_backup(db)
    assert {key: backup["settings"][key] for key in changed} == changed
    for key in changed:
        settings_store.set_value(db, key, settings_store.DEFAULTS[key])
    db.commit()
    ops_hardening.restore_config_backup(db, data=backup, actor=ACTOR)
    db.commit()
    assert {key: settings_store.get_value(db, key) for key in changed} == changed
