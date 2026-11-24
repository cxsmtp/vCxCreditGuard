"""Pacing for large tenants (app/services/pacing.py): fair rotation of the
policy violation and auto-triage work, verification in rotation, a large first
enforcement spread over several cycles, and paged lists.

Small synthetic tenants only; the full load test is scripts/loadtest.py.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models import CreditLimit, EnforcementAction, Notification
from app.models.enums import EnforcementStatus, EntityType, PeriodType
from app.models.limits import LimitPeriodState
from app.services import (
    auto_triage_attribution,
    enforcement,
    evaluation,
    ingestion,
    limits_service,
    org_sync,
    pacing,
    settings_store,
    violations,
)
from app.services import connection as connection_service
from app.services.audit import AuditActor
from tests.conftest import make_api_key
from tests.fake_tenant import FakeTenant, populated_tenant

ACTOR = AuditActor.system("test")
PERIOD = "2026-08"


def tenant_with_projects(count: int) -> FakeTenant:
    """The populated tenant plus ``count`` projects in one group, each spending."""
    tenant = populated_tenant()
    tenant.add_group(group_id="grp-many", name="Many")
    for index in range(count):
        project_id = f"proj-m{index:02d}"
        tenant.add_project(project_id=project_id, name=f"many/{index:02d}", group_ids=["grp-many"])
        tenant.set_entity_credits(
            view="project", name=f"many/{index:02d}", credits=5, entity_id=project_id
        )
    return tenant


@pytest.fixture
def connected(db: Session, monkeypatch: pytest.MonkeyPatch):
    def build(tenant: FakeTenant):
        connection_service.save_connection(
            db, api_key=make_api_key(tenant="acme-corp"), actor=ACTOR
        )
        db.commit()
        client = tenant.client()
        monkeypatch.setattr(connection_service, "get_client", lambda _session: client)
        org_sync.sync_org_model(db, client)
        ingestion.ingest_usage(db, client)
        db.commit()
        return client

    return build


def setting(db: Session, key: str, value) -> None:  # type: ignore[no-untyped-def]
    settings_store.set_value(db, key, value)
    db.commit()


def group_limit(db: Session, *, actions: list[str] | None = None) -> CreditLimit:
    limit = CreditLimit(
        entity_type=EntityType.GROUP,
        entity_id="grp-many",
        entity_label="Many",
        credit_limit=1,
        period_type=PeriodType.MONTHLY,
        enforce=True,
        count_existing_usage=True,
        project_actions=actions or ["auto_triage"],
    )
    db.add(limit)
    db.commit()
    return limit


def applied(db: Session, limit_id: int) -> int:
    return int(
        db.scalar(
            select(func.count()).where(
                EnforcementAction.limit_id == limit_id,
                EnforcementAction.status == EnforcementStatus.APPLIED,
            )
        )
        or 0
    )


def state_of(db: Session, limit_id: int) -> LimitPeriodState:
    db.expire_all()
    return db.scalars(
        select(LimitPeriodState)
        .where(LimitPeriodState.limit_id == limit_id)
        .order_by(LimitPeriodState.id.desc())
    ).first()


# ---------------------------------------------------------------- rollouts


class TestBatchedEnforcement:
    def test_a_large_first_enforcement_resumes_where_it_stopped(
        self, db: Session, connected
    ) -> None:
        tenant = tenant_with_projects(7)
        client = connected(tenant)
        setting(db, settings_store.KEY_MAX_WRITES, 3)
        limit = group_limit(db)

        first = evaluation.evaluate_all(db, client=client, actor=ACTOR)
        assert applied(db, limit.id) == 3
        state = state_of(db, limit.id)
        assert (state.rollout_done, state.rollout_total) == (3, 7)
        assert first.as_stats()["rollouts"] == [
            {"limit_id": limit.id, "limit": "Many", "done": 3, "total": 7, "noun": "projects"}
        ]
        assert first.pacing["writes"]["writes_deferred"] == 4
        # Said once, with the progress.
        [note] = db.scalars(
            select(Notification).where(Notification.title.like("Restricting Many%"))
        ).all()
        assert "3 of 7 projects" in note.title
        still_on = [pid for pid, state in tenant.auto_triage.items() if state["enabled"]]
        assert sum(1 for pid in still_on if pid.startswith("proj-m")) == 4

        evaluation.evaluate_all(db, client=client, actor=ACTOR)
        assert applied(db, limit.id) == 6
        evaluation.evaluate_all(db, client=client, actor=ACTOR)
        assert applied(db, limit.id) == 7
        state = state_of(db, limit.id)
        assert (state.rollout_done, state.rollout_total) == (7, 7)
        assert not any(tenant.auto_triage[f"proj-m{index:02d}"]["enabled"] for index in range(7))
        # Idempotent: one action per target, whatever the number of cycles.
        assert db.scalar(select(func.count()).select_from(EnforcementAction)) == 7

    def test_the_ceiling_judges_the_rollout_once(self, db: Session, connected) -> None:
        tenant = tenant_with_projects(6)
        client = connected(tenant)
        setting(db, settings_store.KEY_MAX_WRITES, 2)
        setting(db, settings_store.KEY_MAX_NEW_TARGETS, 3)
        limit = group_limit(db)

        tripped = evaluation.evaluate_all(db, client=client, actor=ACTOR)
        assert tripped.enforcement_paused and applied(db, limit.id) == 0

        # An admin looks and resumes: this batch is let through once ...
        setting(db, settings_store.KEY_ENFORCEMENT_PAUSED, False)
        setting(db, settings_store.KEY_CEILING_WAIVED_ONCE, True)
        evaluation.evaluate_all(db, client=client, actor=ACTOR)
        assert applied(db, limit.id) == 2
        # ... and its continuation is not "new" on the following cycles.
        for _ in range(2):
            result = evaluation.evaluate_all(db, client=client, actor=ACTOR)
            assert result.enforcement_paused is None
        assert applied(db, limit.id) == 6

        # Projects added to the group since are new, and judged again.
        for index in range(6, 12):
            tenant.add_project(
                project_id=f"proj-m{index:02d}", name=f"many/{index:02d}", group_ids=["grp-many"]
            )
        org_sync.sync_org_model(db, client)
        db.commit()
        again = evaluation.evaluate_all(db, client=client, actor=ACTOR)
        assert again.enforcement_paused is not None
        assert applied(db, limit.id) == 6

    def test_small_limits_are_not_held_up_by_a_large_rollout(
        self, db: Session, connected, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tenant = tenant_with_projects(8)
        client = connected(tenant)
        setting(db, settings_store.KEY_MAX_WRITES, 4)
        monkeypatch.setattr(evaluation, "LARGE_ROLLOUT_WRITES", 2)
        big = group_limit(db)  # the lower id: evaluated first
        user = CreditLimit(
            entity_type=EntityType.USER,
            entity_id="user-sean",
            entity_label="Sean",
            credit_limit=1,
            period_type=PeriodType.MONTHLY,
            enforce=True,
            count_existing_usage=True,
        )
        db.add(user)
        db.commit()

        result = evaluation.evaluate_all(db, client=client, actor=ACTOR)
        # The user's restriction went first; the rollout took what was left.
        assert applied(db, user.id) == 1
        assert applied(db, big.id) == 3
        assert result.rollouts == [
            {"limit_id": big.id, "limit": "Many", "done": 3, "total": 8, "noun": "projects"}
        ]
        assert db.scalar(
            select(Notification).where(Notification.title.like("Restricting Many%3 of 8%"))
        )

    def test_restores_of_a_large_set_are_batched_too(self, db: Session, connected) -> None:
        tenant = tenant_with_projects(5)
        client = connected(tenant)
        limit = group_limit(db)
        evaluation.evaluate_all(db, client=client, actor=ACTOR)
        assert applied(db, limit.id) == 5

        setting(db, settings_store.KEY_MAX_WRITES, 2)
        limit = db.get(CreditLimit, limit.id)
        limit.credit_limit = 1_000_000  # within budget again
        db.commit()
        evaluation.evaluate_all(db, client=client, actor=ACTOR)
        assert applied(db, limit.id) == 3
        evaluation.evaluate_all(db, client=client, actor=ACTOR)
        evaluation.evaluate_all(db, client=client, actor=ACTOR)
        assert applied(db, limit.id) == 0
        assert all(tenant.auto_triage[f"proj-m{index:02d}"]["enabled"] for index in range(5))

    def test_without_a_write_budget_nothing_changes(self, db: Session, connected) -> None:
        tenant = tenant_with_projects(7)
        client = connected(tenant)
        setting(db, settings_store.KEY_MAX_WRITES, 0)
        limit = group_limit(db)
        evaluation.evaluate_all(db, client=client, actor=ACTOR)
        assert applied(db, limit.id) == 7
        assert state_of(db, limit.id).rollout_total is None


# ------------------------------------------------------------ verification


class TestVerificationRotation:
    def test_restrictions_in_force_are_read_back_in_rotation(self, db: Session, connected) -> None:
        tenant = tenant_with_projects(8)
        client = connected(tenant)
        setting(db, settings_store.KEY_SCHEDULE_INTERVAL_MINUTES, 15)
        setting(db, settings_store.KEY_VERIFY_INTERVAL_MINUTES, 60)
        limit = group_limit(db)
        evaluation.evaluate_all(db, client=client, actor=ACTOR)
        assert applied(db, limit.id) == 8

        def reads() -> int:
            return sum(
                1
                for method, path in tenant.requests
                if method == "GET" and "/ai-agents-coordinator/projects/proj-m" in path
            )

        # Just applied (and read back then): spread evenly, a quarter per
        # 15-minute cycle, so each is read back within the hour.
        now = utcnow()
        seen: list[int] = []
        for cycle_number in range(4):
            tenant.requests.clear()
            result = evaluation.evaluate_all(
                db, client=client, actor=ACTOR, now=now + timedelta(minutes=15 * cycle_number)
            )
            seen.append(reads())
            assert result.pacing["verification"]["selected"] == 2
        assert seen == [2, 2, 2, 2]
        db.expire_all()
        verified = db.scalars(
            select(EnforcementAction.last_verified_at).where(EnforcementAction.limit_id == limit.id)
        ).all()
        assert all(moment is not None and moment >= now for moment in verified)

    def test_overdue_ones_go_first_and_the_cap_holds(self, db: Session, connected) -> None:
        tenant = tenant_with_projects(6)
        client = connected(tenant)
        limit = group_limit(db)
        evaluation.evaluate_all(db, client=client, actor=ACTOR)
        old = utcnow() - timedelta(days=1)
        oldest = db.scalars(
            select(EnforcementAction.id).where(EnforcementAction.limit_id == limit.id).limit(2)
        ).all()
        db.execute(
            update(EnforcementAction)
            .where(EnforcementAction.id.in_(oldest))
            .values(last_verified_at=old)
        )
        db.execute(
            update(EnforcementAction)
            .where(EnforcementAction.id.in_(oldest[1:]))
            .values(last_verified_at=None)
        )
        db.commit()
        setting(db, settings_store.KEY_MAX_VERIFICATIONS, 2)

        result = evaluation.evaluate_all(db, client=client, actor=ACTOR)
        stats = result.pacing["verification"]
        assert stats["due"] == 2 and stats["selected"] == 2 and stats["verified"] == 2
        assert stats["never_verified"] == 1
        db.expire_all()
        refreshed = {
            row.id: row.last_verified_at
            for row in db.scalars(select(EnforcementAction).where(EnforcementAction.id.in_(oldest)))
        }
        assert all(moment is not None and moment > old for moment in refreshed.values())

    def test_drift_is_still_found_and_fixed(self, db: Session, connected) -> None:
        tenant = tenant_with_projects(3)
        client = connected(tenant)
        setting(db, settings_store.KEY_VERIFY_INTERVAL_MINUTES, 60)
        limit = group_limit(db)
        evaluation.evaluate_all(db, client=client, actor=ACTOR)
        tenant.auto_triage["proj-m01"]["enabled"] = True
        # Within the hour, every restriction is read back once.
        now = utcnow()
        for step in range(1, 5):
            evaluation.evaluate_all(
                db, client=client, actor=ACTOR, now=now + timedelta(minutes=15 * step)
            )
        assert tenant.auto_triage["proj-m01"]["enabled"] is False
        assert applied(db, limit.id) == 3

    def test_an_admin_change_has_them_verified_first(self, db: Session, connected) -> None:
        tenant = tenant_with_projects(3)
        client = connected(tenant)
        limit = group_limit(db)
        evaluation.evaluate_all(db, client=client, actor=ACTOR)
        limits_service.update_limit(
            db,
            limit=db.get(CreditLimit, limit.id),
            changes={"notes": "checked"},
            actor=ACTOR,
            client=client,
        )
        db.commit()
        db.expire_all()
        assert db.scalars(
            select(EnforcementAction.last_verified_at).where(EnforcementAction.limit_id == limit.id)
        ).all() == [None, None, None]

    def test_interval_zero_verifies_every_one_every_cycle(self, db: Session, connected) -> None:
        tenant = tenant_with_projects(4)
        client = connected(tenant)
        setting(db, settings_store.KEY_VERIFY_INTERVAL_MINUTES, 0)
        group_limit(db)
        evaluation.evaluate_all(db, client=client, actor=ACTOR)
        tenant.requests.clear()
        evaluation.evaluate_all(db, client=client, actor=ACTOR)
        reads = [
            path
            for method, path in tenant.requests
            if method == "GET" and "/ai-agents-coordinator/projects/proj-m" in path
        ]
        assert len(reads) == 4

    def test_coverage_is_stated(self) -> None:
        config = pacing.Pacing(
            verify_interval_minutes=60,
            max_verifications_per_cycle=500,
            max_writes_per_cycle=500,
            violation_projects_per_cycle=150,
            attribution_projects_per_cycle=150,
            attribution_requests_per_cycle=600,
            read_concurrency=4,
            time_budget_pct=80,
            interval_minutes=15,
        )
        assert config.verifications_per_cycle(1000, 0) == 250
        assert config.coverage_minutes(1000) == 60
        # More in force than the cap reaches in an hour: the bound says so.
        assert config.coverage_minutes(4000) == 120


# --------------------------------------------------------------- rotation


class TestViolationRotation:
    def test_every_watched_project_is_listed_within_the_stated_cycles(
        self, db: Session, connected
    ) -> None:
        tenant = tenant_with_projects(7)
        client = connected(tenant)
        limit = group_limit(db, actions=["fusion"])
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()
        setting(db, settings_store.KEY_VIOLATION_PROJECTS, 3)

        listed: list[list[str]] = []
        for _ in range(3):
            tenant.scan_queries.clear()
            result = violations.detect(db, client)
            assert result.watched == 7 and result.each_checked_every_cycles == 3
            listed.append(sorted(query["project-id"][0] for query in tenant.scan_queries))
        assert [len(batch) for batch in listed] == [3, 3, 3]
        # The first two cycles cover six different projects, the third reaches
        # the seventh: none waits for ever, whatever its place in the list.
        assert len(set(listed[0]) | set(listed[1])) == 6
        everyone = {f"proj-m{index:02d}" for index in range(7)}
        assert set(listed[0]) | set(listed[1]) | set(listed[2]) == everyone
        cursors = settings_store.get_value(db, settings_store.KEY_VIOLATION_SCAN_CURSORS)
        assert all(cursors[pid].get("checked") for pid in everyone)

    def test_no_cap_lists_everything(self, db: Session, connected) -> None:
        tenant = tenant_with_projects(4)
        client = connected(tenant)
        limit = group_limit(db, actions=["fusion"])
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()
        setting(db, settings_store.KEY_VIOLATION_PROJECTS, 0)
        tenant.scan_queries.clear()
        result = violations.detect(db, client)
        assert result.projects_checked == 4 and result.skipped_projects == 0


class TestAttributionFairness:
    def test_the_longest_waiting_go_first_increases_and_histories_alike(
        self, db: Session, connected, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tenant = populated_tenant()
        client = connected(tenant)
        setting(db, settings_store.KEY_AUTO_TRIAGE_TO_INITIATOR, True)
        setting(db, settings_store.KEY_ATTRIBUTION_PROJECTS, 2)
        base = datetime(2026, 11, 1, tzinfo=UTC)

        def increase(project_id: str, hours: int):  # type: ignore[no-untyped-def]
            moment = base + timedelta(hours=hours)
            return auto_triage_attribution._Increase(
                project_id=project_id,
                delta_transactions=1,
                delta=auto_triage_attribution.ZERO,
                transactions_after=1,
                credits_after=auto_triage_attribution.ZERO,
                window_start=moment,
                window_end=moment,
                snapshot_id=1,
                widen_floor=moment,
                lookback_start=moment,
            )

        def history(project_id: str, hours: int):  # type: ignore[no-untyped-def]
            moment = base + timedelta(hours=hours)
            return auto_triage_attribution._History(
                project_id=project_id, since=moment, until=moment
            )

        waiting = [
            increase("p-new", 5),
            increase("p-old", 1),
            history("h-older", 0),
            history("h-newest", 9),
        ]
        done: list[str] = []
        monkeypatch.setattr(
            auto_triage_attribution,
            "_plan",
            lambda *_a, **_k: (
                [t for t in waiting if isinstance(t, auto_triage_attribution._Increase)],
                [t for t in waiting if isinstance(t, auto_triage_attribution._History)],
            ),
        )

        def observe(_session, _client, task, budget, _result):  # type: ignore[no-untyped-def]
            done.append(task.project_id)
            waiting.remove(task)

        monkeypatch.setattr(auto_triage_attribution, "_observe", observe)
        monkeypatch.setattr(
            auto_triage_attribution,
            "_collect_history",
            lambda _s, _c, task, _w, budget, _r: observe(_s, _c, task, budget, _r),
        )
        first = auto_triage_attribution.collect(db, client)
        assert done == ["h-older", "p-old"]
        assert first.backlog == 2 and first.each_within_cycles == 2
        assert first.oldest_waiting_minutes is not None
        auto_triage_attribution.collect(db, client)
        assert done == ["h-older", "p-old", "p-new", "h-newest"]


# ------------------------------------------------------------------ the API


class TestLargeLists:
    def test_restrictions_are_paged_and_searchable(
        self, db: Session, connected, admin_client: TestClient
    ) -> None:
        tenant = tenant_with_projects(12)
        client = connected(tenant)
        group_limit(db)
        evaluation.evaluate_all(db, client=client, actor=ACTOR)

        page = admin_client.get("/api/notifications/enforcements/page", params={"limit": 5})
        assert page.status_code == 200
        body = page.json()
        assert body["total"] == 12 and len(body["items"]) == 5
        assert body["by_kind"] == {"disable_auto_triage": 12}
        rest = admin_client.get(
            "/api/notifications/enforcements/page", params={"limit": 5, "offset": 10}
        ).json()
        assert len(rest["items"]) == 2
        first_ids = {item["id"] for item in body["items"]}
        assert not first_ids & {item["id"] for item in rest["items"]}

        found = admin_client.get(
            "/api/notifications/enforcements/page", params={"q": "many/07"}
        ).json()
        assert found["total"] == 1 and found["items"][0]["target_id"] == "proj-m07"

    def test_blast_radius_summarises_its_targets(
        self, db: Session, connected, admin_client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.api.routes import preview

        tenant = tenant_with_projects(12)
        connected(tenant)
        monkeypatch.setattr(preview, "MAX_TARGETS_SHOWN", 5)
        response = admin_client.get(
            "/api/preview/blast-radius",
            params={"entity_type": "group", "entity_id": "grp-many", "project_actions": "fusion"},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["affected_projects"] == 12 and body["disable_fusion"] == 12
        assert body["targets_total"] == 12 and body["targets_truncated"] is True
        assert len(body["targets"]) == 5

    def test_a_limit_with_many_restrictions_is_switched_off_before_it_is_deleted(
        self, db: Session, connected, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tenant = tenant_with_projects(4)
        client = connected(tenant)
        monkeypatch.setattr(limits_service, "API_RESTORE_BATCH", 2)
        limit = group_limit(db)
        evaluation.evaluate_all(db, client=client, actor=ACTOR)
        with pytest.raises(limits_service.LimitRestoreError, match="4 restrictions in force"):
            limits_service.delete_limit(
                db, limit=db.get(CreditLimit, limit.id), actor=ACTOR, client=client
            )
        # Switched off: two now, the rest by the cycle.
        limits_service.update_limit(
            db,
            limit=db.get(CreditLimit, limit.id),
            changes={"enforce": False},
            actor=ACTOR,
            client=client,
        )
        db.commit()
        assert applied(db, limit.id) == 2
        evaluation.evaluate_all(db, client=client, actor=ACTOR)
        assert applied(db, limit.id) == 0

    def test_the_budgets_list_shows_a_rollouts_progress(
        self, db: Session, connected, admin_client: TestClient
    ) -> None:
        tenant = tenant_with_projects(5)
        client = connected(tenant)
        setting(db, settings_store.KEY_MAX_WRITES, 2)
        limit = group_limit(db)
        evaluation.evaluate_all(db, client=client, actor=ACTOR)

        [row] = [r for r in admin_client.get("/api/limits").json() if r["id"] == limit.id]
        assert row["active_restrictions"] == 2
        period = row["current_period"]
        assert (period["rollout_done"], period["rollout_total"]) == (2, 5)
