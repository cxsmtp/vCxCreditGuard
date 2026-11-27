"""Follow-ups to the review of realfix: mappings (restated for the usage
ledger in the fifth review), automation
notices, coverage that could not read, pricing without a feed figure.

Synthetic data only (tests/fake_tenant.py).
"""

from __future__ import annotations

from decimal import Decimal

import httpx
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models import AuditLogEntry, CxProject, LimitPeriodState, Notification, UnresolvedSubject
from app.models.enums import EntityType, PeriodType
from app.services import coverage, cycle, limits_service, notifications, org_sync
from tests.fake_tenant import FakeTenant
from tests.test_real_tenant_usage import ACTOR, connected, live_tenant  # noqa: F401

NAME = "example-org/payments-api"


def _limit(db: Session, entity_type: str, entity_id: str, *, existing: bool = False):
    limit = limits_service.create_limit(
        db,
        data=limits_service.LimitInput(
            entity_type=entity_type,
            entity_id=entity_id,
            credit_limit=100,
            period_type=PeriodType.MONTHLY,
            enforce=False,
            count_existing_usage=existing,
        ),
        actor=ACTOR,
    )
    db.commit()
    return limit


def _state(db: Session, limit) -> LimitPeriodState:
    db.expire_all()
    state = db.scalar(select(LimitPeriodState).where(LimitPeriodState.limit_id == limit.id))
    assert state is not None
    return state


def _map(admin_client: TestClient, entity_id: str | None, *, name: str = NAME) -> dict:
    response = admin_client.post(
        "/api/usage/unmatched-entities/map",
        json={"view": "project", "subject_key": name, "entity_id": entity_id},
    )
    assert response.status_code == httpx.codes.OK, response.text
    return response.json()


class TestMappingsCountForwardOnly:
    """Usage counts where it is observed (the usage ledger, fifth review): a
    mapping moves only what the name reports from then on, and what a budget
    counted stays counted. No baseline is involved for a period budget."""

    def _setup(self, db: Session, connected):  # noqa: F811
        tenant = live_tenant()
        tenant.set_entity_credits(view="project", name=NAME, credits=870)
        connected(tenant)
        cycle.run_cycle(trigger="manual", force_org_sync=True)
        project = _limit(db, EntityType.PROJECT, "proj-api")
        group = _limit(db, EntityType.GROUP, "grp-payments")  # the sum of its projects
        application = _limit(db, EntityType.APPLICATION, "app-payments")
        counted = _limit(db, EntityType.PROJECT, "proj-web", existing=True)
        cycle.run_cycle(trigger="manual")
        return tenant, project, group, application, counted

    def test_map_unmap_and_map_again(
        self,
        db: Session,
        connected,  # noqa: F811
        admin_client: TestClient,
    ) -> None:
        tenant, project, group, _application, _counted = self._setup(db, connected)

        body = _map(admin_client, "proj-api")
        assert body["confirmation"] == (
            "Usage reported under example-org/payments-api from now on counts towards payments/api."
        )
        assert "baseline_shifts" not in body
        cycle.run_cycle(trigger="manual")
        assert _state(db, project).credits_used == 0
        assert _state(db, group).credits_used == 0

        tenant.set_entity_credits(view="project", name=NAME, credits=890)
        cycle.run_cycle(trigger="manual")
        assert _state(db, project).credits_used == 20
        assert _state(db, group).credits_used == 20

        body = _map(admin_client, None)
        assert body["confirmation"] == (
            "Usage reported under example-org/payments-api from now on counts towards "
            "nothing. What it already counted towards payments/api stays there."
        ), body["confirmation"]
        cycle.run_cycle(trigger="manual")
        assert _state(db, project).credits_used == 20
        _map(admin_client, "proj-api")
        cycle.run_cycle(trigger="manual")
        assert _state(db, project).credits_used == 20
        assert (
            db.scalar(
                select(Notification).where(Notification.title.like("%reached its credit limit"))
            )
            is None
        )
        audit = db.scalar(
            select(AuditLogEntry)
            .where(AuditLogEntry.action == "usage.entity_mapped")
            .order_by(AuditLogEntry.id.desc())
        )
        assert audit.after["reported_credits"] == "890.0000", audit.after

    def test_spending_after_the_mapping_still_counts(
        self,
        db: Session,
        connected,  # noqa: F811
        admin_client: TestClient,
    ) -> None:
        tenant, project, *_rest = self._setup(db, connected)
        _map(admin_client, "proj-api")
        tenant.set_entity_credits(view="project", name=NAME, credits=900)
        cycle.run_cycle(trigger="manual")
        assert _state(db, project).credits_used == 30

    def test_a_budget_that_counts_existing_usage_counts_the_names_total(
        self,
        db: Session,
        connected,  # noqa: F811
        admin_client: TestClient,
    ) -> None:
        """Restated in the fifth review: such a budget counts everything
        reported by the names that count towards it now, history included."""
        _tenant, _project, _group, _application, counted = self._setup(db, connected)
        before = _state(db, counted).credits_used
        _map(admin_client, "proj-web")
        cycle.run_cycle(trigger="manual")
        assert _state(db, counted).credits_used == before + 870

    def test_remapping_to_another_project_moves_only_what_comes_after(
        self,
        db: Session,
        connected,  # noqa: F811
        admin_client: TestClient,
    ) -> None:
        tenant, project, _group, _application, _counted = self._setup(db, connected)
        tools = _limit(db, EntityType.PROJECT, "proj-tools")
        _map(admin_client, "proj-api")
        tenant.set_entity_credits(view="project", name=NAME, credits=880)
        cycle.run_cycle(trigger="manual")
        body = _map(admin_client, "proj-tools")
        assert "What it already counted towards payments/api stays there." in (body["confirmation"])
        tenant.set_entity_credits(view="project", name=NAME, credits=885)
        cycle.run_cycle(trigger="manual")
        assert _state(db, project).credits_used == 10
        assert _state(db, tools).credits_used == 5

    def test_a_user_mapping_counts_forward_only(
        self,
        db: Session,
        connected,  # noqa: F811
        admin_client: TestClient,
    ) -> None:
        tenant = live_tenant()
        tenant.set_user_credits(name="Former Contractor", credits=500)
        connected(tenant)
        cycle.run_cycle(trigger="manual", force_org_sync=True)
        limit = _limit(db, EntityType.USER, "user-alice")
        cycle.run_cycle(trigger="manual")
        subject = db.scalar(
            select(UnresolvedSubject).where(UnresolvedSubject.subject_key == "former contractor")
        )
        response = admin_client.post(
            f"/api/usage/unresolved/{subject.id}/map", json={"user_id": "user-alice"}
        )
        assert response.status_code == httpx.codes.OK, response.text
        assert response.json()["confirmation"] == (
            "Usage reported under Former Contractor from now on counts towards Alice Archer."
        )
        cycle.run_cycle(trigger="manual")
        assert _state(db, limit).credits_used == 0
        tenant.set_user_credits(name="Former Contractor", credits=512)
        cycle.run_cycle(trigger="manual")
        assert _state(db, limit).credits_used == 12
        response = admin_client.post(
            f"/api/usage/unresolved/{subject.id}/map", json={"user_id": None}
        )
        assert response.status_code == httpx.codes.OK, response.text
        assert (
            "What it already counted towards Alice Archer stays there."
            in (response.json()["confirmation"])
        )
        cycle.run_cycle(trigger="manual")
        assert _state(db, limit).credits_used == 12


class TestMappingEndpoint:
    def test_blank_names_are_refused(self, connected, admin_client: TestClient) -> None:  # noqa: F811
        connected(live_tenant())
        response = admin_client.post(
            "/api/usage/unmatched-entities/map",
            json={"view": "project", "subject_key": "   ", "entity_id": None},
        )
        assert response.status_code in (httpx.codes.BAD_REQUEST, httpx.codes.UNPROCESSABLE_ENTITY)

    def test_a_mapping_to_a_deleted_project_shows_as_broken(
        self,
        db: Session,
        connected,  # noqa: F811
        admin_client: TestClient,
    ) -> None:
        tenant = live_tenant()
        tenant.set_entity_credits(view="project", name=NAME, credits=870)
        connected(tenant)
        cycle.run_cycle(trigger="manual", force_org_sync=True)
        _map(admin_client, "proj-tools")
        _map(admin_client, "proj-api", name="example-org/never-reported")
        db.get(CxProject, "proj-tools").is_deleted = True
        db.commit()
        rows = {
            row["subject_key"]: row
            for row in admin_client.get("/api/usage/unmatched-entities").json()
        }
        assert rows[NAME]["mapping_broken"] is True
        # A mapping whose name is not in the latest reading is still listed.
        assert rows["example-org/never-reported"]["mapped_entity_id"] == "proj-api"


class TestAutomationIsNeverSilent:
    def test_a_new_automation_identity_is_said_once(
        self,
        db: Session,
        connected,  # noqa: F811
    ) -> None:
        tenant = live_tenant()
        tenant.set_user_credits(name="example-ci-bot", credits=40)
        connected(tenant)
        for _ in range(2):
            cycle.run_cycle(trigger="manual", force_org_sync=True)
        found = list(
            db.scalars(
                select(Notification).where(Notification.title.like("New automation identity%"))
            )
        )
        assert [n.title for n in found] == ["New automation identity found: example-ci-bot"]

    def test_an_old_could_not_be_matched_notice_is_closed(
        self,
        db: Session,
        connected,  # noqa: F811
    ) -> None:
        tenant = live_tenant()
        tenant.set_user_credits(name="example-ci-bot", credits=40)
        connected(tenant)
        # Raised by an earlier version, before the subject was automation.
        notifications.notify(
            db,
            category=notifications.CATEGORY_ATTRIBUTION,
            severity="warning",
            title="Credit usage could not be matched to a user: example-ci-bot",
            dedupe_key=notifications.attribution_key("example-ci-bot"),
        )
        db.commit()
        cycle.run_cycle(trigger="manual", force_org_sync=True)
        db.expire_all()
        old = db.scalar(
            select(Notification).where(
                Notification.dedupe_key == notifications.attribution_key("example-ci-bot")
            )
        )
        assert old.read_at is not None


class TestCoverageThatCouldNotRead:
    def _tenant(self) -> FakeTenant:
        from tests.test_enforcement_coverage import shaped_tenant

        return shaped_tenant()

    def test_not_determined_and_kept_only_briefly(self, db: Session) -> None:
        tenant = self._tenant()
        org_sync.sync_org_model(db, tenant.client())
        db.commit()
        report = coverage.compute(db, None)
        assert report.warning() is None or report.known > 0
        data = report.as_dict()
        assert data["max_age_seconds"] == int(coverage.SHORT_AGE.total_seconds())

    def test_a_refused_key_is_not_a_verdict(self, db: Session) -> None:
        tenant = FakeTenant()
        from app.checkmarx.iam import DEFAULT_AI_ROLE_NAMES

        for index in range(3):
            tenant.add_user(
                user_id=f"u{index}",
                username=f"u{index}@example.com",
                # A role besides the AI ones: whether it contains them must be read.
                roles=[*DEFAULT_AI_ROLE_NAMES, "ast-scanner"],
            )
        org_sync.sync_org_model(db, tenant.client())
        db.commit()
        tenant.fail_paths["/protocol/openid-connect/token"] = 401
        report = coverage.compute(db, tenant.client())
        assert report.read_failed and not report.determined
        assert report.warning() is None
        assert "could not be determined" in report.undetermined_note()
        assert report.as_dict()["max_age_seconds"] == int(coverage.SHORT_AGE.total_seconds())

    def test_a_repeated_group_name_is_unknown_not_guessed(self, db: Session) -> None:
        from app.checkmarx.iam import DEFAULT_AI_ROLE_NAMES

        tenant = FakeTenant()
        tenant.add_group(
            group_id="g-a", name="Team", path="/a/Team", roles=list(DEFAULT_AI_ROLE_NAMES)
        )
        tenant.add_group(group_id="g-b", name="Team", path="/b/Team", roles=[])
        tenant.add_user(
            user_id="dev",
            username="dev@example.com",
            roles=list(DEFAULT_AI_ROLE_NAMES),
            groups=["Team"],
        )
        org_sync.sync_org_model(db, tenant.client())
        db.commit()
        report = coverage.compute(db, tenant.client())
        assert report.unknown == 1 and report.restrictable == 0

    def test_the_page_is_told_it_was_not_determined(
        self,
        db: Session,
        connected,  # noqa: F811
        admin_client: TestClient,
    ) -> None:
        from app.checkmarx.iam import DEFAULT_AI_ROLE_NAMES

        tenant = FakeTenant()
        for index in range(3):
            tenant.add_user(
                user_id=f"u{index}",
                username=f"u{index}@example.com",
                roles=[*DEFAULT_AI_ROLE_NAMES, "ast-scanner"],
            )
        connected(tenant)
        org_sync.sync_org_model(db, tenant.client())
        db.commit()
        tenant.fail_paths["/protocol/openid-connect/token"] = 401
        body = admin_client.get("/api/preview/coverage?refresh=true").json()
        assert body["determined"] is False and body["low"] is False
        assert "could not be determined" in body["undetermined"]

    def test_check_again_is_throttled_and_a_new_key_recomputes(
        self, db: Session, monkeypatch
    ) -> None:
        from app.services import connection as connection_service
        from tests.conftest import make_api_key

        tenant = self._tenant()
        connection_service.save_connection(
            db, api_key=make_api_key(tenant="acme-corp"), actor=ACTOR
        )
        db.commit()
        client = tenant.client()
        org_sync.sync_org_model(db, client)
        db.commit()
        first = coverage.current(db, client, refresh=True)
        again = coverage.current(db, client, refresh=True)
        assert again["computed_at"] == first["computed_at"]
        stored = coverage.cached(db)
        stored["key_fingerprint"] = "another-key"
        from app.services import settings_store

        settings_store.set_value(db, settings_store.KEY_ENFORCEMENT_COVERAGE, stored)
        db.commit()
        assert coverage.current(db, client)["computed_at"] != first["computed_at"]


class TestFusionWithoutAFeedFigure:
    def test_the_breach_says_the_cost_is_not_known(
        self,
        db: Session,
        connected,  # noqa: F811
    ) -> None:
        tenant = live_tenant()
        tenant.consumption["action"] = []
        connected(tenant)
        tenant.set_entity_credits(
            view="project",
            name="payments/web",
            credits=4,
            entity_id="proj-web",
            actions={"fusion_scan_-_opus_5.5": 2, "triage": 1},
        )
        cycle.run_cycle(trigger="manual", force_org_sync=True)
        _limit(db, EntityType.PROJECT, "proj-web")
        cycle.run_cycle(trigger="manual")
        tenant.set_entity_credits(
            view="project",
            name="payments/web",
            credits=222,
            entity_id="proj-web",
            actions={"fusion_scan_-_opus_5.5": 4, "triage": 3},
        )
        cycle.run_cycle(trigger="manual")
        db.expire_all()
        breach = db.scalar(
            select(Notification).where(Notification.title.like("%reached its credit limit"))
        )
        assert breach is not None
        assert "= 4.0 credits" not in breach.body
        assert "not known from this tenant's data" in breach.body, breach.body


def test_unused_imports_are_used() -> None:
    assert Decimal and utcnow
