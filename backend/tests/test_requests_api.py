"""Credit request & approval workflow: endpoints, gating, and grant rollback."""

from __future__ import annotations

from datetime import timedelta

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models import AuditLogEntry, CreditLimit, CreditRequest
from app.models.enums import EntityType
from app.services import connection as connection_service
from app.services import ingestion, org_sync, requests_service
from app.services.audit import AuditActor
from tests.conftest import make_api_key
from tests.fake_tenant import FakeTenant, populated_tenant

ACTOR = AuditActor.system("test")


@pytest.fixture
def tenant(db: Session, monkeypatch: pytest.MonkeyPatch) -> FakeTenant:
    fake = populated_tenant()
    connection_service.save_connection(db, api_key=make_api_key(tenant="acme-corp"), actor=ACTOR)
    client = fake.client()
    org_sync.sync_org_model(db, client)
    ingestion.ingest_usage(db, client)
    db.commit()
    monkeypatch.setattr(connection_service, "get_client", lambda _session: fake.client())
    return fake


def _enable_self_service(admin_client: TestClient) -> None:
    response = admin_client.put("/api/settings", json={"self_service_requests": True})
    assert response.status_code == httpx.codes.OK, response.text
    assert response.json()["self_service_requests"] is True


class TestSelfServiceGating:
    def test_admin_may_always_file_a_request(
        self, admin_client: TestClient, tenant: FakeTenant
    ) -> None:
        response = admin_client.post(
            "/api/requests",
            json={"entity_type": "user", "entity_id": "user-harsh", "requested_limit": 500},
        )
        assert response.status_code == httpx.codes.CREATED, response.text
        body = response.json()
        assert body["status"] == "pending"
        assert body["entity_label"] == "Harsh Gokani"
        assert body["requested_by_name"] == "admin"

    def test_viewer_is_blocked_when_self_service_is_off(
        self, viewer_client: TestClient, tenant: FakeTenant
    ) -> None:
        response = viewer_client.post(
            "/api/requests",
            json={"entity_type": "user", "entity_id": "user-harsh", "requested_limit": 500},
        )
        assert response.status_code == httpx.codes.FORBIDDEN
        assert response.json()["detail"]["code"] == "self_service_disabled"

    def test_viewer_may_file_once_self_service_is_enabled(
        self,
        client: TestClient,
        admin_user,  # noqa: ANN001 - fixture
        viewer_user,  # noqa: ANN001 - fixture
        tenant: FakeTenant,
    ) -> None:
        from tests.conftest import ADMIN_PASSWORD, VIEWER_PASSWORD, login

        login(client, "admin", ADMIN_PASSWORD)
        _enable_self_service(client)
        client.post("/api/auth/logout")

        login(client, "viewer", VIEWER_PASSWORD)
        response = client.post(
            "/api/requests",
            json={"entity_type": "user", "entity_id": "user-harsh", "requested_limit": 500},
        )
        assert response.status_code == httpx.codes.CREATED, response.text
        assert response.json()["requested_by_name"] == "viewer"

    def test_me_reports_who_may_request(
        self,
        client: TestClient,
        admin_user,  # noqa: ANN001
        viewer_user,  # noqa: ANN001
        tenant: FakeTenant,
    ) -> None:
        from tests.conftest import ADMIN_PASSWORD, VIEWER_PASSWORD, login

        login(client, "admin", ADMIN_PASSWORD)
        assert client.get("/api/me").json()["can_request_credits"] is True

        client.post("/api/auth/logout")
        login(client, "viewer", VIEWER_PASSWORD)
        assert client.get("/api/me").json()["can_request_credits"] is False


class TestListVisibility:
    def test_a_viewer_sees_only_their_own_requests(
        self,
        client: TestClient,
        admin_user,  # noqa: ANN001
        viewer_user,  # noqa: ANN001
        tenant: FakeTenant,
    ) -> None:
        from tests.conftest import ADMIN_PASSWORD, VIEWER_PASSWORD, login

        login(client, "admin", ADMIN_PASSWORD)
        _enable_self_service(client)
        admin_client_resp = client.post(
            "/api/requests",
            json={"entity_type": "user", "entity_id": "user-harsh", "requested_limit": 100},
        )
        assert admin_client_resp.status_code == httpx.codes.CREATED
        client.post("/api/auth/logout")

        login(client, "viewer", VIEWER_PASSWORD)
        client.post(
            "/api/requests",
            json={"entity_type": "user", "entity_id": "user-akash", "requested_limit": 200},
        )
        mine = client.get("/api/requests").json()
        assert len(mine) == 1
        assert mine[0]["requested_by_name"] == "viewer"

        client.post("/api/auth/logout")
        login(client, "admin", ADMIN_PASSWORD)
        everyone = client.get("/api/requests").json()
        assert len(everyone) == 2


class TestApproval:
    def test_approving_creates_a_monitor_only_limit_when_none_exists(
        self, admin_client: TestClient, tenant: FakeTenant, db: Session
    ) -> None:
        created = admin_client.post(
            "/api/requests",
            json={"entity_type": "user", "entity_id": "user-harsh", "requested_limit": 500},
        ).json()

        response = admin_client.post(f"/api/requests/{created['id']}/approve", json={})
        assert response.status_code == httpx.codes.OK, response.text
        body = response.json()
        assert body["status"] == "approved"
        assert body["approved_limit"] == 500
        assert body["previous_limit"] is None
        assert body["decided_by_name"] == "admin"

        limit = db.scalar(
            select(CreditLimit).where(
                CreditLimit.entity_type == "user", CreditLimit.entity_id == "user-harsh"
            )
        )
        assert limit is not None
        assert limit.credit_limit == 500
        # A grant never silently turns on enforcement.
        assert limit.enforce is False

    def test_partial_approval_grants_less_and_records_previous(
        self, admin_client: TestClient, tenant: FakeTenant, db: Session
    ) -> None:
        # Seed an existing limit, then request more and approve part of it.
        admin_client.post(
            "/api/limits",
            json={"entity_type": "user", "entity_id": "user-harsh", "credit_limit": 100},
        )
        created = admin_client.post(
            "/api/requests",
            json={"entity_type": "user", "entity_id": "user-harsh", "requested_limit": 1000},
        ).json()

        response = admin_client.post(
            f"/api/requests/{created['id']}/approve", json={"approved_limit": 300}
        )
        body = response.json()
        assert body["approved_limit"] == 300
        assert body["previous_limit"] == 100

        limit = db.scalar(select(CreditLimit).where(CreditLimit.entity_id == "user-harsh"))
        assert limit.credit_limit == 300

    def test_denying_records_the_reason(self, admin_client: TestClient, tenant: FakeTenant) -> None:
        created = admin_client.post(
            "/api/requests",
            json={"entity_type": "user", "entity_id": "user-harsh", "requested_limit": 500},
        ).json()
        response = admin_client.post(
            f"/api/requests/{created['id']}/deny", json={"note": "Budget is frozen this quarter."}
        )
        assert response.status_code == httpx.codes.OK
        body = response.json()
        assert body["status"] == "denied"
        assert body["decision_note"] == "Budget is frozen this quarter."

    def test_a_decided_request_cannot_be_decided_again(
        self, admin_client: TestClient, tenant: FakeTenant
    ) -> None:
        created = admin_client.post(
            "/api/requests",
            json={"entity_type": "user", "entity_id": "user-harsh", "requested_limit": 500},
        ).json()
        admin_client.post(f"/api/requests/{created['id']}/approve", json={})
        again = admin_client.post(f"/api/requests/{created['id']}/deny", json={})
        assert again.status_code == httpx.codes.CONFLICT
        assert again.json()["detail"]["code"] == "not_pending"

    def test_approving_with_a_past_expiry_is_a_validation_error_not_a_conflict(
        self, admin_client: TestClient, tenant: FakeTenant
    ) -> None:
        created = admin_client.post(
            "/api/requests",
            json={"entity_type": "user", "entity_id": "user-harsh", "requested_limit": 500},
        ).json()
        response = admin_client.post(
            f"/api/requests/{created['id']}/approve",
            json={"expires_at": "2000-01-01T00:00:00+00:00"},
        )
        assert response.status_code == httpx.codes.BAD_REQUEST
        assert response.json()["detail"]["code"] == "invalid_decision"

    def test_a_viewer_cannot_approve(
        self,
        client: TestClient,
        admin_user,  # noqa: ANN001
        viewer_user,  # noqa: ANN001
        tenant: FakeTenant,
    ) -> None:
        from tests.conftest import ADMIN_PASSWORD, VIEWER_PASSWORD, login

        login(client, "admin", ADMIN_PASSWORD)
        created = client.post(
            "/api/requests",
            json={"entity_type": "user", "entity_id": "user-harsh", "requested_limit": 500},
        ).json()
        client.post("/api/auth/logout")

        login(client, "viewer", VIEWER_PASSWORD)
        response = client.post(f"/api/requests/{created['id']}/approve", json={})
        assert response.status_code == httpx.codes.FORBIDDEN


class TestTemporaryGrantRollback:
    def _make_approved_request(
        self, db: Session, *, previous: int | None, granted: int, expires_in_hours: int
    ) -> CreditRequest:
        if previous is not None:
            from app.services import limits_service

            limits_service.create_limit(
                db,
                data=limits_service.LimitInput(
                    entity_type=EntityType.USER,
                    entity_id="user-harsh",
                    credit_limit=previous,
                    period_type="monthly",
                ),
                actor=ACTOR,
            )
        request = requests_service.create_request(
            db,
            data=requests_service.RequestInput(
                entity_type=EntityType.USER, entity_id="user-harsh", requested_limit=granted
            ),
            actor=ACTOR,
        )
        requests_service.approve_request(
            db,
            request=request,
            actor=ACTOR,
            expires_at=utcnow() + timedelta(hours=expires_in_hours),
        )
        db.commit()
        return request

    def test_expired_grant_that_created_a_limit_is_removed(
        self, tenant: FakeTenant, db: Session
    ) -> None:
        request = self._make_approved_request(db, previous=None, granted=500, expires_in_hours=1)
        reverted = requests_service.revert_expired_grants(db, now=utcnow() + timedelta(hours=2))
        db.commit()
        assert reverted == 1
        assert db.scalar(select(CreditLimit).where(CreditLimit.entity_id == "user-harsh")) is None
        assert db.get(CreditRequest, request.id).reverted is True

    def test_expired_grant_restores_the_previous_budget(
        self, tenant: FakeTenant, db: Session
    ) -> None:
        self._make_approved_request(db, previous=100, granted=500, expires_in_hours=1)
        requests_service.revert_expired_grants(db, now=utcnow() + timedelta(hours=2))
        db.commit()
        limit = db.scalar(select(CreditLimit).where(CreditLimit.entity_id == "user-harsh"))
        assert limit is not None
        assert limit.credit_limit == 100

    def test_a_grant_changed_since_is_left_alone(self, tenant: FakeTenant, db: Session) -> None:
        from app.services import limits_service

        self._make_approved_request(db, previous=100, granted=500, expires_in_hours=1)
        # An admin changes the limit after the grant; the expiry must not undo it.
        limit = db.scalar(select(CreditLimit).where(CreditLimit.entity_id == "user-harsh"))
        limits_service.update_limit(db, limit=limit, changes={"credit_limit": 750}, actor=ACTOR)
        db.commit()

        reverted = requests_service.revert_expired_grants(db, now=utcnow() + timedelta(hours=2))
        db.commit()
        assert reverted == 0
        assert (
            db.scalar(select(CreditLimit).where(CreditLimit.entity_id == "user-harsh")).credit_limit
            == 750
        )

    def test_an_admin_re_setting_the_same_value_is_not_silently_undone(
        self, tenant: FakeTenant, db: Session
    ) -> None:
        # The grant sets 500; an admin later edits the budget to 500 again on
        # purpose. Because the stamp (not the value) decides ownership, the expiry
        # must NOT delete the deliberately re-set limit.
        from app.services import limits_service

        self._make_approved_request(db, previous=None, granted=500, expires_in_hours=1)
        limit = db.scalar(select(CreditLimit).where(CreditLimit.entity_id == "user-harsh"))
        limits_service.update_limit(db, limit=limit, changes={"credit_limit": 500}, actor=ACTOR)
        db.commit()

        reverted = requests_service.revert_expired_grants(db, now=utcnow() + timedelta(hours=2))
        db.commit()
        assert reverted == 0
        surviving = db.scalar(select(CreditLimit).where(CreditLimit.entity_id == "user-harsh"))
        assert surviving is not None and surviving.credit_limit == 500

    def test_overlapping_grants_chain_the_rollback_baseline(
        self, tenant: FakeTenant, db: Session
    ) -> None:
        # Grant A creates the limit (no prior budget); grant B supersedes it while
        # A is still live. When both have expired, the limit must roll all the way
        # back to "no limit", not stick at A's interim figure.
        first = self._make_approved_request(db, previous=None, granted=500, expires_in_hours=1)
        second = requests_service.create_request(
            db,
            data=requests_service.RequestInput(
                entity_type=EntityType.USER, entity_id="user-harsh", requested_limit=800
            ),
            actor=ACTOR,
        )
        requests_service.approve_request(
            db, request=second, actor=ACTOR, expires_at=utcnow() + timedelta(hours=2)
        )
        db.commit()

        # Approving B supersedes A straight away.
        assert db.get(CreditRequest, first.id).reverted is True
        assert db.get(CreditRequest, second.id).previous_limit is None

        requests_service.revert_expired_grants(db, now=utcnow() + timedelta(hours=3))
        db.commit()
        assert db.scalar(select(CreditLimit).where(CreditLimit.entity_id == "user-harsh")) is None

    def test_a_future_grant_is_not_touched(self, tenant: FakeTenant, db: Session) -> None:
        self._make_approved_request(db, previous=None, granted=500, expires_in_hours=10)
        reverted = requests_service.revert_expired_grants(db, now=utcnow() + timedelta(hours=1))
        db.commit()
        assert reverted == 0
        assert (
            db.scalar(select(CreditLimit).where(CreditLimit.entity_id == "user-harsh")).credit_limit
            == 500
        )

    def test_rollback_is_audited(self, tenant: FakeTenant, db: Session) -> None:
        self._make_approved_request(db, previous=None, granted=500, expires_in_hours=1)
        requests_service.revert_expired_grants(db, now=utcnow() + timedelta(hours=2))
        db.commit()
        actions = set(db.scalars(select(AuditLogEntry.action)))
        assert "credit_request.approved" in actions
        assert "credit_request.expired" in actions
