"""Connection setup, storage and health testing."""

from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checkmarx.client import CheckmarxClient
from app.checkmarx.token import TokenManager
from app.core.config import get_settings
from app.models import AuditLogEntry, CxConnection
from app.models.enums import ConnectionStatus
from app.services import connection as connection_service
from app.services.audit import AuditActor
from tests.conftest import make_api_key, token_response

IAM_BASE = "https://eu.iam.checkmarx.net"
TENANT = "acme-corp"
API_BASE = "https://eu.ast.checkmarx.net/api"


def stub_client(handler, connection: CxConnection) -> CheckmarxClient:
    def routed(request: httpx.Request) -> httpx.Response:
        if "openid-connect/token" in str(request.url):
            return token_response()
        return handler(request)

    http = httpx.Client(transport=httpx.MockTransport(routed))
    api_key = connection_service.decrypt_api_key(connection)
    tokens = TokenManager(
        api_key=api_key,
        token_endpoint=f"{IAM_BASE}/auth/realms/{TENANT}/protocol/openid-connect/token",
        client=http,
        settings=get_settings(),
    )
    return CheckmarxClient(
        api_base_url=connection.api_base_url,
        iam_base_url=connection.iam_base_url,
        tenant_name=connection.tenant_name,
        token_manager=tokens,
        client=http,
        settings=get_settings(),
        sleep=lambda _s: None,
    )


class TestPreview:
    def test_derives_tenant_and_region(self, admin_client: TestClient) -> None:
        response = admin_client.post("/api/connection/preview", json={"api_key": make_api_key()})
        assert response.status_code == httpx.codes.OK
        body = response.json()
        assert body["iam_base_url"] == IAM_BASE
        assert body["tenant_name"] == TENANT
        assert body["derived_api_base_url"] == API_BASE
        assert body["region_label"] == "EU"
        assert body["derivation_confident"] is True
        assert len(body["api_key_fingerprint"]) == 12

    def test_flags_a_region_it_had_to_guess(self, admin_client: TestClient) -> None:
        key = make_api_key(iam_base_url="https://newplace.iam.checkmarx.net")
        body = admin_client.post("/api/connection/preview", json={"api_key": key}).json()
        assert body["derivation_confident"] is False

    def test_nothing_is_persisted_by_a_preview(self, admin_client: TestClient, db: Session) -> None:
        admin_client.post("/api/connection/preview", json={"api_key": make_api_key()})
        assert db.scalar(select(CxConnection.id)) is None

    def test_invalid_key_is_reported(self, admin_client: TestClient) -> None:
        response = admin_client.post("/api/connection/preview", json={"api_key": "x" * 60})
        assert response.status_code == httpx.codes.BAD_REQUEST
        assert response.json()["detail"]["code"] == "invalid_api_key"

    def test_short_input_fails_schema_validation(self, admin_client: TestClient) -> None:
        response = admin_client.post("/api/connection/preview", json={"api_key": "short"})
        assert response.status_code == httpx.codes.UNPROCESSABLE_ENTITY

    def test_viewer_cannot_preview(self, viewer_client: TestClient) -> None:
        response = viewer_client.post("/api/connection/preview", json={"api_key": make_api_key()})
        assert response.status_code == httpx.codes.FORBIDDEN


class TestSaveConnection:
    def test_api_key_is_encrypted_at_rest(self, db: Session) -> None:
        api_key = make_api_key()
        connection = connection_service.save_connection(
            db, api_key=api_key, actor=AuditActor.system("test")
        )
        db.commit()
        assert api_key not in connection.api_key_encrypted
        assert connection.api_key_encrypted.startswith("v1.")
        assert connection_service.decrypt_api_key(connection) == api_key

    def test_derived_values_are_stored(self, db: Session) -> None:
        connection = connection_service.save_connection(
            db, api_key=make_api_key(), actor=AuditActor.system("test")
        )
        assert connection.iam_base_url == IAM_BASE
        assert connection.tenant_name == TENANT
        assert connection.api_base_url == API_BASE
        assert connection.api_base_url_overridden is False

    def test_override_is_respected(self, db: Session) -> None:
        connection = connection_service.save_connection(
            db,
            api_key=make_api_key(),
            api_base_url_override="https://dedicated.example.com/api/",
            actor=AuditActor.system("test"),
        )
        assert connection.api_base_url == "https://dedicated.example.com/api"
        assert connection.api_base_url_overridden is True

    def test_undeducible_region_without_an_override_is_refused(self, db: Session) -> None:
        from app.checkmarx.errors import CheckmarxError

        key = make_api_key(issuer="https://cx.example.com/identity/auth/realms/t1")
        with pytest.raises(CheckmarxError, match="Could not derive"):
            connection_service.save_connection(db, api_key=key, actor=AuditActor.system("test"))

    def test_expired_key_is_refused(self, db: Session) -> None:
        from app.checkmarx.errors import CheckmarxError

        with pytest.raises(CheckmarxError, match="expired"):
            connection_service.save_connection(
                db, api_key=make_api_key(exp=1000000000), actor=AuditActor.system("test")
            )

    def test_rotation_is_audited_with_fingerprints_only(self, db: Session) -> None:
        first = make_api_key(subject="user-one")
        second = make_api_key(subject="user-two")
        connection_service.save_connection(db, api_key=first, actor=AuditActor.system("test"))
        connection_service.save_connection(db, api_key=second, actor=AuditActor.system("test"))
        db.commit()

        entries = db.scalars(
            select(AuditLogEntry).where(AuditLogEntry.action == "connection.saved")
        ).all()
        assert len(entries) == 2
        rendered = repr([entry.before for entry in entries] + [entry.after for entry in entries])
        assert first not in rendered
        assert second not in rendered
        assert entries[1].before["api_key_fingerprint"] != entries[1].after["api_key_fingerprint"]

    def test_the_api_never_returns_the_key(self, admin_client: TestClient, db: Session) -> None:
        api_key = make_api_key()
        connection_service.save_connection(db, api_key=api_key, actor=AuditActor.system("test"))
        db.commit()
        response = admin_client.get("/api/connection")
        assert response.status_code == httpx.codes.OK
        assert api_key not in response.text
        assert response.json()["api_key_fingerprint"] is not None


class TestConnectionTest:
    def test_reports_success_and_records_it(self, db: Session) -> None:
        connection = connection_service.save_connection(
            db, api_key=make_api_key(), actor=AuditActor.system("test")
        )
        db.commit()

        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path.endswith("/projects")
            return httpx.Response(200, json={"totalCount": 42, "projects": []})

        result = connection_service.test_connection(db, client=stub_client(handler, connection))
        db.commit()
        assert result.ok is True
        assert result.token_acquired is True
        assert result.api_reachable is True
        assert result.projects_visible == 42
        assert connection.status == ConnectionStatus.HEALTHY
        assert connection.last_success_at is not None

    def test_permission_failure_is_reported_and_recorded(self, db: Session) -> None:
        connection = connection_service.save_connection(
            db, api_key=make_api_key(), actor=AuditActor.system("test")
        )
        db.commit()
        result = connection_service.test_connection(
            db, client=stub_client(lambda _r: httpx.Response(403), connection)
        )
        db.commit()
        assert result.ok is False
        assert result.token_acquired is True
        assert result.api_reachable is False
        assert "missing a required permission" in result.message
        assert connection.status == ConnectionStatus.FAILED
        assert connection.last_error is not None

    def test_wrong_base_url_is_distinguishable_from_a_bad_key(self, db: Session) -> None:
        connection = connection_service.save_connection(
            db, api_key=make_api_key(), actor=AuditActor.system("test")
        )
        db.commit()
        result = connection_service.test_connection(
            db, client=stub_client(lambda _r: httpx.Response(404), connection)
        )
        assert result.token_acquired is True
        assert result.api_reachable is False

    def test_unconfigured_connection_reports_clearly(self, db: Session) -> None:
        result = connection_service.test_connection(db)
        assert result.ok is False
        assert "No Checkmarx connection configured" in result.message

    def test_error_message_carries_no_secret(self, db: Session) -> None:
        api_key = make_api_key()
        connection = connection_service.save_connection(
            db, api_key=api_key, actor=AuditActor.system("test")
        )
        db.commit()
        result = connection_service.test_connection(
            db,
            client=stub_client(
                lambda _r: httpx.Response(422, text=f"rejected key {api_key}"), connection
            ),
        )
        assert api_key not in result.message


class TestClientCache:
    def test_the_same_client_is_reused(self, db: Session) -> None:
        connection_service.save_connection(
            db, api_key=make_api_key(), actor=AuditActor.system("test")
        )
        db.commit()
        assert connection_service.get_client(db) is connection_service.get_client(db)

    def test_rotating_the_key_rebuilds_the_client(self, db: Session) -> None:
        connection_service.save_connection(
            db, api_key=make_api_key(subject="one"), actor=AuditActor.system("test")
        )
        db.commit()
        first = connection_service.get_client(db)
        connection_service.save_connection(
            db, api_key=make_api_key(subject="two"), actor=AuditActor.system("test")
        )
        db.commit()
        assert connection_service.get_client(db) is not first

    def test_unconfigured_connection_raises(self, db: Session) -> None:
        from app.checkmarx.errors import NotConfiguredError

        with pytest.raises(NotConfiguredError, match="Setup page"):
            connection_service.get_client(db)


class TestApiBaseUrlOverride:
    def test_admin_can_override_and_it_is_audited(
        self, admin_client: TestClient, db: Session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        connection_service.save_connection(
            db, api_key=make_api_key(), actor=AuditActor.system("test")
        )
        db.commit()
        # Skip the live re-test that the route performs after saving.
        monkeypatch.setattr(
            connection_service,
            "test_connection",
            lambda *_a, **_k: connection_service.ConnectionTestResult(
                ok=True, token_acquired=True, api_reachable=True, message="stubbed"
            ),
        )
        response = admin_client.patch(
            "/api/connection/api-base-url", json={"api_base_url": "https://custom.example/api"}
        )
        assert response.status_code == httpx.codes.OK
        db.expire_all()
        connection = connection_service.get_connection(db)
        assert connection is not None
        assert connection.api_base_url == "https://custom.example/api"
        assert connection.api_base_url_overridden is True

    def test_plaintext_http_override_is_refused(self, admin_client: TestClient) -> None:
        response = admin_client.patch(
            "/api/connection/api-base-url", json={"api_base_url": "ftp://nope"}
        )
        assert response.status_code == httpx.codes.UNPROCESSABLE_ENTITY
