"""In-app diagnostics health checks."""

from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.connection import CxConnection
from app.models.enums import ConnectionStatus
from app.services import connection as connection_service
from app.services import diagnostics, ingestion, org_sync, settings_store
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


def _check(report: diagnostics.Diagnostics, key: str) -> diagnostics.Check:
    return next(c for c in report.checks if c.key == key)


def test_no_connection_fails_the_connection_check(db: Session) -> None:
    report = diagnostics.run_diagnostics(db)
    assert _check(report, "connection").status == diagnostics.FAIL
    assert report.overall == diagnostics.FAIL


def test_a_healthy_tenant_reports_a_healthy_connection(tenant: FakeTenant, db: Session) -> None:
    # Mark the connection healthy as a successful cycle would.
    connection = db.scalar(select(CxConnection).limit(1))
    connection.status = ConnectionStatus.HEALTHY
    db.commit()
    report = diagnostics.run_diagnostics(db)
    assert _check(report, "connection").status == diagnostics.OK


def test_a_disabled_scheduler_warns(tenant: FakeTenant, db: Session) -> None:
    settings_store.set_value(db, settings_store.KEY_SCHEDULER_ENABLED, False)
    db.commit()
    report = diagnostics.run_diagnostics(db)
    assert _check(report, "scheduler").status == diagnostics.WARN


def test_unattributed_usage_warns(tenant: FakeTenant, db: Session) -> None:
    from app.db.base import utcnow
    from app.models.usage import UnresolvedSubject

    now = utcnow()
    db.add(
        UnresolvedSubject(
            subject_key="ghost@acme.com",
            subject_name="Ghost",
            credits_used=5,
            times_seen=1,
            first_seen_at=now,
            last_seen_at=now,
            mapped_user_id=None,
        )
    )
    db.commit()
    report = diagnostics.run_diagnostics(db)
    assert _check(report, "attribution").status == diagnostics.WARN


def test_the_endpoint_returns_a_report(admin_client: TestClient, tenant: FakeTenant) -> None:
    response = admin_client.get("/api/ops/diagnostics")
    assert response.status_code == httpx.codes.OK, response.text
    body = response.json()
    assert body["overall"] in {"ok", "warn", "fail"}
    assert {c["key"] for c in body["checks"]} >= {
        "connection",
        "scheduler",
        "usage",
        "attribution",
        "enforcement",
        "dimensions",
    }


def test_a_viewer_may_read_diagnostics(viewer_client: TestClient, tenant: FakeTenant) -> None:
    assert viewer_client.get("/api/ops/diagnostics").status_code == httpx.codes.OK


def test_raw_error_detail_is_withheld_from_non_admins(tenant: FakeTenant, db: Session) -> None:
    secret = "upstream 500 at https://internal.example/api traceback xyz"
    connection = db.scalar(select(CxConnection).limit(1))
    connection.status = ConnectionStatus.FAILED
    connection.last_error = secret
    db.commit()

    admin_view = diagnostics.run_diagnostics(db, include_detail=True)
    viewer_view = diagnostics.run_diagnostics(db, include_detail=False)

    assert secret in _check(admin_view, "connection").detail
    assert secret not in _check(viewer_view, "connection").detail
    # The viewer still learns the connection is failing, just not the raw text.
    assert _check(viewer_view, "connection").status == diagnostics.FAIL
