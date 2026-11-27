"""Unexpected exception text never reaches what users read (Checkmarx SAST,
Information_Exposure_Through_an_Error_Message).

An unexpected error is named by its class and the reader is pointed at the
server log, which has the detail; a Checkmarx One error, written to be read,
keeps its (redacted) message.
"""

from __future__ import annotations

import logging

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checkmarx import iam
from app.checkmarx.errors import CheckmarxResponseError
from app.db.session import session_scope
from app.models.audit import Notification
from app.models.enums import RunStatus
from app.models.usage import SchedulerRun
from app.services import connection as connection_service
from app.services import cycle, error_text, org_sync, role_sources
from app.services.audit import AuditActor
from tests.conftest import make_api_key
from tests.fake_tenant import FakeTenant, populated_tenant

SECRET_DETAIL = "SELECT password FROM utility_user WHERE id=1 /srv/cxcg/app.db"


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


def test_public_error_names_unexpected_errors_and_keeps_domain_ones() -> None:
    shown = error_text.public_error(RuntimeError(SECRET_DETAIL))
    assert shown == "An unexpected error occurred; see the server log (error type: RuntimeError)."
    domain = error_text.public_error(
        CheckmarxResponseError("Checkmarx answered 500 (Bearer abc.def.ghi)")
    )
    assert domain.startswith("Checkmarx answered 500")
    assert "abc.def.ghi" not in domain  # redacted like a log line


class TestRunHistory:
    def test_a_failed_step_is_named_not_quoted(
        self,
        configured_tenant: FakeTenant,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        def boom(*_args, **_kwargs):
            raise RuntimeError(SECRET_DETAIL)

        monkeypatch.setattr(org_sync, "sync_org_model", boom)
        with caplog.at_level(logging.ERROR):
            result = cycle.run_cycle(trigger="manual", force_org_sync=True)

        assert result.status == RunStatus.PARTIAL
        shown = "An unexpected error occurred; see the server log (error type: RuntimeError)."
        assert result.steps["org_sync"] == {"ok": False, "error": shown}
        with session_scope() as session:
            run = session.get(SchedulerRun, result.run_id)
            assert run.error is not None and SECRET_DETAIL not in run.error
            assert "RuntimeError" in run.error and "see the server log" in run.error
            assert SECRET_DETAIL not in str(run.stats)
            warning = session.scalar(
                select(Notification).where(Notification.title.like("%org_sync%"))
            )
            assert warning is not None and SECRET_DETAIL not in (warning.body or "")
        # The detail is in the server log.
        assert any(SECRET_DETAIL in (record.exc_text or "") for record in caplog.records)

    def test_a_cycle_that_fails_outright_is_named_not_quoted(
        self, configured_tenant: FakeTenant, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def boom(*_args, **_kwargs):
            raise ValueError(SECRET_DETAIL)

        monkeypatch.setattr(cycle, "_execute_steps", boom)
        result = cycle.run_cycle(trigger="manual")

        assert result.status == RunStatus.FAILED
        assert result.errors == [
            "An unexpected error occurred; see the server log (error type: ValueError)."
        ]
        with session_scope() as session:
            run = session.get(SchedulerRun, result.run_id)
            assert run.error == (
                "An unexpected error occurred; see the server log (error type: ValueError)."
            )

    def test_a_checkmarx_error_keeps_its_message(
        self, configured_tenant: FakeTenant, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def refused(*_args, **_kwargs):
            raise CheckmarxResponseError("Checkmarx One answered 502 for the group list")

        monkeypatch.setattr(org_sync, "sync_org_model", refused)
        result = cycle.run_cycle(trigger="manual", force_org_sync=True)
        assert result.steps["org_sync"]["error"] == (
            "Checkmarx One answered 502 for the group list"
        )


class TestRoleListing:
    @pytest.fixture(autouse=True)
    def _no_cache(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(role_sources, "_listing_cache", None)

    def test_an_unexpected_error_is_named_not_quoted(
        self,
        admin_client: TestClient,
        configured_tenant: FakeTenant,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def boom(*_args, **_kwargs):
            raise KeyError(SECRET_DETAIL)

        monkeypatch.setattr(iam, "fetch_client_roles", boom)
        body = admin_client.get("/api/settings/client-roles").json()
        assert body["available"] is False
        assert SECRET_DETAIL not in body["message"]
        assert body["message"] == (
            "The tenant's roles could not be read: An unexpected error occurred; "
            "see the server log (error type: KeyError)."
        )

    def test_a_checkmarx_error_is_still_explained(
        self,
        admin_client: TestClient,
        configured_tenant: FakeTenant,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def refused(*_args, **_kwargs):
            raise CheckmarxResponseError("Checkmarx One answered 500 for the roles")

        monkeypatch.setattr(iam, "fetch_client_roles", refused)
        body = admin_client.get("/api/settings/client-roles").json()
        assert body["available"] is False
        assert "answered 500 for the roles" in body["message"]
