"""The Checkmarx One webhook (app/services/cx_webhook.py, POST
/api/webhooks/checkmarx). Synthetic data only (example.com)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import scheduler
from app.models import AuditLogEntry
from app.services import cx_webhook, diagnostics, fastcheck, settings_store
from app.services.audit import AuditActor

URL = "/api/webhooks/checkmarx"
PAYLOAD = {
    "scanId": "11111111-2222-3333-4444-555555555555",
    "projectId": "proj-api",
    "projectName": "api",
    "initiator": "alice.archer@example.com",
    "branch": "main",
    "statusInfo": [{"name": "general", "status": "Completed", "details": ""}],
}


@pytest.fixture(autouse=True)
def fresh_memory(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[float]]:
    fastcheck.reset_memory()
    cx_webhook.reset_memory()
    woken: list[float] = []

    def wake(delay: float = 0.0) -> bool:
        woken.append(delay)
        return True

    monkeypatch.setattr(scheduler, "wake_fast_check", wake)
    yield woken
    fastcheck.reset_memory()
    cx_webhook.reset_memory()


def turn_on(db: Session) -> str:
    secret = cx_webhook.rotate_secret(db, actor=AuditActor.system("test"))
    settings_store.set_value(db, settings_store.KEY_CX_WEBHOOK_ENABLED, True)
    db.commit()
    return secret


def signed(secret: str, body: bytes, *, encoding: str = "base64") -> str:
    digest = hmac.new(secret.encode(), body, hashlib.sha256).digest()
    value = base64.b64encode(digest).decode() if encoding == "base64" else digest.hex()
    return f"sha256={value}"


def deliver(
    client: TestClient,
    secret: str | None,
    payload: dict | None = None,  # type: ignore[type-arg]
    *,
    event: str = "scan_completed_successfully",
    signature: str | None = None,
    body: bytes | None = None,
):  # type: ignore[no-untyped-def]
    raw = body if body is not None else json.dumps(payload or PAYLOAD).encode()
    headers = {"Content-Type": "application/json", cx_webhook.EVENT_HEADER: event}
    if signature is not None:
        headers[cx_webhook.SIGNATURE_HEADER] = signature
    elif secret is not None:
        headers[cx_webhook.SIGNATURE_HEADER] = signed(secret, raw)
    return client.post(URL, content=raw, headers=headers)


def test_off_by_default_is_404(client: TestClient, db: Session) -> None:
    assert deliver(client, "anything").status_code == 404
    # Switched on but without a secret: still 404.
    settings_store.set_value(db, settings_store.KEY_CX_WEBHOOK_ENABLED, True)
    db.commit()
    assert deliver(client, "anything").status_code == 404
    assert not fastcheck.pending()


def test_a_bad_or_missing_signature_is_refused(client: TestClient, db: Session) -> None:
    secret = turn_on(db)
    assert deliver(client, None).status_code == 401
    assert deliver(client, "not-the-secret").status_code == 401
    assert deliver(client, None, signature="sha256=").status_code == 401
    assert deliver(client, None, signature="sha256=" + "A" * 44).status_code == 401
    # Signed over another body.
    other = json.dumps({"scanId": "x"}).encode()
    assert deliver(client, None, signature=signed(secret, other)).status_code == 401
    assert not fastcheck.pending()
    db.expire_all()
    assert settings_store.get_value(db, settings_store.KEY_CX_WEBHOOK_STATUS) is None
    assert cx_webhook.describe(db)["last_rejected"]["result"].startswith("rejected")


def test_a_valid_scan_event_queues_one_fast_check(
    client: TestClient, db: Session, fresh_memory: list[float]
) -> None:
    secret = turn_on(db)
    response = deliver(client, secret)
    assert response.status_code == 202 and response.json() == {"queued": True}
    assert fastcheck.pending() and len(fresh_memory) == 1
    # Hex is accepted too (the documentation does not say which encoding).
    raw = json.dumps(PAYLOAD).encode()
    assert deliver(client, None, signature=signed(secret, raw, encoding="hex")).status_code == 202
    db.expire_all()
    status = settings_store.get_value(db, settings_store.KEY_CX_WEBHOOK_STATUS)
    assert status["hint"] == {
        "event": "scan_completed_successfully",
        "project_id": "proj-api",
        "scan_id": PAYLOAD["scanId"],
        "initiator": "alice.archer@example.com",
    }
    check = next(c for c in diagnostics.run_diagnostics(db).checks if c.key == "cx_webhook")
    assert check.status == diagnostics.OK and "Last delivery just now" in check.detail


def test_a_burst_coalesces_into_one_fast_check(
    client: TestClient, db: Session, fresh_memory: list[float], monkeypatch: pytest.MonkeyPatch
) -> None:
    secret = turn_on(db)
    for _ in range(10):
        assert deliver(client, secret).status_code == 202
    assert len(fresh_memory) == 1  # woken once
    ran: list[str] = []
    monkeypatch.setattr(
        fastcheck,
        "run_fast_check",
        lambda **kwargs: ran.append(kwargs["trigger"]) or fastcheck.FastCheckResult(),
    )
    fastcheck.run_scheduled()
    assert ran == ["webhook"] and not fastcheck.pending()


def test_a_failed_scan_also_queues_and_a_new_project_does_not(
    client: TestClient, db: Session
) -> None:
    secret = turn_on(db)
    response = deliver(client, secret, event="project_created")
    assert response.status_code == 202 and response.json() == {"queued": False}
    assert not fastcheck.pending()
    assert deliver(client, secret, event="scan_failed").json() == {"queued": True}


def test_an_oversized_body_is_refused(client: TestClient, db: Session) -> None:
    secret = turn_on(db)
    big = json.dumps({**PAYLOAD, "padding": "x" * (cx_webhook.MAX_BODY_BYTES + 1)}).encode()
    assert deliver(client, secret, body=big).status_code == 413
    assert not fastcheck.pending()


def test_the_rate_limit(client: TestClient, db: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cx_webhook, "MAX_PER_MINUTE", 3)
    secret = turn_on(db)
    codes = [deliver(client, secret).status_code for _ in range(5)]
    assert codes == [202, 202, 202, 429, 429]


def test_with_no_fast_check_running_nothing_is_queued(
    client: TestClient, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(scheduler, "wake_fast_check", lambda delay=0.0: False)
    secret = turn_on(db)
    response = deliver(client, secret)
    assert response.status_code == 202 and response.json() == {"queued": False}
    assert not fastcheck.pending()
    db.expire_all()
    status = settings_store.get_value(db, settings_store.KEY_CX_WEBHOOK_STATUS)
    assert status["result"] == "ignored: the fast check is not running"


def test_not_json_is_refused(client: TestClient, db: Session) -> None:
    secret = turn_on(db)
    assert deliver(client, secret, body=b"not json").status_code == 400


def test_the_secret_is_rotated_by_an_admin_and_audited(
    admin_client: TestClient, db: Session
) -> None:
    first = admin_client.post("/api/fastpath/webhook-secret")
    assert first.status_code == 200, first.text
    secret = first.json()["secret"]
    assert len(secret) >= 40 and first.json()["path"] == URL
    second = admin_client.post("/api/fastpath/webhook-secret").json()["secret"]
    assert second != secret
    db.expire_all()
    entries = db.scalars(
        select(AuditLogEntry).where(AuditLogEntry.action.like("webhook.secret_%"))
    ).all()
    assert [entry.action for entry in entries] == [
        "webhook.secret_created",
        "webhook.secret_rotated",
    ]
    for entry in entries:
        assert secret not in json.dumps([entry.detail, entry.before, entry.after])
        assert second not in json.dumps([entry.detail, entry.before, entry.after])
    # Turned on from the API: deliveries signed with the old secret are refused.
    turned = admin_client.put("/api/fastpath", json={"webhook_enabled": True})
    assert turned.status_code == 200 and turned.json()["webhook"]["enabled"] is True
    assert "secret" not in json.dumps(turned.json()["webhook"]).replace("secret_configured", "")
    admin_client.headers.pop("X-CSRF-Token", None)
    assert deliver(admin_client, secret).status_code == 401
    assert deliver(admin_client, second).status_code == 202


def test_a_viewer_cannot_rotate_or_change_it(viewer_client: TestClient) -> None:
    assert viewer_client.post("/api/fastpath/webhook-secret").status_code == 403
    assert viewer_client.put("/api/fastpath", json={"webhook_enabled": True}).status_code == 403
    assert viewer_client.get("/api/fastpath").status_code == 200


def test_fast_check_settings_from_the_api(admin_client: TestClient, db: Session) -> None:
    body = admin_client.get("/api/fastpath").json()["fast_check"]
    assert body["enabled"] is True and body["interval_seconds"] == 15
    assert body["requests_per_hour"] == 240
    assert (
        admin_client.put("/api/fastpath", json={"fast_check_interval_seconds": 5}).status_code
        == 422
    )
    changed = admin_client.put(
        "/api/fastpath", json={"fast_check_interval_seconds": 30, "fast_check_enabled": False}
    )
    assert changed.status_code == 200
    assert changed.json()["fast_check"] == {**changed.json()["fast_check"], "enabled": False}
    assert changed.json()["fast_check"]["interval_seconds"] == 30
    db.expire_all()
    audited = db.scalars(
        select(AuditLogEntry).where(AuditLogEntry.action == "settings.updated")
    ).all()
    assert audited and audited[-1].after == {"fast_check_enabled": False, "fast_check_seconds": 30}
