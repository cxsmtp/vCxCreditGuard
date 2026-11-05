"""Ops hardening: attestation, scheduler watchdog, and config backup/restore."""

from __future__ import annotations

from datetime import timedelta

import httpx
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import __version__
from app.db.base import utcnow
from app.models.enums import EntityType, PeriodType, RunStatus
from app.models.limits import CreditLimit, Exemption
from app.models.usage import SchedulerRun
from app.services import limits_service, ops_hardening, settings_store
from app.services.audit import AuditActor

ACTOR = AuditActor.system("test")


def _limit(db: Session, *, entity_id: str, credit_limit: int, **kw) -> CreditLimit:
    return limits_service.create_limit(
        db,
        data=limits_service.LimitInput(
            entity_type=EntityType.USER,
            entity_id=entity_id,
            credit_limit=credit_limit,
            period_type=PeriodType.MONTHLY,
            **kw,
        ),
        actor=ACTOR,
    )


class TestAttestation:
    def test_reports_version_head_and_a_stable_digest(self, db: Session) -> None:
        att = ops_hardening.attestation(db)
        assert att.version == __version__
        # migration_head is read from alembic_version; the unit-test DB is built
        # with create_all (no alembic row), so it is None here and a string in a
        # migrated deployment.
        assert att.migration_head is None or isinstance(att.migration_head, str)
        # The digest is deterministic for an unchanged configuration surface.
        assert att.config_digest == ops_hardening.attestation(db).config_digest

    def test_digest_changes_when_a_setting_changes(self, db: Session) -> None:
        before = ops_hardening.attestation(db).config_digest
        settings_store.set_value(db, settings_store.KEY_CREDIT_UNIT_COST, 1.23)
        db.flush()
        assert ops_hardening.attestation(db).config_digest != before

    def test_update_status_tracks_a_recorded_latest_version(self, db: Session) -> None:
        assert ops_hardening.update_status(db)["update_available"] is False
        ops_hardening.set_latest_version(db, version="99.0.0", actor=ACTOR)
        db.flush()
        status_ = ops_hardening.update_status(db)
        assert status_["latest"] == "99.0.0" and status_["update_available"] is True
        # An older recorded version is not an update.
        ops_hardening.set_latest_version(db, version="0.0.1", actor=ACTOR)
        db.flush()
        assert ops_hardening.update_status(db)["update_available"] is False

    def test_versions_of_differing_length_compare_equal(self, db: Session) -> None:
        # "x.y" and "x.y.0" are the same version, not an available update.
        ops_hardening.set_latest_version(db, version=f"{__version__}.0", actor=ACTOR)
        db.flush()
        assert ops_hardening.update_status(db)["update_available"] is False


class TestWatchdog:
    def test_disabled_scheduler_is_not_a_fault(self, db: Session) -> None:
        settings_store.set_value(db, settings_store.KEY_SCHEDULER_ENABLED, False)
        db.flush()
        watch = ops_hardening.watchdog_status(db)
        assert watch.state == "disabled"
        assert ops_hardening.scheduler_alive(db) is True

    def test_no_runs_is_down(self, db: Session) -> None:
        watch = ops_hardening.watchdog_status(db)
        assert watch.state == "down"
        assert ops_hardening.scheduler_alive(db) is False

    def test_recent_run_is_ok(self, db: Session) -> None:
        now = utcnow()
        db.add(
            SchedulerRun(
                kind="cycle",
                trigger="schedule",
                started_at=now,
                finished_at=now,
                status=RunStatus.SUCCESS,
            )
        )
        db.flush()
        watch = ops_hardening.watchdog_status(db, now=now)
        assert watch.state == "ok"
        assert ops_hardening.scheduler_alive(db, now=now) is True

    def test_long_silence_is_down(self, db: Session) -> None:
        old = utcnow() - timedelta(days=2)
        db.add(
            SchedulerRun(
                kind="cycle",
                trigger="schedule",
                started_at=old,
                finished_at=old,
                status=RunStatus.SUCCESS,
            )
        )
        db.flush()
        watch = ops_hardening.watchdog_status(db)
        assert watch.state == "down"
        assert (
            watch.seconds_since_last_run and watch.seconds_since_last_run > watch.tolerance_seconds
        )


class TestBackupRestore:
    def test_backup_excludes_secrets_and_includes_config(self, db: Session) -> None:
        settings_store.set_secret(db, settings_store.KEY_SMTP_PASSWORD, "s3cret")
        settings_store.set_value(db, settings_store.KEY_CREDIT_UNIT_COST, 2.5)
        _limit(db, entity_id="u1", credit_limit=500, enforce=True)
        db.flush()

        backup = ops_hardening.export_config_backup(db)
        assert backup["backup_version"] == ops_hardening.BACKUP_VERSION
        assert backup["settings"][settings_store.KEY_CREDIT_UNIT_COST] == 2.5
        # No secret value or configured-flag leaks into the backup.
        assert settings_store.KEY_SMTP_PASSWORD not in backup["settings"]
        assert not any(k.endswith(".configured") for k in backup["settings"])
        assert len(backup["limits"]) == 1 and backup["limits"][0]["enforce"] is True

    def test_restore_upserts_limits_and_settings(self, db: Session) -> None:
        # Start with one limit that will be updated, and a backup that also adds one.
        _limit(db, entity_id="u1", credit_limit=100)
        db.flush()
        backup = {
            "backup_version": 1,
            "settings": {settings_store.KEY_CREDIT_UNIT_COST: 3.0},
            "limits": [
                {
                    "entity_type": "user",
                    "entity_id": "u1",
                    "credit_limit": 999,
                    "period_type": "monthly",
                    "enforce": True,
                    "is_active": True,
                },
                {
                    "entity_type": "user",
                    "entity_id": "u2",
                    "credit_limit": 50,
                    "period_type": "monthly",
                },
            ],
            "exemptions": [],
        }
        stats = ops_hardening.restore_config_backup(db, data=backup, actor=ACTOR)
        db.flush()
        assert stats == {
            "settings": 1,
            "limits_created": 1,
            "limits_updated": 1,
            "exemptions": 0,
        }
        u1 = db.scalar(select(CreditLimit).where(CreditLimit.entity_id == "u1"))
        assert u1.credit_limit == 999 and u1.enforce is True
        assert settings_store.credit_unit_cost(db) == 3.0

    def test_restore_round_trips_an_export(self, db: Session) -> None:
        _limit(db, entity_id="u1", credit_limit=400, business_unit="Payments")
        limits_service.add_exemption(
            db, entity_type=EntityType.USER, entity_id="u2", reason="pilot", actor=ACTOR
        )
        db.flush()
        backup = ops_hardening.export_config_backup(db)

        # Wipe, then restore from the export.
        db.query(CreditLimit).delete()
        db.query(Exemption).delete()
        db.flush()
        ops_hardening.restore_config_backup(db, data=backup, actor=ACTOR)
        db.flush()
        restored = db.scalar(select(CreditLimit).where(CreditLimit.entity_id == "u1"))
        assert restored is not None and restored.business_unit == "Payments"
        assert db.scalar(select(Exemption).where(Exemption.entity_id == "u2")) is not None

    def test_restore_rejects_an_unknown_format(self, db: Session) -> None:
        import pytest

        with pytest.raises(ops_hardening.BackupError):
            ops_hardening.restore_config_backup(db, data={"backup_version": 999}, actor=ACTOR)

    def test_restore_rejects_out_of_range_settings_before_applying_anything(
        self, db: Session
    ) -> None:
        import pytest

        before = settings_store.get_value(db, settings_store.KEY_RETENTION_DAYS)
        bad = {
            "backup_version": 1,
            # Below the schema's minimum (ge=7): the form would reject this too.
            "settings": {settings_store.KEY_RETENTION_DAYS: 1},
            "limits": [{"entity_type": "user", "entity_id": "u1", "credit_limit": 10}],
            "exemptions": [],
        }
        with pytest.raises(ops_hardening.BackupError):
            ops_hardening.restore_config_backup(db, data=bad, actor=ACTOR)
        # Nothing was applied: validation runs before any mutation.
        assert settings_store.get_value(db, settings_store.KEY_RETENTION_DAYS) == before
        assert db.scalar(select(CreditLimit).where(CreditLimit.entity_id == "u1")) is None

    def test_restore_rejects_an_unsupported_usage_window(self, db: Session) -> None:
        import pytest

        bad = {
            "backup_version": 1,
            "settings": {settings_store.KEY_USAGE_PERIOD: "since_the_dawn_of_time"},
            "limits": [],
            "exemptions": [],
        }
        with pytest.raises(ops_hardening.BackupError):
            ops_hardening.restore_config_backup(db, data=bad, actor=ACTOR)

    def test_restore_rejects_a_semantically_invalid_limit_as_a_bad_backup(
        self, db: Session
    ) -> None:
        import pytest

        bad = {
            "backup_version": 1,
            "settings": {},
            # A negative budget is type-valid but rejected by the limit service.
            "limits": [{"entity_type": "user", "entity_id": "u1", "credit_limit": -5}],
            "exemptions": [],
        }
        with pytest.raises(ops_hardening.BackupError):
            ops_hardening.restore_config_backup(db, data=bad, actor=ACTOR)

    def test_restore_rejects_malformed_sections(self, db: Session) -> None:
        import pytest

        bad = {"backup_version": 1, "settings": {}, "limits": "not-a-list", "exemptions": []}
        with pytest.raises(ops_hardening.BackupError):
            ops_hardening.restore_config_backup(db, data=bad, actor=ACTOR)

    def test_backup_includes_non_secret_delivery_destinations(self, db: Session) -> None:
        settings_store.set_value(db, settings_store.KEY_SMTP_HOST, "mail.example")
        settings_store.set_value(db, settings_store.KEY_SMTP_FROM, "cxcg@example")
        settings_store.set_secret(db, settings_store.KEY_SMTP_PASSWORD, "s3cret")
        db.flush()
        backup = ops_hardening.export_config_backup(db)
        assert backup["settings"][settings_store.KEY_SMTP_HOST] == "mail.example"
        # ...but never the secret.
        assert settings_store.KEY_SMTP_PASSWORD not in backup["settings"]

    def test_restore_skips_lapsed_overrides(self, db: Session) -> None:
        backup = {
            "backup_version": 1,
            "settings": {},
            "limits": [],
            "exemptions": [
                {
                    "entity_type": "user",
                    "entity_id": "u9",
                    "reason": "old",
                    "expires_at": (utcnow() - timedelta(days=1)).isoformat(),
                }
            ],
        }
        stats = ops_hardening.restore_config_backup(db, data=backup, actor=ACTOR)
        assert stats["exemptions"] == 0


class TestEndpoints:
    def test_attestation_endpoint(self, admin_client: TestClient) -> None:
        body = admin_client.get("/api/ops/attestation").json()
        assert body["version"] == __version__
        assert "config_digest" in body and "update" in body

    def test_backup_and_restore_endpoints(self, admin_client: TestClient) -> None:
        backup = admin_client.get("/api/ops/backup")
        assert backup.status_code == httpx.codes.OK, backup.text
        payload = backup.json()
        restored = admin_client.post("/api/ops/restore", json=payload)
        assert restored.status_code == httpx.codes.OK, restored.text
        assert "limits_created" in restored.json()

    def test_ops_endpoints_require_admin(self, viewer_client: TestClient) -> None:
        assert viewer_client.get("/api/ops/backup").status_code == httpx.codes.FORBIDDEN
        assert (
            viewer_client.post("/api/ops/restore", json={"backup_version": 1}).status_code
            == httpx.codes.FORBIDDEN
        )
        assert viewer_client.get("/api/ops/attestation").status_code == httpx.codes.FORBIDDEN
        assert viewer_client.get("/api/ops/watchdog").status_code == httpx.codes.FORBIDDEN

    def test_restore_rejects_bad_payload_over_http(self, admin_client: TestClient) -> None:
        response = admin_client.post("/api/ops/restore", json={"backup_version": 2})
        assert response.status_code == httpx.codes.BAD_REQUEST
        assert response.json()["detail"]["code"] == "bad_backup"

    def test_healthz_reports_scheduler_liveness(self, client: TestClient) -> None:
        body = client.get("/healthz").json()
        assert "scheduler_alive" in body
