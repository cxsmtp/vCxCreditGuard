"""The in-app updater: registry client, release verification, install, rollback,
auto-update, routes. The registry is synthetic (tests/fake_registry.py)."""

from __future__ import annotations

import io
import json
import logging
import tarfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app import __version__
from app.db.session import get_engine
from app.models.audit import AuditLogEntry, Notification
from app.models.usage import SchedulerLock
from app.services import ops_hardening, settings_store
from app.services.audit import AuditActor
from app.updates import compare_versions, is_release_tag
from app.updates import service as update_service
from app.updates.manifest import ReleaseRejected, load_public_key, verify_release
from app.updates.registry import (
    DigestMismatch,
    RegistryAuthError,
    RegistryClient,
    RegistryError,
    UnsafeArchive,
    extract_app_files,
)
from app.updates.service import Runtime, UpdateError, UpdateService
from tests.conftest import USING_SQLITE, postgres_only, sqlite_only
from tests.fake_registry import (
    GOOD_TOKEN,
    STORAGE_HOST,
    TEST_PUBLIC_KEY,
    FakeRegistry,
    Release,
    app_files,
    ed25519_keypair,
    tar_gz,
)

ADMIN = AuditActor.system("test-admin")
MAJOR, MINOR, PATCH = (int(p) for p in __version__.split("."))
V_NEXT = f"{MAJOR}.{MINOR + 1}.0"
V_LATER = f"{MAJOR}.{MINOR + 2}.0"
V_OLDER = f"{MAJOR}.{MINOR}.{PATCH}" if PATCH == 0 and MINOR == 0 else "0.0.1"


# ------------------------------------------------------------------ fixtures


@pytest.fixture
def builtin_dir(tmp_path: Path) -> Path:
    root = tmp_path / "image-app"
    for rel, data in app_files(__version__).items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return root


def make_service(
    tmp_path: Path,
    builtin_dir: Path,
    registry: FakeRegistry,
    *,
    supervised: bool = True,
    public_key: Any = "test",
    deps: str = "deps-1",
    deployment: str = "single",
) -> UpdateService:
    runtime = Runtime(
        data_dir=tmp_path / "data",
        builtin_dir=builtin_dir,
        builtin_version=__version__,
        running_version=__version__,
        running_source="built-in",
        image_deps_hash=deps,
        supervised=supervised,
        deployment=deployment,
        launcher_pid=None,
    )
    signals: list[int] = []
    service = UpdateService(
        runtime,
        transport=registry.transport(),
        arch="amd64",
        # By default the image trusts the key the fake releases are signed with.
        public_key=load_public_key(TEST_PUBLIC_KEY) if public_key == "test" else public_key,
        signal_launcher=signals.append,
    )
    update_service.set_service(service)
    return service


def save_token(db: Session, token: str = GOOD_TOKEN) -> None:
    settings_store.set_secret(db, settings_store.KEY_UPDATE_TOKEN, token)
    db.commit()


def audit_actions(db: Session) -> list[str]:
    db.expire_all()
    return [row.action for row in db.scalars(select(AuditLogEntry).order_by(AuditLogEntry.id))]


def update_notifications(db: Session) -> list[Notification]:
    db.expire_all()
    return list(db.scalars(select(Notification).where(Notification.category == "updates")))


# ------------------------------------------------------------------ versions


class TestVersions:
    def test_compare(self) -> None:
        assert compare_versions("1.10.0", "1.9.9") == 1
        assert compare_versions("1.2.3", "1.2.3") == 0
        assert compare_versions("0.9.0", "1.0.0") == -1
        assert compare_versions("latest", "0.0.1") == -1

    def test_releases_channel_is_plain_versions_only(self) -> None:
        assert is_release_tag("1.2.3")
        for tag in ("latest", "v1.2.3", "1.2.3-rc1", "sha-abc1234", "1.2", "1.2.3.4"):
            assert not is_release_tag(tag)


# ------------------------------------------------------------------ registry


class TestRegistry:
    def test_token_exchange_and_tags_with_pagination(self) -> None:
        registry = FakeRegistry(releases=[Release(V_NEXT), Release(V_LATER)], page_size=2)
        with RegistryClient(GOOD_TOKEN, transport=registry.transport(), arch="amd64") as client:
            tags = client.tags()
        assert V_NEXT in tags and V_LATER in tags and "latest" in tags
        token_calls = [r for r in registry.requests if r.url.path == "/token"]
        assert len(token_calls) == 1
        assert sum(1 for r in registry.requests if r.url.path.endswith("/tags/list")) >= 3

    def test_wrong_token_is_an_auth_error_and_the_realm_is_never_followed(self) -> None:
        registry = FakeRegistry(releases=[Release(V_NEXT)])
        with (
            RegistryClient(
                "ghp_wrongwrongwrongwrongwrong", transport=registry.transport()
            ) as client,
            pytest.raises(RegistryAuthError),
        ):
            client.tags()
        assert all(r.url.host == "ghcr.io" for r in registry.requests)

    def test_platform_is_selected_from_the_index(self) -> None:
        registry = FakeRegistry(releases=[Release(V_NEXT, arch="arm64")])
        with RegistryClient(GOOD_TOKEN, transport=registry.transport(), arch="arm64") as client:
            image = client.image(V_NEXT)
        assert image.version == V_NEXT and image.deps_hash == "deps-1"
        with (
            RegistryClient(GOOD_TOKEN, transport=registry.transport(), arch="amd64") as client,
            pytest.raises(RegistryError, match="no build for linux/amd64"),
        ):
            client.image(V_NEXT)

    def test_blob_redirect_drops_the_token_and_checks_the_digest(self) -> None:
        registry = FakeRegistry(releases=[Release(V_NEXT)])
        digest = registry.built[V_NEXT]["app_layer_digest"]
        with RegistryClient(GOOD_TOKEN, transport=registry.transport(), arch="amd64") as client:
            data = client.blob(digest)
        assert data == registry.blobs[digest]
        storage = [r for r in registry.requests if r.url.host == STORAGE_HOST]
        assert storage and all("authorization" not in r.headers for r in storage)

    def test_digest_mismatch_is_rejected(self) -> None:
        registry = FakeRegistry(releases=[Release(V_NEXT)])
        digest = registry.built[V_NEXT]["app_layer_digest"]
        registry.corrupt.add(digest)
        with (
            RegistryClient(GOOD_TOKEN, transport=registry.transport(), arch="amd64") as client,
            pytest.raises(DigestMismatch),
        ):
            client.blob(digest)

    def test_redirect_to_another_host_is_refused(self) -> None:
        registry = FakeRegistry(releases=[Release(V_NEXT)], redirect_host="metadata.internal")
        digest = registry.built[V_NEXT]["app_layer_digest"]
        with (
            RegistryClient(GOOD_TOKEN, transport=registry.transport(), arch="amd64") as client,
            pytest.raises(RegistryError, match="does not call"),
        ):
            client.blob(digest)
        assert not any(r.url.host == "metadata.internal" for r in registry.requests)


# ------------------------------------------------------------- safe unpacking


class TestUnpacking:
    def test_regular_files_under_app_are_taken(self) -> None:
        layer = tar_gz([("app/app/main.py", b"x"), ("etc/passwd", b"root")])
        assert extract_app_files(layer).files == {"app/main.py": b"x"}

    @pytest.mark.parametrize(
        "name", ["app/../../etc/cron.d/x", "/app/app/main.py", "app/app/../../../x"]
    )
    def test_traversal_is_rejected(self, name: str) -> None:
        with pytest.raises(UnsafeArchive):
            extract_app_files(tar_gz([(name, b"evil")]))

    def test_symlinks_and_hardlinks_are_rejected(self) -> None:
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
            link = tarfile.TarInfo("app/app/escape")
            link.type = kind
            link.linkname = "/etc/passwd"
            with pytest.raises(UnsafeArchive, match="link"):
                extract_app_files(tar_gz([link]))

    def test_devices_are_rejected(self) -> None:
        device = tarfile.TarInfo("app/app/dev")
        device.type = tarfile.CHRTYPE
        with pytest.raises(UnsafeArchive):
            extract_app_files(tar_gz([device]))

    def test_not_a_tar_is_rejected(self) -> None:
        with pytest.raises(UnsafeArchive):
            extract_app_files(b"not a tar at all")


# ---------------------------------------------------------- release manifest


def release_files(release: Release) -> dict[str, bytes]:
    built = release.build()
    return extract_app_files(built["blobs"][built["app_layer_digest"]]).files


class TestReleaseManifest:
    def test_unsigned_release_verifies_without_a_key(self) -> None:
        verified = verify_release(
            release_files(Release(V_NEXT, private_key_pem=None)), public_key=None
        )
        assert verified.version == V_NEXT and not verified.signed and not verified.has_signature

    def test_signed_release_verifies_with_its_key(self) -> None:
        private, public = ed25519_keypair()
        verified = verify_release(
            release_files(Release(V_NEXT, private_key_pem=private)),
            public_key=load_public_key(public),
        )
        assert verified.signed

    def test_unsigned_release_is_rejected_once_a_key_is_configured(self) -> None:
        _private, public = ed25519_keypair()
        with pytest.raises(ReleaseRejected, match="not signed"):
            verify_release(
                release_files(Release(V_NEXT, private_key_pem=None)),
                public_key=load_public_key(public),
            )

    def test_signature_from_another_key_is_rejected(self) -> None:
        other, _ = ed25519_keypair()
        _private, public = ed25519_keypair()
        with pytest.raises(ReleaseRejected, match="signature does not match"):
            verify_release(
                release_files(Release(V_NEXT, private_key_pem=other)),
                public_key=load_public_key(public),
            )

    def test_a_changed_or_added_file_is_rejected(self) -> None:
        private, public = ed25519_keypair()

        def change(files: dict[str, bytes]) -> None:
            files["app/main.py"] = b"import os; os.system('evil')\n"

        def add(files: dict[str, bytes]) -> None:
            files["app/extra.py"] = b"evil = True\n"

        for tamper in (change, add):
            with pytest.raises(ReleaseRejected, match="do not match its manifest"):
                verify_release(
                    release_files(Release(V_NEXT, private_key_pem=private, tamper=tamper)),
                    public_key=load_public_key(public),
                )

    def test_placeholder_key_file_means_no_key(self) -> None:
        assert load_public_key("# nothing here yet\n") is None


# ---------------------------------------------------------------- the service


class TestCheck:
    def test_without_a_token_nothing_is_called_and_status_says_so(
        self, db: Session, tmp_path: Path, builtin_dir: Path
    ) -> None:
        registry = FakeRegistry(releases=[Release(V_NEXT)])
        service = make_service(tmp_path, builtin_dir, registry)
        service.check(db)
        result = service.auto_tick(datetime(2026, 11, 24, 3, 5, tzinfo=UTC))
        assert registry.requests == []
        assert "registry token" in result
        status = service.status(db)
        assert status["token"] == {"configured": False, "status": "missing"}
        assert status["settings"]["auto_enabled"] is True
        assert status["settings"]["quiet_hour"] == 3
        assert status["notice"]["kind"] == "needs_token"
        assert update_notifications(db) == []

    def test_check_lists_releases_only(
        self, db: Session, tmp_path: Path, builtin_dir: Path
    ) -> None:
        registry = FakeRegistry(releases=[Release(V_NEXT, notes="Faster checks"), Release(V_LATER)])
        service = make_service(tmp_path, builtin_dir, registry)
        save_token(db)
        service.check(db, actor=ADMIN)
        db.commit()
        status = service.status(db)
        assert [row["version"] for row in status["available"]] == [V_LATER, V_NEXT]
        assert status["latest"] == V_LATER and status["update_available"] is True
        assert status["token"]["status"] == "ok"
        assert {"version": V_NEXT, "notes": "Faster checks"} in status["whats_new"]
        assert "update.checked" in audit_actions(db)
        # Auto-update is on: no "available" notification (it will install itself).
        assert update_notifications(db) == []

    def test_manual_mode_notifies_once_that_an_update_is_available(
        self, db: Session, tmp_path: Path, builtin_dir: Path
    ) -> None:
        registry = FakeRegistry(releases=[Release(V_NEXT)])
        service = make_service(tmp_path, builtin_dir, registry)
        save_token(db)
        service.save_settings(db, auto_enabled=False, quiet_hour=3, actor=ADMIN)
        service.check(db)
        service.check(db)
        db.commit()
        titles = [n.title for n in update_notifications(db)]
        assert titles == [f"CxCreditGuard {V_NEXT} is available"]
        assert audit_actions(db).count("update.available") == 1

    def test_a_refused_token_is_reported_once_without_errors(
        self, db: Session, tmp_path: Path, builtin_dir: Path
    ) -> None:
        registry = FakeRegistry(releases=[Release(V_NEXT)])
        service = make_service(tmp_path, builtin_dir, registry)
        save_token(db, "ghp_revokedrevokedrevokedrevoked")
        service.check(db)
        service.auto_tick(datetime(2026, 11, 24, 3, 5, tzinfo=UTC))
        db.commit()
        status = service.status(db)
        assert status["token"]["status"] == "invalid"
        assert status["notice"]["kind"] == "token_invalid"
        assert len(update_notifications(db)) == 1
        assert audit_actions(db).count("update.token_refused") == 1

    def test_the_attestation_reports_the_latest_release(
        self, db: Session, tmp_path: Path, builtin_dir: Path
    ) -> None:
        service = make_service(tmp_path, builtin_dir, FakeRegistry(releases=[Release(V_NEXT)]))
        assert ops_hardening.update_status(db)["update_available"] is False
        save_token(db)
        service.check(db)
        status_ = ops_hardening.update_status(db)
        assert status_ == {"current": __version__, "latest": V_NEXT, "update_available": True}


class TestInstall:
    def test_install_verifies_stores_backs_up_and_asks_the_launcher(
        self, db: Session, tmp_path: Path, builtin_dir: Path
    ) -> None:
        registry = FakeRegistry(releases=[Release(V_NEXT)])
        service = make_service(tmp_path, builtin_dir, registry)
        save_token(db)
        job = service.install(db, V_NEXT, actor=ADMIN, background=False)
        assert job.state == "switching", job.error
        installed = service.store.get(V_NEXT)
        assert installed is not None and installed.info["deps_hash"] == "deps-1"
        assert (installed.dir / "app" / "main.py").read_bytes() == b"app = None\n"
        selection = service.store.selection()
        assert selection is not None
        assert selection["version"] == V_NEXT and selection["previous"] == "built-in"
        assert selection["trial"] is True
        if USING_SQLITE:
            assert Path(selection["pre_update"]["backup"]).is_file()
        request = json.loads((service.store.updates / "request.json").read_text())
        assert request["kind"] == "switch"
        actions = audit_actions(db)
        for action in ("update.install_started", "update.downloaded", "update.switching"):
            assert action in actions
        # Only the app layer and the config were downloaded, never the base layer.
        blob_paths = [p for p in registry.paths() if "/blob/" in p]
        assert len(blob_paths) == 2

    def test_a_tampered_layer_is_not_installed(
        self, db: Session, tmp_path: Path, builtin_dir: Path
    ) -> None:
        registry = FakeRegistry(releases=[Release(V_NEXT)])
        registry.corrupt.add(registry.built[V_NEXT]["app_layer_digest"])
        service = make_service(tmp_path, builtin_dir, registry)
        save_token(db)
        job = service.install(db, V_NEXT, actor=ADMIN, background=False)
        assert job.state == "failed" and "digest" in job.error
        assert service.store.get(V_NEXT) is None and service.store.selection() is None
        assert "update.failed" in audit_actions(db)

    def test_unsigned_release_refused_when_signing_is_configured(
        self, db: Session, tmp_path: Path, builtin_dir: Path
    ) -> None:
        _private, public = ed25519_keypair()
        service = make_service(
            tmp_path,
            builtin_dir,
            FakeRegistry(releases=[Release(V_NEXT, private_key_pem=None)]),
            public_key=load_public_key(public),
        )
        save_token(db)
        # Not even with the confirmation meant for images without a key.
        job = service.install(db, V_NEXT, actor=ADMIN, allow_unsigned=True, background=False)
        assert job.state == "failed" and "not signed" in job.error
        assert service.store.get(V_NEXT) is None

    def test_signed_release_installs_when_signing_is_configured(
        self, db: Session, tmp_path: Path, builtin_dir: Path
    ) -> None:
        private, public = ed25519_keypair()
        service = make_service(
            tmp_path,
            builtin_dir,
            FakeRegistry(releases=[Release(V_NEXT, private_key_pem=private)]),
            public_key=load_public_key(public),
        )
        save_token(db)
        job = service.install(db, V_NEXT, actor=ADMIN, background=False)
        assert job.state == "switching", job.error
        assert service.store.get(V_NEXT).info["signed"] is True  # type: ignore[union-attr]

    def test_unsafe_layer_is_refused(self, db: Session, tmp_path: Path, builtin_dir: Path) -> None:
        evil = tar_gz([("app/../../etc/x", b"evil")])
        service = make_service(
            tmp_path, builtin_dir, FakeRegistry(releases=[Release(V_NEXT, layer_override=evil)])
        )
        save_token(db)
        job = service.install(db, V_NEXT, actor=ADMIN, background=False)
        assert job.state == "failed" and "unsafe path" in job.error
        assert not (tmp_path / "etc").exists()

    def test_different_dependencies_need_a_new_image(
        self, db: Session, tmp_path: Path, builtin_dir: Path
    ) -> None:
        registry = FakeRegistry(releases=[Release(V_NEXT, deps="deps-2")])
        service = make_service(tmp_path, builtin_dir, registry)
        save_token(db)
        job = service.install(db, V_NEXT, actor=ADMIN, background=False)
        assert job.state == "failed" and "different Python packages" in job.error
        # The app layer was never downloaded.
        app_layer = registry.built[V_NEXT]["app_layer_digest"]
        assert not any(app_layer in p for p in registry.paths())
        status = service.status(db)
        assert status["latest_needs_image"] is False  # not checked yet
        service.check(db)
        status = service.status(db)
        assert status["latest_needs_image"] is True
        assert f"podman pull ghcr.io/cxsmtp/vcxcreditguard:{V_NEXT}" in status["image_command"]
        assert [n.title for n in update_notifications(db)] == [
            f"CxCreditGuard {V_NEXT} needs a new image"
        ]

    def test_downgrades_and_unsupervised_installs_are_refused(
        self, db: Session, tmp_path: Path, builtin_dir: Path
    ) -> None:
        registry = FakeRegistry(releases=[Release(V_NEXT)])
        service = make_service(tmp_path, builtin_dir, registry)
        save_token(db)
        with pytest.raises(UpdateError) as refused:
            service.install(db, __version__, actor=ADMIN, background=False)
        assert refused.value.code == "not_newer"
        service = make_service(tmp_path, builtin_dir, registry, supervised=False)
        with pytest.raises(UpdateError) as refused:
            service.install(db, V_NEXT, actor=ADMIN, background=False)
        assert refused.value.code == "not_supervised"

    @postgres_only
    def test_postgres_schema_change_needs_an_explicit_go_ahead(
        self, db: Session, tmp_path: Path, builtin_dir: Path
    ) -> None:
        registry = FakeRegistry(releases=[Release(V_NEXT, migrations=("aaa", "bbb"))])
        service = make_service(tmp_path, builtin_dir, registry)
        save_token(db)
        job = service.install(db, V_NEXT, actor=ADMIN, background=False)
        assert job.state == "failed" and "cannot be backed up" in job.error
        assert service.store.selection() is None
        job = service.install(db, V_NEXT, actor=ADMIN, accept_no_backup=True, background=False)
        assert job.state == "switching", job.error


def set_revision(revision: str | None) -> None:
    with get_engine().begin() as conn:
        conn.execute(text("CREATE TABLE IF NOT EXISTS alembic_version (version_num VARCHAR(32))"))
        conn.execute(text("DELETE FROM alembic_version"))
        if revision:
            conn.execute(text("INSERT INTO alembic_version VALUES (:r)"), {"r": revision})


class TestRollback:
    def _installed(self, db: Session, tmp_path: Path, builtin_dir: Path) -> UpdateService:
        set_revision("aaa")
        registry = FakeRegistry(releases=[Release(V_NEXT, migrations=("aaa", "bbb"))])
        service = make_service(tmp_path, builtin_dir, registry)
        save_token(db)
        job = service.install(
            db, V_NEXT, actor=ADMIN, accept_no_backup=not USING_SQLITE, background=False
        )
        assert job.state == "switching", job.error
        # The launcher started it and confirmed it: now it runs.
        selection = service.store.selection() or {}
        selection["trial"] = False
        service.store.write_selection(selection)
        # ...in a new process: no job in memory, the installed version running.
        service.rt = Runtime(
            **{**service.rt.__dict__, "running_version": V_NEXT, "running_source": "installed"}
        )
        service.job = None
        return service

    @sqlite_only
    def test_rollback_restores_the_backup_only_when_migrations_ran(
        self, db: Session, tmp_path: Path, builtin_dir: Path
    ) -> None:
        service = self._installed(db, tmp_path, builtin_dir)
        backup = (service.store.selection() or {})["pre_update"]["backup"]

        # No migration ran since the update: the database is kept.
        plan = service.rollback_plan()
        assert plan["possible"] and plan["restores_backup"] is False
        # The new version migrated the database: rolling back restores the backup...
        set_revision("bbb")
        plan = service.rollback_plan()
        assert plan["possible"] and plan["restores_backup"] is True
        # ...which the admin must confirm, because data written since is lost.
        with pytest.raises(UpdateError) as refused:
            service.rollback(db, actor=ADMIN, confirm_data_loss=False)
        assert refused.value.code == "confirm_data_loss"
        assert "lost" in str(refused.value)
        service.rollback(db, actor=ADMIN, confirm_data_loss=True)
        selection = service.store.selection() or {}
        assert selection["version"] == "built-in" and selection["restore"] == backup
        assert selection["previous"] == V_NEXT and selection["trial"] is True
        rollback_audit = list(
            db.scalars(select(AuditLogEntry).where(AuditLogEntry.action == "update.rollback"))
        )
        assert rollback_audit and "lost" in (rollback_audit[0].detail or "")

    @sqlite_only
    def test_rollback_without_schema_change_keeps_the_database(
        self, db: Session, tmp_path: Path, builtin_dir: Path
    ) -> None:
        service = self._installed(db, tmp_path, builtin_dir)
        service.rollback(db, actor=ADMIN, confirm_data_loss=False)
        assert (service.store.selection() or {})["restore"] is None

    @postgres_only
    def test_postgres_rollback_after_a_schema_change_is_not_offered(
        self, db: Session, tmp_path: Path, builtin_dir: Path
    ) -> None:
        service = self._installed(db, tmp_path, builtin_dir)
        plan = service.rollback_plan()
        assert plan["possible"] is False and "no backup" in plan["reason"]


class TestAutoUpdate:
    QUIET = datetime(2026, 11, 24, 3, 10, tzinfo=UTC)
    BUSY_HOUR = datetime(2026, 11, 24, 14, 10, tzinfo=UTC)

    def test_installs_only_in_the_quiet_hour(
        self, db: Session, tmp_path: Path, builtin_dir: Path
    ) -> None:
        service = make_service(tmp_path, builtin_dir, FakeRegistry(releases=[Release(V_NEXT)]))
        save_token(db)
        result = service.auto_tick(self.BUSY_HOUR)
        assert "installs at 03:00 UTC" in result and service.store.selection() is None
        result = service.auto_tick(self.QUIET)
        assert result == f"Installing {V_NEXT}.", result
        assert (service.store.selection() or {})["version"] == V_NEXT
        assert (service.store.selection() or {})["by"] == "auto-update"

    def test_never_during_an_enforcement_cycle(
        self, db: Session, tmp_path: Path, builtin_dir: Path
    ) -> None:
        service = make_service(tmp_path, builtin_dir, FakeRegistry(releases=[Release(V_NEXT)]))
        save_token(db)
        from app.db.base import utcnow

        db.add(
            SchedulerLock(
                name="cycle", holder="cycle-1", acquired_at=utcnow(), heartbeat_at=utcnow()
            )
        )
        db.commit()
        result = service.auto_tick(self.QUIET)
        assert "waits for the enforcement cycle" in result
        assert service.store.selection() is None

    def test_never_a_version_that_failed_to_start(
        self, db: Session, tmp_path: Path, builtin_dir: Path
    ) -> None:
        service = make_service(
            tmp_path, builtin_dir, FakeRegistry(releases=[Release(V_NEXT), Release(V_LATER)])
        )
        save_token(db)
        service.store.updates.mkdir(parents=True, exist_ok=True)
        (service.store.updates / "failed.json").write_text(
            json.dumps({V_LATER: {"at": "x", "reason": "did not answer"}})
        )
        result = service.auto_tick(self.QUIET)
        assert result == f"Installing {V_NEXT}.", result

    def test_never_a_downgrade(self, db: Session, tmp_path: Path, builtin_dir: Path) -> None:
        registry = FakeRegistry(releases=[Release("0.0.1")])
        service = make_service(tmp_path, builtin_dir, registry)
        save_token(db)
        result = service.auto_tick(self.QUIET)
        assert result.startswith("Up to date"), result
        assert service.store.selection() is None

    def test_off_means_no_install(self, db: Session, tmp_path: Path, builtin_dir: Path) -> None:
        service = make_service(tmp_path, builtin_dir, FakeRegistry(releases=[Release(V_NEXT)]))
        save_token(db)
        service.save_settings(db, auto_enabled=False, quiet_hour=3, actor=ADMIN)
        db.commit()
        result = service.auto_tick(self.QUIET)
        assert result.startswith("Auto-update is off") and service.store.selection() is None

    def test_needs_image_is_notified_once_and_not_installed(
        self, db: Session, tmp_path: Path, builtin_dir: Path
    ) -> None:
        service = make_service(
            tmp_path, builtin_dir, FakeRegistry(releases=[Release(V_NEXT, deps="deps-2")])
        )
        save_token(db)
        service.auto_tick(self.QUIET)
        service.auto_tick(self.QUIET)
        assert service.store.selection() is None
        assert len(update_notifications(db)) == 1
        assert audit_actions(db).count("update.needs_image") == 1

    def test_checks_the_registry_every_six_hours(
        self, db: Session, tmp_path: Path, builtin_dir: Path
    ) -> None:
        registry = FakeRegistry(releases=[Release("0.0.1")])
        service = make_service(tmp_path, builtin_dir, registry)
        save_token(db)
        service.auto_tick(datetime.now(UTC))
        calls = len(registry.requests)
        service.auto_tick(datetime.now(UTC))
        assert len(registry.requests) == calls


class TestLauncherEvents:
    def test_events_become_audit_and_notifications_once(
        self, db: Session, tmp_path: Path, builtin_dir: Path
    ) -> None:
        service = make_service(tmp_path, builtin_dir, FakeRegistry())
        service.store.record_event(
            {"type": "started", "version": V_NEXT, "from": "built-in", "seconds": 4}
        )
        service.store.record_event(
            {
                "type": "rollback",
                "from": V_LATER,
                "to": V_NEXT,
                "reason": "did not answer",
                "restored_backup": "/app/data/backups/x.sqlite3",
                "switched_at": "2026-11-24T03:00:00+00:00",
            }
        )
        service.store.record_event({"type": "crash", "version": V_NEXT, "code": 1})
        assert service.report_launcher_events(db) == 3
        assert service.report_launcher_events(db) == 0
        db.commit()
        actions = audit_actions(db)
        assert actions.count("update.installed") == 1 and actions.count("update.rolled_back") == 1
        titles = sorted(n.title for n in update_notifications(db))
        assert f"Update to {V_LATER} failed and was rolled back" in titles
        rolled = next(n for n in update_notifications(db) if "rolled back" in n.title)
        assert "lost" in (rolled.body or "")


# ------------------------------------------------------------------- routes


class TestRoutes:
    def test_viewers_cannot_use_any_update_route(
        self, viewer_client: TestClient, tmp_path: Path, builtin_dir: Path
    ) -> None:
        make_service(tmp_path, builtin_dir, FakeRegistry(releases=[Release(V_NEXT)]))
        calls = [
            ("get", "/api/ops/updates", None),
            ("post", "/api/ops/updates/check", None),
            ("post", "/api/ops/updates/install", {"version": V_NEXT}),
            ("post", "/api/ops/updates/rollback", {}),
            ("post", "/api/ops/updates/restart", None),
            ("put", "/api/ops/updates/token", {"token": GOOD_TOKEN}),
            ("put", "/api/ops/updates/settings", {"auto_enabled": False, "quiet_hour": 4}),
        ]
        for method, url, body in calls:
            response = getattr(viewer_client, method)(url, **({"json": body} if body else {}))
            assert response.status_code == httpx.codes.FORBIDDEN, (url, response.text)

    def test_the_old_manual_latest_version_route_is_gone(self, admin_client: TestClient) -> None:
        response = admin_client.post("/api/ops/version/latest", json={"version": "9.9.9"})
        assert response.status_code in (404, 405)

    def test_token_is_write_only_and_never_logged(
        self,
        admin_client: TestClient,
        tmp_path: Path,
        builtin_dir: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        make_service(tmp_path, builtin_dir, FakeRegistry(releases=[Release(V_NEXT)]))
        caplog.set_level(logging.DEBUG)
        response = admin_client.put("/api/ops/updates/token", json={"token": GOOD_TOKEN})
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["token"] == {"configured": True, "status": "ok"}
        assert body["latest"] == V_NEXT
        for url in ("/api/ops/updates", "/api/settings", "/api/me", "/api/ops/attestation"):
            text_ = admin_client.get(url).text
            assert GOOD_TOKEN not in text_, url
        audit = admin_client.get("/api/audit", params={"limit": 200})
        assert GOOD_TOKEN not in audit.text
        assert GOOD_TOKEN not in caplog.text
        assert all(GOOD_TOKEN not in str(record.args) for record in caplog.records)

    def test_token_format_is_checked(
        self, admin_client: TestClient, tmp_path: Path, builtin_dir: Path
    ) -> None:
        make_service(tmp_path, builtin_dir, FakeRegistry())
        response = admin_client.put("/api/ops/updates/token", json={"token": "has spaces in it!"})
        assert response.status_code == 400

    def test_settings_and_install_through_the_api(
        self, admin_client: TestClient, tmp_path: Path, builtin_dir: Path
    ) -> None:
        service = make_service(tmp_path, builtin_dir, FakeRegistry(releases=[Release(V_NEXT)]))
        response = admin_client.put(
            "/api/ops/updates/settings", json={"auto_enabled": False, "quiet_hour": 22}
        )
        assert response.status_code == 200
        assert response.json()["settings"] == {
            "auto_enabled": False,
            "quiet_hour": 22,
            "timezone": "UTC",
        }
        assert (
            admin_client.put(
                "/api/ops/updates/settings", json={"auto_enabled": True, "quiet_hour": 24}
            ).status_code
            == 422
        )
        refused = admin_client.post("/api/ops/updates/install", json={"version": V_NEXT})
        assert refused.status_code == 409
        assert refused.json()["detail"]["code"] == "needs_token"
        admin_client.put("/api/ops/updates/token", json={"token": GOOD_TOKEN})
        response = admin_client.post("/api/ops/updates/install", json={"version": V_NEXT})
        assert response.status_code == 202, response.text
        # The install runs in the background: wait for it to reach the switch.
        for _ in range(200):
            if service.job is not None and service.job.state != "running":
                break
            time.sleep(0.05)
        assert service.job is not None and service.job.state == "switching", service.job
        me = admin_client.get("/api/me").json()
        assert "update_notice" in me

    def test_me_has_no_update_notice_for_viewers(
        self, viewer_client: TestClient, tmp_path: Path, builtin_dir: Path
    ) -> None:
        make_service(tmp_path, builtin_dir, FakeRegistry())
        assert viewer_client.get("/api/me").json()["update_notice"] is None

    def test_rollback_without_a_previous_version_is_refused(
        self, admin_client: TestClient, tmp_path: Path, builtin_dir: Path
    ) -> None:
        make_service(tmp_path, builtin_dir, FakeRegistry())
        response = admin_client.post("/api/ops/updates/rollback", json={})
        assert response.status_code == 409
        assert response.json()["detail"]["code"] == "rollback_impossible"


def test_layer_bytes_helper_round_trip() -> None:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:gz") as archive:
        info = tarfile.TarInfo("app/app/x.py")
        info.size = 1
        archive.addfile(info, io.BytesIO(b"y"))
    assert extract_app_files(raw.getvalue()).files == {"app/x.py": b"y"}


# ------------------------------------------------- security review findings


def _pyc(tmp: Path, source: str, name: str) -> bytes:
    """Bytecode that runs whatever its source says, whatever the .py next to it holds."""
    import py_compile

    src = tmp / f"{name}.py"
    src.write_text(source)
    out = tmp / f"{name}.pyc"
    py_compile.compile(
        str(src),
        cfile=str(out),
        doraise=True,
        invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
    )
    return out.read_bytes()


class TestOnlyTheSignedFilesRun:
    """B1: nothing outside the signed manifest is installed, or run."""

    def test_pyc_files_outside_the_signed_manifest_are_refused(
        self, db: Session, tmp_path: Path, builtin_dir: Path
    ) -> None:
        import subprocess
        import sys

        import cxcg_launcher as L

        work = tmp_path / "craft"
        work.mkdir()
        marker = tmp_path / "PWNED"
        evil = f"open({str(marker)!r}, 'w').write('x')\n"
        tag = sys.implementation.cache_tag
        sitecustomize = _pyc(work, evil, "sitecustomize")
        main_pyc = _pyc(work, evil + "app = None\n", "main")

        def tamper(files: dict[str, bytes]) -> None:
            # Added AFTER the manifest was written and signed.
            files["sitecustomize.pyc"] = sitecustomize
            files[f"app/__pycache__/main.{tag}.pyc"] = main_pyc

        registry = FakeRegistry(releases=[Release(V_NEXT, tamper=tamper)])
        service = make_service(tmp_path, builtin_dir, registry)
        save_token(db)
        job = service.install(db, V_NEXT, actor=ADMIN, background=False)
        assert job.state == "failed", "a release with files outside its manifest was installed"
        assert "not installed" in job.error
        assert service.store.get(V_NEXT) is None
        assert not (service.store.versions / V_NEXT).exists()
        assert service.store.selection() is None

        # Planted in an installed version afterwards: the launcher refuses the version...
        clean = FakeRegistry(releases=[Release(V_NEXT)])
        service = make_service(tmp_path, builtin_dir, clean)
        assert service.install(db, V_NEXT, actor=ADMIN, background=False).state == "switching"
        root = service.store.versions / V_NEXT
        assert L.tree_problems(root) == []
        (root / "sitecustomize.pyc").write_bytes(sitecustomize)
        (root / "app" / "__pycache__").mkdir()
        (root / "app" / "__pycache__" / f"main.{tag}.pyc").write_bytes(main_pyc)
        problems = L.tree_problems(root)
        assert any("sitecustomize.pyc" in p for p in problems), problems
        assert any("__pycache__" in p for p in problems), problems
        paths = L.Paths(service.store.data)
        image = L.ImageInfo(builtin_dir, __version__, "deps-1")
        target = L.choose_target(paths, image)
        assert target.source == "built-in" and target.refused

        # ...and even when the app's folder is the one that runs, nothing in it runs
        # at interpreter start or shadows a module: it is appended to sys.path and
        # serves the app package only, in an isolated interpreter.
        launcher = L.Launcher(paths=paths, image=image)
        chosen = L.Target(V_NEXT, root, "installed", "test", False, V_NEXT)
        (root / "json.py").write_text(evil)
        env = {**launcher.environment(chosen), "PYTHONPATH": str(root)}
        assert "-I" in launcher.command(chosen) and "-B" in launcher.command(chosen)
        result = subprocess.run(  # noqa: S603 - this interpreter, the launcher's own command
            [*launcher.command(chosen), "--dry-run"],
            env=env,
            cwd=str(root),
            capture_output=True,
            text=True,
            check=True,
        )
        assert not marker.exists(), "code from the version's folder ran at start"
        shown = json.loads(result.stdout.strip().splitlines()[-1])
        assert shown["app"] == str((root / "app" / "__init__.py").resolve())
        assert shown["sys_path"][-1] == str(root.resolve())
        assert str(root.resolve()) not in shown["sys_path"][:-1]

    def test_every_file_must_be_listed_and_no_bytecode_ever(self) -> None:
        private, public = ed25519_keypair()
        key = load_public_key(public)

        def listed_pyc(files: dict[str, bytes]) -> None:
            files["app/x.pth"] = b"import os\n"

        for tamper, match in (
            (listed_pyc, "do not match its manifest|outside what a release may ship"),
            (lambda f: f.update({"app/__pycache__/x.pyc": b"\0"}), "outside what"),
            (lambda f: f.update({"version.json": b"{}"}), "version.json"),
        ):
            with pytest.raises(ReleaseRejected, match=match):
                verify_release(
                    release_files(Release(V_NEXT, private_key_pem=private, tamper=tamper)),
                    public_key=key,
                )

    def test_a_manifest_listing_bytecode_is_refused_even_when_signed(self, tmp_path: Path) -> None:
        from app.updates.manifest import build_manifest, manifest_bytes, sign

        private, public = ed25519_keypair()
        files = app_files(V_NEXT)
        files["app/__pycache__/main.cpython-311.pyc"] = b"\0"
        import hashlib

        manifest = {
            "format": 1,
            "version": V_NEXT,
            "revision": "",
            "deps_hash": "deps-1",
            "files": {rel: hashlib.sha256(data).hexdigest() for rel, data in files.items()},
        }
        raw = manifest_bytes(manifest)
        files["release-manifest.json"] = raw
        files["release-manifest.sig"] = sign(raw, private).encode()
        with pytest.raises(ReleaseRejected, match="compiled bytecode"):
            verify_release(files, public_key=load_public_key(public))
        # The release build refuses a tree with bytecode (and lists everything else).
        for rel, data in files.items():
            path = tmp_path / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        with pytest.raises(ReleaseRejected, match="bytecode"):
            build_manifest(tmp_path, version=V_NEXT, revision="", deps_hash="x")
        for cache in tmp_path.rglob("__pycache__"):
            for item in cache.iterdir():
                item.unlink()
            cache.rmdir()
        built = build_manifest(tmp_path, version=V_NEXT, revision="", deps_hash="x")
        assert "app/static/index.html" in built["files"] and "scripts/tool.py" in built["files"]

    def test_the_store_writes_only_listed_files(self, tmp_path: Path) -> None:
        from app.updates.store import VersionStore

        files = release_files(Release(V_NEXT))
        store = VersionStore(tmp_path / "data")
        with pytest.raises(ReleaseRejected, match="not in the release's manifest"):
            store.install(V_NEXT, {**files, "app/evil.py": b"x"}, {})
        with pytest.raises(ReleaseRejected, match="does not match"):
            store.install(V_NEXT, {**files, "app/main.py": b"changed"}, {})
        assert store.get(V_NEXT) is None
        assert store.install(V_NEXT, files, {}).version == V_NEXT


class TestSigningKey:
    """B2: no key, no automatic install; an unsigned manual install is confirmed and
    audited; a key is required once configured; it comes from the image only."""

    QUIET = datetime(2026, 11, 24, 3, 10, tzinfo=UTC)

    def test_auto_update_waits_for_the_signing_key(
        self, db: Session, tmp_path: Path, builtin_dir: Path
    ) -> None:
        registry = FakeRegistry(releases=[Release(V_NEXT, private_key_pem=None)])
        service = make_service(tmp_path, builtin_dir, registry, public_key=None)
        save_token(db)
        for _ in range(2):
            result = service.auto_tick(self.QUIET)
            assert result.startswith("Auto-update waits for the release signing key"), result
        assert service.store.selection() is None
        app_layer = registry.built[V_NEXT]["app_layer_digest"]
        assert not any(app_layer in p for p in registry.paths())
        db.commit()
        titles = [n.title for n in update_notifications(db)]
        assert titles == ["Auto-update waits for the release signing key."]
        status = service.status(db)
        assert status["signing"]["configured"] is False and status["signing"]["auto_waits"]
        assert status["notice"]["kind"] == "needs_signing_key"
        with pytest.raises(UpdateError) as refused:
            service.install(db, V_NEXT, actor=ADMIN, automatic=True, background=False)
        assert refused.value.code == "needs_signing_key"

    def test_unsigned_manual_install_needs_an_explicit_confirmation(
        self, db: Session, tmp_path: Path, builtin_dir: Path
    ) -> None:
        registry = FakeRegistry(releases=[Release(V_NEXT, private_key_pem=None)])
        service = make_service(tmp_path, builtin_dir, registry, public_key=None)
        save_token(db)
        with pytest.raises(UpdateError) as refused:
            service.install(db, V_NEXT, actor=ADMIN, background=False)
        assert refused.value.code == "confirm_unsigned"
        assert registry.requests == []
        job = service.install(db, V_NEXT, actor=ADMIN, allow_unsigned=True, background=False)
        assert job.state == "switching", job.error
        assert service.store.get(V_NEXT).info["signed"] is False  # type: ignore[union-attr]
        assert "update.unsigned_install_confirmed" in audit_actions(db)

    def test_the_key_comes_from_the_image_never_the_data_volume(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.updates import manifest

        _private, public = ed25519_keypair()
        image = tmp_path / "image"
        (image / "app" / "updates").mkdir(parents=True)
        (image / "app" / "updates" / "release-signing-key.pub").write_text(public)
        installed = tmp_path / "data" / "versions" / V_NEXT
        (installed / "app" / "updates").mkdir(parents=True)
        _other_private, other = ed25519_keypair()
        (installed / "app" / "updates" / "release-signing-key.pub").write_text(other)
        monkeypatch.delenv(manifest.PUBLIC_KEY_ENV, raising=False)
        monkeypatch.setenv("CXCG_DATA_DIR", str(tmp_path / "data"))
        # Whichever version runs, the launcher points at the image's own folder.
        monkeypatch.setenv("CXCG_BUILTIN_DIR", str(image))
        key = manifest.configured_public_key()
        assert (
            key is not None and key.public_bytes_raw() == load_public_key(public).public_bytes_raw()
        )
        # A "built-in" folder inside the data volume is never trusted.
        monkeypatch.setenv("CXCG_BUILTIN_DIR", str(installed))
        assert manifest.configured_public_key() is None

    def test_install_route_needs_the_confirmation_without_a_key(
        self, admin_client: TestClient, tmp_path: Path, builtin_dir: Path
    ) -> None:
        make_service(
            tmp_path,
            builtin_dir,
            FakeRegistry(releases=[Release(V_NEXT, private_key_pem=None)]),
            public_key=None,
        )
        admin_client.put("/api/ops/updates/token", json={"token": GOOD_TOKEN})
        refused = admin_client.post("/api/ops/updates/install", json={"version": V_NEXT})
        assert refused.status_code == 409
        assert refused.json()["detail"]["code"] == "confirm_unsigned"
        response = admin_client.post(
            "/api/ops/updates/install", json={"version": V_NEXT, "allow_unsigned": True}
        )
        assert response.status_code == 202, response.text


class TestSkippedAfterRollback:
    """S1: a version an admin rolled back is not reinstalled by auto-update."""

    QUIET = datetime(2026, 11, 25, 3, 5, tzinfo=UTC)

    def _rolled_back(self, db: Session, tmp_path: Path, builtin_dir: Path, registry: FakeRegistry):
        set_revision("aaa")
        service = make_service(tmp_path, builtin_dir, registry)
        save_token(db)
        job = service.install(
            db, V_NEXT, actor=ADMIN, accept_no_backup=not USING_SQLITE, background=False
        )
        assert job.state == "switching", job.error
        selection = service.store.selection() or {}
        selection["trial"] = False
        service.store.write_selection(selection)
        service.rt = Runtime(
            **{**service.rt.__dict__, "running_version": V_NEXT, "running_source": "installed"}
        )
        service.job = None
        service.rollback(db, actor=ADMIN, confirm_data_loss=True)
        # The launcher switched back: the built-in version runs again.
        service.rt = Runtime(
            **{
                **service.rt.__dict__,
                "running_version": service.rt.builtin_version,
                "running_source": "built-in",
            }
        )
        service.job = None
        return service

    def test_manual_rollback_is_not_reinstalled_by_auto_update_that_night(
        self, db: Session, tmp_path: Path, builtin_dir: Path
    ) -> None:
        service = self._rolled_back(db, tmp_path, builtin_dir, FakeRegistry([Release(V_NEXT)]))
        result = service.auto_tick(self.QUIET)
        assert result != f"Installing {V_NEXT}.", "the rolled-back version was reinstalled"
        assert (service.store.selection() or {})["version"] == "built-in"
        status = service.status(db)
        row = next(r for r in status["available"] if r["version"] == V_NEXT)
        assert row["skipped"] == "Skipped after a rollback"
        assert V_NEXT in status["skipped"]
        # An admin installing it again clears it.
        job = service.install(
            db, V_NEXT, actor=ADMIN, accept_no_backup=not USING_SQLITE, background=False
        )
        assert job.state == "switching", job.error
        assert service.store.skipped() == {}

    def test_a_newer_release_supersedes_the_skipped_one(
        self, db: Session, tmp_path: Path, builtin_dir: Path
    ) -> None:
        registry = FakeRegistry([Release(V_NEXT)])
        service = self._rolled_back(db, tmp_path, builtin_dir, registry)
        registry.releases.append(Release(V_LATER))
        registry.rebuild()
        service.store.save_state({"last_check": None})
        result = service.auto_tick(self.QUIET)
        assert result == f"Installing {V_LATER}.", result
        assert service.store.skipped() == {}


class TestReviewMinors:
    QUIET = datetime(2026, 11, 24, 3, 10, tzinfo=UTC)

    def test_content_encoding_gzip_bomb_is_never_decoded(self) -> None:
        import gzip
        import hashlib
        import tracemalloc

        plain = b"\0" * (200 * 1024 * 1024)
        body = gzip.compress(plain, compresslevel=1)
        digest = "sha256:" + hashlib.sha256(plain).hexdigest()
        del plain
        seen: list[httpx.Request] = []

        def handle(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            if request.url.path == "/token":
                return httpx.Response(200, json={"token": "t"})
            # As from the network: the body is a stream, not read yet.
            return httpx.Response(
                200,
                stream=httpx.ByteStream(body),
                headers={"content-encoding": "gzip", "content-length": str(len(body))},
            )

        client = RegistryClient(GOOD_TOKEN, transport=httpx.MockTransport(handle), arch="amd64")
        tracemalloc.start()
        with pytest.raises(RegistryError):
            client.blob(digest, max_bytes=8 * 1024 * 1024)
        _current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        assert peak < 32 * 1024 * 1024, f"{peak} bytes were held to refuse a 2 MB answer"
        assert all(r.headers.get("accept-encoding") == "identity" for r in seen)

    def test_a_body_over_the_limit_is_not_read_to_the_end(self) -> None:
        sent: list[int] = []

        class Endless(httpx.SyncByteStream):
            def __iter__(self):
                for _ in range(10_000):
                    sent.append(1)
                    yield b"\0" * 65536

        def handle(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/token":
                return httpx.Response(200, json={"token": "t"})
            return httpx.Response(200, stream=Endless())

        client = RegistryClient(GOOD_TOKEN, transport=httpx.MockTransport(handle), arch="amd64")
        with pytest.raises(UnsafeArchive):
            client.blob("sha256:" + "0" * 64, max_bytes=1024 * 1024)
        assert len(sent) <= 20

    def test_a_layer_inflating_past_the_limit_is_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.updates import registry as registry_module

        monkeypatch.setattr(registry_module, "MAX_LAYER_STREAM_BYTES", 1024 * 1024)
        layer = tar_gz([("etc/big", b"\0" * (4 * 1024 * 1024)), ("app/app/main.py", b"x")])
        with pytest.raises(UnsafeArchive, match="more than allowed"):
            extract_app_files(layer)

    def test_malformed_registry_json_is_a_clean_error(
        self, admin_client: TestClient, tmp_path: Path, builtin_dir: Path
    ) -> None:
        registry = FakeRegistry(releases=[Release(V_NEXT)])
        config = registry.built[V_NEXT]["config_digest"]
        registry.manifests[V_NEXT] = json.dumps(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {"digest": config, "size": 1},
                "layers": [{"digest": "sha256:" + "0" * 64, "size": "not a number"}],
            }
        ).encode()
        service = make_service(tmp_path, builtin_dir, registry)
        with (
            RegistryClient(GOOD_TOKEN, transport=registry.transport(), arch="amd64") as client,
            pytest.raises(RegistryError, match="cannot read"),
        ):
            client.image(V_NEXT)
        admin_client.put("/api/ops/updates/token", json={"token": GOOD_TOKEN})
        service._last_manual_check = None
        response = admin_client.post("/api/ops/updates/check")
        assert response.status_code == 200, response.text
        assert "cannot read" in response.json()["last_check"]["error"]
        # Once per 30 seconds.
        again = admin_client.post("/api/ops/updates/check")
        assert again.status_code == 429 and again.json()["detail"]["code"] == "too_soon"

    def test_the_signed_dependency_hash_decides_not_the_label(
        self, db: Session, tmp_path: Path, builtin_dir: Path
    ) -> None:
        registry = FakeRegistry(releases=[Release(V_NEXT, deps="deps-2", label_deps="deps-1")])
        service = make_service(tmp_path, builtin_dir, registry)
        save_token(db)
        job = service.install(db, V_NEXT, actor=ADMIN, background=False)
        assert job.state == "failed" and "different image" in job.error
        assert service.store.get(V_NEXT) is None
        # Not tried again at every tick.
        service.check(db)
        service.job = None
        assert service.auto_tick(self.QUIET) != f"Installing {V_NEXT}."

    def test_a_schema_change_on_an_unbacked_database_is_seen_before_downloading(
        self, db: Session, tmp_path: Path, builtin_dir: Path
    ) -> None:
        registry = FakeRegistry(releases=[Release(V_NEXT, migrations=("aaa", "bbb"))])
        service = make_service(tmp_path, builtin_dir, registry)
        service._db_backed_up = lambda: False  # type: ignore[method-assign]
        save_token(db)
        service.check(db)
        app_layer = registry.built[V_NEXT]["app_layer_digest"]
        with pytest.raises(UpdateError) as refused:
            service.install(db, V_NEXT, actor=ADMIN, background=False)
        assert refused.value.code == "needs_backup"
        for _ in range(3):
            result = service.auto_tick(self.QUIET)
            assert "changes the database schema" in result, result
        assert not any(app_layer in p for p in registry.paths())
        db.commit()
        assert audit_actions(db).count("update.needs_backup") == 1
        assert [r["schema_change"] for r in service.status(db)["available"]] == [True]

    def test_an_installable_intermediate_release_is_taken(
        self, db: Session, tmp_path: Path, builtin_dir: Path
    ) -> None:
        registry = FakeRegistry(releases=[Release(V_NEXT), Release(V_LATER, deps="deps-2")])
        service = make_service(tmp_path, builtin_dir, registry)
        save_token(db)
        result = service.auto_tick(self.QUIET)
        assert result == f"Installing {V_NEXT}.", result
        db.commit()
        assert f"CxCreditGuard {V_LATER} needs a new image" in [
            n.title for n in update_notifications(db)
        ]

    def test_a_dead_install_thread_is_not_busy(
        self, db: Session, tmp_path: Path, builtin_dir: Path
    ) -> None:
        import threading

        from app.db.base import utcnow
        from app.updates.service import Job

        service = make_service(tmp_path, builtin_dir, FakeRegistry())
        job = Job(version=V_NEXT, by="x", automatic=False)
        job.thread = threading.Thread(target=lambda: None)
        job.thread.start()
        job.thread.join()
        service.job = job
        assert not service._job_busy()
        job.thread = None
        job.heartbeat_at = utcnow() - update_service.JOB_HEARTBEAT_STALE
        assert not service._job_busy()
        job.heartbeat_at = utcnow()
        assert service._job_busy()

    def test_the_switch_request_waits_for_the_answer(
        self, db: Session, tmp_path: Path, builtin_dir: Path
    ) -> None:
        service = make_service(tmp_path, builtin_dir, FakeRegistry(releases=[Release(V_NEXT)]))
        save_token(db)
        before = time.time()
        service.install(db, V_NEXT, actor=ADMIN, background=False)
        request = json.loads((service.store.updates / "request.json").read_text())
        assert request["not_before"] >= before + update_service.SWITCH_DELAY_SECONDS - 0.01

    def test_an_old_image_says_so(self, db: Session, tmp_path: Path, builtin_dir: Path) -> None:
        service = make_service(tmp_path, builtin_dir, FakeRegistry())
        save_token(db)
        service.rt = Runtime(**{**service.rt.__dict__, "image_created": "2026-01-02T00:00:00Z"})
        status = service.status(db)
        assert status["image_age"]["stale"] is True and status["image_age"]["days"] > 90
        assert status["notice"]["kind"] == "image_old"
        assert "replace the image" in status["notice"]["detail"]
        service.rt = Runtime(**{**service.rt.__dict__, "image_created": now_text()})
        assert service.status(db)["image_age"]["stale"] is False


def now_text() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class TestFollowUpReview:
    """The follow-up security review: a malformed key is not "no key"; a release
    whose SIGNED dependencies differ does not hide an older one that fits."""

    QUIET = datetime(2026, 11, 24, 3, 10, tzinfo=UTC)

    def test_app_malformed_env_key_is_not_no_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from app.updates import manifest

        for value in ("not a pem", "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----"):
            monkeypatch.setenv(manifest.PUBLIC_KEY_ENV, value)
            assert manifest.configured_public_key() is manifest.UNUSABLE_KEY, value

    def test_a_damaged_image_key_file_is_not_no_key(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.updates import manifest

        image = tmp_path / "image"
        key_file = image / "app" / "updates" / "release-signing-key.pub"
        key_file.parent.mkdir(parents=True)
        monkeypatch.delenv(manifest.PUBLIC_KEY_ENV, raising=False)
        monkeypatch.setenv("CXCG_BUILTIN_DIR", str(image))
        key_file.write_text("# the placeholder: comments only\n")
        assert manifest.configured_public_key() is None
        key_file.write_text("# a key pasted badly\nMCowBQYDK2VwAyEA\n")
        assert manifest.configured_public_key() is manifest.UNUSABLE_KEY

    def test_an_invalid_key_refuses_every_install_with_a_clear_status(
        self, db: Session, tmp_path: Path, builtin_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.updates import manifest

        monkeypatch.setenv(manifest.PUBLIC_KEY_ENV, "not a pem")
        registry = FakeRegistry(releases=[Release(V_NEXT, private_key_pem=None)])
        service = make_service(tmp_path, builtin_dir, registry, public_key="configured")
        save_token(db)
        assert service.key_invalid
        for automatic, allow_unsigned in ((True, False), (False, False), (False, True)):
            with pytest.raises(UpdateError) as refused:
                service.install(
                    db,
                    V_NEXT,
                    actor=ADMIN,
                    automatic=automatic,
                    allow_unsigned=allow_unsigned,
                    background=False,
                )
            assert refused.value.code == "invalid_signing_key"
            assert "configured release key is invalid" in str(refused.value)
        result = service.auto_tick(self.QUIET)
        assert result.startswith("The configured release key is invalid"), result
        assert service.store.selection() is None
        status = service.status(db)
        assert status["signing"]["invalid"] is True and status["signing"]["auto_waits"]
        assert "configured release key is invalid" in status["signing"]["message"]
        assert "release key invalid" in status["notice"]["label"]

    def test_a_signed_needs_image_release_does_not_hide_an_older_one_that_fits(
        self, db: Session, tmp_path: Path, builtin_dir: Path
    ) -> None:
        registry = FakeRegistry(
            releases=[Release(V_NEXT), Release(V_LATER, deps="deps-2", label_deps="deps-1")]
        )
        service = make_service(tmp_path, builtin_dir, registry)
        save_token(db)
        first = service.auto_tick(self.QUIET)  # tries V_LATER, learns its signed hash differs
        assert "different image" in first, first
        service.job = None
        second = service.auto_tick(self.QUIET)
        # README: "the newest one that fits this image is installed".
        assert second == f"Installing {V_NEXT}.", (first, second)
