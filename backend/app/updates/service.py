"""Settings -> Updates: check, install, roll back and auto-update.

* **Check** lists the releases published as ``ghcr.io/cxsmtp/vcxcreditguard:X.Y.Z``
  (the releases channel: plain version tags only) with their labels: the
  dependency hash they were built for, whether they are signed, their notes.
* **Install** downloads only the release's app layer, checks every blob against
  its digest, unpacks it safely, verifies its signed file list, keeps it in the
  data volume, backs the database up and asks the launcher to switch. The
  launcher rolls back by itself if the new version does not come up.
* **Roll back** returns to the version that ran before the last switch. When the
  database schema changed since, the backup taken before that switch is put
  back, and everything written since is lost; the admin confirms that first.
* **Auto-update** (on by default) checks every 6 hours (first a minute after
  start) and installs a newer release in the quiet hour (UTC), never during an
  enforcement cycle, never a version that failed to start, never a downgrade.
* A release built for different Python packages than this image ("needs a new
  image") is never installed as a layer: the page shows the pull/run command.

The registry token is read from the settings store only when needed and never
logged, returned, or put in a message.
"""

from __future__ import annotations

import contextlib
import logging
import os
import re
import signal
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app import __version__
from app.core.crypto import PURPOSE_UPDATE_TOKEN, DecryptionError, get_secret_box
from app.db.base import utcnow
from app.models.enums import Severity
from app.services import notifications, settings_store
from app.services.audit import AuditActor, record_audit
from app.updates import BUILT_IN, compare_versions, is_release_tag, parse_version
from app.updates.backup import backup_database, current_revision
from app.updates.manifest import ReleaseRejected, configured_public_key, verify_release
from app.updates.registry import (
    EGRESS_HOSTS,
    IMAGE,
    LAYER_TYPES,
    RegistryAuthError,
    RegistryClient,
    RegistryError,
    ReleaseImage,
    Unpacked,
    extract_app_files,
)
from app.updates.store import VersionStore, now_iso

logger = logging.getLogger(__name__)

CHECK_EVERY = timedelta(hours=6)
TICK_MINUTES = 15
FIRST_TICK_SECONDS = 60
DETAIL_READS_PER_CHECK = 10
JOB_STALE_AFTER = timedelta(minutes=30)
SCHEDULER_RESUME_SECONDS = 300
# Token states (not secrets).
TOKEN_MISSING = "missing"  # noqa: S105 - a state name
TOKEN_INVALID = "invalid"  # noqa: S105 - a state name
TOKEN_RE = re.compile(r"^[A-Za-z0-9_\-]{20,255}$")
NEEDS_TOKEN = (
    "Updates need a registry token: a GitHub token with read:packages for "
    f"{IMAGE}, entered on Settings -> Updates."
)
_REVISION_LINE = re.compile(r"""^revision(?:\s*:\s*str)?\s*=\s*["']([0-9A-Za-z_]+)["']""", re.M)
_VERSION_LINE = re.compile(r"""^__version__\s*=\s*["']([^"']+)["']""", re.M)


class UpdateError(Exception):
    """An update action that cannot go ahead; the message is shown as is."""

    def __init__(self, message: str, *, status_code: int = 409, code: str = "update_refused"):
        super().__init__(message)
        self.status_code = status_code
        self.code = code


def one_line(text: object, limit: int = 600) -> str:
    """Text for the audit log on one line, with no control characters."""
    return re.sub(r"[\x00-\x1f\x7f  ]+", " ", str(text or ""))[:limit]


# ------------------------------------------------------------------ runtime


@dataclass(frozen=True)
class Runtime:
    """What this process is: where it runs from, and whether a launcher supervises it."""

    data_dir: Path
    builtin_dir: Path
    builtin_version: str
    running_version: str
    running_source: str  # "built-in" | "installed" | "source"
    image_deps_hash: str
    supervised: bool
    deployment: str  # "single" | "compose" | "source"
    launcher_pid: int | None = None


def _pid_alive(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def runtime_from_environment() -> Runtime:
    env = os.environ
    pid_text = env.get("CXCG_LAUNCHER_PID", "")
    pid = int(pid_text) if pid_text.isdigit() else None
    supervised = env.get("CXCG_LAUNCHER") == "1" and _pid_alive(pid)
    deployment = env.get("CXCG_DEPLOYMENT", "").strip().lower() or "source"
    if deployment not in ("single", "compose"):
        deployment = "source"
    source = env.get("CXCG_RUNNING_SOURCE") or ("built-in" if deployment != "source" else "source")
    builtin_dir = Path(env.get("CXCG_BUILTIN_DIR") or Path(__file__).resolve().parents[2])
    return Runtime(
        data_dir=Path(env.get("CXCG_DATA_DIR") or "data").resolve(),
        builtin_dir=builtin_dir,
        builtin_version=env.get("CXCG_BUILTIN_VERSION") or __version__,
        running_version=__version__,
        running_source=source if source in ("built-in", "installed", "source") else "source",
        image_deps_hash=env.get("CXCG_IMAGE_DEPS_HASH") or _image_info_deps(),
        supervised=supervised,
        deployment=deployment,
        launcher_pid=pid,
    )


def _image_info_deps() -> str:
    from app.updates.store import read_json

    info = read_json(Path("/usr/local/share/cxcreditguard/image.json"), {}) or {}
    return str(info.get("deps_hash") or "") if isinstance(info, dict) else ""


def migration_revisions(
    files: dict[str, bytes] | None = None, root: Path | None = None
) -> set[str]:
    found: set[str] = set()
    if files is not None:
        for rel, data in files.items():
            if rel.startswith("alembic/versions/") and rel.endswith(".py"):
                match = _REVISION_LINE.search(data.decode("utf-8", "replace"))
                if match:
                    found.add(match.group(1))
    if root is not None:
        with contextlib.suppress(OSError):
            for path in (root / "alembic" / "versions").glob("*.py"):
                match = _REVISION_LINE.search(path.read_text(encoding="utf-8", errors="replace"))
                if match:
                    found.add(match.group(1))
    return found


# ------------------------------------------------------------------ service


@dataclass
class Job:
    version: str
    by: str
    automatic: bool
    state: str = "running"  # running | switching | failed
    step: str = "Starting"
    error: str = ""
    started_at: datetime = field(default_factory=utcnow)

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "by": self.by,
            "automatic": self.automatic,
            "state": self.state,
            "step": self.step,
            "error": self.error,
            "started_at": self.started_at.isoformat(),
        }


class UpdateService:
    def __init__(
        self,
        runtime: Runtime,
        *,
        transport: httpx.BaseTransport | None = None,
        arch: str | None = None,
        public_key: Any = "configured",
        signal_launcher: Callable[[int], None] | None = None,
        session_factory: Callable[[], Any] | None = None,
        engine_factory: Callable[[], Any] | None = None,
    ) -> None:
        self.rt = runtime
        self.store = VersionStore(runtime.data_dir)
        self._transport = transport
        self._arch = arch
        self._public_key = public_key
        self._signal = signal_launcher or self._default_signal
        self._session_factory = session_factory
        self._engine_factory = engine_factory
        self._lock = threading.Lock()
        self.job: Job | None = None

    # -- plumbing

    @property
    def public_key(self) -> Any:
        if self._public_key == "configured":
            try:
                self._public_key = configured_public_key()
            except ValueError:
                logger.error("The configured release public key cannot be read; updates refused")
                self._public_key = _UNUSABLE_KEY
        return self._public_key

    def _session_scope(self) -> Any:
        if self._session_factory is not None:
            return self._session_factory()
        from app.db.session import session_scope

        return session_scope()

    def _engine(self) -> Any:
        if self._engine_factory is not None:
            return self._engine_factory()
        from app.db.session import get_engine

        return get_engine()

    def _client(self, token: str) -> RegistryClient:
        return RegistryClient(token, transport=self._transport, arch=self._arch)

    def _default_signal(self, pid: int) -> None:
        os.kill(pid, signal.SIGUSR1)

    @staticmethod
    def _token(session: Session) -> str | None:
        try:
            return settings_store.get_secret(session, settings_store.KEY_UPDATE_TOKEN)
        except DecryptionError:
            logger.error("The stored registry token cannot be decrypted with the master key")
            return None

    @property
    def running_selector(self) -> str:
        return self.rt.running_version if self.rt.running_source == "installed" else BUILT_IN

    def _running_root(self) -> Path:
        if self.rt.running_source == "installed":
            found = self.store.get(self.rt.running_version)
            if found is not None:
                return found.dir
        return self.rt.builtin_dir

    def needs_image(self, deps_hash: str) -> bool:
        return bool(self.rt.image_deps_hash and deps_hash and deps_hash != self.rt.image_deps_hash)

    def _job_busy(self) -> bool:
        job = self.job
        return (
            job is not None
            and job.state in ("running", "switching")
            and utcnow() - job.started_at < JOB_STALE_AFTER
        )

    # ------------------------------------------------------------ status

    def releases(self) -> dict[str, dict[str, Any]]:
        value = self.store.state().get("releases")
        return value if isinstance(value, dict) else {}

    def candidate(self) -> dict[str, Any] | None:
        """The newest release auto-update may install: newer than the running version and
        never failed to start here. (Whether it needs a new image is the caller's check.)"""
        failed = self.store.failed()
        for version in self._sorted_versions():
            if compare_versions(version, self.rt.running_version) <= 0:
                return None
            if version in failed:
                continue
            return self.releases()[version]
        return None

    def _sorted_versions(self) -> list[str]:
        return sorted(
            (v for v in self.releases() if is_release_tag(v)), key=parse_version, reverse=True
        )

    def latest(self) -> str | None:
        versions = self._sorted_versions()
        return versions[0] if versions else None

    def update_available(self) -> bool:
        latest = self.latest()
        return bool(latest and compare_versions(latest, self.rt.running_version) > 0)

    def token_status(self, session: Session) -> str:
        if not self._token(session):
            return "missing"
        status = self.store.state().get("token_status")
        return status if status in ("ok", "invalid") else "unknown"

    def image_command(self, version: str | None) -> str:
        tag = version or "latest"
        if self.rt.deployment == "compose":
            return (
                f"git fetch --tags && git checkout v{tag}\n"
                "podman compose -f docker-compose.yml up -d --build"
            )
        return (
            "podman login ghcr.io   # a GitHub user and a token with read:packages\n"
            f"podman pull {IMAGE}:{tag}\n"
            "podman rm -f cxcreditguard\n"
            "podman run -d --name cxcreditguard --restart unless-stopped \\\n"
            f"  -p 8000:8000 -v cxcreditguard-data:/app/data {IMAGE}:{tag}"
        )

    def rollback_plan(self) -> dict[str, Any]:
        """Whether the Rollback button can be offered, to what, and at what cost."""
        selection = self.store.selection() or {}
        target = str(selection.get("previous") or "")
        result: dict[str, Any] = {
            "possible": False,
            "target": target or None,
            "restores_backup": False,
            "since": selection.get("at"),
            "reason": "",
        }
        if not self.rt.supervised:
            result["reason"] = "Rollback needs the launcher (the single-container image)."
            return result
        if not target:
            result["reason"] = "There is no previous version to go back to."
            return result
        target_version = self.rt.builtin_version if target == BUILT_IN else target
        if target != BUILT_IN and self.store.get(target) is None:
            result["reason"] = f"{target} is no longer installed."
            return result
        if compare_versions(target_version, self.rt.running_version) >= 0:
            result["reason"] = f"{target_version} is not older than the running version."
            return result
        pre = selection.get("pre_update") if isinstance(selection.get("pre_update"), dict) else {}
        target_root = self.rt.builtin_dir if target == BUILT_IN else self.store.versions / target
        if pre.get("db_kind") == "sqlite":
            changed = current_revision(self._engine()) != pre.get("db_revision")
        else:
            changed = bool(
                migration_revisions(root=self._running_root())
                - migration_revisions(root=target_root)
            )
        backup = pre.get("backup")
        backup_ok = bool(backup) and Path(str(backup)).is_file()
        if changed and not backup_ok:
            result["reason"] = (
                f"The database schema changed since the update to {self.rt.running_version} and "
                "there is no backup from before it, so the older version cannot run against it. "
                "Restore your own database backup to go back."
            )
            return result
        result.update(
            possible=True,
            target_version=target_version,
            restores_backup=bool(changed),
            backup=str(backup) if changed else None,
        )
        return result

    def status(self, session: Session) -> dict[str, Any]:
        state = self.store.state()
        policy = settings_store.update_policy(session)
        failed = self.store.failed()
        selection = self.store.selection() or {}
        installed = []
        for item in self.store.list_installed():
            info = item.info
            installed.append(
                {
                    "version": item.version,
                    "installed_at": info.get("installed_at"),
                    "installed_by": info.get("installed_by"),
                    "signed": bool(info.get("signed")),
                    "revision": str(info.get("revision") or "")[:12],
                    "bytes": info.get("bytes"),
                    "running": self.rt.running_source == "installed"
                    and item.version == self.rt.running_version,
                    "failed": failed.get(item.version, {}).get("reason"),
                }
            )
        available = []
        releases = self.releases()
        for version in self._sorted_versions():
            details = releases[version]
            available.append(
                {
                    "version": version,
                    "created": details.get("created"),
                    "revision": str(details.get("revision") or "")[:12],
                    "signed": bool(details.get("signed")),
                    "needs_image": self.needs_image(str(details.get("deps_hash") or "")),
                    "newer": compare_versions(version, self.rt.running_version) > 0,
                    "running": version == self.rt.running_version,
                    "installed": self.store.get(version) is not None,
                    "failed": failed.get(version, {}).get("reason"),
                    "notes": details.get("notes") or "",
                }
            )
        latest = self.latest()
        whats_new = [
            {"version": row["version"], "notes": row["notes"]}
            for row in available
            if row["newer"] and row["notes"]
        ][:8]
        engine = self._engine()
        events = [
            {k: v for k, v in event.items() if k in _EVENT_FIELDS}
            for event in reversed(self.store.events(50))
        ][:15]
        return {
            "image": IMAGE,
            "egress_hosts": list(EGRESS_HOSTS),
            "deployment": self.rt.deployment,
            "supervised": self.rt.supervised,
            "running": {"version": self.rt.running_version, "source": self.rt.running_source},
            "built_in": self.rt.builtin_version,
            "installed": installed,
            "available": available,
            "latest": latest,
            "update_available": self.update_available(),
            "latest_needs_image": bool(
                latest and self.needs_image(str(releases[latest].get("deps_hash") or ""))
            ),
            "whats_new": whats_new,
            "rollback": self.rollback_plan(),
            "selection": {
                "version": selection.get("version"),
                "previous": selection.get("previous"),
                "at": selection.get("at"),
                "by": selection.get("by"),
            },
            "settings": {
                "auto_enabled": policy.auto_enabled,
                "quiet_hour": policy.quiet_hour,
                "timezone": "UTC",
            },
            "token": {
                "configured": bool(self._token(session)),
                "status": self.token_status(session),
            },
            "signing": {"configured": self.public_key is not None},
            "database": {
                "kind": engine.dialect.name,
                "backups": engine.dialect.name == "sqlite",
            },
            "last_check": state.get("last_check"),
            "last_auto": state.get("last_auto"),
            "job": self.job.as_dict() if self.job else None,
            "failed": failed,
            "events": events,
            "image_command": self.image_command(latest),
            "notice": self.notice(session),
        }

    def notice(self, session: Session) -> dict[str, str] | None:
        """The top-bar light for admins, or None when nothing needs attention."""
        if self.rt.deployment == "source":
            return None
        if self._job_busy():
            return {
                "kind": "installing",
                "tone": "warn",
                "label": "Updating",
                "detail": "An update is being installed.",
            }
        credential = self.token_status(session)
        policy = settings_store.update_policy(session)
        if credential == TOKEN_MISSING:
            # Where nothing can be installed in place, a missing token is not a fault.
            if not policy.auto_enabled or not self.rt.supervised:
                return None
            return {
                "kind": "needs_token",
                "tone": "warn",
                "label": "Updates: needs a registry token",
                "detail": NEEDS_TOKEN,
            }
        if credential == TOKEN_INVALID:
            return {
                "kind": "token_invalid",
                "tone": "bad",
                "label": "Updates: token refused",
                "detail": "The registry refused the update token. Enter a new one on "
                "Settings -> Updates.",
            }
        latest = self.latest()
        if latest and self.update_available():
            details = self.releases()[latest]
            if self.needs_image(str(details.get("deps_hash") or "")) or not self.rt.supervised:
                return {
                    "kind": "needs_image",
                    "tone": "warn",
                    "label": f"Update {latest}: new image",
                    "detail": f"{latest} is published and is installed by replacing the image.",
                }
            return {
                "kind": "available",
                "tone": "warn",
                "label": f"Update {latest} available",
                "detail": (
                    f"Installs automatically at {policy.quiet_hour:02d}:00 UTC."
                    if policy.auto_enabled
                    else "Auto-update is off: install it from Settings -> Updates."
                ),
            }
        return None

    # ------------------------------------------------------------- check

    def check(self, session: Session, *, actor: AuditActor | None = None) -> dict[str, Any]:
        """Read the published releases. Never raises for registry problems."""
        at = now_iso()
        token = self._token(session)
        if not token:
            self.store.save_state(
                {"token_status": "missing", "last_check": {"at": at, "error": NEEDS_TOKEN}}
            )
            return self.store.state()
        releases = dict(self.releases())
        try:
            with self._client(token) as registry:
                tags = registry.tags()
                versions = sorted(
                    (t for t in tags if is_release_tag(t)), key=parse_version, reverse=True
                )
                reads = 0
                for version in versions:
                    if releases.get(version, {}).get("digest"):
                        continue
                    if reads >= DETAIL_READS_PER_CHECK:
                        break
                    reads += 1
                    releases[version] = self._details(version, registry.image(version))
                releases = {v: releases[v] for v in versions if v in releases}
        except RegistryAuthError as exc:
            self.store.save_state(
                {"token_status": "invalid", "last_check": {"at": at, "error": str(exc)}}
            )
            self._token_refused(session, token, str(exc))
            return self.store.state()
        except RegistryError as exc:
            self.store.save_state({"last_check": {"at": at, "error": str(exc)}})
            logger.warning("Update check failed: %s", exc)
            return self.store.state()
        self.store.save_state(
            {
                "token_status": "ok",
                "releases": releases,
                "last_check": {"at": at, "error": None, "count": len(releases)},
            }
        )
        if actor is not None:
            record_audit(
                session,
                action="update.checked",
                actor=actor,
                target_type="updates",
                detail=(
                    f"Checked {IMAGE}: {len(releases)} release(s), "
                    f"latest {self.latest() or 'none'}."
                ),
            )
        self._after_check(session)
        return self.store.state()

    def _details(self, version: str, image: ReleaseImage) -> dict[str, Any]:
        return {
            "version": version,
            "digest": image.digest,
            "created": image.created,
            "revision": image.revision,
            "deps_hash": image.deps_hash,
            "signed": image.signed_label,
            "label_version": image.version,
            "notes": image.notes,
        }

    def _after_check(self, session: Session) -> None:
        policy = settings_store.update_policy(session)
        latest = self.latest()
        if not latest or compare_versions(latest, self.rt.running_version) <= 0:
            return
        details = self.releases()[latest]
        if self.rt.supervised and self.needs_image(str(details.get("deps_hash") or "")):
            self._notify_needs_image(session, latest)
        elif not policy.auto_enabled or not self.rt.supervised:
            created = notifications.notify(
                session,
                category=notifications.CATEGORY_UPDATES,
                severity=Severity.INFO,
                title=f"CxCreditGuard {latest} is available",
                body=(
                    f"Running {self.rt.running_version}. "
                    + (
                        "Install it from Settings -> Updates."
                        if self.rt.supervised
                        else "This installation is updated by replacing its image:\n"
                        + self.image_command(latest)
                    )
                ),
                dedupe_key=f"update-available:{latest}",
            )
            if created is not None:
                record_audit(
                    session,
                    action="update.available",
                    actor=AuditActor.system("updates"),
                    target_type="updates",
                    target_id=latest,
                    detail=f"{latest} is published (running {self.rt.running_version}).",
                )

    def _notify_needs_image(self, session: Session, version: str) -> None:
        created = notifications.notify(
            session,
            category=notifications.CATEGORY_UPDATES,
            severity=Severity.WARNING,
            title=f"CxCreditGuard {version} needs a new image",
            body=(
                f"{version} was built on different Python packages than this image, so it "
                "cannot be installed from Settings -> Updates. Replace the image:\n"
                + self.image_command(version)
            ),
            dedupe_key=f"update-needs-image:{version}",
        )
        if created is not None:
            record_audit(
                session,
                action="update.needs_image",
                actor=AuditActor.system("updates"),
                target_type="updates",
                target_id=version,
                detail=f"{version} needs a new image (its dependencies differ from this image's).",
            )

    def _token_refused(self, session: Session, token: str, message: str) -> None:
        fingerprint = get_secret_box().digest(token, purpose=PURPOSE_UPDATE_TOKEN)[:16]
        created = notifications.notify(
            session,
            category=notifications.CATEGORY_UPDATES,
            severity=Severity.ERROR,
            title="The update registry token was refused",
            body=one_line(message) + " Enter a new token on Settings -> Updates.",
            dedupe_key=f"update-token-invalid:{fingerprint}",
        )
        if created is not None:
            record_audit(
                session,
                action="update.token_refused",
                actor=AuditActor.system("updates"),
                target_type="updates",
                detail=one_line(message),
            )

    # ----------------------------------------------------------- install

    def install(
        self,
        session: Session,
        version: str,
        *,
        actor: AuditActor,
        accept_no_backup: bool = False,
        automatic: bool = False,
        background: bool = True,
    ) -> Job:
        if parse_version(version) is None:
            raise UpdateError(
                "Choose a release version (X.Y.Z).", status_code=400, code="bad_version"
            )
        if not self.rt.supervised:
            raise UpdateError(
                "This installation is not run by the launcher, so it is updated by replacing its "
                "image (the command is on Settings -> Updates).",
                code="not_supervised",
            )
        if compare_versions(version, self.rt.running_version) <= 0:
            raise UpdateError(
                f"{version} is not newer than the running {self.rt.running_version}. Use "
                "Rollback to go back to the previous version.",
                code="not_newer",
            )
        if automatic and version in self.store.failed():
            raise UpdateError(f"{version} failed to start before; it is not retried automatically.")
        if not self._token(session):
            raise UpdateError(NEEDS_TOKEN, code="needs_token")
        with self._lock:
            if self._job_busy():
                raise UpdateError("An update is already in progress.", code="busy")
            job = Job(version=version, by=actor.actor_name or "admin", automatic=automatic)
            self.job = job
        record_audit(
            session,
            action="update.install_started",
            actor=actor,
            target_type="updates",
            target_id=version,
            detail=(
                f"{'Automatic' if automatic else 'Manual'} update from {self.rt.running_version} "
                f"to {version} started."
            ),
        )
        session.commit()
        run = lambda: self._run_install(job, actor, accept_no_backup)  # noqa: E731
        if background:
            threading.Thread(target=run, name="update-install", daemon=True).start()
        else:
            run()
        return job

    def _run_install(self, job: Job, actor: AuditActor, accept_no_backup: bool) -> None:
        version = job.version
        try:
            with self._session_scope() as session:
                token = self._token(session) or ""
            job.step = "Reading the release"
            with self._client(token) as registry:
                image = registry.image(version)
                if image.version and image.version != version:
                    raise ReleaseRejected(
                        f"The image tagged {version} says it is {image.version}: not installed."
                    )
                if self.needs_image(image.deps_hash):
                    with self._session_scope() as session:
                        self._notify_needs_image(session, version)
                    raise UpdateError(
                        f"{version} was built on different Python packages than this image: "
                        "replace the image to update (the command is on this page).",
                        code="needs_image",
                    )
                layers = image.app_layers()
                unpacked = Unpacked()
                for index, layer in enumerate(layers, start=1):
                    if layer.media_type and layer.media_type not in LAYER_TYPES:
                        raise RegistryError(
                            f"A layer has an unsupported format ({layer.media_type})."
                        )
                    job.step = (
                        f"Downloading {index} of {len(layers)} ({max(1, layer.size // 1024)} KB) "
                        "and checking its digest"
                    )
                    extract_app_files(registry.blob(layer.digest), into=unpacked)
                downloaded = registry.downloaded
            job.step = "Verifying the release"
            files = unpacked.files
            verified = verify_release(files, public_key=self.public_key)
            if verified.version != version:
                raise ReleaseRejected(
                    f"The release's manifest names {verified.version}, not {version}."
                )
            if image.deps_hash and verified.deps_hash != image.deps_hash:
                raise ReleaseRejected(
                    "The release's manifest and image disagree on its dependencies."
                )
            match = _VERSION_LINE.search(
                files.get("app/__init__.py", b"").decode("utf-8", "replace")
            )
            if not match or match.group(1) != version:
                raise ReleaseRejected(f"The release's code does not say it is {version}.")
            new_migrations = sorted(
                migration_revisions(files=files) - migration_revisions(root=self._running_root())
            )
            job.step = "Installing"
            self.store.install(
                version,
                files,
                {
                    "image": IMAGE,
                    "tag": version,
                    "digest": image.digest,
                    "revision": verified.revision,
                    "created": image.created,
                    "deps_hash": verified.deps_hash or image.deps_hash,
                    "signed": verified.signed,
                    "has_signature": verified.has_signature,
                    "installed_by": job.by,
                    "migrations_added": new_migrations,
                },
            )
            with self._session_scope() as session:
                record_audit(
                    session,
                    action="update.downloaded",
                    actor=actor,
                    target_type="updates",
                    target_id=version,
                    detail=(
                        f"{version} downloaded ({max(1, downloaded // 1024)} KB, every blob "
                        f"checked against its digest) and verified: {verified.files} files match "
                        "its " + ("signed manifest." if verified.signed else "manifest (unsigned).")
                    ),
                )
            self._switch(
                version,
                actor=actor,
                by=job.by,
                reason="install",
                schema_changes=bool(new_migrations),
                accept_no_backup=accept_no_backup,
                job=job,
            )
        except Exception as exc:  # noqa: BLE001 - every failure is reported, none escapes
            if isinstance(exc, _EXPLAINED):
                message = str(exc)
            else:
                message = f"Unexpected error ({type(exc).__name__}); see the server log."
                logger.exception("Update to %s failed", version)
            job.state = "failed"
            job.error = message
            self.store.save_state(
                {"last_error": {"at": now_iso(), "version": version, "error": message}}
            )
            with contextlib.suppress(Exception), self._session_scope() as session:
                record_audit(
                    session,
                    action="update.failed",
                    actor=actor,
                    target_type="updates",
                    target_id=version,
                    detail=one_line(f"Update to {version} failed: {message} Nothing was changed."),
                )
                if isinstance(exc, RegistryAuthError):
                    self.store.save_state({"token_status": "invalid"})
                    self._token_refused(session, self._token(session) or "", message)

    # ------------------------------------------------------------ switch

    def _switch(
        self,
        target: str,
        *,
        actor: AuditActor,
        by: str,
        reason: str,
        schema_changes: bool = False,
        accept_no_backup: bool = False,
        restore: str | None = None,
        job: Job | None = None,
        detail: str = "",
    ) -> None:
        """Back up, select ``target`` for the launcher (on trial) and ask it to switch."""
        from app.services.cycle import acquire_lock, release_lock

        holder = f"updater-{uuid.uuid4().hex[:12]}"
        if job is not None:
            job.step = "Waiting for the database (no enforcement cycle may run during a switch)"
        with self._session_scope() as session:
            if not acquire_lock(session, holder=holder):
                raise UpdateError(
                    "An enforcement cycle is running. The switch waits until it has finished; "
                    "try again in a few minutes.",
                    code="cycle_running",
                )
        try:
            if job is not None:
                job.step = "Backing up the database"
            label = f"{self.rt.running_version}-to-{target}"
            backup = backup_database(self._engine(), self.store.backups, label=label)
            if backup.path is None and schema_changes and not accept_no_backup:
                raise UpdateError(
                    f"{target} changes the database schema, and this installation's database "
                    f"({backup.kind}) cannot be backed up by the app. Take a backup yourself, then "
                    "install it again and confirm that you have one.",
                    code="needs_backup",
                )
            previous = self.running_selector
            self.store.write_selection(
                {
                    "version": target,
                    "previous": previous,
                    "trial": True,
                    "builtin_version": self.rt.builtin_version,
                    "image_deps_hash": self.rt.image_deps_hash,
                    "at": now_iso(),
                    "by": by,
                    "reason": reason,
                    "pre_update": {**backup.as_dict(), "from_version": self.rt.running_version},
                    "restore": restore,
                }
            )
            keep = {v for v in (target, previous, self.rt.running_version) if parse_version(v)}
            removed = self.store.prune(keep)
            with self._session_scope() as session:
                record_audit(
                    session,
                    action="update.rollback" if reason == "rollback" else "update.switching",
                    actor=actor,
                    target_type="updates",
                    target_id=target,
                    detail=one_line(
                        detail
                        or (
                            f"Switching from {self.rt.running_version} to {target}. Database "
                            + (
                                f"backed up to {backup.path.name}."
                                if backup.path
                                else "not backed up by the app (PostgreSQL)."
                            )
                            + (f" Removed old version(s): {', '.join(removed)}." if removed else "")
                        )
                    ),
                )
            self._pause_scheduler()
        finally:
            with contextlib.suppress(Exception), self._session_scope() as session:
                release_lock(session, holder=holder)
        if job is not None:
            job.state = "switching"
            job.step = f"Switching to {target}: the page reconnects in a few seconds"
        self._ask_launcher("switch", by)

    def _pause_scheduler(self) -> None:
        with contextlib.suppress(Exception):
            from app import scheduler

            running = scheduler.get_scheduler()
            if running.running:
                running.pause()
                # Should the launcher never act on the request, cycles resume.
                timer = threading.Timer(SCHEDULER_RESUME_SECONDS, running.resume)
                timer.daemon = True
                timer.start()

    def _ask_launcher(self, kind: str, by: str) -> None:
        self.store.request(kind, by)
        pid = self.rt.launcher_pid
        if not pid:
            return

        def nudge() -> None:
            with contextlib.suppress(OSError):
                self._signal(pid)

        # Let the answer reach the browser before this process is stopped.
        timer = threading.Timer(0.5, nudge)
        timer.daemon = True
        timer.start()

    # ---------------------------------------------------------- rollback

    def rollback(
        self, session: Session, *, actor: AuditActor, confirm_data_loss: bool
    ) -> dict[str, Any]:
        if self._job_busy():
            raise UpdateError("An update is in progress.", code="busy")
        plan = self.rollback_plan()
        if not plan["possible"]:
            raise UpdateError(
                plan["reason"] or "Rollback is not possible.", code="rollback_impossible"
            )
        since = plan.get("since") or "the update"
        if plan["restores_backup"] and not confirm_data_loss:
            raise UpdateError(
                f"Rolling back restores the database backup taken at {since}, before the update "
                f"to {self.rt.running_version}. Everything written since then is lost. Confirm to "
                "go ahead.",
                code="confirm_data_loss",
            )
        target = str(plan["target"])
        detail = f"Rollback from {self.rt.running_version} to {plan.get('target_version')}" + (
            f", restoring the database backup from {since}: data written since then is lost."
            if plan["restores_backup"]
            else "; the database is kept as it is (its schema did not change)."
        )
        session.commit()
        self._switch(
            target,
            actor=actor,
            by=actor.actor_name or "admin",
            reason="rollback",
            restore=plan.get("backup") if plan["restores_backup"] else None,
            detail=detail,
        )
        return plan

    def restart(self, session: Session, *, actor: AuditActor) -> None:
        if not self.rt.supervised:
            raise UpdateError(
                "Restarting from this page needs the launcher (the single-container image).",
                code="not_supervised",
            )
        record_audit(
            session,
            action="update.restart",
            actor=actor,
            target_type="updates",
            detail="Server restart requested from Settings -> Updates.",
        )
        session.commit()
        self._ask_launcher("restart", actor.actor_name or "admin")

    # ---------------------------------------------------------- settings

    def set_token(self, session: Session, token: str | None, *, actor: AuditActor) -> None:
        value = (token or "").strip()
        if value and not TOKEN_RE.match(value):
            raise UpdateError(
                "That does not look like a GitHub token (letters, digits, _ and -; 20 to 255 "
                "characters).",
                status_code=400,
                code="bad_token",
            )
        settings_store.set_secret(session, settings_store.KEY_UPDATE_TOKEN, value or None)
        self.store.save_state({"token_status": "unknown" if value else "missing"})
        record_audit(
            session,
            action="update.token_set" if value else "update.token_cleared",
            actor=actor,
            target_type="updates",
            detail=(
                "Registry token for updates replaced (value not recorded)."
                if value
                else "Registry token for updates removed."
            ),
        )

    def save_settings(
        self, session: Session, *, auto_enabled: bool, quiet_hour: int, actor: AuditActor
    ) -> None:
        if not 0 <= quiet_hour <= 23:
            raise UpdateError("The quiet hour is 0 to 23 (UTC).", status_code=400, code="bad_hour")
        before = settings_store.update_policy(session)
        settings_store.set_value(session, settings_store.KEY_UPDATE_AUTO, bool(auto_enabled))
        settings_store.set_value(session, settings_store.KEY_UPDATE_QUIET_HOUR, int(quiet_hour))
        record_audit(
            session,
            action="update.settings_changed",
            actor=actor,
            target_type="updates",
            before={"auto_enabled": before.auto_enabled, "quiet_hour": before.quiet_hour},
            after={"auto_enabled": bool(auto_enabled), "quiet_hour": int(quiet_hour)},
            detail=(
                f"Auto-update {'on' if auto_enabled else 'off'}, quiet hour "
                f"{int(quiet_hour):02d}:00 UTC."
            ),
        )

    # ------------------------------------------------------- auto-update

    def auto_tick(self, now: datetime | None = None) -> str:
        """One look by the scheduler. Returns (and records) what it did or waits for."""
        moment = now or utcnow()
        with self._session_scope() as session:
            self.report_launcher_events(session)
            result = self._auto_step(session, moment)
        self.store.save_state({"last_auto": {"at": moment.isoformat(), "result": result}})
        return result

    def _auto_step(self, session: Session, moment: datetime) -> str:
        policy = settings_store.update_policy(session)
        if not self._token(session):
            self.store.save_state({"token_status": "missing"})
            return "Waiting for a registry token (Settings -> Updates)."
        last = (self.store.state().get("last_check") or {}).get("at")
        due = True
        if last:
            with contextlib.suppress(ValueError):
                due = moment - datetime.fromisoformat(last) >= CHECK_EVERY
        if due:
            self.check(session)
            session.commit()
        state = self.store.state()
        if state.get("token_status") == "invalid":
            return "The registry refused the token; enter a new one."
        if not policy.auto_enabled:
            return "Auto-update is off." + (
                f" {self.latest()} is available." if self.update_available() else ""
            )
        candidate = self.candidate()
        if candidate is None:
            error = (state.get("last_check") or {}).get("error")
            return f"Check failed: {error}" if error else f"Up to date ({self.rt.running_version})."
        version = str(candidate["version"])
        if not self.rt.supervised:
            return f"{version} is available; this installation updates by replacing its image."
        if self.needs_image(str(candidate.get("deps_hash") or "")):
            self._notify_needs_image(session, version)
            return f"{version} needs a new image; see Settings -> Updates for the command."
        if moment.hour != policy.quiet_hour:
            return f"{version} is ready; it installs at {policy.quiet_hour:02d}:00 UTC."
        if self._cycle_running(session):
            return f"{version} waits for the enforcement cycle that is running."
        try:
            self.install(
                session,
                version,
                actor=AuditActor.system("auto-update"),
                automatic=True,
                background=False,
            )
        except UpdateError as exc:
            return f"Not installed: {exc}"
        job = self.job
        if job is not None and job.state == "failed":
            return f"Installing {version} failed: {job.error}"
        return f"Installing {version}."

    @staticmethod
    def _cycle_running(session: Session) -> bool:
        from app.models.usage import SchedulerLock
        from app.services.cycle import LOCK_NAME, LOCK_STALE_AFTER

        lock = session.get(SchedulerLock, LOCK_NAME)
        if lock is None or not lock.holder or lock.heartbeat_at is None:
            return False
        return utcnow() - lock.heartbeat_at < LOCK_STALE_AFTER

    # --------------------------------------------- launcher events -> audit

    def report_launcher_events(self, session: Session) -> int:
        """Turn what the launcher did into audit entries and notifications, once each."""
        stored = settings_store.get_value(session, settings_store.KEY_UPDATE_REPORTED_EVENTS, [])
        seen = {str(v) for v in stored} if isinstance(stored, list) else set()
        events = self.store.events(500)
        fresh = [e for e in events if e["id"] not in seen]
        if not fresh:
            return 0
        launcher = AuditActor.system("launcher")
        for event in fresh:
            kind = event.get("type")
            if kind == "started":
                version = str(event.get("version") or "")
                record_audit(
                    session,
                    action="update.installed",
                    actor=launcher,
                    target_type="updates",
                    target_id=version,
                    detail=one_line(
                        f"{version} started and answered its health check after "
                        f"{event.get('seconds')}s (from {event.get('from') or 'the image'})."
                    ),
                )
                notifications.notify(
                    session,
                    category=notifications.CATEGORY_UPDATES,
                    severity=Severity.INFO,
                    title=(
                        f"CxCreditGuard {version} is running"
                        if event.get("reason") != "rollback"
                        else f"Rolled back to CxCreditGuard {version}"
                    ),
                    body=f"Switched from {event.get('from') or 'the image'} at {event.get('at')}.",
                    dedupe_key=f"update-started:{event['id']}",
                )
            elif kind == "rollback":
                restored = event.get("restored_backup")
                body = (
                    f"{event.get('from')} did not start ({event.get('reason')}), so "
                    f"{event.get('to')} runs again and {event.get('from')} is never installed "
                    "automatically again."
                    + (
                        " The database backup taken before the update was restored: data "
                        f"written since {event.get('switched_at') or 'the update'} is lost."
                        if restored
                        else " The database was kept (its schema had not changed)."
                    )
                )
                record_audit(
                    session,
                    action="update.rolled_back",
                    actor=launcher,
                    target_type="updates",
                    target_id=str(event.get("from") or ""),
                    detail=one_line(body),
                )
                notifications.notify(
                    session,
                    category=notifications.CATEGORY_UPDATES,
                    severity=Severity.CRITICAL,
                    title=f"Update to {event.get('from')} failed and was rolled back",
                    body=body,
                    dedupe_key=f"update-rollback:{event['id']}",
                )
            elif kind == "rollback_blocked":
                body = one_line(
                    f"{event.get('version')} did not start ({event.get('reason')}) and could not "
                    f"be rolled back: {event.get('detail')}. Restore a database backup."
                )
                record_audit(
                    session,
                    action="update.rollback_blocked",
                    actor=launcher,
                    target_type="updates",
                    target_id=str(event.get("version") or ""),
                    detail=body,
                )
                notifications.notify(
                    session,
                    category=notifications.CATEGORY_UPDATES,
                    severity=Severity.CRITICAL,
                    title=f"{event.get('version')} failed to start and could not be rolled back",
                    body=body,
                    dedupe_key=f"update-rollback-blocked:{event['id']}",
                )
            elif kind == "restore":
                record_audit(
                    session,
                    action="update.database_restored",
                    actor=launcher,
                    target_type="updates",
                    target_id=str(event.get("to") or ""),
                    detail=one_line(
                        f"Rollback to {event.get('to')}: the database was restored from "
                        f"{Path(str(event.get('backup'))).name}; data written after it was taken "
                        "is lost (the replaced database is kept in the backups folder)."
                    ),
                )
            elif kind == "selection_ignored":
                record_audit(
                    session,
                    action="update.selection_ignored",
                    actor=launcher,
                    target_type="updates",
                    target_id=str(event.get("version") or ""),
                    detail=one_line(event.get("reason")),
                )
        # Only ids still in the events file are worth remembering: it is bounded too.
        current = {e["id"] for e in events}
        settings_store.set_value(
            session,
            settings_store.KEY_UPDATE_REPORTED_EVENTS,
            sorted((seen & current) | {e["id"] for e in fresh}),
        )
        return len(fresh)


# Failures whose message is written for the admin; anything else is logged.
_EXPLAINED = (UpdateError, RegistryError, ReleaseRejected, ValueError)


class _Unusable:
    """A configured key that cannot be read: nothing verifies against it."""

    def verify(self, *_args: object) -> None:
        from cryptography.exceptions import InvalidSignature

        raise InvalidSignature


_UNUSABLE_KEY = _Unusable()

_EVENT_FIELDS = frozenset(
    {
        "id",
        "at",
        "type",
        "version",
        "from",
        "to",
        "reason",
        "seconds",
        "restored_backup",
        "code",
        "by",
    }
)

_service: UpdateService | None = None
_service_lock = threading.Lock()


def get_service() -> UpdateService:
    global _service
    with _service_lock:
        if _service is None:
            _service = UpdateService(runtime_from_environment())
        return _service


def set_service(service: UpdateService | None) -> None:
    """Test helper: replace (or reset) the process-wide service."""
    global _service
    with _service_lock:
        _service = service


def scheduled_tick() -> None:
    """The scheduler's job: never raises."""
    try:
        result = get_service().auto_tick()
        logger.info("Auto-update: %s", result)
    except Exception:  # noqa: BLE001 - the scheduler thread must survive anything
        logger.exception("Auto-update tick failed")
