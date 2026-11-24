"""Installed versions and the files shared with the launcher, in the data volume.

    <data>/versions/<version>/      a release's files and version.json
    <data>/updates/selection.json   which version the launcher runs (and the one before)
    <data>/updates/request.json     "switch" / "restart", for the launcher
    <data>/updates/events.jsonl     what the launcher did (started, rollback, crash, ...)
    <data>/updates/failed.json      versions that failed to start: never auto-installed
    <data>/updates/skipped.json     versions an admin rolled back: not auto-installed again
    <data>/updates/launcher.json    the launcher's own view of what runs
    <data>/updates/state.json       the updater's last check and last automatic step
    <data>/backups/                 database backups taken before each switch

The formats are shared with ``cxcg_launcher.py`` (``PROTOCOL``): a field is only
ever added, never renamed, because an older launcher reads what a newer app writes.
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.updates import BUILT_IN, compare_versions, parse_version
from app.updates.manifest import (
    MANIFEST_FILE,
    SIGNATURE_FILE,
    VERSION_FILE,
    ReleaseRejected,
    forbidden,
    sha256_hex,
)

PROTOCOL = 1
REQUIRED_FILES = ("app/__init__.py", "app/main.py", "alembic.ini", "alembic/env.py")
MAX_VERSION_BYTES = 256 * 1024 * 1024


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def read_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def write_json_atomic(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp")
    temp.write_text(json.dumps(value, indent=2, sort_keys=True, default=str) + "\n", "utf-8")
    os.chmod(temp, 0o600)
    os.replace(temp, path)


@dataclass(frozen=True)
class InstalledVersion:
    version: str
    dir: Path
    info: dict[str, Any]

    @property
    def deps_hash(self) -> str:
        return str(self.info.get("deps_hash") or "")


class VersionStore:
    def __init__(self, data_dir: Path) -> None:
        self.data = data_dir
        self.versions = data_dir / "versions"
        self.updates = data_dir / "updates"
        self.backups = data_dir / "backups"

    # ------------------------------------------------------------ versions

    def list_installed(self) -> list[InstalledVersion]:
        """Complete installed versions, newest first."""
        out: list[InstalledVersion] = []
        try:
            names = [p.name for p in self.versions.iterdir() if p.is_dir()]
        except OSError:
            return out
        for name in names:
            found = self.get(name)
            if found is not None:
                out.append(found)
        out.sort(key=lambda v: parse_version(v.version) or (0, 0, 0), reverse=True)
        return out

    def get(self, version: str) -> InstalledVersion | None:
        if parse_version(version) is None:
            return None
        root = self.versions / version
        info = read_json(root / VERSION_FILE)
        if not isinstance(info, dict) or info.get("version") != version:
            return None
        if not all((root / rel).is_file() for rel in REQUIRED_FILES):
            return None
        return InstalledVersion(version, root, info)

    def install(
        self, version: str, files: dict[str, bytes], meta: dict[str, Any]
    ) -> InstalledVersion:
        """Write a verified release to ``versions/<version>``: staged, then moved in place.

        Only what the release's own manifest lists is written (plus the manifest
        and its signature), each file matching its sha256: anything else in
        ``files``, or anything a release may never ship, refuses the whole release.
        """
        if parse_version(version) is None:
            raise ValueError(f"Not a release version: {version!r}")
        missing = [rel for rel in REQUIRED_FILES if rel not in files]
        if missing:
            raise ValueError(f"The release is missing {', '.join(missing)}: not installed.")
        listed = _listed(files)
        for rel, data in files.items():
            if rel in (MANIFEST_FILE, SIGNATURE_FILE):
                continue
            why = forbidden(rel)
            if why or rel not in listed:
                raise ReleaseRejected(
                    f"{rel[:80]!r} is not in the release's manifest"
                    + (f" ({why})" if why else "")
                    + ": not installed."
                )
            if sha256_hex(data) != listed[rel]:
                raise ReleaseRejected(f"{rel[:80]!r} does not match its manifest: not installed.")
        absent = [rel for rel in listed if rel not in files]
        if absent:
            raise ReleaseRejected(f"The release is missing {absent[0][:80]!r}: not installed.")
        total = sum(len(data) for data in files.values())
        if total > MAX_VERSION_BYTES:
            raise ValueError("The release is larger than allowed: not installed.")
        self.versions.mkdir(parents=True, exist_ok=True)
        target = self.versions / version
        staging = self.versions / f".{version}.installing-{uuid.uuid4().hex[:8]}"
        try:
            staging.mkdir(mode=0o750)
            root = staging.resolve()
            for rel, data in files.items():
                path = (staging / rel).resolve()
                # Containment: a path that would leave the folder is never written.
                if not path.is_relative_to(root) or path == root:
                    raise ValueError(f"Unsafe path in the release: {rel[:80]!r}")
                path.parent.mkdir(parents=True, exist_ok=True)
                with open(path, "xb") as handle:
                    handle.write(data)
                os.chmod(path, 0o644)
            info = {
                **meta,
                "version": version,
                "installed_at": now_iso(),
                "bytes": total,
                "files": len(files),
            }
            write_json_atomic(staging / VERSION_FILE, info)
            old = self.versions / f".{version}.old-{uuid.uuid4().hex[:8]}"
            if target.exists():
                os.replace(target, old)
            os.replace(staging, target)
            shutil.rmtree(old, ignore_errors=True)
        except BaseException:
            shutil.rmtree(staging, ignore_errors=True)
            raise
        installed = self.get(version)
        if installed is None:
            raise ValueError(f"{version} did not install completely.")
        return installed

    def prune(self, keep: set[str]) -> list[str]:
        """Remove every installed version not in ``keep`` (and leftovers of failed installs)."""
        removed: list[str] = []
        try:
            entries = list(self.versions.iterdir())
        except OSError:
            return removed
        for entry in entries:
            if not entry.is_dir() or entry.is_symlink():
                continue
            if entry.name.startswith("."):
                shutil.rmtree(entry, ignore_errors=True)
                continue
            if entry.name in keep:
                continue
            shutil.rmtree(entry, ignore_errors=True)
            removed.append(entry.name)
        return removed

    def disk_usage(self) -> int:
        total = 0
        for item in self.list_installed():
            with contextlib.suppress(TypeError, ValueError):
                total += int(item.info.get("bytes") or 0)
        return total

    # ---------------------------------------------------- shared with the launcher

    def selection(self) -> dict[str, Any] | None:
        value = read_json(self.updates / "selection.json")
        return value if isinstance(value, dict) else None

    def write_selection(self, value: dict[str, Any]) -> None:
        write_json_atomic(self.updates / "selection.json", {"protocol": PROTOCOL, **value})

    def request(self, kind: str, by: str, *, delay: float = 0.0) -> dict[str, Any]:
        """Ask the launcher to switch or restart; not before ``delay`` seconds from now."""
        request: dict[str, Any] = {"id": uuid.uuid4().hex, "kind": kind, "by": by, "at": now_iso()}
        if delay > 0:
            request["not_before"] = round(time.time() + delay, 3)
        write_json_atomic(self.updates / "request.json", request)
        return request

    def failed(self) -> dict[str, dict[str, Any]]:
        value = read_json(self.updates / "failed.json", {})
        return value if isinstance(value, dict) else {}

    def skipped(self) -> dict[str, dict[str, Any]]:
        """Versions an admin rolled back: auto-update does not install them again."""
        value = read_json(self.updates / "skipped.json", {})
        return (
            {k: v for k, v in value.items() if isinstance(v, dict)}
            if isinstance(value, dict)
            else {}
        )

    def skip(self, version: str, *, by: str, reason: str) -> None:
        if parse_version(version) is None:
            return
        skipped = self.skipped()
        skipped[version] = {"at": now_iso(), "by": by, "reason": reason[:300]}
        write_json_atomic(self.updates / "skipped.json", skipped)

    def unskip(self, *, version: str | None = None, up_to: str | None = None) -> list[str]:
        """Clear ``version``, or every version not newer than ``up_to`` (superseded)."""
        skipped = self.skipped()
        gone = [
            v
            for v in skipped
            if v == version or (up_to is not None and compare_versions(v, up_to) <= 0)
        ]
        if gone:
            for v in gone:
                del skipped[v]
            write_json_atomic(self.updates / "skipped.json", skipped)
        return gone

    def launcher_state(self) -> dict[str, Any] | None:
        value = read_json(self.updates / "launcher.json")
        return value if isinstance(value, dict) else None

    def events(self, limit: int = 200) -> list[dict[str, Any]]:
        """The launcher's events, oldest first."""
        try:
            lines = (self.updates / "events.jsonl").read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        out: list[dict[str, Any]] = []
        for line in lines[-limit:]:
            with contextlib.suppress(ValueError):
                event = json.loads(line)
                if isinstance(event, dict) and isinstance(event.get("id"), str):
                    out.append(event)
        return out

    def record_event(self, event: dict[str, Any]) -> dict[str, Any]:
        entry = {"id": uuid.uuid4().hex, "at": now_iso(), **event}
        self.updates.mkdir(parents=True, exist_ok=True)
        with (self.updates / "events.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True, default=str) + "\n")
        return entry

    def state(self) -> dict[str, Any]:
        value = read_json(self.updates / "state.json", {})
        return value if isinstance(value, dict) else {}

    def save_state(self, patch: dict[str, Any]) -> dict[str, Any]:
        state = {**self.state(), **patch}
        write_json_atomic(self.updates / "state.json", state)
        return state


def _listed(files: dict[str, bytes]) -> dict[str, str]:
    try:
        manifest = json.loads(files[MANIFEST_FILE].decode("utf-8"))
        listed = manifest["files"]
    except (KeyError, UnicodeDecodeError, ValueError, TypeError) as exc:
        raise ReleaseRejected("The release has no readable file manifest: not installed.") from exc
    if not isinstance(listed, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in listed.items()
    ):
        raise ReleaseRejected("The release's file manifest has no file list: not installed.")
    return listed


def newer(a: str, b: str) -> bool:
    return compare_versions(a, b) > 0


__all__ = ["BUILT_IN", "InstalledVersion", "VersionStore", "newer"]
