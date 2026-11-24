#!/usr/bin/env python3
"""The single-container image's main process: runs the selected app version.

CxCreditGuard can update itself from Settings -> Updates without replacing the
container: the app downloads a release's own files (one small image layer) into
the data volume, verifies them, and asks this launcher to switch to them. This
file is the part that never changes with an app update - it lives in the image,
outside the app layer, and uses the Python standard library only.

What it does:

* **Select.** At start (and on every switch) it runs the version chosen in
  ``<data>/updates/selection.json`` from ``<data>/versions/<version>/`` when that
  version is installed, intact (exactly the files its release manifest lists,
  each matching: any other file, bytecode included, refuses it), signed with the
  image's release signing key when the image has one, and built for this
  image's dependencies (same deps hash). Otherwise it runs the image's own copy
  in ``/app`` ("built-in"), and the refused version is never auto-installed again.
* **Isolated interpreter.** The app runs as ``python -I -B -u launcher.py serve``:
  no PYTHONPATH, no current or script folder on ``sys.path``, no bytecode
  written. The selected version's folder is APPENDED to ``sys.path`` and only
  serves the ``app`` package: the standard library and the image's packages
  always come first, and nothing in the data volume runs at interpreter start
  (no ``.pth`` file, no ``sitecustomize``).
* **Trial and automatic rollback.** A version just switched to is on trial until
  ``/healthz`` answers with its version. If it exits first, or does not answer
  within ``CXCG_UPDATE_START_TIMEOUT`` seconds (180), the launcher stops it,
  restores the database backup taken before the switch when the failed version
  changed the schema (SQLite), marks the version "failed to start" so automatic
  updates never retry it, and starts the version that ran before.
* **Switch / restart on request.** The app writes ``<data>/updates/request.json``
  and sends SIGUSR1 (the file is also polled, so the signal is only a nudge).
* **Self-healing.** A crash outside a trial is restarted with a growing pause. An
  installed version that crashes 3 times within 10 minutes is rolled back (when
  no database restore is needed) and marked failed.
* **Read-only or full data volume.** Writes to the data volume are guarded: the
  launcher logs and carries on (running the image's own version when it cannot
  read or record a selection) instead of crash-looping.
* **Stop.** SIGTERM / SIGINT go to the app, which shuts down cleanly; the
  launcher then exits with its status, so ``--restart unless-stopped`` and
  Compose behave exactly as with a plain uvicorn process.

Everything it does is appended to ``<data>/updates/events.jsonl``; the app turns
those lines into audit entries and notifications when it next starts.

The same file also computes the image's dependency hash (``deps-hash`` and
``image-info`` commands), used at build time and by the release workflow, so a
release built on different Python packages is never installed as a layer.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import functools
import hashlib
import importlib.util
import json
import os
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROTOCOL = 1
BUILT_IN = "built-in"
VERSION_RE = re.compile(r"^\d{1,4}\.\d{1,4}\.\d{1,4}$")
MANIFEST_FILE = "release-manifest.json"
SIGNATURE_FILE = "release-manifest.sig"
VERSION_FILE = "version.json"
# Not part of what a release manifest covers: written next to the files.
UNCOVERED = frozenset({MANIFEST_FILE, SIGNATURE_FILE, VERSION_FILE})
REQUIRED_FILES = ("app/__init__.py", "app/main.py", "alembic.ini", "alembic/env.py")
IMAGE_INFO_PATH = Path("/usr/local/share/cxcreditguard/image.json")
PUBLIC_KEY_REL = "app/updates/release-signing-key.pub"
PUBLIC_KEY_ENV = "CXCG_UPDATE_PUBLIC_KEY"
DEFAULT_DATABASE_URL = "sqlite:///./data/cxcreditguard.db"
MAX_EVENTS_BYTES = 256 * 1024
REPLACED_DB_KEEP = 2
# An installed version that stops this many times within the window, after its
# health check passed, is rolled back and marked failed.
CRASH_LIMIT = 3
CRASH_WINDOW = 600.0
# A request's not_before further ahead than this is not believed (clock change).
MAX_REQUEST_DELAY = 30.0
_STARTUP_HOOKS = frozenset({"sitecustomize", "usercustomize"})


def say(message: str) -> None:
    print(f"[launcher] {message}", flush=True)


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


# ------------------------------------------------------------------- versions


def parse_version(value: object) -> tuple[int, int, int] | None:
    text = str(value or "")
    if not VERSION_RE.match(text):
        return None
    major, minor, patch = (int(part) for part in text.split("."))
    return (major, minor, patch)


def compare_versions(a: str, b: str) -> int:
    """-1, 0 or 1. An unparseable version sorts below every real one."""
    pa, pb = parse_version(a) or (-1, -1, -1), parse_version(b) or (-1, -1, -1)
    return (pa > pb) - (pa < pb)


_VERSION_LINE = re.compile(r"""^__version__\s*=\s*["']([^"']+)["']""", re.MULTILINE)


def version_of_tree(root: Path) -> str:
    """The ``__version__`` written in ``<root>/app/__init__.py`` (read, never imported)."""
    try:
        match = _VERSION_LINE.search((root / "app" / "__init__.py").read_text(encoding="utf-8"))
    except OSError:
        return ""
    return match.group(1) if match else ""


# ------------------------------------------------------------------ deps hash


def _normalise(data: bytes) -> bytes:
    return data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def deps_hash(
    *,
    constraints: bytes,
    pyproject: bytes,
    base_image: str,
    files: dict[str, bytes],
    os_packages: bytes = b"",
) -> str:
    """What an app layer needs from the image beneath it, as one sha256.

    Two images with the same hash run the same Python packages on the same base
    (named by its DIGEST in release builds, so a rebuilt base with OS, Python or
    OpenSSL fixes is another base), with the same OS packages, launcher and
    entrypoint, so one's app layer runs on the other. A release with a different
    hash needs the image itself replaced - which is how OS fixes arrive.
    """
    packages = sorted(
        line.strip()
        for line in _normalise(os_packages).decode("utf-8").splitlines()
        if line.strip()
    )
    project = tomllib.loads(_normalise(pyproject).decode("utf-8")).get("project", {})
    pins = sorted(
        line.strip()
        for line in _normalise(constraints).decode("utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    )
    payload = {
        "format": 1,
        "base_image": base_image.strip(),
        "requires_python": project.get("requires-python", ""),
        "dependencies": sorted(project.get("dependencies", [])),
        # Installed by the Dockerfiles next to the project's own dependencies.
        "extra": ["psycopg[c]"],
        "constraints": pins,
        **({"os_packages": packages} if packages else {}),
        "files": {
            name: hashlib.sha256(_normalise(data)).hexdigest()
            for name, data in sorted(files.items())
        },
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def deps_hash_from_paths(
    *,
    constraints: Path,
    pyproject: Path,
    base_image: str,
    launcher: Path,
    entrypoint: Path,
    os_packages: Path | None = None,
) -> str:
    return deps_hash(
        constraints=constraints.read_bytes(),
        pyproject=pyproject.read_bytes(),
        base_image=base_image,
        files={"launcher": launcher.read_bytes(), "entrypoint": entrypoint.read_bytes()},
        os_packages=os_packages.read_bytes() if os_packages else b"",
    )


# ----------------------------------------------------------------- data files


def read_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def write_json_atomic(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp")
    temp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(temp, 0o600)
    os.replace(temp, path)


@dataclass(frozen=True)
class Paths:
    data: Path

    @property
    def versions(self) -> Path:
        return self.data / "versions"

    @property
    def updates(self) -> Path:
        return self.data / "updates"

    @property
    def backups(self) -> Path:
        return self.data / "backups"

    @property
    def selection(self) -> Path:
        return self.updates / "selection.json"

    @property
    def events(self) -> Path:
        return self.updates / "events.jsonl"

    @property
    def failed(self) -> Path:
        return self.updates / "failed.json"

    @property
    def request(self) -> Path:
        return self.updates / "request.json"

    @property
    def state(self) -> Path:
        return self.updates / "launcher.json"


def record_event(paths: Paths, event: dict[str, Any]) -> dict[str, Any]:
    entry = {"id": uuid.uuid4().hex, "at": now_iso(), **event}
    try:
        paths.updates.mkdir(parents=True, exist_ok=True)
        with paths.events.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")
        if paths.events.stat().st_size > MAX_EVENTS_BYTES:
            lines = paths.events.read_text(encoding="utf-8").splitlines()[-500:]
            temp = paths.events.with_suffix(".tmp")
            temp.write_text("\n".join(lines) + "\n", encoding="utf-8")
            os.replace(temp, paths.events)
    except OSError as exc:  # a full or read-only volume must never stop the app
        say(f"could not record an event: {exc}")
    return entry


def try_write_json(path: Path, value: Any) -> bool:
    """write_json_atomic, but a full or read-only data volume is logged, not raised."""
    try:
        write_json_atomic(path, value)
    except OSError as exc:
        say(f"could not write {path.name}: {exc}")
        return False
    return True


def mark_failed(paths: Paths, version: str, reason: str) -> None:
    if version == BUILT_IN or not parse_version(version):
        return
    failed = read_json(paths.failed, {})
    if not isinstance(failed, dict):
        failed = {}
    failed[version] = {"at": now_iso(), "reason": reason[:500]}
    try_write_json(paths.failed, failed)


# ------------------------------------------------------------ choosing a version


@dataclass(frozen=True)
class ImageInfo:
    builtin_dir: Path
    builtin_version: str
    deps_hash: str
    # The image's release signing key (PEM), or None: installed versions must be
    # signed with it. Never read from the data volume.
    public_key_pem: str | None = None


@dataclass(frozen=True)
class Target:
    version: str
    dir: Path
    source: str  # "built-in" | "installed"
    reason: str
    trial: bool = False
    selected: str = BUILT_IN  # what selection.json names (BUILT_IN or a version)
    # The selected version is installed but must not run (changed files, unsigned,
    # other dependencies): it is marked failed so it is never installed again.
    refused: bool = False


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def forbidden(rel: str) -> str | None:
    """What a release never ships (as app/updates/manifest.py): bytecode, .pth files,
    interpreter start-up hooks, unsafe paths."""
    parts = rel.split("/")
    base = parts[-1]
    if "__pycache__" in parts or base.endswith((".pyc", ".pyo")):
        return "compiled bytecode"
    if base.endswith(".pth"):
        return "a .pth file"
    if any(part.split(".", 1)[0] in _STARTUP_HOOKS for part in parts):
        return "an interpreter start-up hook"
    if rel.startswith("/") or "\\" in rel or any(part in ("", ".", "..") for part in parts):
        return "an unsafe path"
    return None


def covered_files(root: Path) -> list[str]:
    """Every file under ``root`` (bytecode, caches and links included) except the
    manifest, its signature and version.json, as sorted relative paths. Directory
    links are listed too, so that they are refused."""
    out: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in [*filenames, *(d for d in dirnames if (Path(dirpath) / d).is_symlink())]:
            full = Path(dirpath) / name
            rel = full.relative_to(root).as_posix()
            if rel in UNCOVERED:
                continue
            out.append(rel)
    return sorted(out)


def load_public_key_text(text: str | None) -> str | None:
    """The PEM block of a public key file (comment lines ignored), or None."""
    if not text:
        return None
    pem = "\n".join(
        line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")
    )
    return pem + "\n" if "BEGIN PUBLIC KEY" in pem else None


def signature_problem(root: Path, public_key_pem: str | None) -> str | None:
    """Why ``root``'s manifest is not signed with the image's key (None: it is, or no key)."""
    if public_key_pem is None:
        return None
    try:
        signature = base64.b64decode(
            (root / SIGNATURE_FILE).read_text(encoding="ascii").strip(), validate=True
        )
        data = (root / MANIFEST_FILE).read_bytes()
    except (OSError, UnicodeDecodeError, binascii.Error, ValueError):
        return "it is not signed, and this image only runs signed releases"
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
    except ImportError:
        return "its signature cannot be checked here (no cryptography package)"
    try:
        key = load_pem_public_key(public_key_pem.encode("ascii"))
        if not isinstance(key, Ed25519PublicKey):
            return "the image's release signing key is not an ed25519 key"
        key.verify(signature, data)
    except InvalidSignature:
        return "its signature does not match the image's release signing key"
    except (ValueError, TypeError):
        return "the image's release signing key cannot be read"
    return None


def tree_problems(root: Path, public_key_pem: str | None = None) -> list[str]:
    """Why the files under ``root`` are not exactly the ones its (signed) manifest lists."""
    manifest = read_json(root / MANIFEST_FILE)
    if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), dict):
        return ["no readable release manifest"]
    problems: list[str] = []
    signed = signature_problem(root, public_key_pem)
    if signed:
        problems.append(signed)
    listed: dict[str, str] = manifest["files"]
    for rel, expected in listed.items():
        why = forbidden(rel) if rel not in UNCOVERED else "a file the store writes"
        if why:
            problems.append(f"{why}: {rel!r}")
            continue
        path = root / rel
        if path.is_symlink() or not path.is_file():
            problems.append(f"missing {rel}")
        elif sha256_file(path) != expected:
            problems.append(f"changed {rel}")
    for rel in covered_files(root):
        if rel not in listed:
            why = forbidden(rel)
            problems.append(f"unexpected {rel}" + (f" ({why})" if why else ""))
    return problems


def installed_info(paths: Paths, version: str) -> dict[str, Any] | None:
    if not parse_version(version):
        return None
    root = paths.versions / version
    info = read_json(root / VERSION_FILE)
    if not isinstance(info, dict) or info.get("version") != version:
        return None
    if not all((root / rel).is_file() for rel in REQUIRED_FILES):
        return None
    return info


def choose_target(paths: Paths, image: ImageInfo, *, verify: bool = True) -> Target:
    """The version to run now, and why. Pure apart from reading the data volume."""
    builtin = Target(
        image.builtin_version, image.builtin_dir, BUILT_IN, "the image's own version", False
    )
    selection = read_json(paths.selection)
    if not isinstance(selection, dict):
        return builtin
    chosen = str(selection.get("version") or BUILT_IN)
    trial = bool(selection.get("trial"))
    if chosen == BUILT_IN:
        return Target(
            image.builtin_version,
            image.builtin_dir,
            BUILT_IN,
            "the image's own version (selected)",
            trial,
            BUILT_IN,
        )

    def fallback(reason: str) -> Target:
        return Target(builtin.version, builtin.dir, BUILT_IN, reason, False, chosen)

    def refuse(reason: str) -> Target:
        return Target(builtin.version, builtin.dir, BUILT_IN, reason, False, chosen, True)

    info = installed_info(paths, chosen)
    if info is None:
        return fallback(f"{chosen} is not installed (or incomplete), so the image's own runs")
    if (
        selection.get("builtin_version")
        and selection.get("builtin_version") != image.builtin_version
        and compare_versions(chosen, image.builtin_version) <= 0
    ):
        return fallback(
            f"the image was replaced with {image.builtin_version}, which is not older than {chosen}"
        )
    if image.deps_hash and info.get("deps_hash") != image.deps_hash:
        return refuse(
            f"{chosen} was built for different dependencies than this image, "
            "so the image's own runs"
        )
    root = paths.versions / chosen
    if verify:
        problems = tree_problems(root, image.public_key_pem)
        if problems:
            return refuse(
                f"{chosen}'s files are not exactly its signed release ({problems[0]}), "
                "so the image's own runs"
            )
        manifest = read_json(root / MANIFEST_FILE, {}) or {}
        if image.deps_hash and manifest.get("deps_hash") != image.deps_hash:
            return refuse(
                f"{chosen}'s signed manifest names different dependencies than this image, "
                "so the image's own runs"
            )
    return Target(chosen, root, "installed", "selected on the Updates page", trial, chosen)


# ------------------------------------------------------------------- database


def sqlite_path(database_url: str, cwd: Path) -> Path | None:
    """The SQLite file a database URL names, or None for any other database."""
    url = database_url.strip()
    if not url.startswith("sqlite"):
        return None
    _, _, rest = url.partition(":///")
    rest = rest.split("?", 1)[0]
    if not rest or rest == ":memory:":
        return None
    path = Path(rest)
    return path if path.is_absolute() else (cwd / path)


def db_revision(db_path: Path | None) -> str | None:
    if db_path is None or not db_path.is_file():
        return None
    try:
        with contextlib.closing(
            sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True, timeout=5)
        ) as conn:
            row = conn.execute("SELECT version_num FROM alembic_version LIMIT 1").fetchone()
    except sqlite3.Error:
        return None
    return str(row[0]) if row else None


_REVISION_LINE = re.compile(r"""^revision(?:\s*:\s*str)?\s*=\s*["']([0-9A-Za-z_]+)["']""", re.M)


def migration_revisions(root: Path) -> set[str]:
    found: set[str] = set()
    folder = root / "alembic" / "versions"
    try:
        files = sorted(folder.glob("*.py"))
    except OSError:
        return found
    for file in files:
        try:
            match = _REVISION_LINE.search(file.read_text(encoding="utf-8"))
        except OSError:
            continue
        if match:
            found.add(match.group(1))
    return found


def schema_changed(
    pre_update: dict[str, Any], db_path: Path | None, new_root: Path, old_root: Path
) -> bool:
    """Whether the database's schema moved since the backup before the switch.

    SQLite: its applied revision, read directly. Anything else: whether the
    version that ran has migrations the one before it does not.
    """
    if db_path is not None and pre_update.get("db_kind") == "sqlite":
        return db_revision(db_path) != pre_update.get("db_revision")
    return bool(migration_revisions(new_root) - migration_revisions(old_root))


def safe_backup(paths: Paths, value: object) -> Path | None:
    """A backup path written by the app, accepted only inside the backups folder."""
    if not isinstance(value, str) or not value:
        return None
    candidate = Path(value)
    try:
        resolved = candidate.resolve(strict=True)
        root = paths.backups.resolve(strict=True)
    except OSError:
        return None
    if not resolved.is_relative_to(root) or candidate.is_symlink() or not resolved.is_file():
        return None
    return resolved


def _keep_copy(db_path: Path, kept: Path) -> None:
    """A consistent copy of the live database, WAL content included (SQLite's backup API)."""
    try:
        with (
            contextlib.closing(sqlite3.connect(db_path, timeout=10)) as source,
            contextlib.closing(sqlite3.connect(kept)) as copy,
        ):
            source.backup(copy)
        return
    except sqlite3.Error as exc:
        say(f"could not copy the database through SQLite ({exc}); copying its files")
    with contextlib.suppress(FileNotFoundError):
        kept.unlink()
    shutil.copy2(db_path, kept)
    for suffix in ("-wal", "-shm"):
        side = db_path.with_name(db_path.name + suffix)
        if side.exists():
            shutil.copy2(side, kept.with_name(kept.name + suffix))


def restore_sqlite(paths: Paths, backup: Path, db_path: Path) -> Path | None:
    """Put the backup in place of the database; the replaced one is kept aside.

    The kept copy is taken through SQLite, so what was only in the write-ahead
    log is in it too. The old -wal/-shm/-journal files are removed BEFORE the
    backup is moved in: left behind, SQLite would replay them onto the backup.
    """
    kept: Path | None = None
    paths.backups.mkdir(parents=True, exist_ok=True)
    if db_path.exists():
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        kept = paths.backups / f"replaced-{stamp}-{uuid.uuid4().hex[:6]}.sqlite3"
        _keep_copy(db_path, kept)
        old = sorted(paths.backups.glob("replaced-*.sqlite3"))
        for extra in old[:-REPLACED_DB_KEEP]:
            for suffix in ("", "-wal", "-shm"):
                with contextlib.suppress(OSError):
                    extra.with_name(extra.name + suffix).unlink()
    temp = db_path.with_name(f".{db_path.name}.restore")
    shutil.copy2(backup, temp)
    for suffix in ("-wal", "-shm", "-journal"):
        with contextlib.suppress(FileNotFoundError):
            db_path.with_name(db_path.name + suffix).unlink()
    os.replace(temp, db_path)
    return kept


@dataclass(frozen=True)
class RollbackPlan:
    to: str  # BUILT_IN or a version
    restore: Path | None
    blocked: str | None = None


def plan_rollback(
    paths: Paths, failed: Target, image: ImageInfo, db_path: Path | None
) -> RollbackPlan:
    """Where to go back to after ``failed`` did not start, and whether the
    database must be restored first. Pure apart from reading the data volume."""
    selection = read_json(paths.selection, {}) or {}
    back = str(selection.get("previous") or BUILT_IN)
    if back != BUILT_IN and installed_info(paths, back) is None:
        back = BUILT_IN
    back_root = image.builtin_dir if back == BUILT_IN else paths.versions / back
    pre = selection.get("pre_update") if isinstance(selection.get("pre_update"), dict) else {}
    if not schema_changed(pre, db_path, failed.dir, back_root):
        return RollbackPlan(back, None)
    backup = safe_backup(paths, pre.get("backup"))
    if backup is None or db_path is None:
        return RollbackPlan(
            back,
            None,
            blocked=(
                f"{failed.version} changed the database schema and there is no backup to go "
                "back to, so the version before it could not run against it"
            ),
        )
    return RollbackPlan(back, backup)


# -------------------------------------------------------------------- probing


def probe_host(host: str) -> str:
    """Where to reach the app: loopback when it listens on every interface."""
    value = (host or "").strip().strip("[]")
    if value in ("", "0.0.0.0", "::"):  # noqa: S104 - compared, not bound
        return "127.0.0.1"
    return value


def http_probe(port: int, expected_version: str, host: str = "127.0.0.1") -> bool:
    shown = f"[{host}]" if ":" in host else host
    try:
        with urllib.request.urlopen(  # noqa: S310 - the app's own address, http only
            f"http://{shown}:{port}/healthz", timeout=3
        ) as response:
            body = json.loads(response.read(65536) or b"{}")
            return response.status == 200 and body.get("version") == expected_version
    except (OSError, ValueError, urllib.error.URLError):
        return False


# ------------------------------------------------------------------ the loop


@dataclass
class Launcher:
    paths: Paths
    image: ImageInfo
    port: int = 8000
    host: str = "0.0.0.0"  # noqa: S104 - the container's own interface
    start_timeout: float = 180.0
    stop_timeout: float = 25.0
    database_url: str = DEFAULT_DATABASE_URL
    spawn: Callable[..., Any] = subprocess.Popen
    probe: Callable[[int, str], bool] = http_probe
    clock: Callable[[], float] = time.monotonic
    sleep: Callable[[float], None] = time.sleep
    wall: Callable[[], float] = time.time
    verify: bool = True

    child: Any = None
    current: Target | None = None
    started_at: float = 0.0
    healthy: bool = False
    stopping: bool = False
    nudged: bool = False
    exit_code: int | None = None
    crashes: list[float] = field(default_factory=list)
    crash_version: str = ""
    restart_at: float | None = None

    def __post_init__(self) -> None:
        if self.probe is http_probe:
            self.probe = functools.partial(http_probe, host=probe_host(self.host))

    @property
    def db_path(self) -> Path | None:
        return sqlite_path(self.database_url, self.image.builtin_dir)

    # -- starting and stopping

    def command(self, target: Target) -> list[str]:
        # -I: no PYTHONPATH, no user site, neither the current nor the script's folder
        # on sys.path; -B: no bytecode written; -u: logs as they happen. ``serve``
        # appends the version's folder to sys.path and runs uvicorn in-process.
        return [
            sys.executable,
            "-I",
            "-B",
            "-u",
            str(Path(__file__).resolve()),
            "serve",
            "--app-dir",
            str(target.dir),
            "--host",
            self.host,
            "--port",
            str(self.port),
            "--no-proxy-headers",
        ]

    def environment(self, target: Target) -> dict[str, str]:
        env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME")}
        env.update(
            {
                "CXCG_LAUNCHER": "1",
                "CXCG_LAUNCHER_PID": str(os.getpid()),
                "CXCG_LAUNCHER_PROTOCOL": str(PROTOCOL),
                "CXCG_RUNNING_SOURCE": target.source,
                "CXCG_RUNNING_DIR": str(target.dir),
                "CXCG_BUILTIN_VERSION": self.image.builtin_version,
                "CXCG_BUILTIN_DIR": str(self.image.builtin_dir),
                "CXCG_IMAGE_DEPS_HASH": self.image.deps_hash,
                "CXCG_DATA_DIR": str(self.paths.data),
                # For any Python the app starts: no bytecode, no unsafe sys.path entry.
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONSAFEPATH": "1",
                "PYTHONNOUSERSITE": "1",
            }
        )
        return env

    def start(self, target: Target) -> None:
        self.current = target
        self.healthy = False
        self.restart_at = None
        kind = "installed" if target.source == "installed" else "the image's own"
        say(
            f"starting {target.version} ({kind}; {target.reason})"
            + (" on trial" if target.trial else "")
        )
        self.child = self.spawn(
            self.command(target), cwd=str(self.image.builtin_dir), env=self.environment(target)
        )
        self.started_at = self.clock()
        if target.version != self.crash_version:
            self.crashes = []
            self.crash_version = target.version
        self.write_state()

    def write_state(self) -> None:
        if self.current is None:
            return
        with contextlib.suppress(OSError):
            write_json_atomic(
                self.paths.state,
                {
                    "protocol": PROTOCOL,
                    "pid": os.getpid(),
                    "version": self.current.version,
                    "source": self.current.source,
                    "dir": str(self.current.dir),
                    "reason": self.current.reason,
                    "trial": self.current.trial,
                    "healthy": self.healthy,
                    "builtin_version": self.image.builtin_version,
                    "deps_hash": self.image.deps_hash,
                    "at": now_iso(),
                },
            )

    def stop_child(self, sig: int = signal.SIGTERM) -> int | None:
        child, self.child = self.child, None
        if child is None:
            return None
        if child.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                child.send_signal(sig)
            try:
                return child.wait(timeout=self.stop_timeout)
            except subprocess.TimeoutExpired:
                say("the app did not stop in time; killing it")
                child.kill()
                return child.wait()
        return child.poll()

    # -- decisions

    def builtin_target(self, reason: str) -> Target:
        return Target(self.image.builtin_version, self.image.builtin_dir, BUILT_IN, reason, False)

    def choose(self) -> Target:
        try:
            target = choose_target(self.paths, self.image, verify=self.verify)
        except OSError as exc:  # an unreadable data volume: the image's own still runs
            say(f"cannot read the selection ({exc}); running the image's own version")
            return self.builtin_target("the data volume could not be read")
        selection = read_json(self.paths.selection)
        if (
            isinstance(selection, dict)
            and selection.get("trial")
            and (target.selected != str(selection.get("version") or BUILT_IN) or not target.trial)
        ):
            # What was chosen cannot run at all: no trial to judge.
            selection["trial"] = False
            try_write_json(self.paths.selection, selection)
        if target.selected != BUILT_IN and target.source == BUILT_IN:
            say(target.reason)
            if target.refused:
                # Installed but not runnable here: auto-update never retries it.
                mark_failed(self.paths, target.selected, target.reason)
            record_event(
                self.paths,
                {
                    "type": "selection_ignored",
                    "version": target.selected,
                    "reason": target.reason,
                    "refused": target.refused,
                },
            )
        return target

    def confirm(self) -> None:
        target = self.current
        assert target is not None
        self.healthy = True
        self.write_state()
        if not target.trial:
            say(f"{target.version} is up")
            return
        selection = read_json(self.paths.selection, {}) or {}
        selection["trial"] = False
        try_write_json(self.paths.selection, selection)
        self.current = Target(
            target.version, target.dir, target.source, target.reason, False, target.selected
        )
        seconds = round(self.clock() - self.started_at, 1)
        say(f"{target.version} is up after {seconds}s; the switch is confirmed")
        record_event(
            self.paths,
            {
                "type": "started",
                "version": target.version,
                "source": target.source,
                "from": str(selection.get("previous") or ""),
                "reason": str(selection.get("reason") or "switch"),
                "seconds": seconds,
            },
        )

    def rollback(self, why: str, *, allow_restore: bool = True) -> None:
        failed = self.current
        assert failed is not None
        self.stop_child()
        plan = plan_rollback(self.paths, failed, self.image, self.db_path)
        if plan.restore is not None and not allow_restore:
            plan = RollbackPlan(
                plan.to,
                None,
                blocked=(
                    "going back would restore the pre-update database backup and lose everything "
                    "written since the update; roll back from Settings -> Updates instead"
                ),
            )
        mark_failed(self.paths, failed.version, why)
        selection = read_json(self.paths.selection, {}) or {}
        restored_from = None
        kept = None
        if plan.restore is not None and self.db_path is not None and not plan.blocked:
            try:
                kept = restore_sqlite(self.paths, plan.restore, self.db_path)
                restored_from = str(plan.restore)
            except (OSError, sqlite3.Error) as exc:
                plan = RollbackPlan(
                    plan.to, None, blocked=f"the database backup could not be put back ({exc})"
                )
        if plan.blocked:
            say(f"{failed.version} failed ({why}); NOT rolling back: {plan.blocked}")
            record_event(
                self.paths,
                {
                    "type": "rollback_blocked",
                    "version": failed.version,
                    "reason": why,
                    "detail": plan.blocked,
                },
            )
            selection["trial"] = False
            try_write_json(self.paths.selection, selection)
            self.start(
                Target(
                    failed.version, failed.dir, failed.source, failed.reason, False, failed.selected
                )
            )
            return
        say(
            f"{failed.version} failed ({why}); going back to {plan.to}"
            + (f" and restoring the database from {plan.restore.name}" if plan.restore else "")
        )
        written = try_write_json(
            self.paths.selection,
            {
                "protocol": PROTOCOL,
                "version": plan.to,
                "previous": None,
                "trial": False,
                "builtin_version": self.image.builtin_version,
                "image_deps_hash": self.image.deps_hash,
                "at": now_iso(),
                "by": "automatic rollback",
                "reason": "rollback",
                "pre_update": None,
                "restore": None,
            },
        )
        record_event(
            self.paths,
            {
                "type": "rollback",
                "automatic": True,
                "from": failed.version,
                "to": plan.to,
                "reason": why,
                "restored_backup": restored_from,
                "replaced_database_kept_at": str(kept) if kept else None,
                "switched_at": str(selection.get("at") or ""),
            },
        )
        # Should the selection not have been saved, the failed version must not run again:
        # the image's own does.
        self.start(
            self.choose()
            if written
            else self.builtin_target("rolled back (the selection could not be saved)")
        )

    def apply_pending_restore(self) -> None:
        """A manual rollback that has to put the pre-update database back.

        If the backup cannot be put back, the older version must not run against
        the newer schema: the version the rollback started from is selected again.
        """
        selection = read_json(self.paths.selection)
        if not isinstance(selection, dict) or not selection.get("restore"):
            return
        backup = safe_backup(self.paths, selection.get("restore"))
        db_path = self.db_path
        problem = "the backup is not usable" if backup is None or db_path is None else ""
        if not problem:
            assert backup is not None and db_path is not None
            try:
                kept = restore_sqlite(self.paths, backup, db_path)
            except (OSError, sqlite3.Error) as exc:
                problem = f"it could not be put back ({exc})"
            else:
                say(f"restored the database from {backup.name}")
                record_event(
                    self.paths,
                    {
                        "type": "restore",
                        "backup": str(backup),
                        "replaced_database_kept_at": str(kept) if kept else None,
                        "to": str(selection.get("version") or BUILT_IN),
                    },
                )
        if problem:
            back = str(selection.get("previous") or "")
            say(f"a database restore was asked for, but {problem}; staying on {back or 'it'}")
            record_event(
                self.paths,
                {
                    "type": "restore_failed",
                    "backup": str(selection.get("restore")),
                    "detail": problem,
                    "to": str(selection.get("version") or BUILT_IN),
                    "runs": back or None,
                },
            )
            if back:
                selection.update(
                    {"version": back, "previous": selection.get("version"), "trial": False}
                )
        selection["restore"] = None
        try_write_json(self.paths.selection, selection)

    def take_request(self) -> dict[str, Any] | None:
        request = read_json(self.paths.request)
        if request is None and not self.nudged:
            return None
        if isinstance(request, dict):
            try:
                wait = float(request.get("not_before") or 0) - self.wall()
            except (TypeError, ValueError):
                wait = 0.0
            if 0 < wait <= MAX_REQUEST_DELAY:
                # The app's answer to the browser goes out first; polled again soon.
                return None
        self.nudged = False
        try:
            self.paths.request.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            say(f"could not remove the request ({exc}); acting on it once")
        if not isinstance(request, dict):
            return None
        return request

    def handle_request(self, request: dict[str, Any]) -> None:
        kind = "restart" if request.get("kind") == "restart" else "switch"
        before = self.current.version if self.current else ""
        say(f"{kind} requested by {request.get('by') or 'the app'}")
        self.stop_child()
        self.apply_pending_restore()
        target = self.choose()
        record_event(
            self.paths,
            {"type": kind, "from": before, "to": target.version, "by": request.get("by") or ""},
        )
        self.start(target)

    # -- one step of the loop (tests drive this directly)

    def tick(self) -> None:
        if self.stopping:
            code = self.stop_child()
            self.exit_code = 0 if code is None or code < 0 else code
            return
        if self.child is None:
            if self.restart_at is not None and self.clock() >= self.restart_at:
                assert self.current is not None
                self.start(self.current)
            return
        code = self.child.poll()
        target = self.current
        assert target is not None
        if code is not None:
            self.child = None
            if target.trial:
                self.rollback(f"it stopped with exit code {code} before answering its health check")
                return
            moment = self.clock()
            self.crashes = [t for t in self.crashes if moment - t < CRASH_WINDOW] + [moment]
            if target.source == "installed" and len(self.crashes) >= CRASH_LIMIT:
                record_event(self.paths, {"type": "crash", "version": target.version, "code": code})
                self.crashes = []
                self.rollback(
                    f"it stopped {CRASH_LIMIT} times within {int(CRASH_WINDOW // 60)} minutes "
                    f"(last exit code {code})",
                    allow_restore=False,
                )
                return
            pause = min(30.0, float(2 ** (len(self.crashes) - 1)))
            say(f"{target.version} stopped unexpectedly (exit code {code}); restarting in {pause}s")
            record_event(self.paths, {"type": "crash", "version": target.version, "code": code})
            self.restart_at = moment + pause
            return
        if not self.healthy:
            if self.probe(self.port, target.version):
                self.confirm()
            elif target.trial and self.clock() - self.started_at > self.start_timeout:
                self.rollback(
                    f"it did not answer its health check within {int(self.start_timeout)}s"
                )
                return
        request = self.take_request()
        if request is not None:
            self.handle_request(request)

    def run(self, poll: float = 1.0) -> int:
        def stop(_signum: int, _frame: object) -> None:
            self.stopping = True

        def nudge(_signum: int, _frame: object) -> None:
            self.nudged = True

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        signal.signal(signal.SIGUSR1, nudge)
        stale = read_json(self.paths.request)
        if stale is not None:
            # Asked of the previous container: this start already applies it.
            with contextlib.suppress(OSError):
                self.paths.request.unlink()
        try:
            self.apply_pending_restore()
            target = self.choose()
        except OSError as exc:  # a full or read-only data volume: never a crash loop
            say(f"the data volume cannot be used ({exc}); running the image's own version")
            target = self.builtin_target("the data volume could not be used")
        self.start(target)
        while self.exit_code is None:
            self.tick()
            if self.exit_code is None:
                self.sleep(poll)
        return self.exit_code


def image_public_key(builtin_dir: Path) -> str | None:
    """The release signing key of the image: CXCG_UPDATE_PUBLIC_KEY, else the image's
    own ``/app/app/updates/release-signing-key.pub``. Never the data volume's."""
    from_env = os.environ.get(PUBLIC_KEY_ENV, "").strip()
    if from_env:
        return load_public_key_text(from_env)
    try:
        return load_public_key_text((builtin_dir / PUBLIC_KEY_REL).read_text(encoding="utf-8"))
    except OSError:
        return None


def image_info_from_environment() -> ImageInfo:
    builtin_dir = Path(os.environ.get("CXCG_BUILTIN_DIR") or "/app")
    info = read_json(Path(os.environ.get("CXCG_IMAGE_INFO") or IMAGE_INFO_PATH), {}) or {}
    return ImageInfo(
        builtin_dir=builtin_dir,
        builtin_version=version_of_tree(builtin_dir) or "0.0.0",
        deps_hash=str(info.get("deps_hash") or ""),
        public_key_pem=image_public_key(builtin_dir),
    )


def serve(app_dir: Path, host: str, port: int, *, dry_run: bool = False) -> int:
    """Run the app from ``app_dir`` in this (isolated, ``-I -B``) interpreter.

    The folder is appended to ``sys.path``, after the standard library and the
    image's packages, and must be where ``app`` is imported from: a module of
    the same name as anything else can never shadow it.
    """
    root = app_dir.resolve()
    sys.path[:] = [p for p in sys.path if p not in ("", ".")]
    sys.path.append(str(root))
    spec = importlib.util.find_spec("app")
    origin = Path(spec.origin).resolve() if spec is not None and spec.origin else None
    if origin != root / "app" / "__init__.py":
        say(f"refusing to start: the app package resolves to {origin}, not {root}")
        return 3
    if dry_run:
        print(json.dumps({"sys_path": sys.path, "app": str(origin)}))
        return 0
    import uvicorn  # the image's own, from site-packages

    uvicorn.run("app.main:app", host=host, port=port, proxy_headers=False)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("run", help="run the selected app version (the default)")
    serving = sub.add_parser("serve", help="(used by run) serve one app folder")
    serving.add_argument("--app-dir", type=Path, required=True)
    serving.add_argument("--host", default="0.0.0.0")  # noqa: S104 - the container's own
    serving.add_argument("--port", type=int, default=8000)
    serving.add_argument("--no-proxy-headers", action="store_true")
    serving.add_argument("--dry-run", action="store_true")
    for name in ("deps-hash", "image-info"):
        cmd = sub.add_parser(name)
        cmd.add_argument("--constraints", type=Path, required=True)
        cmd.add_argument("--pyproject", type=Path, required=True)
        cmd.add_argument("--base-image", required=True)
        cmd.add_argument("--entrypoint", type=Path, required=True)
        cmd.add_argument("--launcher", type=Path, default=Path(__file__))
        # The OS packages installed on the base (``apk info -v``), one per line.
        cmd.add_argument("--os-packages", type=Path, default=None)
        if name == "image-info":
            cmd.add_argument("--write", type=Path, required=True)
            # When the OS packages were installed (ISO 8601, UTC): the image's age.
            cmd.add_argument("--created", default="")
    args = parser.parse_args(argv)

    if args.command == "serve":
        return serve(args.app_dir, args.host, args.port, dry_run=args.dry_run)

    if args.command in ("deps-hash", "image-info"):
        value = deps_hash_from_paths(
            constraints=args.constraints,
            pyproject=args.pyproject,
            base_image=args.base_image,
            launcher=args.launcher,
            entrypoint=args.entrypoint,
            os_packages=args.os_packages,
        )
        if args.command == "deps-hash":
            print(value)
        else:
            args.write.parent.mkdir(parents=True, exist_ok=True)
            args.write.write_text(
                json.dumps(
                    {
                        "protocol": PROTOCOL,
                        "deps_hash": value,
                        "base_image": args.base_image,
                        "created": args.created.strip() or now_iso(),
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
        return 0

    # Private files (0600) and folders (0700) whatever umask the entrypoint left:
    # a umask without the owner's execute bit would make new folders unusable.
    os.umask(0o077)
    paths = Paths(Path(os.environ.get("CXCG_DATA_DIR") or "/app/data"))
    for folder in (paths.updates, paths.versions, paths.backups):
        with contextlib.suppress(OSError):
            if folder.is_dir() and not folder.is_symlink():
                folder.chmod(0o700)
    launcher = Launcher(
        paths=paths,
        image=image_info_from_environment(),
        port=int(os.environ.get("CXCG_PORT") or 8000),
        host=os.environ.get("CXCG_HOST") or "0.0.0.0",  # noqa: S104
        start_timeout=float(os.environ.get("CXCG_UPDATE_START_TIMEOUT") or 180),
        database_url=os.environ.get("CXCG_DATABASE_URL") or DEFAULT_DATABASE_URL,
    )
    say(
        f"image {launcher.image.builtin_version}, "
        f"deps {launcher.image.deps_hash[:12] or 'unknown'}, data {launcher.paths.data}"
    )
    return launcher.run()


if __name__ == "__main__":
    sys.exit(main())
