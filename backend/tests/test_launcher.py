"""The launcher's decisions (cxcg_launcher.py), driven without real servers:
which version runs, trial and automatic rollback, the database restore, and
switching on request. Child processes and health probes are fakes."""

from __future__ import annotations

import base64
import hashlib
import json
import py_compile
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

import cxcg_launcher as L
from app.updates.manifest import manifest_bytes, sign
from tests.fake_registry import app_files, ed25519_keypair

BUILTIN = "1.0.0"
NEW = "1.1.0"


def write_tree(
    root: Path,
    version: str,
    *,
    deps: str = "deps-1",
    migrations=("aaa",),
    private_key: bytes | None = None,
) -> Path:
    files = app_files(version, migrations=migrations)
    for rel, data in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    manifest = {
        "format": 1,
        "version": version,
        "revision": "",
        "deps_hash": deps,
        "files": {rel: hashlib.sha256(data).hexdigest() for rel, data in files.items()},
    }
    raw = manifest_bytes(manifest)
    (root / L.MANIFEST_FILE).write_bytes(raw)
    if private_key is not None:
        (root / L.SIGNATURE_FILE).write_text(sign(raw, private_key) + "\n")
    return root


@pytest.fixture
def setup(tmp_path: Path) -> tuple[L.Paths, L.ImageInfo]:
    builtin = write_tree(tmp_path / "image-app", BUILTIN)
    paths = L.Paths(tmp_path / "data")
    return paths, L.ImageInfo(builtin, BUILTIN, "deps-1")


def install(
    paths: L.Paths,
    version: str,
    *,
    deps: str = "deps-1",
    migrations=("aaa",),
    private_key: bytes | None = None,
) -> Path:
    root = write_tree(
        paths.versions / version, version, deps=deps, migrations=migrations, private_key=private_key
    )
    (root / L.VERSION_FILE).write_text(json.dumps({"version": version, "deps_hash": deps}))
    return root


def select(paths: L.Paths, version: str, **extra: Any) -> None:
    L.write_json_atomic(
        paths.selection,
        {
            "version": version,
            "previous": "built-in",
            "trial": True,
            "builtin_version": BUILTIN,
            **extra,
        },
    )


def events(paths: L.Paths) -> list[dict[str, Any]]:
    try:
        return [json.loads(line) for line in paths.events.read_text().splitlines()]
    except FileNotFoundError:
        return []


class FakeProcess:
    def __init__(self, cmd: list[str], **_kw: Any) -> None:
        self.cmd = cmd
        self.code: int | None = None
        self.signals: list[int] = []

    def poll(self) -> int | None:
        return self.code

    def send_signal(self, sig: int) -> None:
        self.signals.append(sig)
        self.code = 0

    def wait(self, timeout: float | None = None) -> int:
        if self.code is None:
            raise subprocess.TimeoutExpired(self.cmd, timeout or 0)
        return self.code

    def kill(self) -> None:
        self.code = -9

    @property
    def app_dir(self) -> str:
        return self.cmd[self.cmd.index("--app-dir") + 1]


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def make_launcher(
    paths: L.Paths, image: L.ImageInfo, *, healthy: set[str] | None = None, **kw: Any
):
    processes: list[FakeProcess] = []
    clock = Clock()
    ok = healthy if healthy is not None else set()

    def spawn(cmd: list[str], **kwargs: Any) -> FakeProcess:
        process = FakeProcess(cmd, **kwargs)
        processes.append(process)
        return process

    launcher = L.Launcher(
        paths=paths,
        image=image,
        spawn=spawn,
        probe=lambda _port, version: version in ok,
        clock=clock,
        sleep=lambda _s: None,
        start_timeout=60,
        **kw,
    )
    return launcher, processes, clock


# ------------------------------------------------------------------ selection


class TestChooseTarget:
    def test_no_selection_runs_the_image(self, setup: tuple[L.Paths, L.ImageInfo]) -> None:
        paths, image = setup
        target = L.choose_target(paths, image)
        assert (target.source, target.version) == ("built-in", BUILTIN)

    def test_a_selected_installed_version_runs(self, setup: tuple[L.Paths, L.ImageInfo]) -> None:
        paths, image = setup
        install(paths, NEW)
        select(paths, NEW)
        target = L.choose_target(paths, image)
        assert (target.source, target.version, target.trial) == ("installed", NEW, True)

    def test_other_dependencies_fall_back_to_the_image(
        self, setup: tuple[L.Paths, L.ImageInfo]
    ) -> None:
        paths, image = setup
        install(paths, NEW, deps="deps-2")
        select(paths, NEW)
        target = L.choose_target(paths, image)
        assert target.source == "built-in" and "different dependencies" in target.reason

    def test_changed_files_fall_back_to_the_image(self, setup: tuple[L.Paths, L.ImageInfo]) -> None:
        paths, image = setup
        root = install(paths, NEW)
        (root / "app" / "main.py").write_text("tampered = True\n")
        select(paths, NEW)
        target = L.choose_target(paths, image)
        assert target.source == "built-in" and "changed" in target.reason

    def test_an_image_replaced_with_a_newer_one_wins(
        self, setup: tuple[L.Paths, L.ImageInfo]
    ) -> None:
        paths, image = setup
        install(paths, NEW)
        select(paths, NEW, builtin_version="0.9.0")
        newer_image = L.ImageInfo(image.builtin_dir, "1.2.0", image.deps_hash)
        assert L.choose_target(paths, newer_image).source == "built-in"
        # A replaced image that is older than the installed version keeps the version.
        older_image = L.ImageInfo(image.builtin_dir, "1.0.5", image.deps_hash)
        assert L.choose_target(paths, older_image).version == NEW


class TestDepsHash:
    def test_stable_across_line_endings_and_sensitive_to_pins(self) -> None:
        pyproject = b'[project]\nname="x"\ndependencies=["fastapi>=1"]\n'
        files = {"launcher": b"a\n", "entrypoint": b"b\n"}
        one = L.deps_hash(
            constraints=b"fastapi==1.0\n", pyproject=pyproject, base_image="py", files=files
        )
        crlf = L.deps_hash(
            constraints=b"# pins\r\nfastapi==1.0\r\n",
            pyproject=pyproject.replace(b"\n", b"\r\n"),
            base_image="py",
            files={k: v.replace(b"\n", b"\r\n") for k, v in files.items()},
        )
        assert one == crlf
        assert one != L.deps_hash(
            constraints=b"fastapi==1.1\n", pyproject=pyproject, base_image="py", files=files
        )
        assert one != L.deps_hash(
            constraints=b"fastapi==1.0\n", pyproject=pyproject, base_image="py2", files=files
        )

    def test_the_repository_files_hash(self) -> None:
        backend = Path(__file__).resolve().parents[1]
        value = L.deps_hash_from_paths(
            constraints=backend / "constraints.txt",
            pyproject=backend / "pyproject.toml",
            base_image="python:3.11-alpine",
            launcher=backend / "cxcg_launcher.py",
            entrypoint=backend.parent / "deploy" / "podman" / "easy-entrypoint.sh",
        )
        assert len(value) == 64


# ------------------------------------------------------------------- the loop


def sqlite_db(path: Path, revision: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS alembic_version (version_num TEXT)")
        conn.execute("DELETE FROM alembic_version")
        conn.execute("INSERT INTO alembic_version VALUES (?)", (revision,))
        conn.execute("CREATE TABLE IF NOT EXISTS marker (value TEXT)")
        conn.execute("DELETE FROM marker")
        conn.execute("INSERT INTO marker VALUES (?)", (revision,))


class TestTrialAndRollback:
    def test_healthy_new_version_is_confirmed(self, setup: tuple[L.Paths, L.ImageInfo]) -> None:
        paths, image = setup
        install(paths, NEW)
        select(paths, NEW)
        launcher, processes, _clock = make_launcher(paths, image, healthy={NEW})
        launcher.start(launcher.choose())
        launcher.tick()
        assert launcher.healthy
        assert L.read_json(paths.selection)["trial"] is False
        assert [e["type"] for e in events(paths)] == ["started"]
        assert processes[0].app_dir == str(paths.versions / NEW)

    def test_not_healthy_in_time_rolls_back_and_marks_the_version_failed(
        self, setup: tuple[L.Paths, L.ImageInfo]
    ) -> None:
        paths, image = setup
        install(paths, NEW)
        select(paths, NEW)
        launcher, processes, clock = make_launcher(paths, image, healthy={BUILTIN})
        launcher.start(launcher.choose())
        launcher.tick()
        assert not launcher.healthy
        clock.now += 61
        launcher.tick()
        assert processes[0].signals, "the failing version was not stopped"
        assert processes[1].app_dir == str(image.builtin_dir)
        assert NEW in L.read_json(paths.failed)
        selection = L.read_json(paths.selection)
        assert selection["version"] == "built-in" and selection["trial"] is False
        rollback = [e for e in events(paths) if e["type"] == "rollback"][0]
        assert rollback["from"] == NEW and rollback["to"] == "built-in"
        assert rollback["restored_backup"] is None

    def test_exit_during_trial_rolls_back(self, setup: tuple[L.Paths, L.ImageInfo]) -> None:
        paths, image = setup
        install(paths, NEW)
        select(paths, NEW)
        launcher, processes, _clock = make_launcher(paths, image)
        launcher.start(launcher.choose())
        processes[0].code = 3
        launcher.tick()
        assert len(processes) == 2 and processes[1].app_dir == str(image.builtin_dir)
        assert "exit code 3" in L.read_json(paths.failed)[NEW]["reason"]

    def test_rollback_restores_the_backup_when_the_schema_changed(
        self, setup: tuple[L.Paths, L.ImageInfo], tmp_path: Path
    ) -> None:
        paths, image = setup
        db = tmp_path / "data" / "cxcreditguard.db"
        sqlite_db(db, "aaa")
        paths.backups.mkdir(parents=True)
        backup = paths.backups / "pre-update-x.sqlite3"
        backup.write_bytes(db.read_bytes())
        install(paths, NEW, migrations=("aaa", "bbb"))
        select(
            paths,
            NEW,
            pre_update={"db_kind": "sqlite", "backup": str(backup), "db_revision": "aaa"},
        )
        launcher, processes, clock = make_launcher(paths, image, database_url=f"sqlite:///{db}")
        launcher.start(launcher.choose())
        sqlite_db(db, "bbb")  # the new version migrated, then hung
        clock.now += 61
        launcher.tick()
        assert L.db_revision(db) == "aaa"
        rollback = [e for e in events(paths) if e["type"] == "rollback"][0]
        assert rollback["restored_backup"] == str(backup.resolve())
        kept = Path(rollback["replaced_database_kept_at"])
        assert kept.is_file() and L.db_revision(kept) == "bbb"

    def test_schema_unchanged_keeps_the_database(
        self, setup: tuple[L.Paths, L.ImageInfo], tmp_path: Path
    ) -> None:
        paths, image = setup
        db = tmp_path / "data" / "cxcreditguard.db"
        sqlite_db(db, "aaa")
        paths.backups.mkdir(parents=True)
        backup = paths.backups / "pre-update-x.sqlite3"
        backup.write_bytes(db.read_bytes())
        with sqlite3.connect(db) as conn:
            conn.execute("UPDATE marker SET value = 'written after the backup'")
        install(paths, NEW)
        select(
            paths,
            NEW,
            pre_update={"db_kind": "sqlite", "backup": str(backup), "db_revision": "aaa"},
        )
        launcher, _processes, clock = make_launcher(paths, image, database_url=f"sqlite:///{db}")
        launcher.start(launcher.choose())
        clock.now += 61
        launcher.tick()
        with sqlite3.connect(db) as conn:
            assert (
                conn.execute("SELECT value FROM marker").fetchone()[0] == "written after the backup"
            )

    def test_no_backup_after_a_schema_change_blocks_the_rollback(
        self, setup: tuple[L.Paths, L.ImageInfo]
    ) -> None:
        paths, image = setup
        install(paths, NEW, migrations=("aaa", "bbb"))
        select(paths, NEW, pre_update={"db_kind": "postgresql", "backup": None})
        launcher, processes, clock = make_launcher(
            paths, image, database_url="postgresql+psycopg://x@db/x"
        )
        launcher.start(launcher.choose())
        clock.now += 61
        launcher.tick()
        assert [e["type"] for e in events(paths)] == ["rollback_blocked"]
        assert processes[-1].app_dir == str(paths.versions / NEW)
        assert NEW in L.read_json(paths.failed)

    def test_a_backup_outside_the_backups_folder_is_never_used(
        self, setup: tuple[L.Paths, L.ImageInfo], tmp_path: Path
    ) -> None:
        paths, _image = setup
        outside = tmp_path / "evil.sqlite3"
        outside.write_bytes(b"x")
        paths.backups.mkdir(parents=True)
        assert L.safe_backup(paths, str(outside)) is None
        assert L.safe_backup(paths, str(paths.backups / ".." / "evil.sqlite3")) is None


class TestRequestsAndStop:
    def test_switch_request_restarts_into_the_selection(
        self, setup: tuple[L.Paths, L.ImageInfo]
    ) -> None:
        paths, image = setup
        launcher, processes, _clock = make_launcher(paths, image, healthy={BUILTIN, NEW})
        launcher.start(launcher.choose())
        launcher.tick()
        install(paths, NEW)
        select(paths, NEW)
        L.write_json_atomic(paths.request, {"kind": "switch", "by": "admin"})
        launcher.tick()
        assert processes[0].signals and processes[1].app_dir == str(paths.versions / NEW)
        assert launcher.current is not None and launcher.current.trial
        assert not paths.request.exists()
        launcher.tick()
        assert launcher.healthy and L.read_json(paths.selection)["trial"] is False

    def test_manual_rollback_restore_is_applied_before_starting(
        self, setup: tuple[L.Paths, L.ImageInfo], tmp_path: Path
    ) -> None:
        paths, image = setup
        db = tmp_path / "data" / "cxcreditguard.db"
        sqlite_db(db, "aaa")
        paths.backups.mkdir(parents=True)
        backup = paths.backups / "pre-update-x.sqlite3"
        backup.write_bytes(db.read_bytes())
        sqlite_db(db, "bbb")
        install(paths, NEW, migrations=("aaa", "bbb"))
        select(paths, NEW, trial=False)
        launcher, processes, _clock = make_launcher(
            paths, image, healthy={BUILTIN, NEW}, database_url=f"sqlite:///{db}"
        )
        launcher.start(launcher.choose())
        L.write_json_atomic(
            paths.selection,
            {"version": "built-in", "previous": NEW, "trial": True, "restore": str(backup)},
        )
        L.write_json_atomic(paths.request, {"kind": "switch", "by": "admin"})
        launcher.tick()
        assert L.db_revision(db) == "aaa"
        assert processes[-1].app_dir == str(image.builtin_dir)
        assert L.read_json(paths.selection)["restore"] is None
        assert "restore" in [e["type"] for e in events(paths)]

    def test_crash_outside_a_trial_restarts_with_a_pause(
        self, setup: tuple[L.Paths, L.ImageInfo]
    ) -> None:
        paths, image = setup
        launcher, processes, clock = make_launcher(paths, image, healthy={BUILTIN})
        launcher.start(launcher.choose())
        launcher.tick()
        processes[0].code = 1
        launcher.tick()
        assert len(processes) == 1 and launcher.restart_at is not None
        clock.now += 2
        launcher.tick()
        assert len(processes) == 2
        assert [e["type"] for e in events(paths)] == ["crash"]

    def test_stop_passes_the_signal_and_exits(self, setup: tuple[L.Paths, L.ImageInfo]) -> None:
        paths, image = setup
        launcher, processes, _clock = make_launcher(paths, image, healthy={BUILTIN})
        launcher.start(launcher.choose())
        launcher.stopping = True
        launcher.tick()
        assert processes[0].signals and launcher.exit_code == 0

    def test_child_environment_points_at_the_selected_version(
        self, setup: tuple[L.Paths, L.ImageInfo]
    ) -> None:
        paths, image = setup
        install(paths, NEW)
        select(paths, NEW)
        launcher, _processes, _clock = make_launcher(paths, image)
        target = launcher.choose()
        env = launcher.environment(target)
        assert env["CXCG_LAUNCHER"] == "1" and env["CXCG_RUNNING_SOURCE"] == "installed"
        # Never PYTHONPATH: the version's folder is only appended for the app package.
        assert "PYTHONPATH" not in env
        assert env["PYTHONDONTWRITEBYTECODE"] == "1" and env["PYTHONSAFEPATH"] == "1"
        assert env["CXCG_IMAGE_DEPS_HASH"] == "deps-1"
        command = launcher.command(target)
        assert command[1:6] == ["-I", "-B", "-X", f"pycache_prefix={L.NO_BYTECODE_PREFIX}", "-u"]
        assert "serve" in command and env["PYTHONPYCACHEPREFIX"] == L.NO_BYTECODE_PREFIX
        assert command[command.index("--app-dir") + 1] == str(paths.versions / NEW)
        assert command[-1] == "--no-proxy-headers"


# --------------------------------------------------- security review findings


class TestOnlyTheManifestRuns:
    def test_bytecode_and_unlisted_files_refuse_the_version_and_mark_it_failed(
        self, setup: tuple[L.Paths, L.ImageInfo]
    ) -> None:
        paths, image = setup
        tag = sys.implementation.cache_tag
        for planted in ("sitecustomize.pyc", f"app/__pycache__/main.{tag}.pyc", "app/x.pth"):
            root = install(paths, NEW)
            path = root / planted
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"\0")
            assert any(planted in problem for problem in L.tree_problems(root)), planted
            select(paths, NEW)
            launcher, processes, _clock = make_launcher(paths, image)
            launcher.start(launcher.choose())
            assert processes[-1].app_dir == str(image.builtin_dir), planted
            assert NEW in L.read_json(paths.failed)
            ignored = [e for e in events(paths) if e["type"] == "selection_ignored"][-1]
            assert ignored["refused"] is True
            path.unlink()
            paths.failed.unlink()

    def test_a_linked_folder_is_refused(self, setup: tuple[L.Paths, L.ImageInfo]) -> None:
        paths, _image = setup
        root = install(paths, NEW)
        (root / "app" / "linked").symlink_to(root.parent)
        assert any("linked" in problem for problem in L.tree_problems(root))

    def test_the_signature_is_checked_against_the_images_key(
        self, setup: tuple[L.Paths, L.ImageInfo]
    ) -> None:
        paths, image = setup
        private, public = ed25519_keypair()
        other, _ = ed25519_keypair()
        keyed = L.ImageInfo(image.builtin_dir, image.builtin_version, image.deps_hash, public)
        install(paths, NEW, private_key=private)
        select(paths, NEW)
        assert L.choose_target(paths, keyed).source == "installed"
        install(paths, NEW, private_key=other)
        target = L.choose_target(paths, keyed)
        assert target.source == "built-in" and "signature does not match" in target.reason
        (paths.versions / NEW / L.SIGNATURE_FILE).unlink()
        target = L.choose_target(paths, keyed)
        assert target.source == "built-in" and "not signed" in target.reason
        # No key in the image: the manifest's own consistency is what is checked.
        assert L.choose_target(paths, image).source == "installed"

    def test_the_key_is_read_from_the_image_or_the_environment(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _private, public = ed25519_keypair()
        image = tmp_path / "image"
        (image / "app" / "updates").mkdir(parents=True)
        (image / "app" / "updates" / "release-signing-key.pub").write_text("# placeholder\n")
        monkeypatch.delenv(L.PUBLIC_KEY_ENV, raising=False)
        assert L.image_public_key(image) is None
        (image / "app" / "updates" / "release-signing-key.pub").write_text("# key\n" + public)
        assert "BEGIN PUBLIC KEY" in (L.image_public_key(image) or "")
        monkeypatch.setenv(L.PUBLIC_KEY_ENV, public)
        assert L.image_public_key(tmp_path / "nowhere") is not None

    def test_the_version_folder_comes_after_the_standard_library(self, tmp_path: Path) -> None:
        root = tmp_path / "version"
        (root / "app").mkdir(parents=True)
        (root / "app" / "__init__.py").write_text('__version__ = "1.1.0"\n')
        marker = tmp_path / "ran"
        (root / "json.py").write_text(f"open({str(marker)!r}, 'w')\n")
        (root / "sitecustomize.py").write_text(f"open({str(marker)!r}, 'w')\n")
        command = [
            sys.executable,
            "-I",
            "-B",
            str(Path(L.__file__).resolve()),
            "serve",
            "--app-dir",
            str(root),
            "--dry-run",
        ]
        result = subprocess.run(  # noqa: S603 - this interpreter, the launcher's own command
            command, cwd=str(root), capture_output=True, text=True, check=True
        )
        shown = json.loads(result.stdout.strip().splitlines()[-1])
        assert not marker.exists()
        assert shown["sys_path"][-1] == str(root.resolve())
        assert shown["app"] == str((root / "app" / "__init__.py").resolve())
        assert not list(root.rglob("__pycache__"))


class TestRestoreKeepsEverything:
    def test_restore_removes_the_wal_first_and_keeps_its_data(self, tmp_path: Path) -> None:
        paths = L.Paths(tmp_path / "data")
        paths.backups.mkdir(parents=True)
        db = tmp_path / "data" / "app.db"
        conn = sqlite3.connect(db)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA wal_autocheckpoint=0")
        conn.execute("CREATE TABLE t (x)")
        conn.execute("INSERT INTO t VALUES (1)")
        conn.commit()
        backup = paths.backups / "pre-update-x.sqlite3"
        copy = sqlite3.connect(backup)
        conn.backup(copy)
        copy.close()
        conn.execute("INSERT INTO t VALUES (2)")
        conn.commit()
        # A killed app: the WAL was never checkpointed. The files as they are on disk.
        snap = tmp_path / "snap"
        snap.mkdir()
        for suffix in ("", "-wal"):
            (snap / f"app.db{suffix}").write_bytes(Path(str(db) + suffix).read_bytes())
        conn.close()
        db.unlink()
        for suffix in ("", "-wal"):
            Path(str(db) + suffix).write_bytes((snap / f"app.db{suffix}").read_bytes())
        kept = L.restore_sqlite(paths, backup, db)
        assert kept is not None
        # The replaced database is kept WITH what was only in its WAL...
        with contextlib_closing(sqlite3.connect(kept)) as check:
            assert check.execute("SELECT x FROM t ORDER BY x").fetchall() == [(1,), (2,)]
        # ...and the restored one is exactly the backup: the old WAL was not replayed.
        assert not Path(str(db) + "-wal").exists()
        with contextlib_closing(sqlite3.connect(db)) as check:
            assert check.execute("SELECT x FROM t ORDER BY x").fetchall() == [(1,)]


def contextlib_closing(conn: sqlite3.Connection):
    import contextlib

    return contextlib.closing(conn)


class TestLauncherRobustness:
    def test_probe_host(self) -> None:
        assert L.probe_host("0.0.0.0") == "127.0.0.1"  # noqa: S104 - not a bind
        assert L.probe_host("::") == "127.0.0.1"
        assert L.probe_host("") == "127.0.0.1"
        assert L.probe_host("10.1.2.3") == "10.1.2.3"
        launcher = L.Launcher(
            paths=L.Paths(Path("/nonexistent")),
            image=L.ImageInfo(Path("/app"), "1.0.0", ""),
            host="10.1.2.3",
        )
        assert launcher.probe.keywords == {"host": "10.1.2.3"}  # type: ignore[attr-defined]

    def test_a_full_data_volume_never_stops_the_launcher(
        self, setup: tuple[L.Paths, L.ImageInfo], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        paths, image = setup
        install(paths, NEW)
        select(paths, NEW)

        def full(*_args: Any, **_kwargs: Any) -> None:
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(L, "write_json_atomic", full)
        launcher, processes, clock = make_launcher(paths, image)
        launcher.start(launcher.choose())
        clock.now += 61
        launcher.tick()  # the trial fails; nothing can be written; the image's own runs
        assert processes[-1].app_dir == str(image.builtin_dir)
        assert launcher.current is not None and launcher.current.source == "built-in"

    def test_an_unreadable_selection_runs_the_image(
        self, setup: tuple[L.Paths, L.ImageInfo]
    ) -> None:
        paths, image = setup
        paths.selection.mkdir(parents=True)  # a folder where a file should be
        launcher, processes, _clock = make_launcher(paths, image, healthy={BUILTIN})
        launcher.start(launcher.choose())
        launcher.tick()
        assert launcher.healthy and processes[0].app_dir == str(image.builtin_dir)

    def test_a_version_that_keeps_crashing_is_rolled_back(
        self, setup: tuple[L.Paths, L.ImageInfo]
    ) -> None:
        paths, image = setup
        install(paths, NEW)
        select(paths, NEW)
        launcher, processes, clock = make_launcher(paths, image, healthy={NEW, BUILTIN})
        launcher.start(launcher.choose())
        launcher.tick()
        assert launcher.healthy and not launcher.current.trial  # type: ignore[union-attr]
        for _ in range(L.CRASH_LIMIT):
            processes[-1].code = 1
            launcher.tick()
            clock.now += 31
            launcher.tick()
        assert processes[-1].app_dir == str(image.builtin_dir)
        assert "times within" in L.read_json(paths.failed)[NEW]["reason"]
        assert L.read_json(paths.selection)["version"] == "built-in"

    def test_a_crash_loop_never_restores_a_backup_by_itself(
        self, setup: tuple[L.Paths, L.ImageInfo], tmp_path: Path
    ) -> None:
        paths, image = setup
        db = tmp_path / "data" / "cxcreditguard.db"
        sqlite_db(db, "aaa")
        paths.backups.mkdir(parents=True)
        backup = paths.backups / "pre-update-x.sqlite3"
        backup.write_bytes(db.read_bytes())
        install(paths, NEW, migrations=("aaa", "bbb"))
        select(
            paths,
            NEW,
            pre_update={"db_kind": "sqlite", "backup": str(backup), "db_revision": "aaa"},
        )
        launcher, processes, clock = make_launcher(
            paths, image, healthy={NEW}, database_url=f"sqlite:///{db}"
        )
        launcher.start(launcher.choose())
        launcher.tick()
        sqlite_db(db, "bbb")
        for _ in range(L.CRASH_LIMIT):
            processes[-1].code = 1
            launcher.tick()
            clock.now += 31
            launcher.tick()
        assert L.db_revision(db) == "bbb"
        assert [e["type"] for e in events(paths)][-1] == "rollback_blocked"
        assert processes[-1].app_dir == str(paths.versions / NEW)

    def test_a_request_waits_for_its_not_before(self, setup: tuple[L.Paths, L.ImageInfo]) -> None:
        paths, image = setup
        launcher, processes, _clock = make_launcher(paths, image, healthy={BUILTIN})
        now = [5000.0]
        launcher.wall = lambda: now[0]
        launcher.start(launcher.choose())
        launcher.tick()
        L.write_json_atomic(paths.request, {"kind": "restart", "by": "admin", "not_before": 5001.5})
        launcher.nudged = True
        launcher.tick()
        assert len(processes) == 1 and paths.request.exists()
        now[0] = 5002.0
        launcher.tick()
        assert len(processes) == 2 and not paths.request.exists()

    def test_os_packages_are_part_of_the_dependency_hash(self) -> None:
        pyproject = b'[project]\nname="x"\ndependencies=["fastapi>=1"]\n'
        files = {"launcher": b"a\n", "entrypoint": b"b\n"}
        base = {"constraints": b"x==1\n", "pyproject": pyproject, "files": files}
        one = L.deps_hash(base_image="py@sha256:1", os_packages=b"libpq-17.1-r0\n", **base)
        assert one != L.deps_hash(base_image="py@sha256:1", os_packages=b"libpq-17.2-r0\n", **base)
        assert one != L.deps_hash(base_image="py@sha256:2", os_packages=b"libpq-17.1-r0\n", **base)


def test_signature_helpers_round_trip() -> None:
    private, public = ed25519_keypair()
    assert base64.b64decode(sign(b"x", private))
    assert L.load_public_key_text("# c\n" + public) is not None


# ------------------------------------------- follow-up security review findings

BACKEND = Path(__file__).resolve().parents[1]


class TestEveryStartIsVerified:
    def test_crash_restart_reverifies_the_installed_tree(
        self, setup: tuple[L.Paths, L.ImageInfo]
    ) -> None:
        paths, image = setup
        root = install(paths, NEW)
        select(paths, NEW)
        launcher, processes, clock = make_launcher(paths, image, healthy={NEW, BUILTIN})
        launcher.start(launcher.choose())
        launcher.tick()
        assert launcher.healthy and processes[-1].app_dir == str(root)
        # A file planted in the data volume after the launcher verified the tree.
        planted = root / "app" / "__pycache__" / f"main.{sys.implementation.cache_tag}.pyc"
        planted.parent.mkdir()
        planted.write_bytes(b"\0")
        processes[-1].code = 1  # the app crashes (or is made to)
        launcher.tick()
        clock.now += 31
        launcher.tick()
        assert len(processes) == 2
        # The restart checks the files again and refuses the tree.
        assert processes[-1].app_dir == str(image.builtin_dir), "restarted an unverified tree"
        assert NEW in L.read_json(paths.failed)

    def test_planted_unchecked_hash_bytecode_is_never_read(self, tmp_path: Path) -> None:
        """-I -B never WRITES bytecode but still reads it; the app's flags read none."""
        pkg = tmp_path / "v" / "app"
        pkg.mkdir(parents=True)
        (pkg / "__init__.py").write_text("")
        (pkg / "main.py").write_text("WHO = 'verified source'\n")
        evil = tmp_path / "evil.py"
        evil.write_text("WHO = 'planted bytecode'\n")
        target = pkg / "__pycache__" / f"main.{sys.implementation.cache_tag}.pyc"
        py_compile.compile(
            str(evil),
            cfile=str(target),
            invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
        )
        code = (
            f"import sys; sys.path.append({str(tmp_path / 'v')!r}); "
            "import app.main as m; print(m.WHO)"
        )

        def run(*flags: str) -> str:
            return subprocess.run(  # noqa: S603 - this interpreter
                [sys.executable, *flags, "-c", code], capture_output=True, text=True, check=True
            ).stdout.strip()

        assert run("-I", "-B") == "planted bytecode"  # what the pyc would do without the prefix
        flags = [f for f in L.INTERPRETER_FLAGS if f != "-u"]
        assert run(*flags) == "verified source"

    def test_the_app_runs_from_a_verified_read_only_copy(
        self, setup: tuple[L.Paths, L.ImageInfo], tmp_path: Path
    ) -> None:
        paths, image = setup
        root = install(paths, NEW)
        select(paths, NEW)
        run_root = tmp_path / "run"
        launcher, processes, clock = make_launcher(
            paths, image, healthy={NEW, BUILTIN}, run_root=run_root
        )
        launcher.start(launcher.choose())
        launcher.tick()
        copy = Path(processes[-1].app_dir)
        assert copy.parent == run_root and launcher.healthy
        listed = json.loads((root / L.MANIFEST_FILE).read_text())["files"]
        assert sorted(L.covered_files(copy)) == sorted(listed)
        assert (copy / L.MANIFEST_FILE).read_bytes() == (root / L.MANIFEST_FILE).read_bytes()
        assert (copy / "app" / "main.py").stat().st_mode & 0o777 == 0o400
        assert (copy / "app").stat().st_mode & 0o777 == 0o500
        assert run_root.stat().st_mode & 0o777 == 0o700
        # Written to the data volume after the check: never in what runs.
        (root / "app" / "late.py").write_text("raise SystemExit('planted')\n")
        assert not (copy / "app" / "late.py").exists()
        # ...and the next start (a crash here) checks again, refuses, removes the copy.
        processes[-1].code = 1
        launcher.tick()
        clock.now += 31
        launcher.tick()
        assert processes[-1].app_dir == str(image.builtin_dir)
        assert list(run_root.iterdir()) == []

    def test_a_file_changed_between_the_check_and_the_copy_is_refused(
        self, setup: tuple[L.Paths, L.ImageInfo], tmp_path: Path
    ) -> None:
        paths, image = setup
        root = install(paths, NEW)
        select(paths, NEW)
        launcher, processes, _clock = make_launcher(paths, image, run_root=tmp_path / "run")
        target = launcher.choose()
        assert target.source == "installed"
        (root / "app" / "main.py").write_text("app = 'swapped after the check'\n")
        launcher.start(target)
        assert processes[-1].app_dir == str(image.builtin_dir)
        assert "changed after they were checked" in L.read_json(paths.failed)[NEW]["reason"]
        assert list((tmp_path / "run").iterdir()) == []

    def test_nothing_is_imported_from_the_data_volume(self, tmp_path: Path) -> None:
        builtin = write_tree(tmp_path / "image-app", BUILTIN)
        data = builtin / "data"  # the data volume lives inside the image's own folder
        marker = tmp_path / "ran"
        payload = f"open({str(marker)!r}, 'w')\n"
        (data / "versions").mkdir(parents=True)
        (data / "__init__.py").write_text(payload)
        (data / "evil.py").write_text(payload)
        (builtin / "planted.py").write_text(payload)  # an optional import's name
        code = (
            "import importlib.util, json, sys\n"
            # The launcher loaded from its file: the backend folder is not on sys.path.
            f"spec = importlib.util.spec_from_file_location('L', {str(L.__file__)!r})\n"
            "L = sys.modules['L'] = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(L)\n"
            "from pathlib import Path\n"
            f"root = Path({str(builtin)!r})\n"
            "sys.path.append(str(root))\n"
            f"L.install_import_guard(root, Path({str(data)!r}))\n"
            "out = {}\n"
            "for name in ('data', 'data.evil', 'planted', 'app', 'app.main', 'json'):\n"
            "    try:\n"
            "        __import__(name)\n"
            "        out[name] = 'imported'\n"
            "    except ImportError:\n"
            "        out[name] = 'refused'\n"
            "print(json.dumps(out))\n"
        )
        result = subprocess.run(  # noqa: S603 - this interpreter
            [sys.executable, "-I", "-B", "-c", code], capture_output=True, text=True, check=True
        )
        shown = json.loads(result.stdout.strip().splitlines()[-1])
        assert shown == {
            "data": "refused",
            "data.evil": "refused",
            "planted": "refused",
            "app": "imported",
            "app.main": "imported",
            "json": "imported",
        }, shown
        assert not marker.exists()

    def test_serve_reads_no_bytecode(self, tmp_path: Path) -> None:
        root = write_tree(tmp_path / "version", NEW)
        launcher = L.Launcher(paths=L.Paths(tmp_path / "data"), image=L.ImageInfo(root, NEW, ""))
        command = launcher.command(L.Target(NEW, root, "installed", "test"))
        result = subprocess.run(  # noqa: S603 - the launcher's own command
            [*command[: command.index("--host")], "--dry-run"],
            cwd=str(root),
            capture_output=True,
            text=True,
            check=True,
        )
        shown = json.loads(result.stdout.strip().splitlines()[-1])
        assert shown["pycache_prefix"] == L.NO_BYTECODE_PREFIX and shown["dont_write_bytecode"]

    def test_migrations_do_not_put_the_builtin_tree_before_the_version(
        self, tmp_path: Path
    ) -> None:
        ignore = shutil.ignore_patterns("__pycache__", "static", "*.pyc")
        trees = {}
        for name in ("builtin", "version"):
            root = tmp_path / name
            root.mkdir()
            for part in ("app", "alembic", "scripts"):
                shutil.copytree(BACKEND / part, root / part, ignore=ignore)
            shutil.copy(BACKEND / "alembic.ini", root / "alembic.ini")
            (root / "scripts" / "which_tree.py").write_text(f"TREE = {name!r}\n")
            trees[name] = root
        code = (
            "import sys, json\n"
            f"sys.path.append({str(trees['version'])!r})\n"
            "import app.db.migrate as m\n"
            "from alembic.script import ScriptDirectory\n"
            "ScriptDirectory.from_config(m.alembic_config('sqlite://'))\n"
            "import scripts.which_tree as w\n"
            "print(json.dumps({'path0': sys.path[0], 'tree': w.TREE}))\n"
        )
        result = subprocess.run(  # noqa: S603 - same flags and cwd as the launcher's child
            # -E -P -B is -I without disabling the user site (this sandbox's packages
            # may live there; the image's are in the system site-packages).
            [sys.executable, "-E", "-P", "-B", "-c", code],
            cwd=str(trees["builtin"]),
            capture_output=True,
            text=True,
            env={"PATH": "/usr/bin:/bin", "CXCG_MASTER_KEY": "A" * 44},
        )
        assert result.returncode == 0, result.stderr[-2000:]
        shown = json.loads(result.stdout.strip().splitlines()[-1])
        # Nothing ahead of the standard library, and no import from the other tree.
        assert shown["path0"] not in (".", ""), shown
        assert shown["tree"] == "version", shown


class TestTheReleaseKey:
    def test_a_malformed_env_key_does_not_disable_the_images_key(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _private, public = ed25519_keypair()
        image = tmp_path / "image"
        (image / "app" / "updates").mkdir(parents=True)
        (image / "app" / "updates" / "release-signing-key.pub").write_text(public)
        monkeypatch.setenv(L.PUBLIC_KEY_ENV, "ssh-ed25519 AAAA... (pasted the wrong format)")
        # A set-but-unusable key refuses everything (fail closed).
        assert L.image_public_key(image) == L.INVALID_KEY
        monkeypatch.setenv(L.PUBLIC_KEY_ENV, "-----BEGIN PUBLIC KEY-----\nnot a key\n")
        assert L.image_public_key(image) == L.INVALID_KEY
        monkeypatch.delenv(L.PUBLIC_KEY_ENV)
        assert L.image_public_key(image) == L.load_public_key_text(public)
        (image / "app" / "updates" / "release-signing-key.pub").write_text("# c\ngarbage\n")
        assert L.image_public_key(image) == L.INVALID_KEY

    def test_an_invalid_key_runs_only_the_image_and_marks_nothing_failed(
        self, setup: tuple[L.Paths, L.ImageInfo]
    ) -> None:
        paths, image = setup
        private, _public = ed25519_keypair()
        install(paths, NEW, private_key=private)
        select(paths, NEW)
        broken = L.ImageInfo(image.builtin_dir, image.builtin_version, image.deps_hash, "invalid")
        launcher, processes, _clock = make_launcher(paths, broken)
        launcher.start(launcher.choose())
        assert processes[-1].app_dir == str(image.builtin_dir)
        assert launcher.current is not None and "key is invalid" in launcher.current.reason
        # Not the version's fault: it runs again once the key is fixed.
        assert not paths.failed.exists()

    def test_an_old_signed_release_cannot_run_under_a_newer_name(
        self, setup: tuple[L.Paths, L.ImageInfo]
    ) -> None:
        paths, image = setup
        private, public = ed25519_keypair()
        keyed = L.ImageInfo(image.builtin_dir, image.builtin_version, image.deps_hash, public)
        root = write_tree(paths.versions / NEW, "1.0.5", private_key=private)
        (root / L.VERSION_FILE).write_text(json.dumps({"version": NEW, "deps_hash": "deps-1"}))
        select(paths, NEW)
        target = L.choose_target(paths, keyed)
        # The signed manifest says 1.0.5; the folder and the selection say 1.1.0.
        assert target.source == "built-in" and target.refused, target.reason
        assert "signed manifest is for 1.0.5" in target.reason

    def test_the_code_must_be_the_selected_version(
        self, setup: tuple[L.Paths, L.ImageInfo]
    ) -> None:
        paths, image = setup
        root = install(paths, NEW)
        (root / "app" / "__init__.py").write_text('__version__ = "1.0.5"\n')
        manifest = json.loads((root / L.MANIFEST_FILE).read_text())
        manifest["files"]["app/__init__.py"] = L.sha256_file(root / "app" / "__init__.py")
        (root / L.MANIFEST_FILE).write_bytes(manifest_bytes(manifest))
        select(paths, NEW)
        target = L.choose_target(paths, image)
        assert target.source == "built-in" and "code says it is 1.0.5" in target.reason


class TestRequestsOnce:
    def test_an_unremovable_request_is_acted_on_once(
        self, setup: tuple[L.Paths, L.ImageInfo], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        paths, image = setup
        launcher, processes, _clock = make_launcher(paths, image, healthy={BUILTIN})
        launcher.start(launcher.choose())
        launcher.tick()
        L.write_json_atomic(paths.request, {"kind": "restart", "by": "admin"})
        real_unlink = Path.unlink

        def unlink(self: Path, *a: Any, **kw: Any) -> None:
            if self == paths.request:
                raise PermissionError(13, "Read-only file system")
            real_unlink(self, *a, **kw)

        monkeypatch.setattr(Path, "unlink", unlink)
        for _ in range(5):
            launcher.tick()
        assert len(processes) == 2, f"{len(processes) - 1} restarts for one request"
        # Remembered in launcher.json: a new launcher does not act on it either.
        again, more, _clock = make_launcher(paths, image, healthy={BUILTIN})
        again.start(again.choose())
        for _ in range(3):
            again.tick()
        assert len(more) == 1
        # A new request (another id) is acted on.
        L.write_json_atomic(paths.request, {"id": "n2", "kind": "restart", "by": "admin"})
        again.tick()
        assert len(more) == 2
