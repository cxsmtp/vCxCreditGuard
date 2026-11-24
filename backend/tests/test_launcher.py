"""The launcher's decisions (cxcg_launcher.py), driven without real servers:
which version runs, trial and automatic rollback, the database restore, and
switching on request. Child processes and health probes are fakes."""

from __future__ import annotations

import base64
import hashlib
import json
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
        assert command[1:4] == ["-I", "-B", "-u"] and "serve" in command
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
