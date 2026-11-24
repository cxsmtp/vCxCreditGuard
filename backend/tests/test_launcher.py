"""The launcher's decisions (cxcg_launcher.py), driven without real servers:
which version runs, trial and automatic rollback, the database restore, and
switching on request. Child processes and health probes are fakes."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
from pathlib import Path
from typing import Any

import pytest

import cxcg_launcher as L
from tests.fake_registry import app_files

BUILTIN = "1.0.0"
NEW = "1.1.0"


def write_tree(root: Path, version: str, *, deps: str = "deps-1", migrations=("aaa",)) -> Path:
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
    (root / L.MANIFEST_FILE).write_text(json.dumps(manifest))
    return root


@pytest.fixture
def setup(tmp_path: Path) -> tuple[L.Paths, L.ImageInfo]:
    builtin = write_tree(tmp_path / "image-app", BUILTIN)
    paths = L.Paths(tmp_path / "data")
    return paths, L.ImageInfo(builtin, BUILTIN, "deps-1")


def install(paths: L.Paths, version: str, *, deps: str = "deps-1", migrations=("aaa",)) -> Path:
    root = write_tree(paths.versions / version, version, deps=deps, migrations=migrations)
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
        assert env["PYTHONPATH"].split(":")[0] == str(paths.versions / NEW)
        assert env["CXCG_IMAGE_DEPS_HASH"] == "deps-1"
        assert launcher.command(target)[-1] == "--no-proxy-headers"
