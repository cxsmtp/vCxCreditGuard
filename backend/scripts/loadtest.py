"""Load test: run governance cycles against a large synthetic tenant and measure them.

Development tool, not part of the product or of the default test run. It builds
a fresh database (SQLite or PostgreSQL), a synthetic tenant of about 2,000
projects (``tests/scale_tenant.py``) with a per-call latency and rate limiting,
seeds limits, runs cycles and reports, per cycle and per step: wall time,
Checkmarx calls by endpoint, database statements, rows, and memory. It then
times the API endpoints the GUI uses at that size.

    cd backend
    python -m scripts.loadtest --database sqlite --cycles 8 --out /tmp/lt.md
    python -m scripts.loadtest \\
        --database "postgresql+psycopg://postgres@/postgres?host=/tmp&port=5433" \\
        --cycles 8 --latency-ms 50 --rate-limit-every 500 --out /tmp/lt-pg.md

For PostgreSQL the URL names a server and a database to connect to for
administration; a fresh database ``cxcg_loadtest_<timestamp>`` is created on it
(and dropped afterwards unless ``--keep``).

The simulated clock moves on by ``--interval-minutes`` before every cycle, so
anything scheduled by time (organisation sync, verification, retention)
behaves as it would on a real schedule, while the cycles run back to back.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import resource
import sys
import tempfile
import time
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))


def _prepare_environment(database: str, workdir: Path) -> tuple[str, str | None]:
    """Point the app at a fresh database. Returns (url, admin url to drop it)."""
    os.environ.setdefault("CXCG_ENV", "development")
    os.environ.setdefault("CXCG_COOKIE_SECURE", "false")
    os.environ.setdefault("CXCG_MASTER_KEY", base64.b64encode(bytes(range(32))).decode())
    os.environ["CXCG_LOG_LEVEL"] = os.environ.get("CXCG_LOG_LEVEL", "ERROR")
    stamp = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
    if database == "sqlite":
        path = workdir / f"loadtest-{stamp}.db"
        url = f"sqlite:///{path.as_posix()}"
        os.environ["CXCG_DATABASE_URL"] = url
        return url, None
    from sqlalchemy import create_engine, text

    name = f"cxcg_loadtest_{stamp}"
    engine = create_engine(database, isolation_level="AUTOCOMMIT")
    with engine.connect() as connection:
        connection.execute(text(f'CREATE DATABASE "{name}"'))
    engine.dispose()
    # The same URL with the new database name (kept as text: a rendered URL
    # would percent-encode a socket directory, which Alembic's config rejects).
    head, _, query = database.partition("?")
    url = head.rsplit("/", 1)[0] + "/" + name + (f"?{query}" if query else "")
    os.environ["CXCG_DATABASE_URL"] = url
    return url, name


class _Clock:
    """Shifts the app's notion of now (``app.db.base.utcnow``) forward."""

    offset = timedelta(0)

    @classmethod
    def now(cls) -> datetime:
        return datetime.now(UTC) + cls.offset


def _install_clock() -> None:
    import app.db.base as base

    class ShiftedDatetime(datetime):
        @classmethod
        def now(cls, tz=None):  # type: ignore[override]
            return datetime.now(tz) + _Clock.offset

    base.datetime = ShiftedDatetime  # type: ignore[attr-defined]


class _Meter:
    """Database statements and Checkmarx calls, attributed to the running step."""

    def __init__(self, tenant: Any) -> None:
        self.tenant = tenant
        self.step = "other"
        self.queries: Counter[str] = Counter()
        self.step_time: dict[str, float] = defaultdict(float)
        self.step_calls: dict[str, Counter[str]] = defaultdict(Counter)
        self.step_rss: dict[str, int] = {}

    statements: Counter[str] | None = None

    def on_execute(self, _conn: Any, _cursor: Any, statement: str, *_args: Any) -> None:
        self.queries[self.step] += 1
        if self.statements is not None:
            self.statements[f"{self.step}: {' '.join(statement.split())[:150]}"] += 1

    def reset(self) -> None:
        self.queries.clear()
        self.step_time.clear()
        self.step_calls.clear()
        self.step_rss.clear()


def _rss_mb() -> float:
    try:
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) / 1024
    except OSError:
        pass
    return 0.0


def _peak_mb() -> float:
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024


def _instrument(meter: _Meter) -> None:
    from sqlalchemy import event

    from app.db.session import get_engine
    from app.services import cycle

    event.listen(get_engine(), "before_cursor_execute", meter.on_execute)
    original = cycle._run_step

    def run_step(session, result, name, work, *, degrades_run=True):  # type: ignore[no-untyped-def]
        meter.step = name
        before = Counter(meter.tenant.calls)
        started = time.monotonic()
        try:
            return original(session, result, name, work, degrades_run=degrades_run)
        finally:
            meter.step_time[name] += time.monotonic() - started
            meter.step_calls[name] += Counter(meter.tenant.calls) - before
            meter.step_rss[name] = max(meter.step_rss.get(name, 0), int(_rss_mb()))
            meter.step = "other"

    cycle._run_step = run_step  # type: ignore[assignment]


def _seed(session: Any, tenant: Any, *, big_group: str) -> dict[str, int]:
    """Limits: 200 user, 50 project, 10 group (one of ~1,000 projects), 5 application."""
    from app.models.enums import EntityType, PeriodType
    from app.models.limits import CreditLimit
    from app.services import settings_store

    all_actions = ["auto_triage", "pr_remediation", "fusion"]
    counts = Counter()

    def add(entity_type: str, entity_id: str, label: str, limit: int, actions=None) -> None:
        session.add(
            CreditLimit(
                entity_type=entity_type,
                entity_id=entity_id,
                entity_label=label,
                credit_limit=limit,
                period_type=PeriodType.MONTHLY,
                warning_threshold_pct=80,
                enforce=True,
                is_active=True,
                count_existing_usage=True,
                project_actions=actions,
            )
        )
        counts[entity_type] += 1

    user_rows = {row.get("email"): row for row in tenant.consumption.get("user", [])}
    for index in range(200):
        email = f"user{index:05d}@example.com"
        used = float(user_rows.get(email, {}).get("creditsUsed", 0))
        # One in five is over budget already.
        add(EntityType.USER, f"user-{index:05d}", email, 1 if index % 5 == 0 else int(used) + 500)
    for index in range(1000, 1050):
        add(
            EntityType.PROJECT,
            f"proj-{index:05d}",
            f"repo-{index:05d}",
            0 if index % 5 == 0 else 100_000,
            all_actions,
        )
    add(EntityType.GROUP, big_group, "Enterprise", 1, all_actions)
    for index, group in enumerate(
        [group["id"] for group in tenant.groups if group["id"].startswith("grp-t")][:9]
    ):
        add(EntityType.GROUP, group, group, 1 if index < 2 else 1_000_000, None)
    for index in range(5):
        add(
            EntityType.APPLICATION,
            f"app-{20 + index:03d}",
            f"Application {20 + index:03d}",
            1 if index == 0 else 10_000_000,
            all_actions,
        )
    settings_store.set_value(session, settings_store.KEY_AUTO_TRIAGE_TO_INITIATOR, True)
    session.commit()
    return {str(key): value for key, value in counts.items()}


def _table_counts(session: Any) -> dict[str, int]:
    from sqlalchemy import func, select

    from app.models import Base

    wanted = [
        "enforcement_action",
        "audit_log_entry",
        "notification",
        "usage_snapshot",
        "usage_record",
        "policy_violation",
        "auto_triage_charge",
        "auto_triage_project_state",
        "limit_period_state",
        "scheduler_run",
        "app_setting",
    ]
    out: dict[str, int] = {}
    for name in wanted:
        table = Base.metadata.tables.get(name)
        if table is not None:
            out[name] = int(session.scalar(select(func.count()).select_from(table)) or 0)
    return out


def _db_size_mb(session: Any, url: str) -> float:
    from sqlalchemy import text

    if url.startswith("sqlite"):
        path = Path(url[len("sqlite:///") :])
        total = sum(p.stat().st_size for p in path.parent.glob(path.name + "*") if p.exists())
        return total / 1_048_576
    return float(session.scalar(text("SELECT pg_database_size(current_database())"))) / 1_048_576


def _usage_bytes(session: Any, url: str) -> dict[str, Any]:
    """What the consumption readings take (PostgreSQL: on disk, and per column)."""
    from sqlalchemy import text

    if url.startswith("sqlite"):
        row = session.execute(
            text(
                "SELECT count(*), coalesce(sum(length(raw)), 0) FROM usage_record "
                "WHERE raw IS NOT NULL"
            )
        ).one()
        return {"records_with_raw": int(row[0]), "record_raw_bytes": int(row[1])}
    disk = session.execute(
        text(
            "SELECT pg_total_relation_size('usage_record'), "
            "pg_total_relation_size('usage_snapshot')"
        )
    ).one()
    rows = session.execute(
        text(
            "SELECT count(*), coalesce(sum(pg_column_size(r.*)), 0), "
            "coalesce(sum(pg_column_size(r.raw)), 0) FROM usage_record r"
        )
    ).one()
    snapshots = session.execute(
        text(
            "SELECT count(*), coalesce(sum(pg_column_size(s.*)), 0), "
            "coalesce(sum(pg_column_size(s.raw)), 0) FROM usage_snapshot s"
        )
    ).one()
    return {
        "usage_record_disk_mb": round(disk[0] / 1_048_576, 2),
        "usage_snapshot_disk_mb": round(disk[1] / 1_048_576, 2),
        "records": int(rows[0]),
        "record_bytes": int(rows[1]),
        "record_raw_bytes": int(rows[2]),
        "snapshots": int(snapshots[0]),
        "snapshot_bytes": int(snapshots[1]),
        "snapshot_raw_bytes": int(snapshots[2]),
    }


def _simulate_thinning(session: Any, *, days: int, rows: int, interval: int) -> dict[str, Any]:
    """A history of ``days`` of readings at the cycle interval, then the retention job.

    Each dimension's latest reading is copied back in time, one snapshot per
    interval, with its first ``rows`` records (raw rows included), so the
    thinning tiers and the raw clearing run on realistic timestamps without
    the full volume. Returns snapshot and row counts, and their logical size,
    before and after one retention run (thinning is idempotent: one run does
    what a month of daily runs would).
    """
    from decimal import Decimal

    from sqlalchemy import func, insert, select, text

    from app.db.base import utcnow
    from app.models.usage import AutoTriageCharge, UsageRecord, UsageSnapshot
    from app.services import retention, settings_store
    from app.services.audit import AuditActor

    now = utcnow()
    # With attribution on, (nearly) every project reading shows some project's
    # Auto Triage rise and so carries a charge: simulated the same way.
    charging = settings_store.auto_triage_to_initiator(session)
    views = list(session.scalars(select(UsageSnapshot.view_by).distinct()))
    for view in views:
        template = session.scalar(
            select(UsageSnapshot)
            .where(UsageSnapshot.view_by == view, UsageSnapshot.held_reason.is_(None))
            .order_by(UsageSnapshot.collected_at.desc())
            .limit(1)
        )
        if template is None:
            continue
        records = list(
            session.scalars(
                select(UsageRecord)
                .where(UsageRecord.snapshot_id == template.id)
                .order_by(UsageRecord.id)
                .limit(rows)
            )
        )
        if not records:
            continue  # a dimension the tenant reports nothing for
        steps = days * 24 * 60 // interval
        for step in range(1, steps + 1):
            snapshot_id = session.execute(
                insert(UsageSnapshot)
                .values(
                    collected_at=now - timedelta(minutes=interval * step),
                    view_by=view,
                    period_param=template.period_param,
                    total_items=template.total_items,
                    pages_fetched=template.pages_fetched,
                    total_credits=template.total_credits,
                )
                .returning(UsageSnapshot.id)
            ).scalar_one()
            if charging and view == "project":
                moment = now - timedelta(minutes=interval * step)
                session.execute(
                    insert(AutoTriageCharge).values(
                        project_id=records[0].entity_id or "simulated",
                        basis="observed",
                        initiator="simulated@example.com",
                        initiator_key="simulated@example.com",
                        scan_count=1,
                        credits=Decimal("1"),
                        window_start=moment - timedelta(minutes=interval),
                        window_end=moment,
                        snapshot_id=snapshot_id,
                        created_at=moment,
                    )
                )
            session.execute(
                insert(UsageRecord),
                [
                    {
                        "snapshot_id": snapshot_id,
                        "view_by": record.view_by,
                        "subject_key": record.subject_key,
                        "subject_name": record.subject_name,
                        "subject_email": record.subject_email,
                        "entity_type": record.entity_type,
                        "entity_id": record.entity_id,
                        "credits_used": record.credits_used,
                        "percent_of_total": record.percent_of_total,
                        "transactions": record.transactions,
                        "actions": record.actions,
                        "raw": record.raw,
                    }
                    for record in records
                ],
            )
            if step % 500 == 0:
                session.commit()
        session.commit()

    def measure() -> dict[str, Any]:
        # Compacted first, so the sizes on disk are what the rows take, not
        # what deleted or updated rows left behind.
        session.commit()
        with (
            session.get_bind()
            .connect()
            .execution_options(isolation_level="AUTOCOMMIT") as connection
        ):
            connection.execute(text("VACUUM FULL usage_record"))
            connection.execute(text("VACUUM FULL usage_snapshot"))
            disk = connection.execute(
                text(
                    "SELECT pg_total_relation_size('usage_record') "
                    "+ pg_total_relation_size('usage_snapshot')"
                )
            ).scalar_one()
        snapshots = dict(
            session.execute(
                select(UsageSnapshot.view_by, func.count()).group_by(UsageSnapshot.view_by)
            ).all()
        )
        sizes = session.execute(
            text(
                "SELECT count(*), coalesce(sum(pg_column_size(r.*)), 0), "
                "coalesce(sum(pg_column_size(r.raw)), 0) FROM usage_record r"
            )
        ).one()
        return {
            "snapshots_per_view": snapshots,
            "auto_triage_charges": session.scalar(
                select(func.count()).select_from(AutoTriageCharge)
            ),
            "disk_mb": round(disk / 1_048_576, 2),
            "records": int(sizes[0]),
            "record_bytes": int(sizes[1]),
            "record_raw_bytes": int(sizes[2]),
        }

    before = measure()
    started = time.monotonic()
    result = retention.prune(session, retention_days=365, actor=AuditActor.system("loadtest"))
    session.commit()
    seconds = time.monotonic() - started
    after = measure()
    return {
        "days": days,
        "attribution": charging,
        "rows_per_snapshot": rows,
        "interval_minutes": interval,
        "before": before,
        "after": after,
        "prune_seconds": round(seconds, 1),
        "prune": result.as_stats(),
    }


def _restricted_progress(session: Any) -> dict[str, int]:
    from sqlalchemy import func, select

    from app.models.limits import EnforcementAction

    rows = session.execute(
        select(EnforcementAction.status, func.count()).group_by(EnforcementAction.status)
    ).all()
    out = {str(status): int(count) for status, count in rows}
    projects = session.scalar(
        select(func.count(func.distinct(EnforcementAction.target_id))).where(
            EnforcementAction.status == "applied", EnforcementAction.target_type == "cx_project"
        )
    )
    out["projects_restricted"] = int(projects or 0)
    return out


def _resume_enforcement(session: Any) -> None:
    """What an admin pressing Resume does (Settings → Enforcement)."""
    from app.services import settings_store

    settings_store.set_value(session, settings_store.KEY_ENFORCEMENT_PAUSED, False)
    settings_store.set_value(session, settings_store.KEY_ENFORCEMENT_PAUSE_REASON, None)
    settings_store.set_value(session, settings_store.KEY_CEILING_WAIVED_ONCE, True)
    session.commit()


def _time_api(tenant: Any, admin_password: str) -> list[dict[str, Any]]:
    from fastapi.testclient import TestClient

    from app import main
    from app.core.config import get_settings

    main.upgrade_to_head = lambda *_a, **_k: None  # type: ignore[assignment]
    app = main.create_app(get_settings(), run_scheduler=False)
    endpoints = [
        "/api/me",
        "/api/dashboard",
        "/api/limits",
        "/api/notifications?limit=50",
        "/api/notifications/enforcements",
        "/api/notifications/enforcements?limit=1000",
        "/api/notifications/enforcements/page?limit=50",
        "/api/notifications/enforcements/page?limit=50&q=repo-0099",
        "/api/preview/dry-run",
        "/api/preview/blast-radius?entity_type=group&entity_id=grp-big",
        "/api/reports/summary",
        "/api/reports/projection",
        "/api/reports/chargeback",
        "/api/violations",
        "/api/org/entities?entity_type=project&q=repo-01",
        "/api/org/entities?entity_type=user&q=user00",
        "/api/audit",
        "/api/ops/status",
        "/api/ops/diagnostics",
        "/api/usage/auto-triage-attribution",
        "/api/usage/unresolved",
        "/api/requests",
        "/api/settings",
    ]
    rows: list[dict[str, Any]] = []
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.post(
            "/api/auth/login", json={"username": "loadtest-admin", "password": admin_password}
        )
        response.raise_for_status()
        client.headers["X-CSRF-Token"] = client.cookies.get("cxcg_csrf", "")
        for path in endpoints:
            best = None
            status = None
            size = 0
            for _ in range(2):
                started = time.monotonic()
                response = client.get(path)
                elapsed = time.monotonic() - started
                best = elapsed if best is None else min(best, elapsed)
                status = response.status_code
                size = len(response.content)
            rows.append(
                {"path": path, "status": status, "ms": round(best * 1000), "kb": size // 1024}
            )
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--database", default="sqlite", help="'sqlite' or a PostgreSQL URL")
    parser.add_argument("--cycles", type=int, default=8)
    parser.add_argument("--projects", type=int, default=2000)
    parser.add_argument("--users", type=int, default=1000)
    parser.add_argument("--groups", type=int, default=100)
    parser.add_argument("--applications", type=int, default=30)
    parser.add_argument("--latency-ms", type=float, default=50.0)
    parser.add_argument("--rate-limit-every", type=int, default=500)
    parser.add_argument("--retry-after", type=float, default=1.0)
    parser.add_argument("--interval-minutes", type=int, default=15)
    parser.add_argument("--label", default="run")
    parser.add_argument("--out", type=Path, help="write the Markdown report here")
    parser.add_argument("--json", type=Path, help="write the raw measurements here")
    parser.add_argument("--keep", action="store_true", help="keep the PostgreSQL database")
    parser.add_argument("--no-api", action="store_true", help="skip timing the API")
    parser.add_argument(
        "--profile-cycle", type=int, default=0, help="profile this cycle (cProfile, top SQL)"
    )
    parser.add_argument(
        "--simulate-thinning-days",
        type=int,
        default=0,
        help="after the cycles, copy the latest readings back over this many days and run "
        "the retention job (PostgreSQL only)",
    )
    parser.add_argument(
        "--simulate-rows",
        type=int,
        default=25,
        help="records per simulated snapshot (sizes scale per record)",
    )
    args = parser.parse_args(argv)

    workdir = Path(tempfile.mkdtemp(prefix="cxcg-loadtest-"))
    url, pg_name = _prepare_environment(args.database, workdir)
    _install_clock()

    from app.core.config import reset_settings_cache

    reset_settings_cache()
    from app.db.migrate import upgrade_to_head
    from app.db.session import get_engine, session_scope
    from app.models.enums import UtilityRole
    from app.services import auth as auth_service
    from app.services import connection as connection_service
    from app.services import cycle, settings_store
    from app.services.audit import AuditActor
    from tests.conftest import make_api_key
    from tests.scale_tenant import BIG_GROUP_ID, build_scale_tenant

    upgrade_to_head()
    started_build = time.monotonic()
    tenant = build_scale_tenant(
        projects=args.projects,
        users=args.users,
        groups=args.groups,
        applications=args.applications,
        latency_ms=args.latency_ms,
        rate_limit_every=args.rate_limit_every,
        retry_after_seconds=args.retry_after,
        clock=_Clock.now,
    )
    build_seconds = time.monotonic() - started_build
    shared_client = tenant.client()
    connection_service.get_client = lambda _session: shared_client  # type: ignore[assignment]
    connection_service.optional_client = lambda _session: shared_client  # type: ignore[assignment]

    admin_password = "Load!Test#Pass9"  # noqa: S105 - a throwaway local database
    with session_scope() as session:
        auth_service.create_user(
            session,
            username="loadtest-admin",
            password=admin_password,
            role=UtilityRole.ADMIN,
            actor=AuditActor.system("loadtest"),
        )
        connection_service.save_connection(
            session, api_key=make_api_key(tenant="acme-corp"), actor=AuditActor.system("loadtest")
        )
    with session_scope() as session:
        seeded = _seed(session, tenant, big_group=BIG_GROUP_ID)

    meter = _Meter(tenant)
    _instrument(meter)
    cycles: list[dict[str, Any]] = []
    for number in range(1, args.cycles + 1):
        if number > 1:
            tenant.advance()
        _Clock.offset += timedelta(minutes=args.interval_minutes)
        tenant.reset_counts()
        meter.reset()
        profiler = None
        if number == args.profile_cycle:
            import cProfile

            meter.statements = Counter()
            profiler = cProfile.Profile()
            profiler.enable()
        started = time.monotonic()
        result = cycle.run_cycle(trigger="manual")
        wall = time.monotonic() - started
        if profiler is not None:
            import io
            import pstats

            profiler.disable()
            out = io.StringIO()
            pstats.Stats(profiler, stream=out).sort_stats("cumulative").print_stats(45)
            print(out.getvalue()[:12000])
            for text, count in meter.statements.most_common(25):
                print(f"{count:6d}  {text}")
            meter.statements = None
        with session_scope() as session:
            progress = _restricted_progress(session)
            tables = _table_counts(session)
            size = _db_size_mb(session, url)
            usage = _usage_bytes(session, url)
            paused = settings_store.enforcement_guard(session).paused
        steps = {
            name: {
                "seconds": round(meter.step_time.get(name, 0.0), 2),
                "calls": sum(meter.step_calls.get(name, Counter()).values()),
                "queries": meter.queries.get(name, 0),
                "rss_mb": meter.step_rss.get(name, 0),
                "by_endpoint": dict(meter.step_calls.get(name, Counter()).most_common()),
            }
            for name in meter.step_time
        }
        record = {
            "cycle": number,
            "status": str(result.status),
            "seconds": round(wall, 1),
            "calls": sum(tenant.calls.values()),
            "rate_limited": tenant.rate_limited,
            "queries": sum(meter.queries.values()),
            "rss_mb": round(_rss_mb()),
            "peak_mb": round(_peak_mb()),
            "db_mb": round(size, 1),
            "usage": usage,
            "progress": progress,
            "tables": tables,
            "paused": paused,
            "steps": steps,
            "evaluate": result.steps.get("evaluate"),
            "violations": result.steps.get("violations"),
            "auto_triage_attribution": result.steps.get("auto_triage_attribution"),
            "http": result.steps.get("http"),
            "by_endpoint": dict(tenant.calls.most_common()),
            "errors": result.errors[:5],
        }
        cycles.append(record)
        print(
            f"cycle {number}: {record['status']} {record['seconds']}s calls={record['calls']} "
            f"429={record['rate_limited']} queries={record['queries']} rss={record['rss_mb']}MB "
            f"progress={progress} paused={paused}",
            flush=True,
        )
        if number == 1 or paused:
            with session_scope() as session:
                _resume_enforcement(session)

    api_rows = [] if args.no_api else _time_api(tenant, admin_password)
    simulation = None
    if args.simulate_thinning_days and not url.startswith("sqlite"):
        with session_scope() as session:
            simulation = _simulate_thinning(
                session,
                days=args.simulate_thinning_days,
                rows=args.simulate_rows,
                interval=args.interval_minutes,
            )
        print(json.dumps(simulation, indent=1, default=str), flush=True)
    report = {
        "label": args.label,
        "database": "sqlite" if url.startswith("sqlite") else "postgresql",
        "args": {k: str(v) for k, v in vars(args).items()},
        "tenant": {
            "projects": len(tenant.projects),
            "users": len(tenant.users),
            "groups": len(tenant.groups),
            "applications": len(tenant.applications),
            "scans": sum(len(v) for v in tenant.scans.values()),
            "build_seconds": round(build_seconds, 1),
        },
        "limits": seeded,
        "cycles": cycles,
        "api": api_rows,
        "simulation": simulation,
        "peak_mb": round(_peak_mb()),
    }
    if args.json:
        args.json.write_text(json.dumps(report, indent=2, default=str))
    markdown = render(report)
    if args.out:
        args.out.write_text(markdown)
    print(markdown)

    get_engine().dispose()
    if pg_name and not args.keep:
        from sqlalchemy import create_engine, text

        engine = create_engine(args.database, isolation_level="AUTOCOMMIT")
        with engine.connect() as connection:
            connection.execute(text(f'DROP DATABASE IF EXISTS "{pg_name}" WITH (FORCE)'))
        engine.dispose()
    return 0


def render(report: dict[str, Any]) -> str:
    lines: list[str] = []
    tenant = report["tenant"]
    lines.append(f"# Load test: {report['label']} ({report['database']})\n")
    lines.append(
        f"Tenant: {tenant['projects']} projects, {tenant['users']} users, {tenant['groups']} "
        f"groups, {tenant['applications']} applications, {tenant['scans']} scans. "
        f"Limits: {report['limits']}. Latency {report['args']['latency_ms']} ms per call, "
        f"429 every {report['args']['rate_limit_every']} calls "
        f"(Retry-After {report['args']['retry_after']} s). Peak RSS {report['peak_mb']} MB.\n"
    )
    lines.append("## Cycles\n")
    lines.append(
        "| # | status | wall s | CX calls | 429 | DB stmts | RSS MB | DB MB | applied | "
        "projects restricted | pending/failed | paused |"
    )
    lines.append("|---|---|---|---|---|---|---|---|---|---|---|---|")
    for c in report["cycles"]:
        p = c["progress"]
        lines.append(
            f"| {c['cycle']} | {c['status']} | {c['seconds']} | {c['calls']} | "
            f"{c['rate_limited']} | {c['queries']} | {c['rss_mb']} | {c['db_mb']} | "
            f"{p.get('applied', 0)} | {p.get('projects_restricted', 0)} | "
            f"{p.get('pending', 0)}/{p.get('failed', 0)} | {c['paused']} |"
        )
    for c in report["cycles"]:
        lines.append(f"\n## Cycle {c['cycle']} by step\n")
        lines.append("| step | wall s | CX calls | DB stmts | RSS MB | top endpoints |")
        lines.append("|---|---|---|---|---|---|")
        for name, s in sorted(c["steps"].items(), key=lambda kv: -kv[1]["seconds"]):
            top = ", ".join(f"{k} {v}" for k, v in list(s["by_endpoint"].items())[:4])
            lines.append(
                f"| {name} | {s['seconds']} | {s['calls']} | {s['queries']} "
                f"| {s['rss_mb']} | {top} |"
            )
        extra = {
            key: c.get(key)
            for key in ("evaluate", "violations", "auto_triage_attribution", "http")
            if c.get(key)
        }
        if extra:
            lines.append("\n```json\n" + json.dumps(extra, indent=1, default=str)[:4000] + "\n```")
        lines.append(f"\nRows: {c['tables']}")
        if c["errors"]:
            lines.append(f"\nErrors: {c['errors']}")
    lines.append("\n## Consumption readings per cycle\n")
    lines.append("```json")
    for c in report["cycles"]:
        lines.append(json.dumps({"cycle": c["cycle"], **(c.get("usage") or {})}))
    lines.append("```")
    if report.get("simulation"):
        lines.append("\n## Thinning simulation\n")
        lines.append(
            "```json\n" + json.dumps(report["simulation"], indent=1, default=str) + "\n```"
        )
    if report["api"]:
        lines.append("\n## API (after the cycles)\n")
        lines.append("| endpoint | status | ms | KB |")
        lines.append("|---|---|---|---|")
        for row in report["api"]:
            lines.append(f"| `{row['path']}` | {row['status']} | {row['ms']} | {row['kb']} |")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
