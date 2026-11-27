"""Background scheduler.

APScheduler's ``max_instances=1`` plus ``coalesce=True`` stops a slow cycle from
piling up inside this process, and the database lock in ``app/services/cycle.py``
covers the multi process case. ``reconfigure()`` is what makes the interval
changeable from the GUI without a restart: the job is replaced in place.
"""

from __future__ import annotations

import logging

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from app.db import instance_guard
from app.db.session import get_engine, session_scope
from app.services import settings_store, wording
from app.services.cycle import run_cycle

logger = logging.getLogger(__name__)

JOB_ID = "governance-cycle"
UPDATE_JOB_ID = "update-check"
FAST_JOB_ID = "fast-check"
# Tolerate a late fire rather than dropping the run entirely.
MISFIRE_GRACE_SECONDS = 300

_scheduler: BackgroundScheduler | None = None


def _job() -> None:
    if not instance_guard.still_held(get_engine()):
        logger.critical(
            "Another CxCreditGuard instance has taken over this database. This one is no "
            "longer running scheduled cycles; stop one of the two."
        )
        return
    result = run_cycle(trigger="schedule")
    logger.info(
        "Cycle %s finished with status %s%s",
        result.run_id,
        result.status,
        f" ({result.skipped_reason})" if result.skipped_reason else "",
    )


def _build_trigger() -> IntervalTrigger | CronTrigger | None:
    with session_scope() as session:
        config = settings_store.schedule_config(session)
    if not config.enabled:
        return None
    if config.mode == "cron" and config.cron:
        try:
            return CronTrigger.from_crontab(config.cron, timezone="UTC")
        except ValueError:
            logger.error(
                "Cron expression %r is not valid, falling back to every %d minutes",
                config.cron,
                config.interval_minutes,
            )
    return IntervalTrigger(minutes=config.interval_minutes, timezone="UTC")


def get_scheduler() -> BackgroundScheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = BackgroundScheduler(
            timezone="UTC",
            job_defaults={
                "coalesce": True,
                "max_instances": 1,
                "misfire_grace_time": MISFIRE_GRACE_SECONDS,
            },
        )
    return _scheduler


def is_running() -> bool:
    """True once this process's scheduler has started and until it is shut down.

    False when it never started: a process created without it (tests, a
    second instance that does not run cycles) or one whose start failed.
    """
    return _scheduler is not None and bool(_scheduler.running)


def start() -> None:
    scheduler = get_scheduler()
    trigger = _build_trigger()
    if trigger is None:
        logger.warning("The scheduler is disabled in settings, no cycles will run")
    else:
        scheduler.add_job(_job, trigger=trigger, id=JOB_ID, replace_existing=True)
    _add_update_job(scheduler)
    _apply_fast_job(scheduler)
    if not scheduler.running:
        scheduler.start()
    logger.info("Scheduler started with %s", describe_schedule())


def _update_job() -> None:
    if not instance_guard.still_held(get_engine()):
        return
    from app.updates.service import scheduled_tick

    scheduled_tick()


def _add_update_job(scheduler: BackgroundScheduler) -> None:
    """Auto-update: a first look a minute after start, then every 15 minutes (it
    checks the registry every 6 hours and installs only in the quiet hour)."""
    from datetime import UTC, datetime, timedelta

    from app.updates.service import FIRST_TICK_SECONDS, TICK_MINUTES

    scheduler.add_job(
        _update_job,
        trigger=IntervalTrigger(minutes=TICK_MINUTES, timezone="UTC"),
        id=UPDATE_JOB_ID,
        replace_existing=True,
        next_run_time=datetime.now(UTC) + timedelta(seconds=FIRST_TICK_SECONDS),
    )


def _fast_job() -> None:
    if not instance_guard.still_held(get_engine()):
        return
    from app.services import fastcheck

    fastcheck.run_scheduled()


def _apply_fast_job(scheduler: BackgroundScheduler) -> None:
    """The fast check (app/services/fastcheck.py): its own job, every few
    seconds, while it and the scheduler are on."""
    from app.services import fastcheck

    with session_scope() as session:
        on = settings_store.schedule_config(session).enabled
        config = fastcheck.config(session)
    if not (on and config.enabled):
        if scheduler.get_job(FAST_JOB_ID) is not None:
            scheduler.remove_job(FAST_JOB_ID)
        return
    scheduler.add_job(
        _fast_job,
        trigger=IntervalTrigger(seconds=config.interval_seconds, timezone="UTC"),
        id=FAST_JOB_ID,
        replace_existing=True,
        misfire_grace_time=max(5, config.interval_seconds),
    )


def wake_fast_check(delay: float = 0.0) -> bool:
    """Run the fast check as soon as possible (after ``delay`` seconds).
    False when no fast check job runs in this process."""
    from datetime import UTC, datetime, timedelta

    if _scheduler is None or not _scheduler.running:
        return False
    job = _scheduler.get_job(FAST_JOB_ID)
    if job is None:
        return False
    job.modify(next_run_time=datetime.now(UTC) + timedelta(seconds=max(0.0, delay)))
    return True


def reconfigure() -> str:
    """Apply the current settings to the running scheduler. Returns a description."""
    scheduler = get_scheduler()
    _apply_fast_job(scheduler)
    trigger = _build_trigger()
    if trigger is None:
        if scheduler.get_job(JOB_ID) is not None:
            scheduler.remove_job(JOB_ID)
        return "disabled"
    scheduler.add_job(_job, trigger=trigger, id=JOB_ID, replace_existing=True)
    description = describe_schedule()
    logger.info("Scheduler reconfigured: %s", description)
    return description


def describe_schedule() -> str:
    with session_scope() as session:
        config = settings_store.schedule_config(session)
    if not config.enabled:
        return "disabled"
    if config.mode == "cron" and config.cron:
        return f"cron {config.cron} (UTC)"
    return f"every {wording.plural(config.interval_minutes, 'minute')}"


def next_run_time():  # type: ignore[no-untyped-def]
    """When the next cycle is due, or None.

    A job added while the scheduler is not running is "pending" and has no
    ``next_run_time`` attribute at all, which is why this reads defensively rather
    than trusting the attribute to exist. That happens whenever the schedule is
    changed from the Settings page in a process that runs the API without the
    background scheduler.
    """
    scheduler = get_scheduler()
    if not scheduler.running:
        return None
    job = scheduler.get_job(JOB_ID)
    return getattr(job, "next_run_time", None) if job is not None else None


def shutdown(wait: bool = False) -> None:
    global _scheduler
    if _scheduler is not None and _scheduler.running:
        _scheduler.shutdown(wait=wait)
    _scheduler = None
