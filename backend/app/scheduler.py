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

from app.db.session import session_scope
from app.services import settings_store
from app.services.cycle import run_cycle

logger = logging.getLogger(__name__)

JOB_ID = "governance-cycle"
# Tolerate a late fire rather than dropping the run entirely.
MISFIRE_GRACE_SECONDS = 300

_scheduler: BackgroundScheduler | None = None


def _job() -> None:
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


def start() -> None:
    scheduler = get_scheduler()
    trigger = _build_trigger()
    if trigger is None:
        logger.warning("The scheduler is disabled in settings, no cycles will run")
    else:
        scheduler.add_job(_job, trigger=trigger, id=JOB_ID, replace_existing=True)
    if not scheduler.running:
        scheduler.start()
    logger.info("Scheduler started with %s", describe_schedule())


def reconfigure() -> str:
    """Apply the current settings to the running scheduler. Returns a description."""
    scheduler = get_scheduler()
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
    return f"every {config.interval_minutes} minute(s)"


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
