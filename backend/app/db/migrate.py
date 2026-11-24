"""Programmatic Alembic upgrade.

Called at startup so a fresh container, a developer checkout and the test suite
all converge on the same schema without a manual step. It is also exposed as
``python -m app.db.migrate`` for the Docker entrypoint.
"""

from __future__ import annotations

import logging
from pathlib import Path

from alembic.config import Config

from alembic import command
from app.core.config import get_settings

logger = logging.getLogger(__name__)

BACKEND_DIR = Path(__file__).resolve().parents[2]
ALEMBIC_INI = BACKEND_DIR / "alembic.ini"


def alembic_config(database_url: str | None = None) -> Config:
    config = Config(str(ALEMBIC_INI))
    config.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    config.set_main_option("sqlalchemy.url", database_url or get_settings().database_url)
    # Never change sys.path in this process (whatever an alembic.ini says): a
    # relative entry would be the working folder - under the launcher, the image's
    # own copy of the app - ahead of the version that runs.
    config.set_main_option("prepend_sys_path", "")
    # Leave logging alone. Left to itself, Alembic's env.py replaces the root
    # logger's handlers with the ones in alembic.ini - which, in a process that
    # goes on to serve the app, silently removes the handler that redacts
    # secrets and drops everything below WARNING. (The `alembic` command line
    # does not come through here and still gets its own logging.)
    config.attributes["configure_logger"] = False
    return config


def upgrade_to_head(database_url: str | None = None) -> None:
    logger.info("Applying database migrations")
    command.upgrade(alembic_config(database_url), "head")
    logger.info("Database schema is up to date")


if __name__ == "__main__":
    from app.core.logging import configure_logging

    configure_logging(get_settings().log_level)
    upgrade_to_head()
