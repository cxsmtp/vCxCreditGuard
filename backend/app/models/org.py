"""Local mirror of the Checkmarx One organisation model.

Synced periodically so limit evaluation, entity pickers and enforcement can run
without hammering the Checkmarx APIs. Rows are soft deleted (``is_deleted``)
rather than removed, so historical consumption events keep resolvable names.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin
from app.db.types import JSONColumn, UTCDateTime


class SyncedMixin:
    is_deleted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    last_synced_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    raw: Mapped[dict | None] = mapped_column(JSONColumn)


class CxUser(Base, TimestampMixin, SyncedMixin):
    __tablename__ = "cx_user"

    # Checkmarx / IAM user id (Keycloak UUID) is the natural key.
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    username: Mapped[str | None] = mapped_column(String(256), index=True)
    email: Mapped[str | None] = mapped_column(String(320), index=True)
    first_name: Mapped[str | None] = mapped_column(String(128))
    last_name: Mapped[str | None] = mapped_column(String(128))
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    auth_provider: Mapped[str | None] = mapped_column(String(32))
    last_login_at: Mapped[datetime | None] = mapped_column(UTCDateTime)

    # Role and group names exactly as /users/v2 reports them. Names, not ids:
    # useful for display and for spotting which users hold the AI roles, but
    # enforcement always re-reads authoritative role mappings from the admin API
    # before changing anything.
    role_names: Mapped[list | None] = mapped_column(JSONColumn)
    group_names: Mapped[list | None] = mapped_column(JSONColumn)

    @property
    def display_name(self) -> str:
        full = " ".join(part for part in (self.first_name, self.last_name) if part).strip()
        return full or self.username or self.email or self.id


class CxGroup(Base, TimestampMixin, SyncedMixin):
    __tablename__ = "cx_group"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    # Full IAM path, e.g. /engineering/platform. Groups can be nested.
    path: Mapped[str | None] = mapped_column(String(1024))
    parent_id: Mapped[str | None] = mapped_column(String(64), index=True)


class CxGroupMembership(Base):
    __tablename__ = "cx_group_membership"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    group_id: Mapped[str] = mapped_column(
        ForeignKey("cx_group.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[str] = mapped_column(
        ForeignKey("cx_user.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # True when membership comes from a parent group rather than a direct assignment.
    inherited: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    last_synced_at: Mapped[datetime | None] = mapped_column(UTCDateTime)

    __table_args__ = (UniqueConstraint("group_id", "user_id", name="group_user"),)


class CxProject(Base, TimestampMixin, SyncedMixin):
    __tablename__ = "cx_project"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    repo_url: Mapped[str | None] = mapped_column(String(1024))
    # Needed by the repos-manager call that controls PR triage and remediation.
    # Null when the project has no supported SCM integration, in which case that
    # half of project enforcement is skipped and says so.
    repo_id: Mapped[str | None] = mapped_column(String(64))

    # Last observed AI state, refreshed on sync so enforcement stays idempotent
    # without re-reading on every cycle. Null means not yet observed.
    auto_triage_enabled: Mapped[bool | None] = mapped_column(Boolean)
    auto_triage_config: Mapped[dict | None] = mapped_column(JSONColumn)
    pr_remediation_severities: Mapped[list | None] = mapped_column(JSONColumn)
    ai_state_checked_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


class CxProjectGroup(Base):
    """Project to group assignment (Checkmarx projects carry a list of group ids)."""

    __tablename__ = "cx_project_group"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[str] = mapped_column(
        ForeignKey("cx_project.id", ondelete="CASCADE"), nullable=False, index=True
    )
    group_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    last_synced_at: Mapped[datetime | None] = mapped_column(UTCDateTime)

    __table_args__ = (UniqueConstraint("project_id", "group_id", name="project_group"),)


class CxApplication(Base, TimestampMixin, SyncedMixin):
    __tablename__ = "cx_application"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(String(2048))


class CxApplicationProject(Base):
    __tablename__ = "cx_application_project"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    application_id: Mapped[str] = mapped_column(
        ForeignKey("cx_application.id", ondelete="CASCADE"), nullable=False, index=True
    )
    project_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    last_synced_at: Mapped[datetime | None] = mapped_column(UTCDateTime)

    __table_args__ = (UniqueConstraint("application_id", "project_id", name="application_project"),)
