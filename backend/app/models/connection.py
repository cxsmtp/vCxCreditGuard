"""Checkmarx One connection details and generic application settings."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin
from app.db.types import UTCDateTime
from app.models.enums import ConnectionStatus


class CxConnection(Base, TimestampMixin):
    """Singleton row (id=1) holding the tenant connection.

    The API key is stored encrypted with purpose "cx-api-key". Access tokens are
    never persisted: they live in memory in the token manager only.
    """

    __tablename__ = "cx_connection"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    api_key_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    # Derived from the API key's iss claim, shown to the admin for confirmation.
    iam_base_url: Mapped[str] = mapped_column(String(512), nullable=False)
    tenant_name: Mapped[str] = mapped_column(String(256), nullable=False)
    # Auto derived from the IAM region, overridable for dedicated tenants.
    api_base_url: Mapped[str] = mapped_column(String(512), nullable=False)
    api_base_url_overridden: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=ConnectionStatus.UNCONFIGURED
    )
    last_success_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_failure_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_error: Mapped[str | None] = mapped_column(Text)
    # Fingerprint of the stored key so the GUI and audit log can refer to which
    # key is in use without ever handling the value itself.
    api_key_fingerprint: Mapped[str | None] = mapped_column(String(16))


class AppSetting(Base, TimestampMixin):
    """Key/value store for runtime settings changed from the GUI.

    Values are JSON encoded text. Rows flagged ``is_secret`` hold ciphertext and
    are never returned to the API unmasked.
    """

    __tablename__ = "app_setting"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[str | None] = mapped_column(Text)
    is_secret: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    description: Mapped[str | None] = mapped_column(String(512))
