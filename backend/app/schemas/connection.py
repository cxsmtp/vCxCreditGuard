"""Request and response schemas for the Checkmarx One connection."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field, field_validator

from app.models.enums import ConnectionStatus
from app.schemas.auth import StrictModel

# Generous bounds: a Keycloak refresh token is typically 700 to 2000 characters.
API_KEY_MIN = 40
API_KEY_MAX = 8192


class ApiKeyRequest(StrictModel):
    api_key: str = Field(min_length=API_KEY_MIN, max_length=API_KEY_MAX)


class SaveConnectionRequest(ApiKeyRequest):
    # Optional override for dedicated or newly added regions.
    api_base_url: str | None = Field(default=None, max_length=512)

    @field_validator("api_base_url")
    @classmethod
    def _must_be_https_url(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        candidate = value.strip()
        if not candidate.startswith(("https://", "http://")):
            raise ValueError("API base URL must start with https:// or http://")
        if candidate.startswith("http://") and "localhost" not in candidate:
            raise ValueError("Refusing a plaintext http:// API base URL for a remote host.")
        return candidate


class ApiBaseUrlRequest(StrictModel):
    api_base_url: str = Field(min_length=8, max_length=512)

    @field_validator("api_base_url")
    @classmethod
    def _must_be_https_url(cls, value: str) -> str:
        candidate = value.strip()
        if not candidate.startswith(("https://", "http://")):
            raise ValueError("API base URL must start with https:// or http://")
        return candidate


class ConnectionPreviewResponse(BaseModel):
    """Derived tenant details shown for confirmation before saving."""

    iam_base_url: str
    tenant_name: str
    derived_api_base_url: str | None
    region_label: str
    derivation_confident: bool
    api_key_fingerprint: str
    key_expires_at: datetime | None
    client_id: str | None


class ConnectionStatusResponse(BaseModel):
    configured: bool
    status: ConnectionStatus
    tenant_name: str | None = None
    iam_base_url: str | None = None
    api_base_url: str | None = None
    api_base_url_overridden: bool = False
    api_key_fingerprint: str | None = None
    last_success_at: datetime | None = None
    last_failure_at: datetime | None = None
    last_error: str | None = None


class ConnectionTestResponse(BaseModel):
    ok: bool
    token_acquired: bool
    api_reachable: bool
    message: str
    tenant_name: str | None = None
    iam_base_url: str | None = None
    api_base_url: str | None = None
    token_seconds_remaining: float | None = None
    projects_visible: int | None = None
