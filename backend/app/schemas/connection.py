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
    # What the key may do, checked right after a successful token exchange.
    permissions: KeyPermissionReport | None = None


# ----------------------------------------------------- API key permissions


class KeyPermissionCheck(BaseModel):
    id: str
    label: str
    purpose: str
    method: str
    path: str
    kind: str
    # ok | denied | not_found | error | skipped | not_tested
    status: str
    detail: str | None = None
    # For an untested write: "will_fail" | "probably_denied" | None
    expectation: str | None = None
    runtime_denied_at: datetime | None = None
    needed_for: list[str]
    required: bool
    required_reason: str
    breaks: str
    problem: bool
    severe: bool


class KeyPermissionRuntimeDenial(BaseModel):
    method: str
    path: str
    check_id: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    count: int = 0


class KeyTokenClaims(BaseModel):
    """Role and group names from the key's access token. Never the token."""

    readable: bool
    realm_roles: list[str] = Field(default_factory=list)
    client_roles: dict[str, list[str]] = Field(default_factory=dict)
    roles: list[str] = Field(default_factory=list)
    groups: list[str] = Field(default_factory=list)


class KeyPermissionExplanation(BaseModel):
    why: list[str] = Field(default_factory=list)
    missing: list[str] = Field(default_factory=list)
    roles: list[str] = Field(default_factory=list)
    what_to_do: list[str] = Field(default_factory=list)


class KeyPermissionSummary(BaseModel):
    """What every page needs for the banner and the top bar light."""

    # ok | limited | insufficient | unknown
    verdict: str
    # True only when something needed with the current setup is confirmed
    # missing: the banner, the admin pop-up and the top bar light show then.
    # Other gaps are shown on the Connection page only.
    attention: bool = False
    summary: str
    # "CreditGuard can't ..." phrases, most serious first.
    missing: list[str] = Field(default_factory=list)
    checked_at: datetime | None = None
    # Changes whenever the set of missing permissions changes.
    problem_key: str | None = None


class KeyPermissionReport(KeyPermissionSummary):
    """The full report. Checks, token roles and run-time refusals are admin only."""

    details_visible: bool
    trigger: str | None = None
    key_fingerprint: str | None = None
    enforce_users: bool = False
    enforce_projects: bool = False
    enforce_fusion: bool = False
    auto_triage_charging: bool = False
    checks: list[KeyPermissionCheck] = Field(default_factory=list)
    runtime_denials: list[KeyPermissionRuntimeDenial] = Field(default_factory=list)
    token: KeyTokenClaims | None = None
    explanation: KeyPermissionExplanation = Field(default_factory=KeyPermissionExplanation)


class KeyPermissionsResponse(BaseModel):
    # False until a check has run for the key in use.
    available: bool
    report: KeyPermissionReport | None = None


ConnectionTestResponse.model_rebuild()
