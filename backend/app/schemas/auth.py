"""Request and response schemas for authentication and account management.

Every field is length bounded. ``extra="forbid"`` means an unexpected field is a
400 rather than being silently ignored.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.models.enums import UtilityRole

USERNAME_PATTERN = r"^[a-zA-Z0-9._-]+$"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class LoginRequest(StrictModel):
    username: str = Field(min_length=3, max_length=64, pattern=USERNAME_PATTERN)
    password: str = Field(min_length=1, max_length=128)
    totp_code: str | None = Field(default=None, min_length=6, max_length=8, pattern=r"^[0-9 ]+$")


class SessionInfo(BaseModel):
    username: str
    role: UtilityRole
    email: str | None = None
    totp_enabled: bool
    must_change_password: bool
    idle_expires_at: datetime
    absolute_expires_at: datetime
    last_login_at: datetime | None = None


class ChangePasswordRequest(StrictModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=12, max_length=128)


class CreateUserRequest(StrictModel):
    username: str = Field(min_length=3, max_length=64, pattern=USERNAME_PATTERN)
    password: str = Field(min_length=12, max_length=128)
    role: UtilityRole
    email: EmailStr | None = None
    must_change_password: bool = True


class UpdateUserRequest(StrictModel):
    role: UtilityRole | None = None
    is_active: bool | None = None
    email: EmailStr | None = None


class UserSummary(BaseModel):
    id: int
    username: str
    email: str | None = None
    role: UtilityRole
    is_active: bool
    totp_enabled: bool
    last_login_at: datetime | None = None
    locked_until: datetime | None = None
    created_at: datetime


class TotpEnrollResponse(BaseModel):
    secret: str
    otpauth_uri: str


class TotpConfirmRequest(StrictModel):
    code: str = Field(min_length=6, max_length=8, pattern=r"^[0-9 ]+$")


class MessageResponse(BaseModel):
    message: str
