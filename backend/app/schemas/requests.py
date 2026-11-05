"""Schemas for the credit request / approval workflow."""

from __future__ import annotations

from datetime import datetime

from pydantic import Field, field_validator

from app.models.enums import EntityType, RequestStatus
from app.schemas.auth import StrictModel


class RequestCreateRequest(StrictModel):
    entity_type: EntityType
    entity_id: str = Field(min_length=1, max_length=64)
    requested_limit: int = Field(ge=0, le=100_000_000)
    reason: str | None = Field(default=None, max_length=2048)


class RequestDecisionRequest(StrictModel):
    """An admin's approval or denial.

    ``approved_limit`` lets an admin grant less (or more) than asked; omitting it
    grants exactly the requested amount. ``expires_at`` makes the grant temporary:
    the budget is rolled back once it passes. Both are ignored for a denial.
    """

    approved_limit: int | None = Field(default=None, ge=0, le=100_000_000)
    expires_at: datetime | None = None
    note: str | None = Field(default=None, max_length=2048)

    @field_validator("expires_at")
    @classmethod
    def _aware(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("expires_at must include a timezone offset.")
        return value


class RequestResponse(StrictModel):
    id: int
    entity_type: EntityType
    entity_id: str
    entity_label: str | None
    requested_limit: int
    reason: str | None
    status: RequestStatus
    requested_by_name: str | None
    requested_at: datetime
    decided_by_name: str | None
    decided_at: datetime | None
    decision_note: str | None
    approved_limit: int | None
    previous_limit: int | None
    expires_at: datetime | None
    reverted: bool
    created_at: datetime
