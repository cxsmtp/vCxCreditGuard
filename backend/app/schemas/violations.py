"""Schemas for policy violations."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Any

from pydantic import BaseModel, Field

from app.schemas.auth import StrictModel


class ViolationResponse(BaseModel):
    id: int
    kind: str
    kind_label: str
    # Information, not a violation: nothing to follow up, never counted as open.
    information: bool = False
    detected_at: datetime
    updated_at: datetime | None = None
    limit_id: int | None
    limit_label: str | None
    # The limit's entity, for a link to the budget (null once it is deleted).
    limit_entity_type: str | None = None
    limit_entity_id: str | None = None
    enforcement_action_id: int | None
    target_type: str
    target_id: str
    target_label: str | None
    actor: str | None
    source: str | None
    detail: str
    evidence: dict[str, Any] | None
    credits: Decimal | None
    severity: str
    status: str
    acknowledged_by: str | None
    acknowledged_at: datetime | None
    resolved_by: str | None
    resolved_at: datetime | None
    note: str | None


class ViolationListResponse(BaseModel):
    items: list[ViolationResponse]
    total: int
    open: int


class ViolationStatusRequest(StrictModel):
    note: str | None = Field(default=None, max_length=2000)
