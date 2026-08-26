"""SQLAlchemy models.

Every model must be imported here: Alembic's autogenerate and the test harness
both discover tables through ``Base.metadata``.
"""

from app.db.base import Base
from app.models.audit import AuditLogEntry, Notification
from app.models.auth import LoginAttempt, UtilitySession, UtilityUser
from app.models.connection import AppSetting, CxConnection
from app.models.limits import CreditLimit, EnforcementAction, Exemption, LimitPeriodState
from app.models.org import (
    CxApplication,
    CxApplicationProject,
    CxGroup,
    CxGroupMembership,
    CxProject,
    CxProjectGroup,
    CxUser,
)
from app.models.usage import (
    DimensionState,
    SchedulerLock,
    SchedulerRun,
    UnresolvedSubject,
    UsageRecord,
    UsageSnapshot,
)

__all__ = [
    "AppSetting",
    "AuditLogEntry",
    "Base",
    "CreditLimit",
    "CxApplication",
    "CxApplicationProject",
    "CxConnection",
    "CxGroup",
    "CxGroupMembership",
    "CxProject",
    "CxProjectGroup",
    "CxUser",
    "DimensionState",
    "EnforcementAction",
    "Exemption",
    "LimitPeriodState",
    "LoginAttempt",
    "Notification",
    "SchedulerLock",
    "SchedulerRun",
    "UnresolvedSubject",
    "UsageRecord",
    "UsageSnapshot",
    "UtilitySession",
    "UtilityUser",
]
