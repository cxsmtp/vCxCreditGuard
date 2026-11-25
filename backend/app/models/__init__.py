"""SQLAlchemy models.

Every model must be imported here: Alembic's autogenerate and the test harness
both discover tables through ``Base.metadata``.
"""

from app.db.base import Base
from app.db.length_guard import install_length_guards  # noqa: E402
from app.models.audit import AuditLogEntry, Notification
from app.models.auth import LoginAttempt, PasswordResetToken, UtilitySession, UtilityUser
from app.models.connection import AppSetting, CxConnection
from app.models.limits import (
    CreditLimit,
    CreditRequest,
    EnforcementAction,
    Exemption,
    LimitPeriodState,
)
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
    AutoTriageCharge,
    AutoTriageProjectState,
    BudgetUsage,
    CreditBalanceSnapshot,
    DimensionState,
    EntityMapping,
    SchedulerLock,
    SchedulerRun,
    UnresolvedSubject,
    UsageDelta,
    UsageEntityOffset,
    UsageMissingName,
    UsageRecord,
    UsageSnapshot,
)
from app.models.violations import PolicyViolation

# Once every model is known: see app/db/length_guard.py.
install_length_guards(Base)

__all__ = [
    "AppSetting",
    "AuditLogEntry",
    "AutoTriageCharge",
    "AutoTriageProjectState",
    "Base",
    "CreditBalanceSnapshot",
    "CreditLimit",
    "CreditRequest",
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
    "EntityMapping",
    "Exemption",
    "LimitPeriodState",
    "LoginAttempt",
    "PasswordResetToken",
    "PolicyViolation",
    "Notification",
    "SchedulerLock",
    "SchedulerRun",
    "UnresolvedSubject",
    "BudgetUsage",
    "UsageDelta",
    "UsageEntityOffset",
    "UsageMissingName",
    "UsageRecord",
    "UsageSnapshot",
    "UtilitySession",
    "UtilityUser",
]
