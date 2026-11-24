"""Enumerations shared by the models, services and API schemas.

All of these are persisted as short strings rather than native database enums so
that adding a value is a code change, not a migration.
"""

from __future__ import annotations

from enum import StrEnum


class UtilityRole(StrEnum):
    """Role inside CxCreditGuard itself (not a Checkmarx role)."""

    ADMIN = "admin"
    VIEWER = "viewer"


class EntityType(StrEnum):
    """The four levels a credit limit can be attached to."""

    USER = "user"
    GROUP = "group"
    PROJECT = "project"
    APPLICATION = "application"


class PeriodType(StrEnum):
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    CUSTOM = "custom"
    LIFETIME = "lifetime"


class UsageView(StrEnum):
    """The ``viewBy`` dimensions of GET /api/credits/consumption.

    All five are recognised by the endpoint on the tenant this was verified
    against. Support is still probed at runtime and recorded in ``dimension_state``,
    because an unrecognised value does not fail: it silently returns the USER view,
    so a 200 is not evidence that the dimension exists.
    """

    USER = "user"
    ACTION = "action"
    APPLICATION = "application"
    PROJECT = "project"
    GROUP = "group"


class ActionType(StrEnum):
    """AI actions that consume Checkmarx One credits.

    Values are the raw ``actionType`` strings the consumption endpoint reports,
    lowercased. UNKNOWN is a deliberate catch all: the feed is authoritative, and
    an action type we do not recognise must still be counted rather than dropped.
    """

    TRIAGE = "triage"
    AUTO_TRIAGE = "auto_triage"
    REMEDIATION = "remediation"
    DAST_CORRELATION = "dast_correlation"
    FUSION = "fusion"
    UNKNOWN = "unknown"


class LimitStatus(StrEnum):
    """State of one entity's limit within one budget period."""

    OK = "ok"
    WARNED = "warned"
    BREACHED = "breached"
    RESTRICTED = "restricted"
    RESTORED = "restored"


class EnforcementKind(StrEnum):
    """The restrictive changes the utility knows how to make, and undo.

    A project level breach fans out to the project actions its limit selects
    (``CreditLimit.project_actions``): Auto Triage is a project configuration,
    PR triage and remediation is a repository setting that only exists for
    projects wired to a supported SCM integration, and Fusion has two halves -
    the project's scan setting ``scan.config.ai.fusionEnabled`` and, for a
    project with a repository, the repository's ``fusionScanConfig``. One kind
    per write, so each half succeeds, fails and is restored on its own.
    """

    REMOVE_USER_ROLES = "remove_user_roles"
    DISABLE_AUTO_TRIAGE = "disable_auto_triage"
    DISABLE_PR_REMEDIATION = "disable_pr_remediation"
    DISABLE_FUSION = "disable_fusion"
    DISABLE_REPO_FUSION = "disable_repo_fusion"


class ProjectAction(StrEnum):
    """What a project, group or application limit turns off on its projects.

    Stored per limit in ``CreditLimit.project_actions``. A limit whose list is
    null predates the choice and keeps the original behaviour (``LEGACY``).
    """

    AUTO_TRIAGE = "auto_triage"
    PR_REMEDIATION = "pr_remediation"
    FUSION = "fusion"


# What a limit with no stored choice turns off: the two actions there were
# before the choice existed, so an upgrade changes nothing.
LEGACY_PROJECT_ACTIONS: tuple[str, ...] = (
    ProjectAction.AUTO_TRIAGE.value,
    ProjectAction.PR_REMEDIATION.value,
)
# The order they are stored, listed and applied in.
PROJECT_ACTION_ORDER: tuple[str, ...] = tuple(action.value for action in ProjectAction)


class EnforcementStatus(StrEnum):
    PENDING = "pending"
    APPLIED = "applied"
    FAILED = "failed"
    REVERSED = "reversed"


class Severity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    ERROR = "error"


class ActorType(StrEnum):
    """Who performed an audited action."""

    ADMIN = "admin"
    SYSTEM = "system"


class RunStatus(StrEnum):
    RUNNING = "running"
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"


class ConnectionStatus(StrEnum):
    UNCONFIGURED = "unconfigured"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILED = "failed"


class RequestStatus(StrEnum):
    """A credit request's lifecycle. Pending until an admin decides."""

    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
