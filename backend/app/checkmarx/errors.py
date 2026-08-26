"""Exception hierarchy for the Checkmarx One integration.

Kept narrow on purpose: the scheduler needs to tell apart "this call can be
retried later" from "an admin has to fix the configuration", because the first
should be logged and retried while the second must raise a notification and
stop the cycle from taking destructive action on stale data.
"""

from __future__ import annotations


class CheckmarxError(RuntimeError):
    """Base class for every failure talking to Checkmarx One."""


class ApiKeyError(CheckmarxError, ValueError):
    """The supplied API key is not a usable Checkmarx One API key."""


class CheckmarxAuthError(CheckmarxError):
    """Token exchange or refresh failed. Needs admin attention, not a retry."""


class CheckmarxPermissionError(CheckmarxError):
    """Authenticated but not authorised (403). The service account lacks a permission."""

    def __init__(self, message: str, *, method: str = "", url: str = "") -> None:
        super().__init__(message)
        self.method = method
        self.url = url


class CheckmarxNotFoundError(CheckmarxError):
    """404 from an endpoint we expected to exist."""


class CheckmarxRateLimitError(CheckmarxError):
    """429, and we exhausted our retry budget."""

    def __init__(self, message: str, *, retry_after_seconds: float | None = None) -> None:
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds


class CheckmarxUnavailableError(CheckmarxError):
    """Network failure or 5xx that survived every retry. Safe to retry next cycle."""


class CheckmarxResponseError(CheckmarxError):
    """A 4xx we do not model, or a response body we could not parse."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class NotConfiguredError(CheckmarxError):
    """No Checkmarx connection has been set up yet."""
