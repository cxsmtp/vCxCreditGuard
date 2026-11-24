"""What an error may say where a user can read it.

Run history, cycle errors, notifications and API answers are read by people
who have no business seeing an unexpected exception's own text: it can carry
SQL, file paths, internal identifiers or a fragment of a payload. So:

* a **domain error** (a Checkmarx One failure, a misconfigured period) is
  written to be read: its message is kept, passed through the log redaction
  (bearer tokens, JWTs, registered secrets) once more;
* anything else is named by its class alone, with a pointer to the server log,
  which has the full detail (the caller logs it with ``exc_info``, through the
  redacting log filter).
"""

from __future__ import annotations

from app.checkmarx.errors import CheckmarxError
from app.core.logging import redact

SEE_THE_LOG = "see the server log"


def _domain_errors() -> tuple[type[BaseException], ...]:
    """Every error class whose messages are written for the people who read them.

    Each was reviewed: its messages say what went wrong and what to do, for
    an admin (Checkmarx One, mail and webhook delivery, configuration and the
    master key, updates and the release registry, backups) or for whoever made
    the request (limits, credit requests, policy violations, passwords). None
    quotes a payload, a query or a secret; they are redacted all the same.
    Not here: ``AuthError`` (sign-in failures are answered by the auth routes
    on purpose, never echoed), and anything not raised by the app itself.
    """
    # Imported here, so this module stays import-light (anything may use it).
    from app.core.config import ConfigError
    from app.core.crypto import DecryptionError
    from app.core.passwords import PasswordPolicyError
    from app.services.delivery import DeliveryError
    from app.services.limits_service import LimitError
    from app.services.ops_hardening import BackupError
    from app.services.periods import PeriodError
    from app.services.requests_service import GrantExpiryError, RequestError
    from app.services.violations import ViolationError
    from app.updates.registry import RegistryError
    from app.updates.service import UpdateError

    # GrantExpiryError is composed of public_error() texts of its own causes.
    return (
        CheckmarxError,
        PeriodError,
        GrantExpiryError,
        DeliveryError,
        ConfigError,
        DecryptionError,
        LimitError,
        RequestError,
        ViolationError,
        BackupError,
        PasswordPolicyError,
        UpdateError,
        RegistryError,
    )


def is_domain_error(exc: BaseException) -> bool:
    return isinstance(exc, _domain_errors())


def public_error(exc: BaseException) -> str:
    """The error as a user may read it: a domain error's own (redacted) message,
    or only the class name of an unexpected one."""
    if is_domain_error(exc):
        return redact(str(exc))
    return f"Unexpected error ({type(exc).__name__}); {SEE_THE_LOG}."
