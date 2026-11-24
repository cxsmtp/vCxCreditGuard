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
    # Imported here: periods imports nothing of ours, but keeping this module
    # import-light lets anything (models included) use it.
    from app.services.periods import PeriodError
    from app.services.requests_service import GrantExpiryError

    # GrantExpiryError is composed of public_error() texts of its own causes.
    return (CheckmarxError, PeriodError, GrantExpiryError)


def is_domain_error(exc: BaseException) -> bool:
    return isinstance(exc, _domain_errors())


def public_error(exc: BaseException) -> str:
    """The error as a user may read it: a domain error's own (redacted) message,
    or only the class name of an unexpected one."""
    if is_domain_error(exc):
        return redact(str(exc))
    return f"Unexpected error ({type(exc).__name__}); {SEE_THE_LOG}."
