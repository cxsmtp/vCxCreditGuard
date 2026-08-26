"""Logging with a redaction filter.

Two layers of defence:

1. Pattern based redaction catches anything that looks like a JWT, a bearer
   header, an OAuth form field or a password/secret key in a dict repr.
2. A runtime registry of literal secret values (the decrypted API key, access
   tokens) that are scrubbed by exact match, so even an unusual log line cannot
   leak them.
"""

from __future__ import annotations

import logging
import logging.config
import re
import threading
from typing import Final

REDACTED: Final = "[REDACTED]"
_MIN_REGISTERED_SECRET_LENGTH: Final = 8

_PATTERNS: Final[tuple[tuple[re.Pattern[str], str], ...]] = (
    # JSON Web Tokens (API key, access token, id token) anywhere in the message.
    (re.compile(r"\bey[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*"), REDACTED),
    # Authorization headers.
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9\-._~+/=]+"), r"\1 " + REDACTED),
    # OAuth / form encoded credential fields.
    (
        re.compile(r"(?i)\b(refresh_token|access_token|client_secret|code|password)=[^&\s\"']+"),
        r"\1=" + REDACTED,
    ),
    # JSON or dict style credential fields.
    (
        re.compile(
            r"(?i)([\"']?(?:refresh_token|access_token|api_?key|password|secret|token"
            r"|totp_secret|authorization)[\"']?\s*[:=]\s*)[\"']?[^\s,}\"']+[\"']?"
        ),
        r"\1" + REDACTED,
    ),
)


class _SecretRegistry:
    """Thread safe set of literal strings that must never reach a log sink."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._secrets: set[str] = set()

    def add(self, secret: str | None) -> None:
        if not secret or len(secret) < _MIN_REGISTERED_SECRET_LENGTH:
            return
        with self._lock:
            self._secrets.add(secret)

    def discard(self, secret: str | None) -> None:
        if not secret:
            return
        with self._lock:
            self._secrets.discard(secret)

    def scrub(self, text: str) -> str:
        with self._lock:
            secrets = tuple(self._secrets)
        for secret in secrets:
            if secret in text:
                text = text.replace(secret, REDACTED)
        return text


_registry = _SecretRegistry()


def register_secret(secret: str | None) -> None:
    """Register a live secret value so it is scrubbed from every log record."""
    _registry.add(secret)


def unregister_secret(secret: str | None) -> None:
    _registry.discard(secret)


def redact(text: str) -> str:
    """Apply pattern redaction and literal scrubbing to a string."""
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return _registry.scrub(text)


class RedactingFilter(logging.Filter):
    """Rewrites log records in place so no sink ever sees a secret.

    The message is interpolated first and then redacted as a single string.
    Redacting the format string and its arguments separately looks tidier but is
    wrong: a pattern such as ``refresh_token=%s`` has its own placeholder
    replaced, and the record then fails to format at all.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            rendered = record.getMessage()
        except Exception:  # noqa: BLE001 - a broken log line must not break the app
            rendered = str(record.msg)
        record.msg = redact(rendered)
        record.args = None
        if record.exc_text:
            record.exc_text = redact(record.exc_text)
        return True


def configure_logging(level: str = "INFO") -> None:
    logging.config.dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "filters": {"redact": {"()": RedactingFilter}},
            "formatters": {
                "standard": {
                    "format": "%(asctime)s %(levelname)-8s %(name)s: %(message)s",
                    "datefmt": "%Y-%m-%dT%H:%M:%S%z",
                }
            },
            "handlers": {
                "console": {
                    "class": "logging.StreamHandler",
                    "formatter": "standard",
                    "filters": ["redact"],
                    "stream": "ext://sys.stdout",
                }
            },
            "root": {"handlers": ["console"], "level": level.upper()},
            "loggers": {
                # httpx logs full request URLs at INFO; queries can carry ids but
                # never secrets, still route it through the filter.
                "httpx": {"level": "WARNING", "handlers": ["console"], "propagate": False},
                "uvicorn.access": {
                    "level": "INFO",
                    "handlers": ["console"],
                    "propagate": False,
                },
            },
        }
    )
    for handler in logging.getLogger().handlers:
        handler.addFilter(RedactingFilter())
