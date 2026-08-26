"""Application configuration.

Everything is read from the environment with the ``CXCG_`` prefix. Nothing in
here has a secret default: the master key must be supplied explicitly or the
application refuses to start.
"""

from __future__ import annotations

import base64
import binascii
import functools
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

MASTER_KEY_LENGTH = 32


class ConfigError(RuntimeError):
    """Raised when the process is configured in a way we refuse to run with."""


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="CXCG_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Runtime
    env: Literal["development", "production"] = "production"
    log_level: str = "INFO"
    host: str = "0.0.0.0"  # noqa: S104 - bind address is deployment controlled
    port: int = 8000

    # Secrets
    master_key: str | None = None
    master_key_file: Path | None = None

    # Database
    database_url: str = "sqlite:///./data/cxcreditguard.db"

    # Sessions / cookies
    session_idle_ttl_minutes: int = Field(default=60, ge=1, le=1440)
    session_absolute_ttl_hours: int = Field(default=12, ge=1, le=168)
    cookie_secure: bool = True
    hsts_enabled: bool = True
    allowed_origins: str = ""

    # Login protection
    login_max_attempts: int = Field(default=5, ge=1, le=100)
    login_lockout_base_seconds: int = Field(default=30, ge=1)
    login_lockout_max_seconds: int = Field(default=3600, ge=1)
    login_rate_limit_per_minute: int = Field(default=10, ge=1)

    # First run bootstrap
    bootstrap_admin_username: str | None = None
    bootstrap_admin_password: str | None = None

    # Checkmarx One client
    cx_request_timeout_seconds: float = Field(default=30.0, gt=0)
    cx_max_retries: int = Field(default=4, ge=0, le=10)
    cx_backoff_base_seconds: float = Field(default=0.5, gt=0)
    cx_backoff_max_seconds: float = Field(default=20.0, gt=0)
    cx_token_refresh_margin_seconds: int = Field(default=300, ge=0)
    cx_client_id: str = "ast-app"

    @model_validator(mode="after")
    def _validate_production_posture(self) -> Settings:
        if self.env == "production" and not self.cookie_secure:
            raise ConfigError(
                "CXCG_COOKIE_SECURE cannot be false when CXCG_ENV=production. "
                "Serve the utility over HTTPS or run with CXCG_ENV=development."
            )
        return self

    @property
    def is_production(self) -> bool:
        return self.env == "production"

    @property
    def cors_origins(self) -> list[str]:
        return [origin.strip() for origin in self.allowed_origins.split(",") if origin.strip()]

    def master_key_bytes(self) -> bytes:
        """Resolve the 32 byte master key from env var or mounted secret file.

        Raises ConfigError rather than falling back to anything derivable, so a
        misconfigured deployment fails loudly instead of encrypting secrets under
        a predictable key.
        """
        raw: str | None = None
        source = ""
        if self.master_key_file is not None:
            if not self.master_key_file.is_file():
                raise ConfigError(
                    f"CXCG_MASTER_KEY_FILE points at {self.master_key_file} which does not exist."
                )
            raw = self.master_key_file.read_text(encoding="utf-8")
            source = "CXCG_MASTER_KEY_FILE"
        elif self.master_key:
            raw = self.master_key
            source = "CXCG_MASTER_KEY"

        if not raw or not raw.strip():
            raise ConfigError(
                "No master key configured. Set CXCG_MASTER_KEY (base64 of 32 random "
                "bytes) or CXCG_MASTER_KEY_FILE. Generate one with: "
                'python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"'
            )

        try:
            key = base64.b64decode(raw.strip(), validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ConfigError(f"{source} is not valid base64.") from exc

        if len(key) != MASTER_KEY_LENGTH:
            raise ConfigError(
                f"{source} decoded to {len(key)} bytes; AES-256-GCM needs exactly "
                f"{MASTER_KEY_LENGTH}."
            )
        return key


@functools.lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def reset_settings_cache() -> None:
    """Test helper: drop the cached Settings instance."""
    get_settings.cache_clear()
