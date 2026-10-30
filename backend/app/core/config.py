from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

# The local runbook uses a root .env; never commit this file.
load_dotenv(Path.cwd() / ".env")

_SEVERITY_CATEGORIES = {"security_headers", "cookies", "tls", "transport", "response_configuration", "input_validation"}
_SEVERITY_LEVELS = {"critical", "high", "medium", "low", "informational"}


def parse_severity_overrides(raw: str) -> dict[str, str]:
    """Parse an optional JSON map of supported finding categories to severity labels."""
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("SEVERITY_OVERRIDES_JSON must be a JSON object") from exc
    if not isinstance(value, dict):
        raise ValueError("SEVERITY_OVERRIDES_JSON must be a JSON object")
    if any(not isinstance(category, str) or category not in _SEVERITY_CATEGORIES for category in value):
        raise ValueError("SEVERITY_OVERRIDES_JSON contains an unsupported finding category")
    if any(not isinstance(level, str) or level.casefold() not in _SEVERITY_LEVELS for level in value.values()):
        raise ValueError("SEVERITY_OVERRIDES_JSON values must be Critical, High, Medium, Low, or Informational")
    return {category: level.casefold() for category, level in value.items()}


@dataclass(frozen=True)
class Settings:
    app_env: str = os.getenv("APP_ENV", "development")
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./data/vulnsight.db")
    session_secret: str = os.getenv("SESSION_SECRET", "")
    session_ttl_hours: int = int(os.getenv("SESSION_TTL_HOURS", "12"))
    cookie_secure: bool = os.getenv("COOKIE_SECURE", "true").lower() == "true"
    cookie_samesite: str = os.getenv("COOKIE_SAMESITE", "none").lower()
    hsts_enabled: bool = os.getenv("HSTS_ENABLED", "false").lower() == "true"
    scan_max_requests: int = int(os.getenv("SCAN_MAX_REQUESTS", "8"))
    scan_max_redirects: int = int(os.getenv("SCAN_MAX_REDIRECTS", "3"))
    scan_timeout_seconds: int = int(os.getenv("SCAN_TIMEOUT_SECONDS", "8"))
    scan_max_response_bytes: int = int(os.getenv("SCAN_MAX_RESPONSE_BYTES", "524288"))
    scan_max_concurrent_jobs: int = int(os.getenv("SCAN_MAX_CONCURRENT_JOBS", "2"))
    scan_max_duration_seconds: int = int(os.getenv("SCAN_MAX_DURATION_SECONDS", "60"))
    scan_rate_per_minute: int = int(os.getenv("SCAN_RATE_PER_MINUTE", "6"))
    max_targets_per_user: int = int(os.getenv("MAX_TARGETS_PER_USER", "100"))
    target_allowed_ports: tuple[int, ...] = tuple(
        int(part.strip()) for part in os.getenv("TARGET_ALLOWED_PORTS", "80,443").split(",") if part.strip()
    )
    severity_overrides: dict[str, str] = field(
        default_factory=lambda: parse_severity_overrides(os.getenv("SEVERITY_OVERRIDES_JSON", "{}"))
    )
    data_dir: Path = Path(os.getenv("DATA_DIR", "data"))


settings = Settings()


def validate_runtime_settings() -> None:
    if len(settings.session_secret.encode()) < 32 or settings.session_secret.startswith("replace-with-"):
        raise ValueError("Set SESSION_SECRET to a random value of at least 32 bytes before starting the app")
    if settings.cookie_samesite not in {"lax", "strict", "none"}:
        raise ValueError("COOKIE_SAMESITE must be lax, strict or none")
    if settings.cookie_samesite == "none" and not settings.cookie_secure:
        raise ValueError("SameSite=None cookies require COOKIE_SECURE=true")
    if settings.session_ttl_hours < 1 or settings.session_ttl_hours > 168:
        raise ValueError("SESSION_TTL_HOURS must be between 1 and 168")
    if settings.scan_max_requests < 1 or settings.scan_max_requests > 32:
        raise ValueError("SCAN_MAX_REQUESTS must be between 1 and 32")
    if settings.scan_max_redirects < 0 or settings.scan_max_redirects > 5:
        raise ValueError("SCAN_MAX_REDIRECTS must be between 0 and 5")
    if settings.scan_timeout_seconds < 1 or settings.scan_timeout_seconds > 20:
        raise ValueError("SCAN_TIMEOUT_SECONDS must be between 1 and 20")
    if settings.scan_max_response_bytes < 4096 or settings.scan_max_response_bytes > 2_097_152:
        raise ValueError("SCAN_MAX_RESPONSE_BYTES must be between 4096 and 2097152")
    if settings.scan_max_concurrent_jobs < 1 or settings.scan_max_concurrent_jobs > 8:
        raise ValueError("SCAN_MAX_CONCURRENT_JOBS must be between 1 and 8")
    if settings.scan_max_duration_seconds < 10 or settings.scan_max_duration_seconds > 600:
        raise ValueError("SCAN_MAX_DURATION_SECONDS must be between 10 and 600")
    if settings.scan_rate_per_minute < 1 or settings.scan_rate_per_minute > 60:
        raise ValueError("SCAN_RATE_PER_MINUTE must be between 1 and 60")
    if settings.max_targets_per_user < 1 or settings.max_targets_per_user > 1000:
        raise ValueError("MAX_TARGETS_PER_USER must be between 1 and 1000")
    if settings.target_allowed_ports != (80, 443):
        raise ValueError("TARGET_ALLOWED_PORTS is fixed to 80,443 in this safe initial edition")
    if not settings.database_url.startswith("sqlite:"):
        raise ValueError("This initial edition supports SQLite DATABASE_URL values only")
    if settings.database_url.startswith("sqlite:///./"):
        Path(settings.database_url.removeprefix("sqlite:///./")).parent.mkdir(parents=True, exist_ok=True)
    elif settings.database_url.startswith("sqlite:////"):
        Path("/" + settings.database_url.removeprefix("sqlite:////")).parent.mkdir(parents=True, exist_ok=True)
