from __future__ import annotations

from datetime import timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.core.audit import record_audit
from app.core.auth import AuthContext, get_auth_context, reject_cross_site_browser_request, verify_csrf
from app.core.config import settings
from app.core.rate_limit import enforce_rate_limit
from app.db.session import get_db
from app.models.entities import User

router = APIRouter(prefix="/api/settings", tags=["settings"])


class SettingsUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    theme: Literal["dark", "light"] | None = None
    default_report_format: Literal["pdf", "json"] | None = None
    report_retention_days: Literal[0, 30, 90, 180, 365] | None = None


def _preferences(user: User) -> dict:
    values = dict(user.preferences or {})
    return {
        "theme": values.get("theme", "dark") if values.get("theme") in {"dark", "light"} else "dark",
        "default_report_format": values.get("default_report_format", "pdf") if values.get("default_report_format") in {"pdf", "json"} else "pdf",
        "report_retention_days": values.get("report_retention_days", 0) if values.get("report_retention_days") in {0, 30, 90, 180, 365} else 0,
    }


def serialize_settings(user: User) -> dict:
    preferences = _preferences(user)
    created = user.created_at
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    return {
        "user": {"id": user.id, "email": user.email, "role": user.role, "created_at": created.isoformat()},
        "preferences": preferences,
        "scan_limits": {
            "allowed_ports": list(settings.target_allowed_ports),
            "max_requests_per_scan": settings.scan_max_requests,
            "max_redirects_per_request": settings.scan_max_redirects,
            "request_timeout_seconds": settings.scan_timeout_seconds,
            "max_response_bytes": settings.scan_max_response_bytes,
            "max_concurrent_jobs": settings.scan_max_concurrent_jobs,
            "max_scan_duration_seconds": settings.scan_max_duration_seconds,
            "scan_rate_per_minute": settings.scan_rate_per_minute,
            "max_targets_per_user": settings.max_targets_per_user,
        },
        "security": {
            "session_ttl_hours": settings.session_ttl_hours,
            "cookie_secure": settings.cookie_secure,
            "cookie_samesite": settings.cookie_samesite,
            "hsts_enabled": settings.hsts_enabled,
        },
        "reports": {
            "retention_days": preferences["report_retention_days"],
            "cleanup_behavior": "Reports older than the configured period are removed when this user's Reports page is next loaded; no background retention daemon is enabled.",
            "max_retention_days": 365,
        },
        "integrations": {
            "owasp_zap": {"configured": False, "active_scanning_enabled": False,
                           "message": "OWASP ZAP is not configured. No ZAP or active scan is launched."},
        },
        "severity_policy": {
            "overrides": dict(settings.severity_overrides),
            "configuration": "SEVERITY_OVERRIDES_JSON may override a finding category's default severity label; defaults are conservative, deterministic triage labels, not CVSS scores.",
        },
        "api_version": "1.0.0",
        "environment": "local" if settings.app_env in {"development", "test", "local"} else "hosted",
    }


@router.get("")
def get_settings(context: AuthContext = Depends(get_auth_context)) -> dict:
    return serialize_settings(context.user)


@router.patch("")
def update_settings(payload: SettingsUpdate, request: Request,
                    context: AuthContext = Depends(get_auth_context), db: Session = Depends(get_db)) -> dict:
    reject_cross_site_browser_request(request)
    verify_csrf(request, context)
    enforce_rate_limit(request, f"settings-update:{context.user.id}", 30, 3600)
    changed = payload.model_dump(exclude_none=True)
    if not changed:
        raise HTTPException(status_code=422, detail="Provide at least one preference to update")
    updated = _preferences(context.user)
    updated.update(changed)
    context.user.preferences = updated
    record_audit(db, actor_id=context.user.id, action="user.preferences_update", resource_type="user",
                 resource_id=context.user.id, details={"changed_preferences": sorted(changed.keys())})
    db.commit()
    db.refresh(context.user)
    return serialize_settings(context.user)
