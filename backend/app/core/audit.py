from sqlalchemy.orm import Session

from app.models.entities import AuditLog


def record_audit(db: Session, *, actor_id: str, action: str, resource_type: str, resource_id: str, details: dict | None = None) -> None:
    """Persist a minimal audit event; callers must not include cookies, tokens or credential values."""
    safe = details or {}
    if any(key.lower() in {"password", "token", "cookie", "authorization", "secret"} for key in safe):
        raise ValueError("Sensitive values must not be written to audit detail")
    db.add(AuditLog(actor_id=actor_id, action=action, resource_type=resource_type, resource_id=resource_id, details=safe))
