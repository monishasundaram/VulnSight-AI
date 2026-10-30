from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.target_schemas import TargetCreate, TargetUpdate
from app.core.audit import record_audit
from app.core.auth import AuthContext, get_auth_context, verify_csrf
from app.core.config import settings
from app.core.rate_limit import enforce_rate_limit
from app.db.session import get_db
from app.models.entities import Scan, Target
from app.scanners.scope import ScopeError, validate_target_url

router = APIRouter(prefix="/api/targets", tags=["targets"])


def target_json(target: Target) -> dict:
    allowed = (target.scope_configuration or {}).get("allowed_hosts", [])
    return {
        "id": target.id, "name": target.name, "base_url": target.base_url,
        "description": target.description, "owner_reference": target.owner_reference,
        "authorization_status": target.authorization_status, "allowed_hostnames": allowed,
        "scope_notes": target.scope_notes, "enabled": target.enabled,
        "last_scan_at": target.last_scan_at.isoformat() if target.last_scan_at else None,
        "created_at": target.created_at.isoformat() if target.created_at else None,
        "updated_at": target.updated_at.isoformat() if target.updated_at else None,
    }


def _validated_scope(base_url: str, allowed_hosts: list[str]) -> tuple[str, dict]:
    try:
        canonical, host, port, normalized = validate_target_url(base_url, allowed_hosts)
    except ScopeError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return canonical, {"allowed_hosts": list(normalized), "ports": [port], "scheme_host": host}


def owned_target(db: Session, target_id: str, owner_id: str) -> Target:
    target = db.scalar(select(Target).where(Target.id == target_id, Target.owner_id == owner_id))
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    return target


@router.get("")
def list_targets(context: AuthContext = Depends(get_auth_context), db: Session = Depends(get_db)) -> dict:
    items = db.scalars(select(Target).where(Target.owner_id == context.user.id).order_by(Target.updated_at.desc())).all()
    return {"items": [target_json(item) for item in items], "total": len(items)}


@router.post("", status_code=201)
def create_target(payload: TargetCreate, request: Request, context: AuthContext = Depends(get_auth_context), db: Session = Depends(get_db)) -> dict:
    verify_csrf(request, context)
    enforce_rate_limit(request, f"target-create:{context.user.id}", 10, 3600)
    count = db.scalar(select(func.count(Target.id)).where(Target.owner_id == context.user.id)) or 0
    if count >= settings.max_targets_per_user:
        raise HTTPException(status_code=409, detail="Target limit reached")
    canonical, scope = _validated_scope(payload.base_url, payload.allowed_hostnames)
    target = Target(
        owner_id=context.user.id, name=payload.name.strip(), base_url=canonical,
        description=payload.description.strip(), owner_reference=payload.owner_reference.strip(),
        authorization_status="authorized", authorization_confirmed_at=datetime.now(timezone.utc),
        scope_configuration=scope, scope_notes=payload.scope_notes.strip(), enabled=True,
    )
    db.add(target)
    db.flush()
    record_audit(db, actor_id=context.user.id, action="target.register", resource_type="target", resource_id=target.id,
                 details={"host": scope["scheme_host"], "allowed_hosts": scope["allowed_hosts"]})
    db.commit()
    db.refresh(target)
    return target_json(target)


@router.get("/{target_id}")
def get_target(target_id: str, context: AuthContext = Depends(get_auth_context), db: Session = Depends(get_db)) -> dict:
    return target_json(owned_target(db, target_id, context.user.id))


@router.patch("/{target_id}")
def update_target(target_id: str, payload: TargetUpdate, request: Request, context: AuthContext = Depends(get_auth_context), db: Session = Depends(get_db)) -> dict:
    verify_csrf(request, context)
    enforce_rate_limit(request, f"target-edit:{context.user.id}", 60, 60)
    target = owned_target(db, target_id, context.user.id)
    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=422, detail="No target fields were supplied")
    current_allowed = (target.scope_configuration or {}).get("allowed_hosts", [])
    new_url = changes.get("base_url", target.base_url)
    new_hosts = changes.get("allowed_hostnames", current_allowed)
    # The UI may submit its whole edit form. Revalidate but only demand renewed consent for an actual scope change.
    canonical, new_scope = _validated_scope(new_url, new_hosts)
    actual_scope_change = canonical != target.base_url or new_scope["allowed_hosts"] != current_allowed
    if actual_scope_change and changes.get("authorization_confirmed") is not True:
        raise HTTPException(status_code=403, detail="Changing target scope requires renewed authorization confirmation")
    if changes.get("enabled") is True and target.enabled is False and changes.get("authorization_confirmed") is not True:
        raise HTTPException(status_code=403, detail="Re-enabling a target requires renewed authorization confirmation")
    if actual_scope_change:
        target.base_url = canonical
        target.scope_configuration = new_scope
        target.authorization_status = "authorized"
        target.authorization_confirmed_at = datetime.now(timezone.utc)
    for field in ("name", "description", "owner_reference", "scope_notes", "enabled"):
        if field in changes:
            value = changes[field]
            setattr(target, field, value.strip() if field in {"name", "description", "owner_reference", "scope_notes"} and value is not None else value)
    db.flush()
    record_audit(db, actor_id=context.user.id, action="target.update", resource_type="target", resource_id=target.id,
                 details={"changed_fields": sorted(key for key in changes if key != "authorization_confirmed")})
    db.commit()
    db.refresh(target)
    return target_json(target)


@router.delete("/{target_id}", status_code=204)
def delete_target(
    target_id: str,
    request: Request,
    context: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> Response:
    verify_csrf(request, context)
    enforce_rate_limit(request, f"target-delete:{context.user.id}", 30, 60)
    target = owned_target(db, target_id, context.user.id)
    scan_count = db.scalar(select(func.count(Scan.id)).where(Scan.target_id == target.id)) or 0
    if scan_count:
        raise HTTPException(
            status_code=409,
            detail="This target has scan history and cannot be deleted. Disable it instead to preserve scans, findings and audit history.",
        )
    record_audit(
        db,
        actor_id=context.user.id,
        action="target.delete",
        resource_type="target",
        resource_id=target.id,
        details={"host": (target.scope_configuration or {}).get("scheme_host", "")},
    )
    db.delete(target)
    db.commit()
    return Response(status_code=204)
