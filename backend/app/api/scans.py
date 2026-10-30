from __future__ import annotations

from datetime import date, datetime, time, timedelta, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.scan_schemas import ScanCreate
from app.core.audit import record_audit
from app.core.auth import AuthContext, get_auth_context, reject_cross_site_browser_request, verify_csrf
from app.core.config import settings
from app.core.rate_limit import enforce_rate_limit
from app.db.session import get_db
from app.models.entities import Finding, Scan, ScanEvent, Target
from app.scanners.scope import ScopeError, validate_target_url
from app.workers.scan_manager import ScanManager, WorkerCapacityError

router = APIRouter(prefix="/api/scans", tags=["scans"])
scan_manager = ScanManager()
TERMINAL = {"completed", "failed", "cancelled"}


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def owned_scan(db: Session, scan_id: str, owner_id: str) -> Scan:
    scan = db.scalar(
        select(Scan)
        .join(Target, Scan.target_id == Target.id)
        .where(Scan.id == scan_id, Scan.initiated_by == owner_id, Target.owner_id == owner_id)
    )
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


def finding_json(finding: Finding) -> dict:
    return {
        "id": finding.id,
        "scan_id": finding.scan_id,
        "title": finding.title,
        "category": finding.category,
        "severity": finding.severity,
        "affected_url": finding.affected_url,
        "description": finding.description,
        "evidence": finding.evidence,
        "impact": finding.impact,
        "remediation": finding.remediation,
        "references": finding.references,
        "confidence": finding.confidence,
        "verification_status": finding.verification_status,
        "status": finding.status,
        "detected_at": _iso(finding.detected_at),
    }


def scan_json(db: Session, scan: Scan, *, include_events: bool = False) -> dict:
    target = db.get(Target, scan.target_id)
    now = datetime.now(timezone.utc)
    started = scan.started_at
    if started.tzinfo is None:
        started = started.replace(tzinfo=timezone.utc)
    elapsed = scan.duration_seconds
    if elapsed is None and scan.status in {"queued", "running"}:
        elapsed = max(0.0, (now - started).total_seconds())
    count = db.scalar(select(func.count(Finding.id)).where(Finding.scan_id == scan.id)) or 0
    result = {
        "id": scan.id,
        "target_id": scan.target_id,
        "target_name": target.name if target else "Unavailable target",
        "target_url": target.base_url if target else "",
        "name": scan.name or (target.name if target else "Scan"),
        "description": scan.description,
        "profile": scan.profile,
        "status": scan.status,
        "stage": scan.stage,
        "started_at": _iso(scan.started_at),
        "completed_at": _iso(scan.completed_at),
        "archived_at": _iso(scan.archived_at),
        "duration_seconds": elapsed,
        "error_summary": scan.error_summary,
        "cancel_requested": scan.cancel_requested,
        "checks_total": scan.checks_total,
        "checks_completed": scan.checks_completed,
        "progress_percent": round(scan.checks_completed * 100 / scan.checks_total) if scan.checks_total else 0,
        "findings_count": count,
        "created_at": _iso(scan.started_at),
        "limitations": [
            "Passive, bounded GET checks only; no login/credential attacks, arbitrary plugins, active exploit or denial-of-service tests.",
            "A single TLS handshake and sampled HTTP response do not establish complete application security.",
            "OWASP ZAP is not configured; no ZAP or OWASP Top 10 coverage is claimed.",
        ],
    }
    if include_events:
        events = db.scalars(select(ScanEvent).where(ScanEvent.scan_id == scan.id).order_by(ScanEvent.created_at, ScanEvent.id).limit(500)).all()
        result["events"] = [
            {"id": event.id, "stage": event.stage, "event_type": event.event_type,
             "message": event.message, "check_key": event.check_key, "created_at": _iso(event.created_at)}
            for event in events
        ]
    return result


def _target_scope(db: Session, target_id: str, owner_id: str) -> Target:
    target = db.scalar(select(Target).where(Target.id == target_id, Target.owner_id == owner_id))
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    if not target.enabled or target.authorization_status != "authorized":
        raise HTTPException(status_code=409, detail="Target is disabled or not currently authorized")
    scope = target.scope_configuration or {}
    allowed_hosts = scope.get("allowed_hosts", [])
    try:
        validate_target_url(target.base_url, allowed_hosts)
    except ScopeError as exc:
        raise HTTPException(status_code=409, detail="Target no longer meets public authorized-scope checks") from exc
    return target


@router.post("", status_code=202)
def create_scan(payload: ScanCreate, request: Request,
                context: AuthContext = Depends(get_auth_context), db: Session = Depends(get_db)) -> dict:
    reject_cross_site_browser_request(request)
    verify_csrf(request, context)
    enforce_rate_limit(request, f"scan-start:{context.user.id}", settings.scan_rate_per_minute, 60)
    if payload.zap_passive_authorized:
        raise HTTPException(status_code=409, detail="Optional OWASP ZAP is not configured; no ZAP scan was launched")
    target = _target_scope(db, str(payload.target_id), context.user.id)
    now = datetime.now(timezone.utc)
    target.last_scan_at = now
    scan = Scan(
        target_id=target.id,
        initiated_by=context.user.id,
        profile=payload.profile,
        name=payload.name or target.name,
        description=payload.description,
        status="queued",
        stage="queued",
        started_at=now,
        cancel_requested=False,
        zap_authorized=False,
        zap_active_authorized=False,
        checks_total=8 if payload.profile in {"standard", "advanced"} else 6,
        checks_completed=0,
    )
    db.add(scan)
    db.flush()
    db.add(ScanEvent(scan_id=scan.id, stage="queued", event_type="status",
                     message="Scan accepted and queued for a bounded worker; progress will reflect persisted checks."))
    record_audit(db, actor_id=context.user.id, action="scan.start", resource_type="scan", resource_id=scan.id,
                 details={"target_id": target.id, "profile": payload.profile})
    db.commit()
    db.refresh(scan)
    try:
        scan_manager.submit(scan.id)
    except WorkerCapacityError as exc:
        scan.status = "failed"
        scan.stage = "worker_capacity"
        scan.completed_at = datetime.now(timezone.utc)
        scan.error_summary = "No worker slot was available; no scan requests were sent. Retry when capacity is available."
        db.add(ScanEvent(scan_id=scan.id, stage=scan.stage, event_type="error", message=scan.error_summary))
        db.commit()
        raise HTTPException(status_code=429, detail=scan.error_summary, headers={"Retry-After": "30"}) from exc
    return scan_json(db, scan, include_events=True)


@router.get("")
def list_scans(
    target_id: UUID | None = None,
    status: str | None = Query(default=None, pattern="^(queued|running|completed|failed|cancelled)$"),
    query: str | None = Query(default=None, max_length=120),
    date_from: date | None = None,
    date_to: date | None = None,
    sort: str = Query(default="started_at", pattern="^(started_at|findings_count)$"),
    direction: str = Query(default="desc", pattern="^(asc|desc)$"),
    page: int = Query(default=1, ge=1, le=10000),
    page_size: int = Query(default=20, ge=1, le=100),
    include_archived: bool = Query(default=False),
    context: AuthContext = Depends(get_auth_context), db: Session = Depends(get_db),
) -> dict:
    base = select(Scan).join(Target, Scan.target_id == Target.id).where(
        Scan.initiated_by == context.user.id, Target.owner_id == context.user.id
    )
    if not include_archived:
        base = base.where(Scan.archived_at.is_(None))
    if target_id:
        base = base.where(Scan.target_id == str(target_id))
    if status:
        base = base.where(Scan.status == status)
    if query:
        term = f"%{query.strip()}%"
        base = base.where(
            Scan.name.ilike(term) | Target.name.ilike(term) | Target.base_url.ilike(term) | Scan.id.ilike(term)
        )
    if date_from and date_to and date_to < date_from:
        raise HTTPException(status_code=422, detail="date_to must be on or after date_from")
    if date_from:
        base = base.where(Scan.started_at >= datetime.combine(date_from, time.min, tzinfo=timezone.utc))
    if date_to:
        exclusive_end = datetime.combine(date_to + timedelta(days=1), time.min, tzinfo=timezone.utc)
        base = base.where(Scan.started_at < exclusive_end)
    total = db.scalar(select(func.count()).select_from(base.subquery())) or 0
    finding_count = select(func.count(Finding.id)).where(Finding.scan_id == Scan.id).correlate(Scan).scalar_subquery()
    sort_column = finding_count if sort == "findings_count" else Scan.started_at
    ordering = sort_column.asc() if direction == "asc" else sort_column.desc()
    rows = db.scalars(base.order_by(ordering, Scan.id.asc()).offset((page - 1) * page_size).limit(page_size)).all()
    return {"items": [scan_json(db, item) for item in rows], "total": total, "page": page, "page_size": page_size}


@router.get("/{scan_id}")
def get_scan(scan_id: UUID, context: AuthContext = Depends(get_auth_context), db: Session = Depends(get_db)) -> dict:
    scan = owned_scan(db, str(scan_id), context.user.id)
    return scan_json(db, scan, include_events=True)


@router.get("/{scan_id}/events")
def get_scan_events(scan_id: UUID, after: datetime | None = None,
                    context: AuthContext = Depends(get_auth_context), db: Session = Depends(get_db)) -> dict:
    scan = owned_scan(db, str(scan_id), context.user.id)
    query = select(ScanEvent).where(ScanEvent.scan_id == scan.id)
    if after is not None:
        if after.tzinfo is None:
            after = after.replace(tzinfo=timezone.utc)
        query = query.where(ScanEvent.created_at > after)
    events = db.scalars(query.order_by(ScanEvent.created_at, ScanEvent.id).limit(500)).all()
    return {"items": [{"id": item.id, "stage": item.stage, "event_type": item.event_type,
                        "message": item.message, "check_key": item.check_key, "created_at": _iso(item.created_at)}
                       for item in events]}


@router.get("/{scan_id}/findings")
def get_scan_findings(scan_id: UUID, context: AuthContext = Depends(get_auth_context), db: Session = Depends(get_db)) -> dict:
    scan = owned_scan(db, str(scan_id), context.user.id)
    findings = db.scalars(select(Finding).where(Finding.scan_id == scan.id).order_by(Finding.detected_at.desc(), Finding.id)).all()
    return {"items": [finding_json(item) for item in findings], "total": len(findings)}


@router.post("/{scan_id}/cancel")
def cancel_scan(scan_id: UUID, request: Request,
                context: AuthContext = Depends(get_auth_context), db: Session = Depends(get_db)) -> dict:
    reject_cross_site_browser_request(request)
    verify_csrf(request, context)
    enforce_rate_limit(request, f"scan-cancel:{context.user.id}", 30, 60)
    scan = owned_scan(db, str(scan_id), context.user.id)
    if scan.status in TERMINAL:
        raise HTTPException(status_code=409, detail="A completed scan cannot be cancelled")
    scan.cancel_requested = True
    scan.stage = "cancellation_requested"
    db.add(ScanEvent(scan_id=scan.id, stage=scan.stage, event_type="status",
                     message="Cancellation requested; active request is closing and no further requests will be sent."))
    record_audit(db, actor_id=context.user.id, action="scan.cancel", resource_type="scan", resource_id=scan.id,
                 details={"status": scan.status})
    db.commit()
    scan_manager.cancel(scan.id)
    db.refresh(scan)
    return scan_json(db, scan, include_events=True)


@router.delete("/{scan_id}")
def archive_scan(
    scan_id: UUID,
    request: Request,
    context: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> dict:
    reject_cross_site_browser_request(request)
    verify_csrf(request, context)
    enforce_rate_limit(request, f"scan-archive:{context.user.id}", 30, 60)
    scan = owned_scan(db, str(scan_id), context.user.id)
    if scan.status not in TERMINAL:
        raise HTTPException(status_code=409, detail="An active scan cannot be removed from history")
    if scan.archived_at is None:
        now = datetime.now(timezone.utc)
        scan.archived_at = now
        db.add(ScanEvent(
            scan_id=scan.id,
            stage="archived",
            event_type="status",
            message="Removed from the default scan history; scan results, findings, reports and audit records are retained.",
            created_at=now,
        ))
        record_audit(
            db,
            actor_id=context.user.id,
            action="scan.archive",
            resource_type="scan",
            resource_id=scan.id,
            details={"retains_findings_reports_and_events": True},
        )
        db.commit()
        db.refresh(scan)
    return scan_json(db, scan, include_events=True)


@router.post("/{scan_id}/restore")
def restore_scan(
    scan_id: UUID,
    request: Request,
    context: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> dict:
    reject_cross_site_browser_request(request)
    verify_csrf(request, context)
    enforce_rate_limit(request, f"scan-restore:{context.user.id}", 30, 60)
    scan = owned_scan(db, str(scan_id), context.user.id)
    if scan.status not in TERMINAL:
        raise HTTPException(status_code=409, detail="Only a terminal scan can be restored to history")
    if scan.archived_at is not None:
        scan.archived_at = None
        now = datetime.now(timezone.utc)
        db.add(ScanEvent(
            scan_id=scan.id,
            stage="restored",
            event_type="status",
            message="Restored to the default scan history; all associated findings and reports remain available.",
            created_at=now,
        ))
        record_audit(
            db,
            actor_id=context.user.id,
            action="scan.restore",
            resource_type="scan",
            resource_id=scan.id,
            details={"findings_reports_and_events_retained": True},
        )
        db.commit()
        db.refresh(scan)
    return scan_json(db, scan, include_events=True)
