from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.scans import finding_json
from app.core.audit import record_audit
from app.core.auth import AuthContext, get_auth_context, reject_cross_site_browser_request, verify_csrf
from app.core.rate_limit import enforce_rate_limit
from app.db.session import get_db
from app.models.entities import Finding, FindingStatusHistory, Scan, Target

router = APIRouter(prefix="/api/findings", tags=["findings"])
VALID_SEVERITIES = {"critical", "high", "medium", "low", "informational"}
VALID_STATUSES = {"open", "in_progress", "resolved", "accepted_risk"}


class FindingStatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    status: Literal["open", "in_progress", "resolved", "accepted_risk"]
    justification: str = Field(default="", max_length=2000)


def owned_finding(db: Session, finding_id: str, owner_id: str) -> Finding:
    finding = db.scalar(
        select(Finding).join(Scan, Finding.scan_id == Scan.id)
        .join(Target, Scan.target_id == Target.id).where(
            Finding.id == finding_id, Scan.initiated_by == owner_id, Target.owner_id == owner_id
        )
    )
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


def detail_json(db: Session, finding: Finding) -> dict:
    result = finding_json(finding)
    scan = db.get(Scan, finding.scan_id)
    target = db.get(Target, scan.target_id) if scan else None
    history = db.scalars(
        select(FindingStatusHistory).where(FindingStatusHistory.finding_id == finding.id)
        .order_by(FindingStatusHistory.changed_at, FindingStatusHistory.id)
    ).all()
    result["scan"] = {"id": scan.id, "name": scan.name, "profile": scan.profile,
                       "status": scan.status, "started_at": scan.started_at.isoformat()} if scan else None
    result["target"] = {"id": target.id, "name": target.name, "base_url": target.base_url} if target else None
    result["status_history"] = [
        {"id": row.id, "previous_status": row.previous_status, "new_status": row.new_status,
         "justification": row.justification, "changed_at": row.changed_at.isoformat()}
        for row in history
    ]
    return result


@router.get("")
def list_findings(
    severity: str | None = Query(default=None, pattern="^(critical|high|medium|low|informational)$"),
    status: str | None = Query(default=None, pattern="^(open|in_progress|resolved|accepted_risk)$"),
    category: str | None = Query(default=None, max_length=64),
    scan_id: UUID | None = None,
    target_id: UUID | None = None,
    query: str | None = Query(default=None, max_length=120),
    page: int = Query(default=1, ge=1, le=10000),
    page_size: int = Query(default=25, ge=1, le=100),
    context: AuthContext = Depends(get_auth_context), db: Session = Depends(get_db),
) -> dict:
    statement = (
        select(Finding).join(Scan, Finding.scan_id == Scan.id)
        .join(Target, Scan.target_id == Target.id)
        .where(Scan.initiated_by == context.user.id, Target.owner_id == context.user.id)
    )
    if severity:
        statement = statement.where(Finding.severity == severity)
    if status:
        statement = statement.where(Finding.status == status)
    if category:
        statement = statement.where(Finding.category == category)
    if scan_id:
        statement = statement.where(Finding.scan_id == str(scan_id))
    if target_id:
        statement = statement.where(Scan.target_id == str(target_id))
    if query:
        term = f"%{query.strip()}%"
        statement = statement.where((Finding.title.ilike(term)) | (Finding.description.ilike(term)))
    total = db.scalar(select(func.count()).select_from(statement.subquery())) or 0
    rows = db.scalars(statement.order_by(Finding.detected_at.desc(), Finding.id)
                      .offset((page - 1) * page_size).limit(page_size)).all()
    items = []
    for row in rows:
        scan = db.get(Scan, row.scan_id)
        target = db.get(Target, scan.target_id) if scan else None
        item = finding_json(row)
        item["target_name"] = target.name if target else "Unavailable target"
        item["scan_name"] = scan.name if scan else "Unavailable scan"
        items.append(item)
    return {"items": items, "total": int(total), "page": page, "page_size": page_size}


@router.get("/filters")
def finding_filters(context: AuthContext = Depends(get_auth_context), db: Session = Depends(get_db)) -> dict:
    visible_ids = (
        select(Finding.id).join(Scan, Finding.scan_id == Scan.id)
        .join(Target, Scan.target_id == Target.id)
        .where(Scan.initiated_by == context.user.id, Target.owner_id == context.user.id)
    )
    categories = db.scalars(
        select(Finding.category).where(Finding.id.in_(visible_ids)).distinct().order_by(Finding.category)
    ).all()
    scan_rows = db.execute(
        select(Scan.id, Scan.name, Target.name).join(Target, Scan.target_id == Target.id)
        .join(Finding, Finding.scan_id == Scan.id)
        .where(Scan.initiated_by == context.user.id, Target.owner_id == context.user.id)
        .distinct().order_by(Scan.started_at.desc(), Scan.id).limit(100)
    ).all()
    return {
        "categories": list(categories),
        "scans": [{"id": row[0], "name": row[1], "target_name": row[2]} for row in scan_rows],
    }


@router.get("/{finding_id}")
def get_finding(finding_id: UUID, context: AuthContext = Depends(get_auth_context),
                db: Session = Depends(get_db)) -> dict:
    finding = owned_finding(db, str(finding_id), context.user.id)
    return detail_json(db, finding)


@router.patch("/{finding_id}")
def update_finding(finding_id: UUID, payload: FindingStatusUpdate, request: Request,
                   context: AuthContext = Depends(get_auth_context), db: Session = Depends(get_db)) -> dict:
    reject_cross_site_browser_request(request)
    verify_csrf(request, context)
    enforce_rate_limit(request, f"finding-status:{context.user.id}", 60, 60)
    finding = owned_finding(db, str(finding_id), context.user.id)
    previous = finding.status
    new_status = payload.status
    if previous == new_status:
        raise HTTPException(status_code=409, detail="Finding already has this status")
    if previous not in VALID_STATUSES or new_status not in VALID_STATUSES:
        raise HTTPException(status_code=409, detail="Finding status transition is not permitted")
    justification = payload.justification.strip()
    requires_justification = new_status == "accepted_risk" or previous in {"resolved", "accepted_risk"} and new_status == "open"
    if requires_justification and len(justification) < 10:
        raise HTTPException(status_code=422, detail="Provide at least 10 characters of justification for accepting risk or reopening a finding")
    finding.status = new_status
    db.add(FindingStatusHistory(
        finding_id=finding.id, changed_by=context.user.id, previous_status=previous,
        new_status=new_status, justification=justification,
    ))
    record_audit(db, actor_id=context.user.id, action="finding.status_change", resource_type="finding",
                 resource_id=finding.id,
                 details={"previous_status": previous, "new_status": new_status,
                          "justification_provided": bool(justification)})
    db.commit()
    db.refresh(finding)
    return detail_json(db, finding)
