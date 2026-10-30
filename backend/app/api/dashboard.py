from __future__ import annotations

from datetime import date, datetime, time, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.scans import scan_json
from app.core.auth import AuthContext, get_auth_context
from app.db.session import get_db
from app.models.entities import Finding, Scan, Target

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])
OPEN_STATUSES = ("open", "in_progress")
ACTIVE_FINDING_STATUSES = ("open", "in_progress", "accepted_risk")


def _range_counts(db: Session, owner_id: str, start: datetime, end: datetime) -> dict[str, int]:
    scan_count = db.scalar(
        select(func.count(Scan.id)).join(Target, Scan.target_id == Target.id).where(
            Target.owner_id == owner_id, Scan.initiated_by == owner_id,
            Scan.started_at >= start, Scan.started_at < end,
        )
    ) or 0
    open_count = db.scalar(
        select(func.count(Finding.id)).join(Scan, Finding.scan_id == Scan.id)
        .join(Target, Scan.target_id == Target.id).where(
            Target.owner_id == owner_id, Scan.initiated_by == owner_id,
            Finding.detected_at >= start, Finding.detected_at < end,
            Finding.status.in_(OPEN_STATUSES),
        )
    ) or 0
    return {"total_scans": int(scan_count), "open_findings": int(open_count)}


@router.get("/summary")
def summary(context: AuthContext = Depends(get_auth_context), db: Session = Depends(get_db)) -> dict:
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=7)
    previous_start = start - timedelta(days=7)
    scans_query = select(Scan).join(Target, Scan.target_id == Target.id).where(
        Scan.initiated_by == context.user.id, Target.owner_id == context.user.id
    )
    total_scans = db.scalar(select(func.count()).select_from(scans_query.subquery())) or 0
    assessed_targets = db.scalar(
        select(func.count(func.distinct(Scan.target_id))).join(Target, Scan.target_id == Target.id).where(
            Scan.initiated_by == context.user.id, Target.owner_id == context.user.id, Scan.status == "completed"
        )
    ) or 0
    open_findings = db.scalar(
        select(func.count(Finding.id)).join(Scan, Finding.scan_id == Scan.id)
        .join(Target, Scan.target_id == Target.id).where(
            Scan.initiated_by == context.user.id, Target.owner_id == context.user.id,
            Finding.status.in_(OPEN_STATUSES),
        )
    ) or 0
    critical_high = db.scalar(
        select(func.count(Finding.id)).join(Scan, Finding.scan_id == Scan.id)
        .join(Target, Scan.target_id == Target.id).where(
            Scan.initiated_by == context.user.id, Target.owner_id == context.user.id,
            Finding.status.in_(OPEN_STATUSES), Finding.severity.in_(("critical", "high")),
        )
    ) or 0
    severity_rows = db.execute(
        select(Finding.severity, func.count(Finding.id)).join(Scan, Finding.scan_id == Scan.id)
        .join(Target, Scan.target_id == Target.id).where(
            Scan.initiated_by == context.user.id, Target.owner_id == context.user.id,
            Finding.status.in_(ACTIVE_FINDING_STATUSES),
        ).group_by(Finding.severity)
    ).all()
    severity_counts = {name: 0 for name in ("critical", "high", "medium", "low", "informational")}
    severity_counts.update({str(severity): int(count) for severity, count in severity_rows})
    current_period = _range_counts(db, context.user.id, start, now)
    previous_period = _range_counts(db, context.user.id, previous_start, start)
    comparisons = {
        key: (current_period[key] - previous_period[key] if previous_period[key] > 0 else None)
        for key in current_period
    }
    latest_scans = db.scalars(scans_query.order_by(Scan.started_at.desc(), Scan.id).limit(5)).all()
    latest_findings = db.scalars(
        select(Finding).join(Scan, Finding.scan_id == Scan.id)
        .join(Target, Scan.target_id == Target.id).where(
            Scan.initiated_by == context.user.id, Target.owner_id == context.user.id,
        ).order_by(Finding.detected_at.desc(), Finding.id).limit(6)
    ).all()
    recent_scans = [scan_json(db, item) for item in latest_scans]
    recent_findings = []
    for finding in latest_findings:
        parent_scan = db.get(Scan, finding.scan_id)
        target = db.get(Target, parent_scan.target_id) if parent_scan else None
        recent_findings.append({
            "id": finding.id, "scan_id": finding.scan_id,
            "title": finding.title, "severity": finding.severity,
            "category": finding.category, "status": finding.status,
            "target_name": target.name if target else "Unavailable target",
            "affected_url": finding.affected_url, "detected_at": finding.detected_at.isoformat(),
        })
    return {
        "generated_at": now.isoformat(),
        "total_scans": int(total_scans),
        "targets_assessed": int(assessed_targets),
        "open_findings": int(open_findings),
        "critical_high_findings": int(critical_high),
        "severity_counts": severity_counts,
        "comparison_days": 7,
        "comparisons": comparisons,
        "recent_scans": recent_scans,
        "recent_findings": recent_findings,
    }


@router.get("/activity")
def activity(days: int = Query(default=14, ge=7, le=90),
             context: AuthContext = Depends(get_auth_context), db: Session = Depends(get_db)) -> dict:
    today = datetime.now(timezone.utc).date()
    first_day = today - timedelta(days=days - 1)
    start = datetime.combine(first_day, time.min, tzinfo=timezone.utc)
    end = datetime.combine(today + timedelta(days=1), time.min, tzinfo=timezone.utc)
    raw_scans = db.execute(
        select(func.date(Scan.started_at), func.count(Scan.id))
        .join(Target, Scan.target_id == Target.id).where(
            Scan.initiated_by == context.user.id, Target.owner_id == context.user.id,
            Scan.started_at >= start, Scan.started_at < end,
        ).group_by(func.date(Scan.started_at))
    ).all()
    raw_findings = db.execute(
        select(func.date(Finding.detected_at), func.count(Finding.id))
        .join(Scan, Finding.scan_id == Scan.id).join(Target, Scan.target_id == Target.id).where(
            Scan.initiated_by == context.user.id, Target.owner_id == context.user.id,
            Finding.detected_at >= start, Finding.detected_at < end,
        ).group_by(func.date(Finding.detected_at))
    ).all()
    scan_counts = {str(day): int(count) for day, count in raw_scans}
    finding_counts = {str(day): int(count) for day, count in raw_findings}
    items = []
    for offset in range(days):
        day = first_day + timedelta(days=offset)
        key = day.isoformat()
        items.append({"date": key, "scans": scan_counts.get(key, 0), "findings": finding_counts.get(key, 0)})
    return {"days": days, "from": start.isoformat(), "to": end.isoformat(), "items": items}
