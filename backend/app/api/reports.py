from __future__ import annotations

from datetime import timedelta, timezone
from hashlib import sha256
from html import escape
from io import BytesIO
import json
import os
from pathlib import Path
from urllib.parse import quote
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path as ApiPath, Query, Request, Response
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.report_schemas import ReportRequest
from app.api.scans import finding_json, owned_scan, scan_json
from app.core.audit import record_audit
from app.core.auth import AuthContext, get_auth_context, reject_cross_site_browser_request, verify_csrf
from app.core.config import settings
from app.core.rate_limit import enforce_rate_limit
from app.db.session import get_db
from app.models.entities import Finding, Report, Scan, ScanEvent, Target, User, utcnow

router = APIRouter(prefix="/api/reports", tags=["reports"])
SEVERITIES = ("critical", "high", "medium", "low", "informational")
TERMINAL = {"completed", "failed", "cancelled"}


def _safe_url(path: Path) -> Path:
    root = settings.data_dir.resolve() / "reports"
    resolved = path.resolve()
    if not resolved.is_relative_to(root):
        raise HTTPException(status_code=500, detail="Report storage path is invalid")
    return resolved


def build_report_data(db: Session, scan, owner_id: str) -> dict:
    target = db.get(Target, scan.target_id)
    findings = db.scalars(
        select(Finding).where(Finding.scan_id == scan.id).order_by(Finding.detected_at, Finding.id)
    ).all()
    events = db.scalars(
        select(ScanEvent).where(ScanEvent.scan_id == scan.id, ScanEvent.event_type == "check")
        .order_by(ScanEvent.created_at, ScanEvent.id)
    ).all()
    counts = {severity: sum(1 for item in findings if item.severity == severity) for severity in SEVERITIES}
    observed = sum(counts.values())
    executive = (
        f"The {scan.profile} assessment recorded {observed} evidence-backed finding(s) "
        f"across {scan.checks_completed} of {scan.checks_total} checks. "
        "Results are limited to the bounded checks listed below and do not establish complete security."
    )
    limitations = [
        "Only bounded passive and benign GET checks were used; no active exploit, credential attack, data extraction or denial-of-service check was performed.",
        "A single TLS handshake and sampled HTTP response do not establish every protocol, endpoint, authentication state or application security property.",
        "OWASP ZAP is not configured; no ZAP or OWASP Top 10 coverage is claimed.",
    ]
    if scan.error_summary:
        limitations.append(f"Scan state: {scan.status}. {scan.error_summary}")
    if scan.profile == "advanced":
        limitations.append("The Advanced profile remained passive; optional OWASP ZAP execution was not available in this installation.")
    scope_config = target.scope_configuration or {} if target else {}
    started = scan.started_at
    started_text = started.isoformat() if started else None
    completed_text = scan.completed_at.isoformat() if scan.completed_at else None
    return {
        "report_title": "VulnSight AI Security Assessment Report",
        "schema_version": "1.0",
        "generated_at": utcnow().isoformat(),
        "scan": {
            "id": scan.id, "name": scan.name, "description": scan.description,
            "profile": scan.profile, "status": scan.status,
            "started_at": started_text, "completed_at": completed_text,
            "duration_seconds": scan.duration_seconds,
            "checks_completed": scan.checks_completed, "checks_total": scan.checks_total,
            "checks": [
                {"key": item.check_key, "stage": item.stage, "message": item.message, "recorded_at": item.created_at.isoformat()}
                for item in events
            ],
        },
        "authorized_scope": {
            "target_id": target.id if target else scan.target_id,
            "target_name": target.name if target else "Unavailable target",
            "base_url": target.base_url if target else None,
            "allowed_hostnames": list(scope_config.get("allowed_hosts", [])),
            "allowed_ports": list(scope_config.get("ports", [])),
            "owner_reference": target.owner_reference if target else None,
            "authorization_status_at_report": target.authorization_status if target else "unavailable",
        },
        "executive_summary": executive,
        "severity_counts": counts,
        "finding_count": observed,
        "findings": [finding_json(item) for item in findings],
        "limitations": limitations,
        "disclaimer": "This report describes observations from a limited, authorized assessment at the recorded time. It is not a guarantee that the application is secure, does not replace a full security review, and should be interpreted by qualified personnel in context.",
        "generated_by": "VulnSight AI",
    }


def _paragraph(value: object, style: ParagraphStyle) -> Paragraph:
    escaped = escape(str(value)).replace("\n", "<br/>")
    return Paragraph(escaped, style)


def _render_pdf(data: dict) -> bytes:
    buffer = BytesIO()
    document = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=0.62 * inch, leftMargin=0.62 * inch,
                                 topMargin=0.62 * inch, bottomMargin=0.62 * inch,
                                 title="VulnSight AI Assessment Report", author="VulnSight AI")
    base_styles = getSampleStyleSheet()
    title = ParagraphStyle("VulnSightTitle", parent=base_styles["Title"], fontName="Helvetica-Bold",
                           fontSize=20, textColor=colors.HexColor("#0B1020"), alignment=TA_LEFT, spaceAfter=8)
    h2 = ParagraphStyle("VulnSightH2", parent=base_styles["Heading2"], fontName="Helvetica-Bold",
                        fontSize=12, textColor=colors.HexColor("#16354A"), spaceBefore=12, spaceAfter=6)
    body = ParagraphStyle("VulnSightBody", parent=base_styles["BodyText"], fontName="Helvetica",
                          fontSize=8.5, leading=12, spaceAfter=4)
    small = ParagraphStyle("VulnSightSmall", parent=body, fontSize=7.5, leading=10)
    story = [
        _paragraph(data["report_title"], title),
        _paragraph(f"Scan {data['scan']['id']} · {data['scan']['profile'].title()} · {data['scan']['status'].title()}", body),
        _paragraph(f"Target: {data['authorized_scope']['target_name']} ({data['authorized_scope']['base_url']})", body),
        _paragraph(f"Authorized hostnames: {', '.join(data['authorized_scope']['allowed_hostnames']) or 'not available'} · Ports: {', '.join(str(x) for x in data['authorized_scope']['allowed_ports']) or 'not available'}", body),
        _paragraph(f"Started: {data['scan']['started_at']} · Completed: {data['scan']['completed_at']} · Duration: {data['scan']['duration_seconds']} seconds", body),
        Spacer(1, 6), _paragraph("Executive summary", h2), _paragraph(data["executive_summary"], body),
        _paragraph("Severity distribution", h2),
    ]
    table_data = [["Critical", "High", "Medium", "Low", "Informational"]]
    table_data.append([str(data["severity_counts"][key]) for key in SEVERITIES])
    table = Table(table_data, colWidths=[1.15 * inch] * 5, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#182235")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("TEXTCOLOR", (0, 1), (-1, 1), colors.HexColor("#0B1020")),
        ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#E7EEF5")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"), ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#9AA9BD")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"), ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.extend([table, _paragraph("Completed checks", h2)])
    for check in data["scan"]["checks"]:
        story.append(_paragraph(f"{check['stage']} — {check['message']} ({check['recorded_at']})", small))
    story.append(_paragraph("Findings and remediation", h2))
    if not data["findings"]:
        story.append(_paragraph("No findings were recorded by the checks that completed. This is not proof that the target is secure.", body))
    for index, finding in enumerate(data["findings"], 1):
        story.append(_paragraph(f"{index}. {finding['title']} — {finding['severity'].title()} ({finding['category']})", h2))
        story.append(_paragraph(f"URL: {finding['affected_url']} · Status: {finding['status']} · Confidence: {finding['confidence']} · Verification: {finding['verification_status']}", small))
        story.append(_paragraph(finding["description"], body))
        story.append(_paragraph(f"Impact: {finding['impact']}", body))
        story.append(_paragraph(f"Evidence: {json.dumps(finding['evidence'], ensure_ascii=False)[:2500]}", small))
        story.append(_paragraph(f"Remediation: {finding['remediation']}", body))
        if finding["references"]:
            story.append(_paragraph(f"References: {'; '.join(finding['references'])}", small))
    story.append(_paragraph("Limitations and disclaimer", h2))
    for item in data["limitations"]:
        story.append(_paragraph(f"- {item}", small))
    story.append(_paragraph(data["disclaimer"], small))
    document.build(story)
    return buffer.getvalue()


def _report_path(owner_id: str, scan_id: str, report_format: str) -> Path:
    root = (settings.data_dir / "reports").resolve()
    path = root / owner_id / f"{scan_id}.{report_format}"
    return _safe_url(path)


def _purge_expired_reports(db: Session, owner_id: str, retention_days: int) -> None:
    if retention_days <= 0:
        return
    cutoff = utcnow() - timedelta(days=retention_days)
    expired = db.scalars(
        select(Report).join(Scan, Report.scan_id == Scan.id).join(Target, Scan.target_id == Target.id)
        .where(Scan.initiated_by == owner_id, Target.owner_id == owner_id)
    ).all()
    deleted = False
    for report in expired:
        generated_at = report.generated_at
        if generated_at.tzinfo is None:
            generated_at = generated_at.replace(tzinfo=timezone.utc)
        if generated_at >= cutoff:
            continue
        path = _report_path(owner_id, report.scan_id, report.format)
        try:
            path.unlink(missing_ok=True)
        except OSError:
            continue
        record_audit(db, actor_id=owner_id, action="report.retention_delete", resource_type="report",
                     resource_id=report.id, details={"format": report.format, "retention_days": retention_days})
        db.delete(report)
        deleted = True
    if deleted:
        db.commit()


def _build_bytes(data: dict, report_format: str) -> bytes:
    if report_format == "json":
        return (json.dumps(data, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8")
    if report_format == "pdf":
        return _render_pdf(data)
    raise HTTPException(status_code=422, detail="Unsupported report format")


@router.get("")
def list_reports(context: AuthContext = Depends(get_auth_context), db: Session = Depends(get_db)) -> dict:
    user = db.get(User, context.user.id)
    retention_days = (user.preferences or {}).get("report_retention_days", 0) if user else 0
    if retention_days not in {0, 30, 90, 180, 365}:
        retention_days = 0
    _purge_expired_reports(db, context.user.id, retention_days)
    rows = db.execute(
        select(Report, Target.name, Scan.name, Scan.profile, Scan.status)
        .join(Scan, Report.scan_id == Scan.id).join(Target, Scan.target_id == Target.id)
        .where(Scan.initiated_by == context.user.id, Target.owner_id == context.user.id)
        .order_by(Report.generated_at.desc(), Report.id)
    ).all()
    return {"items": [
        {"id": report.id, "scan_id": report.scan_id, "format": report.format,
         "generated_at": report.generated_at.isoformat(), "sha256": report.sha256,
         "target_name": target_name, "scan_name": scan_name, "profile": profile,
         "status": status, "download_url": f"/api/reports/{report.scan_id}/download/{report.format}"}
        for report, target_name, scan_name, profile, status in rows
    ], "total": len(rows)}


@router.get("/eligible-scans")
def eligible_scans(
    page: int = Query(default=1, ge=1, le=10000),
    page_size: int = Query(default=20, ge=1, le=100),
    context: AuthContext = Depends(get_auth_context), db: Session = Depends(get_db),
) -> dict:
    base = select(Scan).join(Target, Scan.target_id == Target.id).where(
        Scan.initiated_by == context.user.id,
        Target.owner_id == context.user.id,
        Scan.status.in_(TERMINAL),
    )
    total = db.scalar(select(func.count()).select_from(base.subquery())) or 0
    rows = db.scalars(base.order_by(Scan.started_at.desc(), Scan.id).offset((page - 1) * page_size).limit(page_size)).all()
    return {"items": [scan_json(db, scan) for scan in rows], "total": total, "page": page, "page_size": page_size}


@router.get("/{scan_id}")
def preview_report(scan_id: UUID, context: AuthContext = Depends(get_auth_context),
                   db: Session = Depends(get_db)) -> dict:
    scan = owned_scan(db, str(scan_id), context.user.id)
    if scan.status not in TERMINAL:
        raise HTTPException(status_code=409, detail="A report is available only after the scan reaches a terminal state")
    return build_report_data(db, scan, context.user.id)


@router.post("/{scan_id}", status_code=201)
def generate_report(scan_id: UUID, payload: ReportRequest, request: Request,
                    context: AuthContext = Depends(get_auth_context), db: Session = Depends(get_db)) -> dict:
    reject_cross_site_browser_request(request)
    verify_csrf(request, context)
    enforce_rate_limit(request, f"report-generate:{context.user.id}", 30, 3600)
    scan = owned_scan(db, str(scan_id), context.user.id)
    if scan.status not in TERMINAL:
        raise HTTPException(status_code=409, detail="Reports are generated only from completed, failed or cancelled scan records")
    data = build_report_data(db, scan, context.user.id)
    content = _build_bytes(data, payload.format)
    path = _report_path(context.user.id, scan.id, payload.format)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temp_path = path.with_suffix(path.suffix + ".tmp")
    descriptor = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(content)
        output.flush()
        os.fsync(output.fileno())
    temp_path.replace(path)
    digest = sha256(content).hexdigest()
    report = db.scalar(select(Report).where(Report.scan_id == scan.id, Report.format == payload.format))
    if report is None:
        report = Report(scan_id=scan.id, format=payload.format, storage_reference=str(path.relative_to(settings.data_dir.resolve())), sha256=digest)
        db.add(report)
    else:
        report.generated_at = utcnow()
        report.storage_reference = str(path.relative_to(settings.data_dir.resolve()))
        report.sha256 = digest
    db.commit()
    db.refresh(report)
    record_audit(db, actor_id=context.user.id, action="report.generate", resource_type="report", resource_id=report.id,
                 details={"scan_id": scan.id, "format": report.format, "sha256": digest})
    db.commit()
    return {"id": report.id, "scan_id": report.scan_id, "format": report.format,
            "generated_at": report.generated_at.isoformat(), "sha256": report.sha256,
            "size_bytes": len(content), "filename": f"vulnsight-scan-{scan.id}.{report.format}",
            "download_url": f"/api/reports/{scan.id}/download/{report.format}"}


@router.get("/{scan_id}/download/{report_format}")
def download_report(scan_id: UUID, report_format: str = ApiPath(pattern="^(pdf|json)$"),
                    context: AuthContext = Depends(get_auth_context), db: Session = Depends(get_db)) -> Response:
    scan = owned_scan(db, str(scan_id), context.user.id)
    report = db.scalar(select(Report).where(Report.scan_id == scan.id, Report.format == report_format))
    if report is None:
        raise HTTPException(status_code=404, detail="Generate this report format before downloading it")
    path = _report_path(context.user.id, scan.id, report_format)
    try:
        content = path.read_bytes()
    except FileNotFoundError as exc:
        raise HTTPException(status_code=410, detail="The generated report file is no longer available") from exc
    if sha256(content).hexdigest() != report.sha256:
        raise HTTPException(status_code=410, detail="The generated report integrity check failed")
    content_type = "application/pdf" if report_format == "pdf" else "application/json"
    filename = f"vulnsight-scan-{scan.id}.{report_format}"
    return Response(content=content, media_type=content_type,
                    headers={"Content-Disposition": f"attachment; filename=\"{quote(filename)}\"",
                             "Cache-Control": "private, no-store", "ETag": f'"{report.sha256}"'})
