from __future__ import annotations

from datetime import datetime, timezone
import uuid

from sqlalchemy import Boolean, CheckConstraint, DateTime, Float, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    email: Mapped[str] = mapped_column(String(254), nullable=False, unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(24), nullable=False, default="user")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    disabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    preferences: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    targets: Mapped[list["Target"]] = relationship(back_populates="owner")
    sessions: Mapped[list["AuthSession"]] = relationship(back_populates="user", cascade="all, delete-orphan")


class AuthSession(Base):
    __tablename__ = "auth_sessions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    csrf_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    user: Mapped[User] = relationship(back_populates="sessions")


class Target(Base):
    __tablename__ = "targets"
    __table_args__ = (Index("ix_targets_owner_enabled", "owner_id", "enabled"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    base_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    owner_reference: Mapped[str] = mapped_column(String(160), nullable=False, default="")
    authorization_status: Mapped[str] = mapped_column(String(24), nullable=False, default="pending")
    authorization_confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    scope_configuration: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    scope_notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)
    owner: Mapped[User] = relationship(back_populates="targets")
    scans: Mapped[list["Scan"]] = relationship(back_populates="target")


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (
        CheckConstraint("profile IN ('quick','standard','advanced')", name="ck_scan_profile"),
        CheckConstraint("status IN ('queued','running','completed','failed','cancelled')", name="ck_scan_status"),
        Index("ix_scans_owner_started", "initiated_by", "started_at"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id", ondelete="RESTRICT"), nullable=False, index=True)
    initiated_by: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True)
    profile: Mapped[str] = mapped_column(String(16), nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="queued", index=True)
    stage: Mapped[str] = mapped_column(String(80), nullable=False, default="queued")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    duration_seconds: Mapped[float | None] = mapped_column(Float)
    error_summary: Mapped[str | None] = mapped_column(String(500))
    cancel_requested: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    zap_authorized: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    zap_active_authorized: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    checks_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    checks_completed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    target: Mapped[Target] = relationship(back_populates="scans")
    events: Mapped[list["ScanEvent"]] = relationship(back_populates="scan", cascade="all, delete-orphan", order_by="ScanEvent.created_at")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class ScanEvent(Base):
    __tablename__ = "scan_events"
    __table_args__ = (Index("ix_scan_events_scan_time", "scan_id", "created_at"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    stage: Mapped[str] = mapped_column(String(80), nullable=False)
    event_type: Mapped[str] = mapped_column(String(24), nullable=False, default="check")
    message: Mapped[str] = mapped_column(String(300), nullable=False)
    check_key: Mapped[str | None] = mapped_column(String(80))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    scan: Mapped[Scan] = relationship(back_populates="events")


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        CheckConstraint("severity IN ('critical','high','medium','low','informational')", name="ck_finding_severity"),
        CheckConstraint("status IN ('open','in_progress','resolved','accepted_risk')", name="ck_finding_status"),
        Index("ix_findings_scan_severity", "scan_id", "severity"),
        Index("ix_findings_status_detected", "status", "detected_at"),
        UniqueConstraint("scan_id", "fingerprint", name="uq_finding_scan_fingerprint"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(240), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    affected_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    impact: Mapped[str] = mapped_column(Text, nullable=False, default="")
    remediation: Mapped[str] = mapped_column(Text, nullable=False)
    references: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[str] = mapped_column(String(20), nullable=False, default="medium")
    verification_status: Mapped[str] = mapped_column(String(24), nullable=False, default="observed")
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="open", index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    scan: Mapped[Scan] = relationship(back_populates="findings")
    history: Mapped[list["FindingStatusHistory"]] = relationship(back_populates="finding", cascade="all, delete-orphan")


class FindingStatusHistory(Base):
    __tablename__ = "finding_status_history"
    __table_args__ = (Index("ix_finding_history_finding_time", "finding_id", "changed_at"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    changed_by: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    previous_status: Mapped[str] = mapped_column(String(24), nullable=False)
    new_status: Mapped[str] = mapped_column(String(24), nullable=False)
    justification: Mapped[str] = mapped_column(Text, nullable=False, default="")
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    finding: Mapped[Finding] = relationship(back_populates="history")


class Report(Base):
    __tablename__ = "reports"
    __table_args__ = (UniqueConstraint("scan_id", "format", name="uq_report_scan_format"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    format: Mapped[str] = mapped_column(String(8), nullable=False)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    storage_reference: Mapped[str] = mapped_column(String(255), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (Index("ix_audit_actor_time", "actor_id", "created_at"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    actor_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(40), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(36), nullable=False)
    details: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow, index=True)
