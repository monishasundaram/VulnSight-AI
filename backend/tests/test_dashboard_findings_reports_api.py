from __future__ import annotations

import json
import uuid
from datetime import timedelta
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.config import settings
from app.db.session import SessionLocal
from app.main import app
from app.models.entities import AuditLog, Finding, FindingStatusHistory, Report, Scan, ScanEvent, Target, utcnow


def _register(client: TestClient) -> dict:
    response = client.post(
        "/api/auth/register",
        json={"email": f"{uuid.uuid4().hex}@example.com", "password": "A-long-test-password-123!"},
    )
    assert response.status_code == 201, response.text
    return response.json()


def _add_completed_scan(user_id: str, *, scan_name: str = "Persisted local test assessment") -> tuple[str, str, list[str]]:
    with SessionLocal() as db:
        target = Target(
            owner_id=user_id, name="Report API synthetic fixture", base_url="https://report-fixture.example.test/",
            description="Test-only persisted fixture", owner_reference="test-suite", authorization_status="authorized",
            authorization_confirmed_at=utcnow(), scope_configuration={"allowed_hosts": ["report-fixture.example.test"], "ports": [443]},
            scope_notes="Never used to send network traffic in this database-only test", enabled=True,
        )
        db.add(target)
        db.flush()
        now = utcnow()
        scan = Scan(
            target_id=target.id, initiated_by=user_id, profile="standard", name=scan_name,
            description="Synthetic database result used only in automated tests", status="completed", stage="completed",
            started_at=now - timedelta(seconds=3), completed_at=now, duration_seconds=3.0,
            checks_total=8, checks_completed=8,
        )
        db.add(scan)
        db.flush()
        db.add(ScanEvent(
            scan_id=scan.id, stage="security_headers", event_type="check", check_key="security_headers",
            message="Test fixture observed that Content-Security-Policy was absent.", created_at=now,
        ))
        finding_data = [
            {"title": "Content Security Policy is missing", "category": "security_headers", "severity": "high",
             "affected_url": target.base_url, "description": "The test fixture returned no Content-Security-Policy header.",
             "evidence": {"missing_header": "Content-Security-Policy"}, "impact": "Browser restrictions may be weaker.",
             "remediation": "Define a restrictive policy appropriate to the application.",
             "references": ["https://owasp.org/www-project-secure-headers/"], "confidence": "high",
             "verification_status": "observed", "fingerprint": "fixture-csp"},
            {"title": "Cookie attributes are incomplete", "category": "cookies", "severity": "medium",
             "affected_url": target.base_url, "description": "A synthetic cookie lacks hardening attributes.",
             "evidence": {"cookie_name": "session", "missing_attributes": ["Secure", "HttpOnly", "SameSite"]},
             "impact": "The cookie may be exposed to avoidable client-side or transport risks.",
             "remediation": "Set Secure, HttpOnly and an appropriate SameSite policy.", "references": [],
             "confidence": "high", "verification_status": "observed", "fingerprint": "fixture-cookie"},
            {"title": "Benign query marker was reflected", "category": "input_validation", "severity": "low",
             "affected_url": target.base_url, "description": "A non-executable marker appeared in the local fixture response.",
             "evidence": {"probe_method": "GET", "marker_reflected": True}, "impact": "Reflection alone does not prove script execution.",
             "remediation": "Review context-sensitive output encoding.", "references": [], "confidence": "medium",
             "verification_status": "suspected", "fingerprint": "fixture-reflection"},
        ]
        findings = []
        for item in finding_data:
            finding = Finding(scan_id=scan.id, **item)
            db.add(finding)
            findings.append(finding)
        db.commit()
        return target.id, scan.id, [item.id for item in findings]


def test_dashboard_uses_current_users_persisted_scan_history_and_findings():
    with TestClient(app) as owner, TestClient(app) as other:
        auth = _register(owner)
        other_auth = _register(other)
        _add_completed_scan(auth["user"]["id"])
        _add_completed_scan(other_auth["user"]["id"], scan_name="Other user's private synthetic scan")

        summary = owner.get("/api/dashboard/summary")
        assert summary.status_code == 200, summary.text
        data = summary.json()
        assert data["total_scans"] == 1
        assert data["targets_assessed"] == 1
        assert data["open_findings"] == 3
        assert data["critical_high_findings"] == 1
        assert data["severity_counts"] == {"critical": 0, "high": 1, "medium": 1, "low": 1, "informational": 0}
        assert data["recent_scans"][0]["name"] == "Persisted local test assessment"
        assert len(data["recent_findings"]) == 3

        activity = owner.get("/api/dashboard/activity?days=7")
        assert activity.status_code == 200
        activity_rows = activity.json()["items"]
        assert len(activity_rows) == 7
        assert sum(item["scans"] for item in activity_rows) == 1
        assert sum(item["findings"] for item in activity_rows) == 3
        assert sum(item["scans"] for item in other.get("/api/dashboard/activity?days=7").json()["items"]) == 1
        assert "Other user's private" not in summary.text


def test_finding_filter_status_audit_justification_and_owner_authorization():
    with TestClient(app) as owner, TestClient(app) as other:
        auth = _register(owner)
        other_auth = _register(other)
        _, scan_id, finding_ids = _add_completed_scan(auth["user"]["id"])
        finding_id = finding_ids[0]

        listed = owner.get("/api/findings?severity=high&status=open&page=1&page_size=10")
        assert listed.status_code == 200
        assert listed.json()["total"] == 1
        assert listed.json()["items"][0]["scan_id"] == scan_id
        options = owner.get("/api/findings/filters")
        assert options.status_code == 200
        assert options.json()["categories"] == ["cookies", "input_validation", "security_headers"]
        assert options.json()["scans"][0]["id"] == scan_id
        assert other.get("/api/findings/filters").json() == {"categories": [], "scans": []}
        assert owner.get("/api/findings", params={"scan_id": scan_id, "category": "cookies"}).json()["total"] == 1
        assert owner.get(f"/api/findings/{finding_id}").status_code == 200
        assert owner.get(f"/api/findings?query=Content%20Security").json()["total"] == 1

        no_reason = owner.patch(
            f"/api/findings/{finding_id}", headers={"X-CSRF-Token": auth["csrfToken"]},
            json={"status": "accepted_risk", "justification": "short"},
        )
        assert no_reason.status_code == 422
        accepted = owner.patch(
            f"/api/findings/{finding_id}", headers={"X-CSRF-Token": auth["csrfToken"]},
            json={"status": "accepted_risk", "justification": "Approved exception REF-204 with an owner and expiry review."},
        )
        assert accepted.status_code == 200
        assert accepted.json()["status"] == "accepted_risk"
        assert len(accepted.json()["status_history"]) == 1
        reopened_without_reason = owner.patch(
            f"/api/findings/{finding_id}", headers={"X-CSRF-Token": auth["csrfToken"]},
            json={"status": "open"},
        )
        assert reopened_without_reason.status_code == 422
        reopened = owner.patch(
            f"/api/findings/{finding_id}", headers={"X-CSRF-Token": auth["csrfToken"]},
            json={"status": "open", "justification": "Reopening after the mitigation was withdrawn."},
        )
        assert reopened.status_code == 200
        assert reopened.json()["status"] == "open"
        assert len(reopened.json()["status_history"]) == 2

        assert other_auth["user"]["id"] != auth["user"]["id"]
        assert other.get(f"/api/findings/{finding_id}").status_code == 404
        assert other.patch(
            f"/api/findings/{finding_id}", headers={"X-CSRF-Token": other_auth["csrfToken"]},
            json={"status": "resolved"},
        ).status_code == 404
        with SessionLocal() as db:
            rows = db.scalars(select(FindingStatusHistory).where(FindingStatusHistory.finding_id == finding_id)).all()
            assert [(item.previous_status, item.new_status) for item in rows] == [
                ("open", "accepted_risk"), ("accepted_risk", "open")
            ]


def test_report_preview_generation_download_integrity_and_owner_checks():
    with TestClient(app) as owner, TestClient(app) as other:
        auth = _register(owner)
        other_auth = _register(other)
        _, scan_id, finding_ids = _add_completed_scan(auth["user"]["id"], scan_name="Evidence report fixture")

        preview = owner.get(f"/api/reports/{scan_id}")
        assert preview.status_code == 200
        report_data = preview.json()
        assert report_data["scan"]["id"] == scan_id
        assert report_data["finding_count"] == 3
        assert report_data["severity_counts"]["high"] == 1
        assert report_data["findings"][0]["id"] in finding_ids
        assert any("no active exploit" in item.lower() for item in report_data["limitations"])
        eligible = owner.get("/api/reports/eligible-scans?page=1&page_size=20")
        assert eligible.status_code == 200 and eligible.json()["total"] == 1
        assert eligible.json()["items"][0]["id"] == scan_id
        assert other.get("/api/reports/eligible-scans").json()["total"] == 0

        for report_format, expected_type, signature in (
            ("json", "application/json", None), ("pdf", "application/pdf", b"%PDF-"),
        ):
            generated = owner.post(
                f"/api/reports/{scan_id}", headers={"X-CSRF-Token": auth["csrfToken"]},
                json={"format": report_format},
            )
            assert generated.status_code == 201, generated.text
            assert generated.json()["size_bytes"] > 100
            downloaded = owner.get(generated.json()["download_url"])
            assert downloaded.status_code == 200
            assert downloaded.headers["content-type"].startswith(expected_type)
            assert downloaded.headers["content-disposition"].startswith("attachment;")
            if report_format == "json":
                saved = json.loads(downloaded.content)
                assert saved["scan"]["id"] == scan_id
                assert saved["finding_count"] == 3
                assert "cookie value" not in downloaded.text.lower()
            else:
                assert signature is not None
                assert downloaded.content.startswith(signature)
        reports = owner.get("/api/reports")
        assert reports.status_code == 200 and reports.json()["total"] == 2
        assert other.get(f"/api/reports/{scan_id}").status_code == 404
        assert other.get(f"/api/reports/{scan_id}/download/pdf").status_code == 404
        assert other.post(
            f"/api/reports/{scan_id}", headers={"X-CSRF-Token": other_auth["csrfToken"]},
            json={"format": "json"},
        ).status_code == 404


def test_report_retention_removes_only_expired_private_artifacts_on_list():
    with TestClient(app) as owner:
        auth = _register(owner)
        _, scan_id, _ = _add_completed_scan(auth["user"]["id"], scan_name="Retention test fixture")
        generated = owner.post(
            f"/api/reports/{scan_id}", headers={"X-CSRF-Token": auth["csrfToken"]},
            json={"format": "json"},
        )
        assert generated.status_code == 201, generated.text
        with SessionLocal() as db:
            report = db.scalar(select(Report).where(Report.scan_id == scan_id, Report.format == "json"))
            assert report is not None
            artifact = (Path(settings.data_dir).resolve() / report.storage_reference).resolve()
            assert artifact.is_file()
            report.generated_at = utcnow() - timedelta(days=40)
            db.commit()

        updated = owner.patch(
            "/api/settings", headers={"X-CSRF-Token": auth["csrfToken"]},
            json={"report_retention_days": 30},
        )
        assert updated.status_code == 200
        assert "when this user's Reports page is next loaded" in updated.json()["reports"]["cleanup_behavior"]
        listed = owner.get("/api/reports")
        assert listed.status_code == 200 and listed.json()["total"] == 0
        assert not artifact.exists()
        with SessionLocal() as db:
            assert db.scalar(select(Report).where(Report.scan_id == scan_id, Report.format == "json")) is None
            audit = db.scalars(select(AuditLog).where(AuditLog.actor_id == auth["user"]["id"], AuditLog.action == "report.retention_delete")).all()
            assert len(audit) == 1
            assert audit[0].details == {"format": "json", "retention_days": 30}
