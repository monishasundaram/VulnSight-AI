from __future__ import annotations

import uuid

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db.session import SessionLocal
from app.main import app
from app.models.entities import AuditLog, User


def _register(client: TestClient) -> dict:
    response = client.post(
        "/api/auth/register",
        json={"email": f"{uuid.uuid4().hex}@example.com", "password": "A-long-test-password-123!"},
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_preferences_persist_and_limits_never_reveal_server_secrets():
    with TestClient(app) as client, TestClient(app) as other:
        auth = _register(client)
        other_auth = _register(other)
        initial = client.get("/api/settings")
        assert initial.status_code == 200
        assert initial.json()["preferences"] == {"theme": "dark", "default_report_format": "pdf", "report_retention_days": 0}
        limits = initial.json()["scan_limits"]
        assert limits["allowed_ports"] == [80, 443]
        assert limits["max_requests_per_scan"] <= 32
        assert limits["max_scan_duration_seconds"] <= 600
        assert initial.json()["integrations"]["owasp_zap"]["configured"] is False
        assert initial.json()["severity_policy"]["overrides"] == {}
        assert "not CVSS scores" in initial.json()["severity_policy"]["configuration"]
        assert "session_secret" not in initial.text.lower()
        assert "database_url" not in initial.text.lower()
        assert "SESSION_SECRET" not in initial.text

        update = client.patch(
            "/api/settings", headers={"X-CSRF-Token": auth["csrfToken"]},
            json={"theme": "light", "default_report_format": "json", "report_retention_days": 30},
        )
        assert update.status_code == 200, update.text
        assert update.json()["preferences"] == {"theme": "light", "default_report_format": "json", "report_retention_days": 30}
        assert "when this user's Reports page is next loaded" in update.json()["reports"]["cleanup_behavior"]
        assert client.get("/api/settings").json()["preferences"]["theme"] == "light"
        assert other.get("/api/settings").json()["preferences"]["theme"] == "dark"
        assert other_auth["user"]["id"] != auth["user"]["id"]

        invalid = client.patch(
            "/api/settings", headers={"X-CSRF-Token": auth["csrfToken"]},
            json={"report_retention_days": 31},
        )
        assert invalid.status_code == 422
        unknown = client.patch(
            "/api/settings", headers={"X-CSRF-Token": auth["csrfToken"]},
            json={"smtp_password": "must-not-be-accepted"},
        )
        assert unknown.status_code == 422
        cross_site = client.patch(
            "/api/settings", headers={"X-CSRF-Token": auth["csrfToken"], "Sec-Fetch-Site": "cross-site"},
            json={"theme": "dark"},
        )
        assert cross_site.status_code == 403
        with SessionLocal() as db:
            user = db.scalar(select(User).where(User.id == auth["user"]["id"]))
            assert user and user.preferences["theme"] == "light"
            audit = db.scalars(select(AuditLog).where(AuditLog.actor_id == user.id, AuditLog.action == "user.preferences_update")).all()
            assert len(audit) == 1
            assert audit[0].details == {"changed_preferences": ["default_report_format", "report_retention_days", "theme"]}
