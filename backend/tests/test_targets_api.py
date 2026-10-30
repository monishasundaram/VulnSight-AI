from __future__ import annotations

import uuid

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db.session import SessionLocal
from app.main import app
from app.models.entities import AuditLog, Scan, utcnow


def create_user(client: TestClient) -> dict:
    response = client.post("/api/auth/register", json={"email": f"{uuid.uuid4().hex}@example.com", "password": "A-long-test-password-123!"})
    assert response.status_code == 201, response.text
    return response.json()


def test_target_api_requires_explicit_authorization_and_isolation(monkeypatch):
    import app.scanners.scope as scope
    monkeypatch.setattr(scope, "resolve_public_addresses", lambda hostname, port: ("93.184.216.34",))
    with TestClient(app) as owner, TestClient(app) as other:
        auth = create_user(owner)
        other_auth = create_user(other)
        csrf = auth["csrfToken"]
        target_data = {
            "name": "Authorized site", "base_url": "https://demo.example.test/",
            "description": "owned lab", "owner_reference": "project-alpha",
            "allowed_hostnames": ["demo.example.test"], "scope_notes": "GET checks only",
            "authorization_confirmed": True,
        }
        missing_confirmation = dict(target_data, authorization_confirmed=False)
        assert owner.post("/api/targets", json=missing_confirmation, headers={"X-CSRF-Token": csrf}).status_code == 422
        created = owner.post("/api/targets", json=target_data, headers={"X-CSRF-Token": csrf})
        assert created.status_code == 201, created.text
        target = created.json()
        assert target["authorization_status"] == "authorized"
        assert target["allowed_hostnames"] == ["demo.example.test"]
        assert owner.get("/api/targets").json()["total"] == 1
        assert other.get("/api/targets").json() == {"items": [], "total": 0}
        assert other.get(f"/api/targets/{target['id']}").status_code == 404
        assert other.patch(f"/api/targets/{target['id']}", json={"name": "stolen"}, headers={"X-CSRF-Token": other_auth["csrfToken"]}).status_code == 404
        no_reauth = owner.patch(f"/api/targets/{target['id']}", json={"allowed_hostnames": ["demo.example.test", "other.example.test"]}, headers={"X-CSRF-Token": csrf})
        assert no_reauth.status_code == 403
        disabled = owner.patch(f"/api/targets/{target['id']}", json={"enabled": False}, headers={"X-CSRF-Token": csrf})
        assert disabled.status_code == 200 and disabled.json()["enabled"] is False
        no_reenable = owner.patch(f"/api/targets/{target['id']}", json={"enabled": True}, headers={"X-CSRF-Token": csrf})
        assert no_reenable.status_code == 403
        reenabled = owner.patch(f"/api/targets/{target['id']}", json={"enabled": True, "authorization_confirmed": True}, headers={"X-CSRF-Token": csrf})
        assert reenabled.status_code == 200 and reenabled.json()["enabled"] is True


def test_target_deletion_is_owner_scoped_and_never_cascades_scan_history(monkeypatch):
    import app.scanners.scope as scope

    monkeypatch.setattr(scope, "resolve_public_addresses", lambda hostname, port: ("93.184.216.34",))
    with TestClient(app) as owner, TestClient(app) as other:
        owner_auth = create_user(owner)
        other_auth = create_user(other)

        def register(name: str) -> dict:
            response = owner.post(
                "/api/targets",
                headers={"X-CSRF-Token": owner_auth["csrfToken"]},
                json={
                    "name": name,
                    "base_url": "https://demo.example.test/",
                    "description": "isolated local API fixture",
                    "owner_reference": "authorized test fixture",
                    "allowed_hostnames": ["demo.example.test"],
                    "scope_notes": "synthetic; no external request is made",
                    "authorization_confirmed": True,
                },
            )
            assert response.status_code == 201, response.text
            return response.json()

        target_with_history = register("History-protected target")
        with SessionLocal() as db:
            db.add(Scan(
                target_id=target_with_history["id"],
                initiated_by=owner_auth["user"]["id"],
                profile="quick",
                status="completed",
                completed_at=utcnow(),
            ))
            db.commit()
        blocked = owner.delete(
            f"/api/targets/{target_with_history['id']}",
            headers={"X-CSRF-Token": owner_auth["csrfToken"]},
        )
        assert blocked.status_code == 409
        assert "preserve scans, findings and audit history" in blocked.json()["detail"]
        assert owner.get(f"/api/targets/{target_with_history['id']}").status_code == 200

        empty_target = register("Target with no history")
        assert owner.delete(f"/api/targets/{empty_target['id']}").status_code == 403
        assert other.delete(
            f"/api/targets/{empty_target['id']}",
            headers={"X-CSRF-Token": other_auth["csrfToken"]},
        ).status_code == 404
        removed = owner.delete(
            f"/api/targets/{empty_target['id']}",
            headers={"X-CSRF-Token": owner_auth["csrfToken"]},
        )
        assert removed.status_code == 204
        assert owner.get(f"/api/targets/{empty_target['id']}").status_code == 404
        with SessionLocal() as db:
            audit = db.scalar(select(AuditLog).where(
                AuditLog.actor_id == owner_auth["user"]["id"],
                AuditLog.action == "target.delete",
                AuditLog.resource_id == empty_target["id"],
            ))
            assert audit is not None
            assert db.get(Scan, db.scalar(select(Scan.id).where(Scan.target_id == target_with_history["id"]))) is not None
