from fastapi.testclient import TestClient

from app.main import app


def test_health_uses_database_and_security_headers():
    with TestClient(app) as client:
        response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["database"] == "sqlite"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert "frame-ancestors" not in response.headers.get("content-security-policy", "")
    assert "x-frame-options" not in response.headers
