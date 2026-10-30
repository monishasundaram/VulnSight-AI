from fastapi.testclient import TestClient

from app.main import app


def test_route_manifest_is_real_json_not_spa_fallback():
    with TestClient(app) as client:
        response = client.get("/manus-routes.json")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    payload = response.json()
    assert set(payload) == {"routes"}
    paths = {route["path"] for route in payload["routes"]}
    assert "/" in paths and "/scans/:scanId" in paths and "/findings/:findingId" in paths


def test_original_favicon_is_served_as_svg_not_spa_html():
    with TestClient(app) as client:
        response = client.get("/favicon.svg")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("image/svg+xml")
    assert response.text.lstrip().startswith("<svg")
