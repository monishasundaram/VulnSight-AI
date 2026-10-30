from __future__ import annotations

import os
import socket
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from fastapi.testclient import TestClient
from sqlalchemy import select

import app.api.scans as scans_api
import app.main as main_module
import app.scanners.scope as scope_module
from app.core.auth import CSRF_COOKIE
from app.db.session import SessionLocal
from app.main import app
from app.models.entities import AuditLog, Finding, ScanEvent, Target, User, utcnow
from app.workers.scan_manager import ScanManager


class SyntheticHttpFixture:
    """Private loopback fixture enabled only by injected test DNS/connector functions."""
    def __init__(self, *, delay_seconds: float = 0.0):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.listener.settimeout(0.1)
        self.host, self.port = self.listener.getsockname()
        self.delay_seconds = delay_seconds
        self.stopped = threading.Event()
        self.first_get = threading.Event()
        self.get_count = 0
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def connector(self, address: tuple[str, int], timeout: float) -> socket.socket:
        # The production transport still validates/resolves the approved public address;
        # only the test connector maps the pinned destination to the loopback fixture.
        return socket.create_connection((self.host, self.port), timeout=timeout)

    def _serve(self) -> None:
        while not self.stopped.is_set():
            try:
                connection, _ = self.listener.accept()
            except (TimeoutError, socket.timeout):
                continue
            except OSError:
                break
            with connection:
                connection.settimeout(0.4)
                data = bytearray()
                try:
                    while b"\r\n\r\n" not in data and len(data) < 16_384:
                        part = connection.recv(4096)
                        if not part:
                            break
                        data.extend(part)
                except (OSError, TimeoutError, socket.timeout):
                    continue
                if not data.startswith(b"GET "):
                    # A TLS ClientHello receives no application-level HTTP response.
                    continue
                with self._lock:
                    self.get_count += 1
                self.first_get.set()
                if self.delay_seconds:
                    time.sleep(self.delay_seconds)
                try:
                    line = bytes(data).split(b"\r\n", 1)[0].decode("ascii", "replace")
                    request_url = line.split(" ", 2)[1]
                    query = parse_qs(urlsplit(request_url).query)
                    marker = query.get("vulnsight_probe", [""])[0]
                    body = (f"<p>{marker}</p>" if marker else "<main>synthetic fixture</main>").encode("utf-8")
                    response = (
                        b"HTTP/1.1 200 OK\r\n"
                        b"Content-Type: text/html; charset=utf-8\r\n"
                        b"Server: SyntheticFixture/0.1\r\n"
                        b"Set-Cookie: session=SENSITIVE_CANARY; Path=/\r\n"
                        + f"Content-Length: {len(body)}\r\n".encode("ascii")
                        + b"Connection: close\r\n\r\n"
                        + body
                    )
                    connection.sendall(response)
                except OSError:
                    pass

    def close(self) -> None:
        self.stopped.set()
        try:
            self.listener.close()
        except OSError:
            pass
        self._thread.join(timeout=1)


def _register(client: TestClient) -> dict:
    response = client.post(
        "/api/auth/register",
        json={"email": f"{uuid.uuid4().hex}@example.com", "password": "A-long-test-password-123!"},
    )
    assert response.status_code == 201, response.text
    return response.json()


def _insert_target(user_id: str, host: str) -> str:
    with SessionLocal() as db:
        target = Target(
            owner_id=user_id, name="Synthetic vulnerable fixture", base_url=f"http://{host}/",
            description="Local-only intentionally insecure response fixture", owner_reference="tests",
            authorization_status="authorized", authorization_confirmed_at=utcnow(),
            scope_configuration={"allowed_hosts": [host], "ports": [80], "scheme_host": host},
            scope_notes="Test-only injected resolver and loopback connector", enabled=True,
        )
        db.add(target)
        db.commit()
        return target.id


def _install_test_worker(monkeypatch, fixture: SyntheticHttpFixture, host: str) -> ScanManager:
    resolver = lambda _hostname, _port: ("93.184.216.34",)
    monkeypatch.setattr(scope_module, "resolve_public_addresses", resolver)
    worker = ScanManager(max_workers=1, resolver=resolver, connector=fixture.connector)
    monkeypatch.setattr(scans_api, "scan_manager", worker)
    monkeypatch.setattr(main_module, "scan_manager", worker)
    return worker


def _start_scan(client: TestClient, auth: dict, target_id: str, profile: str = "standard"):
    return client.post(
        "/api/scans",
        headers={"X-CSRF-Token": auth["csrfToken"]},
        json={"target_id": target_id, "profile": profile, "authorization_confirmed": True,
              "name": "Synthetic check", "description": "Authorized local test fixture"},
    )


def _wait_for_status(client: TestClient, scan_id: str, expected: str, timeout: float = 5.0) -> dict:
    deadline = time.monotonic() + timeout
    latest = {}
    while time.monotonic() < deadline:
        response = client.get(f"/api/scans/{scan_id}")
        assert response.status_code == 200, response.text
        latest = response.json()
        if latest["status"] == expected:
            return latest
        time.sleep(0.025)
    raise AssertionError(f"Timed out waiting for {expected}; latest backend state: {latest}")


def test_scan_persists_real_progress_findings_and_enforces_owner_scope(monkeypatch):
    fixture = SyntheticHttpFixture()
    try:
        worker = _install_test_worker(monkeypatch, fixture, "fixture.example.test")
        with TestClient(app) as owner, TestClient(app) as other:
            auth = _register(owner)
            other_auth = _register(other)
            target_id = _insert_target(auth["user"]["id"], "fixture.example.test")

            missing_consent = owner.post(
                "/api/scans", headers={"X-CSRF-Token": auth["csrfToken"]},
                json={"target_id": target_id, "profile": "quick", "authorization_confirmed": False},
            )
            assert missing_consent.status_code == 422
            started = _start_scan(owner, auth, target_id)
            assert started.status_code == 202, started.text
            scan_id = started.json()["id"]
            target_list = owner.get("/api/targets")
            assert target_list.status_code == 200
            assert target_list.json()["items"][0]["last_scan_at"] == started.json()["started_at"]
            completed = _wait_for_status(owner, scan_id, "completed")

            assert completed["name"] == "Synthetic check"
            assert completed["checks_total"] == 8
            assert completed["checks_completed"] == 8
            assert completed["progress_percent"] == 100
            assert completed["duration_seconds"] is not None
            assert completed["findings_count"] >= 5
            assert "OWASP ZAP is not configured" in completed["limitations"][-1]
            assert fixture.get_count == 2  # One real page GET plus one benign marker GET.

            scan_day = completed["started_at"][:10]
            filtered_history = owner.get("/api/scans", params={
                "target_id": target_id, "query": "Synthetic vulnerable fixture",
                "date_from": scan_day, "date_to": scan_day,
                "sort": "findings_count", "direction": "desc",
            })
            assert filtered_history.status_code == 200, filtered_history.text
            assert filtered_history.json()["total"] == 1
            assert filtered_history.json()["items"][0]["id"] == scan_id
            assert filtered_history.json()["items"][0]["completed_at"] is not None
            assert filtered_history.json()["items"][0]["duration_seconds"] is not None
            bad_date_range = owner.get("/api/scans", params={"date_from": "2099-12-31", "date_to": "2000-01-01"})
            assert bad_date_range.status_code == 422

            details = owner.get(f"/api/scans/{scan_id}").json()
            assert {event["check_key"] for event in details["events"] if event["event_type"] == "check"} == {
                "target_scope", "tls", "http_connectivity", "https_redirect", "security_headers",
                "cookies", "safe_input_reflection", "response_configuration",
            }
            findings_response = owner.get(f"/api/scans/{scan_id}/findings")
            assert findings_response.status_code == 200
            findings = findings_response.json()["items"]
            assert any(item["category"] == "security_headers" for item in findings)
            assert any(item["category"] == "cookies" for item in findings)
            assert any(item["category"] == "input_validation" and item["verification_status"] == "suspected" for item in findings)
            assert any(item["category"] == "response_configuration" for item in findings)
            assert "SENSITIVE_CANARY" not in findings_response.text
            assert "SENSITIVE_CANARY" not in owner.get(f"/api/scans/{scan_id}/events").text
            assert owner.get("/api/scans").json()["total"] == 1

            pdf_created = owner.post(
                f"/api/reports/{scan_id}", headers={"X-CSRF-Token": auth["csrfToken"]},
                json={"format": "pdf"},
            )
            assert pdf_created.status_code == 201, pdf_created.text
            pdf_download = owner.get(pdf_created.json()["download_url"])
            assert pdf_download.status_code == 200 and pdf_download.content.startswith(b"%PDF-")
            assert b"Local-only intentionally insecure response fixture" not in pdf_download.content
            json_created = owner.post(
                f"/api/reports/{scan_id}", headers={"X-CSRF-Token": auth["csrfToken"]},
                json={"format": "json"},
            )
            assert json_created.status_code == 201, json_created.text
            json_download = owner.get(json_created.json()["download_url"])
            assert json_download.status_code == 200
            json_report = json_download.json()
            assert json_report["scan"]["id"] == scan_id
            assert json_report["finding_count"] == completed["findings_count"]
            assert "SENSITIVE_CANARY" not in json_download.text
            export_path = os.environ.get("VULNSIGHT_SAMPLE_REPORT")
            if export_path:
                sample = Path(export_path).resolve()
                sample.parent.mkdir(parents=True, exist_ok=True)
                temporary = sample.with_suffix(sample.suffix + ".tmp")
                temporary.write_bytes(pdf_download.content)
                temporary.chmod(0o600)
                temporary.replace(sample)

            archived = owner.delete(f"/api/scans/{scan_id}", headers={"X-CSRF-Token": auth["csrfToken"]})
            assert archived.status_code == 200, archived.text
            assert archived.json()["archived_at"] is not None
            assert owner.get("/api/scans").json()["total"] == 0
            archived_history = owner.get("/api/scans?include_archived=true")
            assert archived_history.status_code == 200 and archived_history.json()["total"] == 1
            assert owner.get(f"/api/scans/{scan_id}/findings").json()["total"] == completed["findings_count"]
            archived_events = owner.get(f"/api/scans/{scan_id}/events").json()["items"]
            assert any("findings, reports and audit records are retained" in event["message"] for event in archived_events)
            with SessionLocal() as db:
                assert len(db.scalars(select(Finding).where(Finding.scan_id == scan_id)).all()) == completed["findings_count"]
                audit_actions = db.scalars(select(AuditLog.action).where(AuditLog.resource_id == scan_id)).all()
                assert "scan.archive" in audit_actions

            restored = owner.post(f"/api/scans/{scan_id}/restore", headers={"X-CSRF-Token": auth["csrfToken"]})
            assert restored.status_code == 200 and restored.json()["archived_at"] is None
            assert owner.get("/api/scans").json()["total"] == 1
            with SessionLocal() as db:
                audit_actions = db.scalars(select(AuditLog.action).where(AuditLog.resource_id == scan_id)).all()
                assert "scan.restore" in audit_actions

            assert other.get(f"/api/scans/{scan_id}").status_code == 404
            assert other.get(f"/api/scans/{scan_id}/findings").status_code == 404
            assert other.get(f"/api/scans/{scan_id}/events").status_code == 404
            assert other.get("/api/scans").json()["total"] == 0
            assert other.post(
                f"/api/scans/{scan_id}/cancel", headers={"X-CSRF-Token": other_auth["csrfToken"]}
            ).status_code == 404
            assert worker.active_count() == 0
    finally:
        fixture.close()


def test_scan_cancel_closes_active_request_and_persists_cancellation(monkeypatch):
    fixture = SyntheticHttpFixture(delay_seconds=1.0)
    try:
        _install_test_worker(monkeypatch, fixture, "cancel.example.test")
        with TestClient(app) as client:
            auth = _register(client)
            target_id = _insert_target(auth["user"]["id"], "cancel.example.test")
            started = _start_scan(client, auth, target_id, profile="quick")
            assert started.status_code == 202, started.text
            scan_id = started.json()["id"]
            assert fixture.first_get.wait(timeout=3), "The real HTTP request did not reach the local fixture"
            archive_active = client.delete(f"/api/scans/{scan_id}", headers={"X-CSRF-Token": auth["csrfToken"]})
            assert archive_active.status_code == 409
            cancel = client.post(
                f"/api/scans/{scan_id}/cancel", headers={"X-CSRF-Token": auth["csrfToken"]}
            )
            assert cancel.status_code == 200, cancel.text
            cancelled = _wait_for_status(client, scan_id, "cancelled")
            assert cancelled["completed_at"] is not None
            assert any(event["event_type"] == "status" and "no further requests" in event["message"]
                       for event in cancelled["events"])
            assert fixture.get_count == 1
            denied = client.post(
                f"/api/scans/{scan_id}/cancel", headers={"X-CSRF-Token": auth["csrfToken"]}
            )
            assert denied.status_code == 409
    finally:
        fixture.close()
