from __future__ import annotations

import socket
import threading

import pytest

from app.scanners.budget import RequestBudget
from app.scanners.safe_http import HttpResponse, SafeHttpClient, ScanTransportError


def local_http_server(responses: list[bytes]):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    port = listener.getsockname()[1]
    received: list[bytes] = []

    def serve():
        try:
            for response in responses:
                conn, _ = listener.accept()
                with conn:
                    conn.settimeout(1)
                    received.append(conn.recv(8192))
                    conn.sendall(response)
        finally:
            listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return port, received, thread


def test_get_pins_public_resolution_sends_no_cookies_and_parses_safe_metadata():
    port, received, thread = local_http_server([
        b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nSet-Cookie: session=secret-value; HttpOnly\r\nX-Test: yes\r\nConnection: close\r\n\r\nhello world"
    ])
    client = SafeHttpClient(
        resolver=lambda host, port: ("93.184.216.34",),
        connector=lambda address, timeout: socket.create_connection(("127.0.0.1", port), timeout),
    )
    result = client.get("http://allowed.example/", ["allowed.example"])
    thread.join(timeout=2)
    request = received[0].decode("ascii")
    assert request.startswith("GET / HTTP/1.1")
    assert "Host: allowed.example" in request
    assert "Cookie:" not in request and "Authorization:" not in request
    assert result.status_code == 200 and result.body == b"hello world"
    assert result.set_cookie_headers == ("session=secret-value; HttpOnly",)
    assert "secret-value" not in repr(result.headers)
    assert "secret-value" not in result.url


def test_redirect_to_private_metadata_is_not_followed():
    port, received, thread = local_http_server([
        b"HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest/meta-data\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    ])
    client = SafeHttpClient(
        max_redirects=2,
        resolver=lambda host, port: ("93.184.216.34",),
        connector=lambda address, timeout: socket.create_connection(("127.0.0.1", port), timeout),
    )
    result = client.get("http://allowed.example/", ["allowed.example"])
    thread.join(timeout=2)
    assert result.redirects and result.redirects[0].followed is False
    assert result.redirects[0].blocked_reason == "out_of_scope"
    assert len(received) == 1


def test_https_downgrade_redirect_is_blocked_without_a_second_connection():
    class StubClient(SafeHttpClient):
        def __init__(self):
            super().__init__(resolver=lambda host, port: ("93.184.216.34",))
            self.calls = 0

        def _single_get(self, url, host, port, allowed, *, allow_query):
            self.calls += 1
            return HttpResponse(302, "https://allowed.example/", {"location": "http://allowed.example/plain"}, (), b"", False, (), {})

    client = StubClient()
    result = client.get("https://allowed.example/", ["allowed.example"])
    assert client.calls == 1
    assert result.redirects[0].blocked_reason == "https_downgrade"
    assert result.redirects[0].followed is False


def test_dns_rebinding_to_private_ip_fails_before_socket_creation():
    answers = iter([("93.184.216.34",), ("127.0.0.1",)])
    attempted = []

    def connector(address: tuple[str, int], timeout: float) -> socket.socket:
        attempted.append(address)
        raise AssertionError("A socket must not be opened after DNS resolves to a private address")

    client = SafeHttpClient(
        resolver=lambda host, port: next(answers),
        connector=connector,
    )
    with pytest.raises(ScanTransportError) as error:
        client.get("http://allowed.example/", ["allowed.example"])
    assert error.value.kind == "scope"
    assert attempted == []


def test_single_scan_budget_limits_real_http_connections():
    port, received, thread = local_http_server([
        b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"
    ])
    budget = RequestBudget(1)
    client = SafeHttpClient(
        request_budget=budget,
        resolver=lambda host, port: ("93.184.216.34",),
        connector=lambda address, timeout: socket.create_connection(("127.0.0.1", port), timeout),
    )
    assert client.get("http://allowed.example/", ["allowed.example"]).status_code == 204
    assert budget.used == 1 and budget.remaining == 0
    with pytest.raises(ScanTransportError) as error:
        client.get("http://allowed.example/again", ["allowed.example"])
    assert error.value.kind == "request_limit"
    thread.join(timeout=2)
    assert len(received) == 1


def test_response_body_is_truncated_at_the_configured_limit():
    body = b"x" * 5000
    port, _, thread = local_http_server([
        b"HTTP/1.1 200 OK\r\nContent-Length: 5000\r\nConnection: close\r\n\r\n" + body
    ])
    client = SafeHttpClient(
        max_response_bytes=4096,
        resolver=lambda host, port: ("93.184.216.34",),
        connector=lambda address, timeout: socket.create_connection(("127.0.0.1", port), timeout),
    )
    result = client.get("http://allowed.example/", ["allowed.example"])
    thread.join(timeout=2)
    assert len(result.body) == 4096 and result.body_truncated is True
