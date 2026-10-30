from __future__ import annotations

import pytest

from app.scanners.scope import ScopeError, validate_public_ip, validate_target_url


def test_target_validation_canonicalizes_only_explicit_public_authorized_hosts(monkeypatch):
    import app.scanners.scope as scope
    monkeypatch.setattr(scope, "resolve_public_addresses", lambda hostname, port: ("93.184.216.34",))
    url, hostname, port, allowed = validate_target_url("https://Example.COM/security", ["example.com"])
    assert url == "https://example.com/security"
    assert (hostname, port, allowed) == ("example.com", 443, ("example.com",))


@pytest.mark.parametrize("url,hosts", [
    ("http://127.0.0.1/", ["127.0.0.1"]),
    ("http://169.254.169.254/latest/meta-data", ["169.254.169.254"]),
    ("https://user:pass@example.com/", ["example.com"]),
    ("file:///etc/passwd", ["example.com"]),
    ("https://example.com:8443/", ["example.com"]),
    ("https://evil.example/", ["example.com"]),
    ("https://example.com/?token=secret", ["example.com"]),
    ("https://localhost/", ["localhost"]),
    ("https://metadata.google.internal/", ["metadata.google.internal"]),
    ("https://example.com.evil.test/", ["example.com"]),
])
def test_target_validation_rejects_unsafe_or_out_of_scope_urls(url, hosts):
    with pytest.raises(ScopeError):
        validate_target_url(url, hosts)


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "fc00::1", "ff02::1", "0.0.0.0"])
def test_public_ip_guard_rejects_non_public_destinations(address):
    with pytest.raises(ScopeError):
        validate_public_ip(address)


def test_mixed_or_private_dns_answers_fail_closed(monkeypatch):
    import app.scanners.scope as scope
    monkeypatch.setattr(scope.socket, "getaddrinfo", lambda *args, **kwargs: [
        (2, 1, 6, "", ("93.184.216.34", 443)),
        (2, 1, 6, "", ("127.0.0.1", 443)),
    ])
    with pytest.raises(ScopeError):
        scope.resolve_public_addresses("example.com", 443)
