from __future__ import annotations

from collections.abc import Sequence

from app.scanners.cookies import analyze_cookies
from app.scanners.headers import analyze_security_headers
from app.scanners.types import FindingCandidate


def _titles(findings: Sequence[FindingCandidate]) -> set[str]:
    return {finding.title for finding in findings}


def test_header_names_are_case_insensitive_and_csp_can_protect_framing() -> None:
    findings = analyze_security_headers(
        {
            "cOnTeNt-SeCuRiTy-PoLiCy": "default-src 'self'; frame-ancestors 'none'",
            "STRICT-TRANSPORT-SECURITY": "max-age=31536000; includeSubDomains",
            "X-CONTENT-TYPE-OPTIONS": "NOSNIFF",
            "rEfErReR-PoLiCy": "strict-origin-when-cross-origin",
            "PeRmIsSiOnS-PoLiCy": "geolocation=()",
        },
        "https://example.test/account",
    )

    titles = _titles(findings)
    assert "Missing Content-Security-Policy header" not in titles
    assert "Missing Strict-Transport-Security header" not in titles
    assert "Missing X-Content-Type-Options header" not in titles
    assert "Missing Referrer-Policy header" not in titles
    assert "Missing Permissions-Policy header" not in titles
    assert "Missing effective framing protection" not in titles


def test_hsts_is_only_expected_on_https() -> None:
    http_findings = analyze_security_headers({}, "http://example.test/")
    https_findings = analyze_security_headers({}, "https://example.test/")

    assert not any("HSTS" in finding.title or "Strict-Transport-Security" in finding.title for finding in http_findings)
    assert "Missing Strict-Transport-Security header" in _titles(https_findings)


def test_x_frame_options_is_alternative_to_csp_frame_ancestors() -> None:
    findings = analyze_security_headers(
        {"X-Frame-Options": "SAMEORIGIN"},
        "https://example.test/",
    )
    assert "Missing effective framing protection" not in _titles(findings)


def test_secure_cookie_has_no_attribute_findings() -> None:
    findings = analyze_cookies(
        ["session=opaque-value-that-must-not-leak; Secure; HttpOnly; SameSite=Lax"],
        "https://example.test/",
    )
    assert findings == []


def test_missing_cookie_flags_are_contextual_and_never_expose_cookie_value() -> None:
    secret = "cookie-secret-should-never-appear"
    findings = analyze_cookies([f"session={secret}"], "https://example.test/")

    titles = _titles(findings)
    assert "Cookie is missing Secure" in titles
    assert "Cookie is missing HttpOnly" in titles
    assert "Cookie is missing SameSite" in titles
    assert all(finding.confidence == "low" for finding in findings)
    assert all(secret not in repr(finding) for finding in findings)
    assert all(secret not in repr(finding.evidence) for finding in findings)
    assert all("set-cookie" not in finding.evidence for finding in findings)


def test_malformed_cookie_does_not_crash_or_leak_input() -> None:
    malformed = "broken-cookie-header-with-secret-malformed-value"
    findings = analyze_cookies([malformed, "also-broken=\x00\x01"], "https://example.test/")

    assert isinstance(findings, list)
    assert all(malformed not in repr(finding) for finding in findings)
    assert all(malformed not in repr(finding.evidence) for finding in findings)
