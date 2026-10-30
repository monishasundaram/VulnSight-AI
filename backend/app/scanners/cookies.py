from __future__ import annotations

from collections.abc import Sequence
from http.cookies import CookieError, SimpleCookie

from app.scanners.types import FindingCandidate


_COOKIE_REFERENCE = "https://owasp.org/www-community/controls/SecureCookieAttribute"
_SESSION_REFERENCE = "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"


def _cookie_finding(
    *,
    affected_url: str,
    title: str,
    cookie_name: str,
    description: str,
    expected_setting: str,
    observed_attributes: tuple[str, ...],
    remediation: str,
    severity: str = "low",
) -> FindingCandidate:
    # Deliberately include only the name and attribute metadata, never a value or raw header.
    evidence = {
        "cookie_name": cookie_name,
        "expected_setting": expected_setting,
        "observed_attributes": observed_attributes,
    }
    return FindingCandidate(
        title=title,
        category="cookies",
        severity=severity,  # type: ignore[arg-type]
        affected_url=affected_url,
        description=description,
        evidence=evidence,
        impact="This cookie attribute is a contextual defense-in-depth control; the cookie's role and application behavior determine practical impact.",
        remediation=remediation,
        references=(_COOKIE_REFERENCE, _SESSION_REFERENCE),
        confidence="low",
        verification_status="observed",
    )


def _parse_cookie_header(header: str) -> list[tuple[str, bool, bool, str, tuple[str, ...]]]:
    """Parse one Set-Cookie value and retain only safe metadata."""
    parsed = SimpleCookie()
    try:
        parsed.load(header)
    except (CookieError, ValueError, TypeError):
        return []
    except Exception:
        # Be defensive around parser behavior for malformed or unusual input.
        return []

    result: list[tuple[str, bool, bool, str, tuple[str, ...]]] = []
    try:
        morsels = parsed.items()
        for name, morsel in morsels:
            if not isinstance(name, str) or not name:
                continue
            secure = bool(morsel["secure"])
            httponly = bool(morsel["httponly"])
            samesite = morsel["samesite"].strip().casefold()
            attributes: list[str] = []
            if secure:
                attributes.append("Secure")
            if httponly:
                attributes.append("HttpOnly")
            if samesite:
                attributes.append("SameSite=" + samesite)
            result.append((name, secure, httponly, samesite, tuple(attributes)))
    except (AttributeError, KeyError, TypeError, ValueError):
        return []
    except Exception:
        return []
    return result


def analyze_cookies(set_cookie_headers: Sequence[str], affected_url: str) -> list[FindingCandidate]:
    """Return contextual, low-confidence findings for missing cookie attributes.

    Cookie values are parsed by ``SimpleCookie`` but are never copied into a finding,
    evidence field, title, or description.
    """
    findings: list[FindingCandidate] = []
    try:
        headers = iter(set_cookie_headers)
    except (TypeError, ValueError):
        return findings

    try:
        for raw_header in headers:
            if not isinstance(raw_header, str):
                continue
            for cookie_name, secure, httponly, samesite, attributes in _parse_cookie_header(raw_header):
                if not secure:
                    findings.append(
                        _cookie_finding(
                            affected_url=affected_url,
                            title="Cookie is missing Secure",
                            cookie_name=cookie_name,
                            description="The cookie is set without the Secure attribute; review this in the context of the cookie's role and transport requirements.",
                            expected_setting="Secure for cookies that should only travel over HTTPS",
                            observed_attributes=attributes,
                            remediation="Set Secure where the cookie is intended for HTTPS-only transport.",
                        )
                    )
                if not httponly:
                    findings.append(
                        _cookie_finding(
                            affected_url=affected_url,
                            title="Cookie is missing HttpOnly",
                            cookie_name=cookie_name,
                            description="The cookie is set without HttpOnly; review whether client-side scripts need to read it.",
                            expected_setting="HttpOnly unless client-side script access is deliberately required",
                            observed_attributes=attributes,
                            remediation="Set HttpOnly for cookies that do not need to be read by client-side scripts.",
                        )
                    )
                if not samesite:
                    findings.append(
                        _cookie_finding(
                            affected_url=affected_url,
                            title="Cookie is missing SameSite",
                            cookie_name=cookie_name,
                            description="The cookie is set without SameSite; the appropriate setting depends on the application's cross-site flow.",
                            expected_setting="A deliberate SameSite value, commonly Lax or Strict",
                            observed_attributes=attributes,
                            remediation="Set SameSite deliberately based on the application's cross-site navigation and embedding requirements.",
                        )
                    )
                elif samesite not in {"lax", "strict", "none"}:
                    findings.append(
                        _cookie_finding(
                            affected_url=affected_url,
                            title="Cookie has an unrecognized SameSite value",
                            cookie_name=cookie_name,
                            description="The cookie's SameSite value is not one of the standard Lax, Strict, or None values.",
                            expected_setting="SameSite=Lax, SameSite=Strict, or SameSite=None",
                            observed_attributes=attributes,
                            remediation="Use a standard SameSite value that matches the application's requirements.",
                        )
                    )
                elif samesite == "none" and not secure:
                    findings.append(
                        _cookie_finding(
                            affected_url=affected_url,
                            title="SameSite=None cookie is missing Secure",
                            cookie_name=cookie_name,
                            description="A SameSite=None cookie is observed without Secure; user agents commonly require Secure for this combination.",
                            expected_setting="SameSite=None together with Secure",
                            observed_attributes=attributes,
                            remediation="Set Secure when using SameSite=None, or choose another SameSite mode if cross-site use is unnecessary.",
                        )
                    )
    except Exception:
        # A malformed custom Sequence/iterator should not abort analysis of earlier entries.
        return findings
    return findings
