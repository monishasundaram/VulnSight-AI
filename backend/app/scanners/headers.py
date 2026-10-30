from __future__ import annotations

import re
from collections.abc import Mapping
from urllib.parse import urlsplit

from app.scanners.types import FindingCandidate


_SECURITY_HEADERS_REFERENCE = "https://owasp.org/www-project-secure-headers/"
_HSTS_REFERENCE = "https://datatracker.ietf.org/doc/html/rfc6797"


def _normalise_headers(headers: Mapping[str, str]) -> dict[str, tuple[str, str]]:
    """Return headers keyed by lowercase name without trusting malformed input."""
    result: dict[str, tuple[str, str]] = {}
    try:
        items = headers.items()
    except (AttributeError, TypeError):
        return result

    try:
        for raw_name, raw_value in items:
            if not isinstance(raw_name, str):
                continue
            name = raw_name.strip()
            if not name:
                continue
            try:
                value = raw_value if isinstance(raw_value, str) else str(raw_value)
            except Exception:
                value = ""
            result[name.casefold()] = (name, value)
    except Exception:
        # A hostile/custom Mapping should not make a scan fail.
        return result
    return result


def _base_evidence(
    *,
    expected_setting: str,
    observed_name: str,
    present_policy: bool,
    observed_value: str | None = None,
) -> dict[str, object]:
    evidence: dict[str, object] = {
        "expected_setting": expected_setting,
        "observed_name": observed_name,
        "present_policy": present_policy,
    }
    if observed_value is not None:
        evidence["observed_value"] = observed_value
    return evidence


def _finding(
    *,
    title: str,
    affected_url: str,
    description: str,
    evidence: dict[str, object],
    remediation: str,
    references: tuple[str, ...] = (_SECURITY_HEADERS_REFERENCE,),
    severity: str = "low",
) -> FindingCandidate:
    return FindingCandidate(
        title=title,
        category="security_headers",
        severity=severity,  # type: ignore[arg-type]
        affected_url=affected_url,
        description=description,
        evidence=evidence,
        impact="Security behavior may be weaker than the recommended baseline; actual exploitability depends on the application context.",
        remediation=remediation,
        references=references,
        confidence="low",
        verification_status="observed",
    )


def _csp_directives(value: str) -> set[str]:
    directives: set[str] = set()
    for part in value.split(";"):
        words = part.strip().split()
        if words:
            directives.add(words[0].casefold())
    return directives


def _is_https(url: str) -> bool:
    try:
        return urlsplit(url).scheme.casefold() == "https"
    except (TypeError, ValueError):
        return False


def _analyse_hsts(
    *,
    header: tuple[str, str] | None,
    affected_url: str,
) -> list[FindingCandidate]:
    if not _is_https(affected_url):
        return []

    observed_name = header[0] if header else "Strict-Transport-Security"
    if header is None:
        return [
            _finding(
                title="Missing Strict-Transport-Security header",
                affected_url=affected_url,
                description="HTTPS responses do not advertise HTTP Strict Transport Security.",
                evidence=_base_evidence(
                    expected_setting="Strict-Transport-Security with max-age=31536000 and includeSubDomains",
                    observed_name=observed_name,
                    present_policy=False,
                ),
                remediation="Send Strict-Transport-Security over HTTPS with a deliberate max-age; consider includeSubDomains after validating all subdomains.",
                references=(_HSTS_REFERENCE, _SECURITY_HEADERS_REFERENCE),
            )
        ]

    value = header[1]
    max_age_match = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?:;|$)", value, re.IGNORECASE)
    include_subdomains = any(
        part.strip().casefold() == "includesubdomains" for part in value.split(";")
    )
    findings: list[FindingCandidate] = []
    if max_age_match is None:
        findings.append(
            _finding(
                title="HSTS policy has no valid max-age",
                affected_url=affected_url,
                description="The observed Strict-Transport-Security value does not contain a valid max-age directive.",
                evidence={
                    **_base_evidence(
                        expected_setting="Strict-Transport-Security with a positive max-age (commonly at least 31536000 seconds)",
                        observed_name=observed_name,
                        present_policy=True,
                        observed_value=value,
                    ),
                    "max_age": None,
                    "include_subdomains": include_subdomains,
                },
                remediation="Provide a deliberate numeric max-age in the Strict-Transport-Security policy.",
                references=(_HSTS_REFERENCE, _SECURITY_HEADERS_REFERENCE),
            )
        )
    else:
        max_age = int(max_age_match.group(1))
        if max_age < 31536000:
            findings.append(
                _finding(
                    title="HSTS max-age is shorter than recommended",
                    affected_url=affected_url,
                    description="The observed HSTS policy has a max-age shorter than the commonly recommended one-year baseline.",
                    evidence={
                        **_base_evidence(
                            expected_setting="Strict-Transport-Security max-age of at least 31536000 seconds",
                            observed_name=observed_name,
                            present_policy=True,
                            observed_value=value,
                        ),
                        "max_age": max_age,
                        "include_subdomains": include_subdomains,
                    },
                    remediation="Increase max-age deliberately after confirming that the site and its subdomains support HTTPS.",
                    references=(_HSTS_REFERENCE, _SECURITY_HEADERS_REFERENCE),
                )
            )

    if not include_subdomains:
        findings.append(
            _finding(
                title="HSTS does not include subdomains",
                affected_url=affected_url,
                description="The HSTS policy does not extend to subdomains; this may be intentional, but should be reviewed in context.",
                evidence={
                    **_base_evidence(
                        expected_setting="Consider includeSubDomains when every relevant subdomain supports HTTPS",
                        observed_name=observed_name,
                        present_policy=True,
                        observed_value=value,
                    ),
                    "max_age": int(max_age_match.group(1)) if max_age_match else None,
                    "include_subdomains": False,
                },
                remediation="Add includeSubDomains only after validating HTTPS coverage for all affected subdomains.",
                references=(_HSTS_REFERENCE, _SECURITY_HEADERS_REFERENCE),
                severity="informational",
            )
        )
    return findings


def analyze_security_headers(headers: Mapping[str, str], affected_url: str) -> list[FindingCandidate]:
    """Return deterministic, low-confidence candidates for missing or weak response headers."""
    normalised = _normalise_headers(headers)
    findings: list[FindingCandidate] = []

    csp = normalised.get("content-security-policy")
    if csp is None:
        findings.append(
            _finding(
                title="Missing Content-Security-Policy header",
                affected_url=affected_url,
                description="The response does not advertise a Content-Security-Policy; whether one is appropriate depends on the application.",
                evidence=_base_evidence(
                    expected_setting="A deliberate Content-Security-Policy appropriate to the application",
                    observed_name="Content-Security-Policy",
                    present_policy=False,
                ),
                remediation="Define and deploy a restrictive Content-Security-Policy after testing the application's required resources.",
            )
        )
    elif not csp[1].strip():
        findings.append(
            _finding(
                title="Content-Security-Policy is empty",
                affected_url=affected_url,
                description="The response includes an empty Content-Security-Policy value, so it does not express a usable policy.",
                evidence=_base_evidence(
                    expected_setting="A non-empty, deliberate Content-Security-Policy",
                    observed_name=csp[0],
                    present_policy=True,
                    observed_value=csp[1],
                ),
                remediation="Replace the empty value with a tested Content-Security-Policy appropriate to the application.",
            )
        )

    findings.extend(_analyse_hsts(header=normalised.get("strict-transport-security"), affected_url=affected_url))

    xcto = normalised.get("x-content-type-options")
    if xcto is None:
        findings.append(
            _finding(
                title="Missing X-Content-Type-Options header",
                affected_url=affected_url,
                description="The response does not explicitly opt out of MIME-type sniffing.",
                evidence=_base_evidence(
                    expected_setting="X-Content-Type-Options: nosniff",
                    observed_name="X-Content-Type-Options",
                    present_policy=False,
                ),
                remediation="Send X-Content-Type-Options: nosniff for applicable responses.",
            )
        )
    elif xcto[1].strip().casefold() != "nosniff":
        findings.append(
            _finding(
                title="X-Content-Type-Options is not nosniff",
                affected_url=affected_url,
                description="The observed X-Content-Type-Options value is not the recommended nosniff directive.",
                evidence=_base_evidence(
                    expected_setting="X-Content-Type-Options: nosniff",
                    observed_name=xcto[0],
                    present_policy=True,
                    observed_value=xcto[1],
                ),
                remediation="Set X-Content-Type-Options to nosniff.",
            )
        )

    referrer = normalised.get("referrer-policy")
    if referrer is None:
        findings.append(
            _finding(
                title="Missing Referrer-Policy header",
                affected_url=affected_url,
                description="The response does not state how much referrer information may be sent to other origins.",
                evidence=_base_evidence(
                    expected_setting="A deliberate Referrer-Policy such as strict-origin-when-cross-origin",
                    observed_name="Referrer-Policy",
                    present_policy=False,
                ),
                remediation="Set a Referrer-Policy appropriate to the application's privacy and navigation requirements.",
            )
        )
    elif any(policy.strip().casefold() in {"unsafe-url", "no-referrer-when-downgrade"} for policy in referrer[1].split(",")):
        findings.append(
            _finding(
                title="Referrer-Policy permits broad referrer disclosure",
                affected_url=affected_url,
                description="The response includes a Referrer-Policy value that can disclose more URL information than a strict cross-origin policy.",
                evidence=_base_evidence(
                    expected_setting="A deliberate policy such as strict-origin-when-cross-origin or no-referrer",
                    observed_name=referrer[0],
                    present_policy=True,
                    observed_value=referrer[1],
                ),
                remediation="Review the policy and prefer a restrictive value that meets the application's requirements.",
            )
        )

    permissions = normalised.get("permissions-policy")
    if permissions is None:
        findings.append(
            _finding(
                title="Missing Permissions-Policy header",
                affected_url=affected_url,
                description="The response does not explicitly restrict browser features that the application does not need.",
                evidence=_base_evidence(
                    expected_setting="A deliberate Permissions-Policy appropriate to the features used",
                    observed_name="Permissions-Policy",
                    present_policy=False,
                ),
                remediation="Define a least-privilege Permissions-Policy for browser features used by the application.",
            )
        )

    # A CSP frame-ancestors directive is an alternative to X-Frame-Options.
    frame_protected_by_csp = csp is not None and "frame-ancestors" in _csp_directives(csp[1])
    xfo = normalised.get("x-frame-options")
    frame_protected_by_xfo = xfo is not None and xfo[1].strip().split()[0].casefold() in {"deny", "sameorigin"} if xfo and xfo[1].strip() else False
    if not frame_protected_by_csp and not frame_protected_by_xfo:
        observed_name = xfo[0] if xfo else (csp[0] if csp else "Content-Security-Policy / X-Frame-Options")
        observed_value = xfo[1] if xfo else (csp[1] if csp else None)
        findings.append(
            _finding(
                title="Missing effective framing protection",
                affected_url=affected_url,
                description="Neither CSP frame-ancestors nor an effective X-Frame-Options directive was observed.",
                evidence=_base_evidence(
                    expected_setting="CSP frame-ancestors or X-Frame-Options: DENY/SAMEORIGIN",
                    observed_name=observed_name,
                    present_policy=bool(xfo or csp),
                    observed_value=observed_value,
                ),
                remediation="Set CSP frame-ancestors or X-Frame-Options to a deliberate framing policy.",
            )
        )

    return findings
