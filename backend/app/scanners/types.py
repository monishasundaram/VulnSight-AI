from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Literal

Severity = Literal["critical", "high", "medium", "low", "informational"]
Confidence = Literal["low", "medium", "high"]
VerificationStatus = Literal["observed", "suspected", "confirmed"]


@dataclass(frozen=True)
class FindingCandidate:
    title: str
    category: str
    severity: Severity
    affected_url: str
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)
    impact: str = ""
    remediation: str = ""
    references: tuple[str, ...] = ()
    confidence: Confidence = "medium"
    verification_status: VerificationStatus = "observed"

    def safe_evidence(self) -> dict[str, Any]:
        """Return evidence with any accidentally supplied cookie/credential values removed."""
        forbidden = {"cookie_value", "set_cookie", "authorization", "password", "token_value", "secret"}
        return {key: value for key, value in self.evidence.items() if key.lower() not in forbidden}


def apply_severity_override(candidate: FindingCandidate, overrides: dict[str, str]) -> FindingCandidate:
    """Apply a validated deployment-level override for this finding's category, if configured."""
    severity = overrides.get(candidate.category)
    return replace(candidate, severity=severity) if severity else candidate  # type: ignore[arg-type]
