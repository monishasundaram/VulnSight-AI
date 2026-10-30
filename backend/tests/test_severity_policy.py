import pytest

from app.core.config import parse_severity_overrides
from app.scanners.types import FindingCandidate, apply_severity_override


def _candidate() -> FindingCandidate:
    return FindingCandidate(
        title="Header policy observation",
        category="security_headers",
        severity="low",
        affected_url="https://authorized.example/",
        description="Test-only candidate.",
    )


def test_severity_override_is_validated_and_applied_by_finding_category():
    overrides = parse_severity_overrides('{"security_headers":"MEDIUM","cookies":"informational"}')
    assert overrides == {"security_headers": "medium", "cookies": "informational"}
    assert apply_severity_override(_candidate(), overrides).severity == "medium"


def test_severity_policy_defaults_to_empty_and_preserves_analyzer_severity():
    assert parse_severity_overrides("{}") == {}
    assert apply_severity_override(_candidate(), {}).severity == "low"


@pytest.mark.parametrize("raw", [
    "[]",
    '"security_headers:high"',
    '{"unknown_category":"high"}',
    '{"security_headers":"urgent"}',
    '{"cookies":null}',
])
def test_invalid_severity_policy_is_rejected(raw: str):
    with pytest.raises(ValueError):
        parse_severity_overrides(raw)
