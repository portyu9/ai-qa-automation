"""Exact native workflow identity regression for protected owner CI recovery.

A workflow's display name, not its filename or guessed historical label,
controls workflow_run wake delivery. The owner issuer must verify the same
observed native names and immutable workflow IDs before it can authorize a PR.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WAKE = ROOT / ".github/workflows/protected-maintenance-authorizer.yml"
ISSUER = ROOT / "scripts/auto_protected_maintenance_authorizer.py"
EXPECTED = {
    339754724: ('ci', '.github/workflows/ci.yml'),
    359681647: ('CodeQL', '.github/workflows/codeql.yml'),
    377768728: ('security', '.github/workflows/security.yml'),
}


def assert_exact_binding(wake: str, issuer: str) -> None:
    assert 'workflows: ["ci", "CodeQL", "security"]' in wake
    assert "CI — ƳƤ AI QA Automation Framework" not in wake
    assert '"Security"' not in wake
    assert "OWNER_WAKE_WORKFLOWS = {" in issuer
    for identity, (name, path) in EXPECTED.items():
        assert f'{identity}: ("{name}", "{path}")' in issuer
        assert f'("{name}", "{name}", "{path}"' not in issuer
    assert '            "ci",\n' in issuer
    assert '("security-gate", "security", ".github/workflows/security.yml", None)' in issuer
    assert "CI — ƳƤ AI QA Automation Framework" not in issuer
    assert '"Security"' not in issuer
    assert 'workflow.get("name") == workflow_name' in issuer
    assert 'workflow.get("run_attempt") == 1' in issuer
    assert 'workflow.get("head_sha") == head_sha' in issuer
    assert 'and workflow.get("event") == "pull_request"' in issuer


def test_native_owner_wake_matches_live_ci_and_security_workflows() -> None:
    assert_exact_binding(WAKE.read_text(encoding="utf-8"),
                         ISSUER.read_text(encoding="utf-8"))


def test_stale_workflow_names_are_rejected() -> None:
    wake = WAKE.read_text(encoding="utf-8")
    issuer = ISSUER.read_text(encoding="utf-8")
    broken_wake = wake.replace('["ci", "CodeQL", "security"]',
                               '["CI — ƳƤ AI QA Automation Framework", "CodeQL", "Security"]', 1)
    broken_issuer = issuer.replace('339754724: ("ci"', '339754724: ("CI — ƳƤ AI QA Automation Framework"', 1)
    import pytest
    with pytest.raises(AssertionError):
        assert_exact_binding(broken_wake, issuer)
    with pytest.raises(AssertionError):
        assert_exact_binding(wake, broken_issuer)
