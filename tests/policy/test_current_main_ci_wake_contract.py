"""Adversarial policy regression for exact-main reusable CI and CodeQL recovery.

The wake is only a trusted liveness source. Native job or successfully completed
exact-subject reusable gates, never a dispatch acknowledgment, prove validation.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
contract = importlib.import_module("verify_ci_contract")
SOURCE = ROOT / ".github" / "workflows" / "current-main-ci-wake.yml"


def validate(source: str) -> None:
    """Check independent admission, bounded recovery and exact reviewed bytes."""
    required = (
        '    - cron: "17,47 * * * *"',
        "  workflow_dispatch:",
        "  workflow_run:",
        "    types: [completed]",
        "    schedule|workflow_dispatch) ;;",
        "Trusted PR Auto Gate — ƳƤ AI QA Automation Framework",
        "Ruleset Reconciler — ƳƤ AI QA Automation Framework",
        ".workflow_id == 346203190",
        ".workflow_id == 372619559",
        ".run_attempt == 1",
        ".head_repository.full_name == $repo",
        '.event == "schedule"',
        '.conclusion == "success"',
        "github.ref == 'refs/heads/main' &&",
        "github.event.workflow_run.event == 'schedule'",
        "github.event.workflow_run.conclusion == 'success'",
        "  group: trusted-current-main-ci-wake",
        "  cancel-in-progress: false",
        "    permissions:\n      contents: read\n      actions: read",
        'test "$GITHUB_REF" = "refs/heads/main"',
        'test "$GITHUB_WORKFLOW_REF" = "$GITHUB_REPOSITORY/.github/workflows/current-main-ci-wake.yml@refs/heads/main"',
        '[[ "$EXPECTED_SHA" =~ ^[0-9a-f]{40}$ ]]',
        'if [ "$live_main" != "$EXPECTED_SHA" ]; then',
        "(.total_count == (.workflow_runs | length))",
        "(.total_count | type == \"number\" and . >= 0 and . <= 100)",
        ".head_sha == $sha",
        '.head_branch == "main"',
        ".repository.full_name == $repo",
        '(.event == "push" or .event == "workflow_dispatch")',
        '(.status == "completed" and .conclusion == "success" and',
        "((.created_at | fromdateiso8601) >= ($now - 86400))",
        "(.created_at | fromdateiso8601) >= ($now - 14400)",
        '.conclusion != "startup_failure"',
        "actions/workflows/ci.yml/runs?head_sha=",
        "actions/workflows/current-main-ci-wake.yml/runs?head_sha=",
        "actions/runs/${prior_run}/jobs?per_page=100",
        "(.total_count == (.jobs | length))",
        '.name == "Exact Current-Main Recovery Gate"',
        "    name: Exact Current-Main Recovery Gate",
        "    needs: [plan, validate-ci, validate-codeql]",
        "    uses: ./.github/workflows/reusable-ci.yml",
        "    uses: ./.github/workflows/reusable-codeql.yml",
        "      security-events: write",
        "      - name: Require full exact-main CI and CodeQL",
        'test "${{ needs.validate-ci.result }}" = "success"',
        'test "${{ needs.validate-codeql.result }}" = "success"',
        'echo "run_validation=true" >> "$GITHUB_OUTPUT"',
        'echo "run_validation=false" >> "$GITHUB_OUTPUT"',
    )
    for item in required:
        assert item in source, f"lost exact-main recovery control: {item}"
    assert source.count("name: Trusted current-main CI wake") == 1
    assert source.count("    uses: ./.github/workflows/reusable-ci.yml") == 1
    assert source.count("    uses: ./.github/workflows/reusable-codeql.yml") == 1
    assert source.count("      security-events: write") == 1
    assert source.count("      actions: read") == 2
    assert source.count("cron:") == 1
    assert source.count('live_main="$(gh api') == 1
    assert source.count("run_validation=true") == 1
    for forbidden in (
        "/dispatches",
        "actions: write",
        "contents: write",
        "checks: write",
        "statuses: write",
        "id-token: write",
        "gh pr merge",
        "--force",
        "continue-on-error: true",
    ):
        assert forbidden not in source, f"wake gained unreviewed authority: {forbidden}"
    # The independently anchored Git blob rejects all unreviewed semantic drift.
    assert contract._verify_current_main_ci_wake_workflow(source)["authority"] == (
        "exact-current-main-reusable-ci-and-codeql-only"
    )


def test_exact_current_main_reusable_recovery_is_reviewed() -> None:
    validate(SOURCE.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "needle",
    [
        "    schedule|workflow_dispatch) ;;",
        ".workflow_id == 346203190",
        ".workflow_id == 372619559",
        ".head_repository.full_name == $repo",
        ".run_attempt == 1",
        "github.event.workflow_run.event == 'schedule'",
        "github.event.workflow_run.conclusion == 'success'",
        'test "$GITHUB_REF" = "refs/heads/main"',
        'if [ "$live_main" != "$EXPECTED_SHA" ]; then',
        ".head_sha == $sha",
        ".repository.full_name == $repo",
    ],
)
def test_untrusted_trigger_or_stale_main_is_rejected(needle: str) -> None:
    current = SOURCE.read_text(encoding="utf-8")
    assert needle in current
    with pytest.raises((AssertionError, ValueError)):
        validate(current.replace(needle, "", 1))


@pytest.mark.parametrize(
    "needle",
    [
        "(.total_count == (.workflow_runs | length))",
        "(.total_count == (.jobs | length))",
        "actions/runs/${prior_run}/jobs?per_page=100",
        '.name == "Exact Current-Main Recovery Gate"',
        "((.created_at | fromdateiso8601) >= ($now - 86400))",
        '.conclusion != "startup_failure"',
        "(.created_at | fromdateiso8601) >= ($now - 14400)",
        'echo "run_validation=false" >> "$GITHUB_OUTPUT"',
    ],
)
def test_incomplete_or_stale_native_evidence_cannot_suppress_validation(needle: str) -> None:
    current = SOURCE.read_text(encoding="utf-8")
    assert needle in current
    with pytest.raises((AssertionError, ValueError)):
        validate(current.replace(needle, "", 1))


@pytest.mark.parametrize(
    "needle",
    [
        "    uses: ./.github/workflows/reusable-ci.yml",
        "    uses: ./.github/workflows/reusable-codeql.yml",
        "      security-events: write",
        "    needs: [plan, validate-ci, validate-codeql]",
        'test "${{ needs.validate-ci.result }}" = "success"',
        'test "${{ needs.validate-codeql.result }}" = "success"',
        'echo "run_validation=true" >> "$GITHUB_OUTPUT"',
    ],
)
def test_full_evidence_gates_and_codeql_authority_are_mandatory(needle: str) -> None:
    current = SOURCE.read_text(encoding="utf-8")
    assert needle in current
    with pytest.raises((AssertionError, ValueError)):
        validate(current.replace(needle, "", 1))


def test_misrouted_reusable_workflow_cannot_be_substituted() -> None:
    current = SOURCE.read_text(encoding="utf-8")
    changed = current.replace(
        "uses: ./.github/workflows/reusable-ci.yml",
        "uses: ./.github/workflows/reusable-codeql.yml",
        1,
    )
    with pytest.raises((AssertionError, ValueError)):
        validate(changed)



def test_protected_owner_wake_uses_live_native_ci_security_names() -> None:
    root = Path(__file__).resolve().parents[2]
    wake_path = root / ".github/workflows/protected-maintenance-authorizer.yml"
    issuer_path = root / "scripts/auto_protected_maintenance_authorizer.py"
    wake = wake_path.read_text(encoding="utf-8")
    issuer = issuer_path.read_text(encoding="utf-8")
    assert 'workflows: ["ci", "CodeQL", "security"]' in wake
    assert '339754724: ("ci", ".github/workflows/ci.yml")' in issuer
    assert '359681647: ("CodeQL", ".github/workflows/codeql.yml")' in issuer
    assert '377768728: ("security", ".github/workflows/security.yml")' in issuer
    gate_label = '("security-gate", "security", ".github/workflows/security.yml", None)'
    assert gate_label in issuer
    assert "CI — ƳƤ AI QA Automation Framework" not in wake
    assert "CI — ƳƤ AI QA Automation Framework" not in issuer
    assert '"Security"' not in wake
    assert '"Security"' not in issuer
    assert 'workflow.get("name") == workflow_name' in issuer
    assert 'workflow.get("run_attempt") == 1' in issuer
    assert 'workflow.get("head_sha") == head_sha' in issuer


@pytest.mark.parametrize(
    ("trusted_condition", "unsafe_replacement"),
    [
        (
            "github.event.workflow_run.event == 'schedule'",
            "github.event.workflow_run.event == 'pull_request'",
        ),
        (
            "github.event.workflow_run.conclusion == 'success'",
            "github.event.workflow_run.conclusion == 'skipped'",
        ),
    ],
)
def test_non_scheduled_native_wake_is_filtered_without_dispatch(
    trusted_condition: str, unsafe_replacement: str
) -> None:
    original = SOURCE.read_text(encoding="utf-8")
    assert original.count(trusted_condition) == 1
    with pytest.raises((AssertionError, ValueError)):
        validate(original.replace(trusted_condition, unsafe_replacement, 1))
