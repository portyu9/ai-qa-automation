"""Regression contract for scheduled exact-current-main CI liveness recovery.

GITHUB_TOKEN merges suppress ordinary push workflow wakeups; this policy
ensures the recovery route dispatches only the *actual* reviewed CI workflow.
"""
from pathlib import Path

import pytest

SOURCE = Path(__file__).resolve().parents[2] / ".github/workflows/current-main-ci-wake.yml"


def validate(source: str) -> None:
    required = (
        '    - cron: "13,43 * * * *"',
        "  workflow_dispatch:",
        "  group: trusted-current-main-ci-wake",
        "  cancel-in-progress: false",
        "    permissions:\n      contents: read\n      actions: read",
        "    permissions:\n      contents: read\n      actions: write",
        "    if: needs.plan.outputs.dispatch == 'true' && github.ref == 'refs/heads/main'",
        'test "$GITHUB_REF" = "refs/heads/main"',
        'test "$GITHUB_WORKFLOW_REF" = "$GITHUB_REPOSITORY/.github/workflows/current-main-ci-wake.yml@refs/heads/main"',
        '[[ "$EXPECTED_SHA" =~ ^[0-9a-f]{40}$ ]]',
        '[[ "$SUBJECT_SHA" =~ ^[0-9a-f]{40}$ ]]',
        'test "$SUBJECT_SHA" = "$GITHUB_SHA"',
        'test "$(gh api "repos/${GITHUB_REPOSITORY}/actions/workflows/ci.yml" --jq .path)" = ".github/workflows/ci.yml"',
        "(.total_count == (.workflow_runs | length))",
        '(.total_count | type == "number" and . >= 0 and . <= 100)',
        ".head_sha == $sha",
        '.head_branch == "main"',
        ".repository.full_name == $repo",
        '(.event == "push" or .event == "workflow_dispatch")',
        '(.status == "completed" and .conclusion == "success")',
        "(.created_at | fromdateiso8601) >= ($now - 14400)",
        'echo "dispatch=false" >> "$GITHUB_OUTPUT"',
        'echo "dispatch=true" >> "$GITHUB_OUTPUT"',
        'if [ "$live_main" != "$SUBJECT_SHA" ]; then',
        "gh api --include --method POST",
        '    "repos/${GITHUB_REPOSITORY}/actions/workflows/ci.yml/dispatches"',
        'subject_ref:"main"',
        "HTTP/[0-9.]+ 204",
    )
    for item in required:
        assert item in source, f"missing exact-main CI wake protection: {item}"
    assert source.count("name: Trusted current-main CI wake") == 1
    assert source.count("    name: Dispatch exact accepted-main CI") == 1
    assert source.count("      actions: write") == 1
    assert source.count("      actions: read") == 1
    assert source.count("cron:") == 1
    assert source.count("      - name:") == 2
    assert source.count('dispatches"') == 1
    assert "pull_request:" not in source
    assert "contents: write" not in source
    assert "id-token: write" not in source
    assert "--force" not in source
    assert "gh pr merge" not in source
    assert source.count('live_main="$(gh api') == 2


def test_exact_current_main_ci_recovery_is_reviewed() -> None:
    validate(SOURCE.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "needle",
    [
        "      actions: write",
        'test "$SUBJECT_SHA" = "$GITHUB_SHA"',
        "      actions: read",
        "(.total_count == (.workflow_runs | length))",
        '(.event == "push" or .event == "workflow_dispatch")',
        '(.status == "completed" and .conclusion == "success")',
        "HTTP/[0-9.]+ 204",
    ],
)
def test_privilege_or_provenance_reduction_is_rejected(needle: str) -> None:
    source = SOURCE.read_text(encoding="utf-8")
    assert source.count(needle) == 1
    with pytest.raises(AssertionError):
        validate(source.replace(needle, "", 1))


def test_misrouting_dispatch_to_another_workflow_is_rejected() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    broken = source.replace(
        "actions/workflows/ci.yml/dispatches", "actions/workflows/security.yml/dispatches"
    )
    with pytest.raises(AssertionError):
        validate(broken)
