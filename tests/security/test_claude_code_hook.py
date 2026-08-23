import json
import subprocess
import sys
from pathlib import Path

HOOK = Path(".claude/hooks/policy_guard.py")


def _run_hook(payload: dict[str, object]) -> dict[str, object] | None:
    result = subprocess.run(
        [sys.executable, str(HOOK)],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=True,
    )
    return json.loads(result.stdout) if result.stdout.strip() else None


def _assert_governance_path_denied(path: str, tool_name: str = "Edit") -> None:
    output = _run_hook(
        {
            "tool_name": tool_name,
            "tool_input": {"file_path": str(Path.cwd() / path)},
        }
    )
    assert output is not None
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "SEC-GOV-001" in output["hookSpecificOutput"]["permissionDecisionReason"]


def test_hook_blocks_governance_hook_mutation() -> None:
    _assert_governance_path_denied(".claude/hooks/policy_guard.py")


def test_hook_blocks_workflow_mutation() -> None:
    _assert_governance_path_denied(".github/workflows/ci.yml", tool_name="Write")


def test_hook_blocks_release_and_security_governance_mutation() -> None:
    for path in (
        "SECURITY.md",
        "docs/THREAT_MODEL.md",
        "docs/PRODUCTION_READINESS.md",
        "evals/thresholds.json",
        ".github/CODEOWNERS",
        "pyproject.toml",
    ):
        _assert_governance_path_denied(path)


def test_policy_guard_internal_parse_failure_uses_blocking_exit_code() -> None:
    result = subprocess.run(
        [sys.executable, str(HOOK)],
        input="{malformed-json",
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 2
    assert result.stdout == ""
    assert "SEC-HOOK-001" in result.stderr
    assert "malformed-json" not in result.stderr
