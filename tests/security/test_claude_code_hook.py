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


def test_hook_blocks_governance_hook_mutation() -> None:
    output = _run_hook(
        {
            "tool_name": "Edit",
            "tool_input": {"file_path": str(Path.cwd() / ".claude/hooks/policy_guard.py")},
        }
    )
    assert output is not None
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_hook_blocks_workflow_mutation() -> None:
    output = _run_hook(
        {
            "tool_name": "Write",
            "tool_input": {"file_path": str(Path.cwd() / ".github/workflows/ci.yml")},
        }
    )
    assert output is not None
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
