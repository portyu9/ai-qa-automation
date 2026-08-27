from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "trusted-merge-authorization.yml"


def _embedded_guard_code() -> str:
    text = WORKFLOW.read_text(encoding="utf-8")
    start_marker = "          python - <<'PY'\n"
    end_marker = "          PY\n"
    start = text.index(start_marker) + len(start_marker)
    end = text.index(end_marker, start)
    return textwrap.dedent(text[start:end])


def _run_guard(
    tmp_path: Path,
    *,
    action: str,
    actor: str,
    head_sha: str = "a" * 40,
) -> subprocess.CompletedProcess[str]:
    event_path = tmp_path / "event.json"
    event_path.write_text(
        json.dumps(
            {
                "action": action,
                "pull_request": {"head": {"sha": head_sha}},
                "sender": {"login": actor},
            }
        ),
        encoding="utf-8",
    )
    env = {
        "PATH": os.environ.get("PATH", ""),
        "GITHUB_EVENT_PATH": str(event_path),
        "REPOSITORY_OWNER": "portyu9",
    }
    return subprocess.run(
        [sys.executable, "-c", _embedded_guard_code()],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )


def test_trusted_workflow_has_no_pr_code_or_write_authority() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")

    assert "  pull_request_target:\n" in text
    for event_type in (
        "opened",
        "reopened",
        "synchronize",
        "ready_for_review",
        "converted_to_draft",
    ):
        assert f"      - {event_type}\n" in text
    assert "permissions:\n  contents: read\n" in text
    assert "uses:" not in text
    assert "actions/checkout" not in text
    assert "${{ secrets." not in text
    assert "github.token" not in text
    assert ": write" not in text
    assert "runs-on: ubuntu-24.04" in text
    assert "timeout-minutes: 5" in text
    assert "cancel-in-progress: true" in text


def test_owner_ready_for_review_authorizes_exact_head(tmp_path: Path) -> None:
    result = _run_guard(tmp_path, action="ready_for_review", actor="portyu9")

    assert result.returncode == 0
    assert "trusted owner authorization accepted for exact PR head" in result.stdout


@pytest.mark.parametrize(
    "action",
    ["opened", "reopened", "synchronize", "converted_to_draft"],
)
def test_non_authorizing_events_fail_closed(tmp_path: Path, action: str) -> None:
    result = _run_guard(tmp_path, action=action, actor="portyu9")

    assert result.returncode != 0
    assert "is not owner-authorized" in result.stderr


def test_non_owner_ready_for_review_is_denied(tmp_path: Path) -> None:
    result = _run_guard(tmp_path, action="ready_for_review", actor="contributor")

    assert result.returncode != 0
    assert "not owner-authorized by repository owner" in result.stderr


def test_malformed_head_identity_is_denied(tmp_path: Path) -> None:
    result = _run_guard(
        tmp_path,
        action="ready_for_review",
        actor="portyu9",
        head_sha="short",
    )

    assert result.returncode != 0
    assert "head SHA is not a full Git object ID" in result.stderr
