from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import claude_agent_sdk
import pytest

from ai_qa_automation.agent import run_agent
from ai_qa_automation.config import Settings


class _ProviderMustNotStart:
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        del args, kwargs
        raise AssertionError("provider client must not be constructed for an unresolved baseline")


@pytest.mark.asyncio
async def test_unresolvable_configured_baseline_blocks_before_provider(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    artifact_root = tmp_path / "artifacts"
    monkeypatch.setattr(claude_agent_sdk, "ClaudeSDKClient", _ProviderMustNotStart)

    result = await run_agent(
        "Inspect the repository without changing it.",
        workspace,
        Settings(
            control_root=Path.cwd(),
            artifact_root=artifact_root,
            base_ref="refs/heads/definitely-missing",
        ),
    )

    report = result["report"]
    assert report["terminal_status"] == "BLOCKED"
    assert report["summary"] == "Configured repository baseline could not be resolved safely."
    assert report["validation_results"] == []
    assert report["files_modified"] == []
    assert result["agent_result"] == ""
    assert any(
        "model execution was not started" in limitation for limitation in report["limitations"]
    )

    run_dir = artifact_root / report["run_id"]
    journal_lines = (run_dir / "journal.jsonl").read_text(encoding="utf-8").splitlines()
    events = [json.loads(line)["event"] for line in journal_lines]
    assert "runtime_bootstrap_baseline_denied" in events
    assert "agent_run_started" not in events
