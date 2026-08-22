import os
from pathlib import Path

import pytest

from ai_qa_automation.agent import run_agent
from ai_qa_automation.config import Settings


@pytest.mark.model
@pytest.mark.asyncio
async def test_live_agent_runs_deterministic_pytest_before_success(tmp_path: Path):
    if not os.getenv("ANTHROPIC_API_KEY"):
        pytest.skip("ANTHROPIC_API_KEY is required for model-backed evaluation")
    (tmp_path / "test_sample.py").write_text("def test_truth():\n    assert 2 + 2 == 4\n")
    result = await run_agent(
        "Use the run_pytest QA tool to execute the target tests. Report the evidence; do not modify files.",
        tmp_path,
        Settings(
            control_root=Path.cwd(),
            artifact_root=tmp_path / "artifacts",
            max_turns=5,
            max_tool_calls=6,
            max_cost_usd=1.0,
        ),
    )
    assert result["report"]["terminal_status"] in {"SUCCESS", "NOT_VERIFIED"}
    assert result["report"]["validation_results"]
