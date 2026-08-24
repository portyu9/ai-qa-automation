import os
from pathlib import Path

import pytest

from ai_qa_automation.agent import run_agent
from ai_qa_automation.config import Settings
from tests.evaluations.live_smoke_contract import assert_live_agent_smoke_contract


@pytest.mark.model
@pytest.mark.asyncio
async def test_live_agent_executes_exact_bounded_pytest_without_mutation(tmp_path: Path):
    if not os.getenv("ANTHROPIC_API_KEY"):
        pytest.skip("ANTHROPIC_API_KEY is required for model-backed evaluation")
    (tmp_path / "test_sample.py").write_text("def test_truth():\n    assert 2 + 2 == 4\n")
    result = await run_agent(
        (
            'Call the run_pytest QA tool exactly once with args ["test_sample.py"]. '
            "Do not call any other QA tool. Do not modify files. Report the deterministic evidence."
        ),
        tmp_path,
        Settings(
            control_root=Path.cwd(),
            artifact_root=tmp_path / "artifacts",
            max_turns=5,
            max_tool_calls=1,
            max_cost_usd=1.0,
        ),
    )
    assert_live_agent_smoke_contract(result)
