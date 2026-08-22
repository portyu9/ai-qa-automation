from pathlib import Path

from ai_qa_automation.models import ToolDecision
from ai_qa_automation.policy import PolicyEngine


def test_force_push_and_hard_reset_are_denied(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    policy = PolicyEngine(tmp_path, target)
    for command in ["git push origin main --force", "git reset --hard HEAD~1", "git clean -fdx"]:
        assert (
            policy.authorize_tool("command_runner", {"command": command}).decision
            is ToolDecision.DENY
        )
