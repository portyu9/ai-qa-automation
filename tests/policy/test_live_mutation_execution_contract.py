from pathlib import Path

from ai_qa_automation.models import ToolDecision
from ai_qa_automation.policy import PolicyEngine


def policy(tmp_path: Path) -> PolicyEngine:
    target = tmp_path / "target"
    target.mkdir()
    return PolicyEngine(tmp_path, target, allow_test_writes=True)


def test_live_create_test_requires_pytest_executable_python_path(tmp_path: Path) -> None:
    subject = policy(tmp_path)

    python = subject.authorize_tool(
        "mcp__qa__create_test_file",
        {"path": "tests/test_checkout.py"},
    )
    typescript = subject.authorize_tool(
        "mcp__qa__create_test_file",
        {"path": "tests/checkout.spec.ts"},
    )

    assert python.decision is ToolDecision.ALLOW
    assert typescript.decision is ToolDecision.DENY
    assert typescript.rule_id == "WRITE-RUNTIME-001"
    assert "pytest-backed" in typescript.reason


def test_live_locator_heal_rejects_non_python_mutation_path(tmp_path: Path) -> None:
    decision = policy(tmp_path).authorize_tool(
        "mcp__qa__apply_locator_heal",
        {"path": "tests/checkout.spec.js"},
    )

    assert decision.decision is ToolDecision.DENY
    assert decision.rule_id == "WRITE-RUNTIME-001"
