from __future__ import annotations

from pathlib import Path

import pytest

from ai_qa_automation.models import ToolDecision
from ai_qa_automation.policy import PolicyEngine


def policy(tmp_path: Path) -> PolicyEngine:
    target = tmp_path / "target"
    target.mkdir()
    return PolicyEngine(tmp_path, target)


@pytest.mark.parametrize(
    "relative_path",
    [
        ".env",
        ".env.local",
        ".env.production",
        ".env.test",
        ".env.secrets",
        "config/.env.production",
        "services/api/.env.local",
    ],
)
def test_secret_shaped_environment_files_are_protected(
    tmp_path: Path, relative_path: str
) -> None:
    decision = policy(tmp_path).authorize_path(Path(relative_path), write=False)
    assert decision.decision is ToolDecision.DENY
    assert decision.rule_id == "GOV-001"


@pytest.mark.parametrize(
    "relative_path",
    [
        ".env.example",
        "config/.env.example",
        "examples/service/.env.example",
    ],
)
def test_env_example_remains_readable_reference_documentation(
    tmp_path: Path, relative_path: str
) -> None:
    decision = policy(tmp_path).authorize_path(Path(relative_path), write=False)
    assert decision.decision is ToolDecision.ALLOW
    assert decision.rule_id == "FS-ALLOW"


@pytest.mark.parametrize(
    "relative_path",
    [
        ".git/.env.example",
        ".claude/.env.example",
    ],
)
def test_protected_parent_directory_wins_over_env_example_exception(
    tmp_path: Path, relative_path: str
) -> None:
    decision = policy(tmp_path).authorize_path(Path(relative_path), write=False)
    assert decision.decision is ToolDecision.DENY
    assert decision.rule_id == "GOV-001"
