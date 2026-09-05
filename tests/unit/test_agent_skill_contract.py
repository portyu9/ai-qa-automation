from __future__ import annotations

import ast
from pathlib import Path

from ai_qa_automation.runtime.control_plane_provenance import TRUSTED_PROJECT_SKILLS


def test_runtime_literal_skill_allowlist_matches_provenance_requirements() -> None:
    repository_root = Path(__file__).resolve().parents[2]
    agent_path = repository_root / "src" / "ai_qa_automation" / "agent.py"
    if not agent_path.is_file():
        agent_path = repository_root / "ai_qa_automation" / "agent.py"
    tree = ast.parse(agent_path.read_text(encoding="utf-8"), filename=str(agent_path))
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "ClaudeAgentOptions"
    ]
    assert len(calls) == 1
    skills = [keyword for keyword in calls[0].keywords if keyword.arg == "skills"]
    assert len(skills) == 1
    assert isinstance(skills[0].value, ast.List)
    observed = tuple(
        item.value
        for item in skills[0].value.elts
        if isinstance(item, ast.Constant) and isinstance(item.value, str)
    )
    assert len(observed) == len(skills[0].value.elts)
    assert observed == TRUSTED_PROJECT_SKILLS
