from __future__ import annotations

import pytest
from pydantic import ValidationError

from ai_qa_automation.config import Settings


def test_runtime_budget_settings_are_independently_configurable(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("AI_QA_MAX_TOOL_CALLS", "31")
    monkeypatch.setenv("AI_QA_MAX_NETWORK_CALLS", "7")
    monkeypatch.setenv("AI_QA_MAX_MUTATIONS", "2")
    monkeypatch.setenv("AI_QA_MAX_REPEATED_ACTION", "4")

    settings = Settings(control_root=tmp_path)

    assert settings.max_tool_calls == 31
    assert settings.max_network_calls == 7
    assert settings.max_mutations == 2
    assert settings.max_repeated_action == 4


def test_artifact_root_defaults_to_trusted_control_root(tmp_path) -> None:
    settings = Settings(control_root=tmp_path)

    assert settings.control_root == tmp_path.resolve()
    assert settings.artifact_root == (tmp_path / "artifacts").resolve()


def test_invalid_runtime_budget_is_rejected(tmp_path) -> None:
    with pytest.raises(ValidationError):
        Settings(control_root=tmp_path, max_network_calls=0)
