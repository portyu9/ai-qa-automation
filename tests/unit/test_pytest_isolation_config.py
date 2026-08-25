from __future__ import annotations

from pathlib import Path

import pytest

from ai_qa_automation.agent import configuration_fingerprint
from ai_qa_automation.config import Settings


def test_pytest_isolation_assertions_default_fail_closed(tmp_path: Path) -> None:
    settings = Settings(control_root=tmp_path)

    assert settings.pytest_process_isolation_enforced is False
    assert settings.pytest_external_egress_enforced is False


def test_pytest_isolation_assertions_are_explicit_environment_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AI_QA_PYTEST_PROCESS_ISOLATION_ENFORCED", "true")
    monkeypatch.setenv("AI_QA_PYTEST_EXTERNAL_EGRESS_ENFORCED", "true")

    settings = Settings(control_root=tmp_path)

    assert settings.pytest_process_isolation_enforced is True
    assert settings.pytest_external_egress_enforced is True


def test_pytest_isolation_assertions_change_configuration_provenance(tmp_path: Path) -> None:
    blocked = Settings(control_root=tmp_path)
    enabled = Settings(
        control_root=tmp_path,
        pytest_process_isolation_enforced=True,
        pytest_external_egress_enforced=True,
    )

    assert configuration_fingerprint(blocked) != configuration_fingerprint(enabled)
