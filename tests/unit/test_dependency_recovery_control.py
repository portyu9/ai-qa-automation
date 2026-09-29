from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / ".github" / "scripts" / "dependency_recovery.py"
SCRIPT_DIR = SCRIPT.parent


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("dependency_recovery_control_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(SCRIPT_DIR))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(SCRIPT_DIR))
    return module


recovery = _load()


def test_recovery_reproves_governance_config_before_rerun(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    posts: list[str] = []
    guarded: list[dict[str, Any]] = []

    class Api:
        def list_all(self, path: str, *, max_pages: int = 3) -> list[dict[str, Any]]:
            assert path == "/actions/runs/17/jobs?filter=latest"
            return [
                {
                    "id": 41,
                    "name": "Quality / Python 3.11.16",
                    "status": "completed",
                    "conclusion": "failure",
                }
            ]

        def post(self, path: str) -> None:
            posts.append(path)

    governance = {"baseBranch": "main"}
    recovery_policy = {
        "maxRunAttempts": 2,
        "aggregateJobs": ["Required PR Gate"],
    }
    monkeypatch.setattr(recovery, "_fetch_job_logs", lambda api, job_id: "transient")
    monkeypatch.setattr(
        recovery,
        "classify_failed_job",
        lambda job, logs, config: {"transient": True, "reason": "network"},
    )

    def guard(api: Any, config: dict[str, Any]) -> str:
        assert config is governance
        guarded.append(config)
        return "a" * 40

    monkeypatch.setattr(recovery, "require_current_control_revision", guard)

    assert recovery._recover_run(
        Api(),
        {"id": 17, "run_attempt": 1},
        recovery_policy,
        governance,
    )
    assert guarded == [governance]
    assert posts == ["/actions/jobs/41/rerun"]
