from __future__ import annotations

import json
from pathlib import Path

import pytest

from ai_qa_automation.models import ValidationStatus
from ai_qa_automation.tools import contracts
from ai_qa_automation.tools.execution_env import BoundedSubprocessResult


def _result(kind: str) -> BoundedSubprocessResult:
    return BoundedSubprocessResult(
        returncode=0,
        stdout=json.dumps({"kind": kind}),
        stderr="",
        stdout_truncated=False,
        stderr_truncated=False,
        timed_out=False,
    )


def test_json_schema_worker_command_binds_memory_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    def fake_run(
        command: list[str],
        *,
        cwd: Path,
        env: dict[str, str],
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> BoundedSubprocessResult:
        del cwd, env, timeout_seconds, max_output_bytes
        observed["command"] = command
        return _result("pass")

    monkeypatch.setattr(contracts, "run_bounded_subprocess", fake_run)

    result = contracts.validate_json_schema(12, {"type": "integer"})

    assert result.status is ValidationStatus.PASS
    command = observed["command"]
    assert isinstance(command, list)
    assert command[9] == str(contracts._MAX_JSON_SCHEMA_WORKER_MEMORY_BYTES)
    assert command[10] == contracts._DEFAULT_JSON_SCHEMA_DIALECT


def test_json_schema_worker_memory_authority_is_installed_before_dependency_import() -> None:
    worker = contracts._JSON_SCHEMA_WORKER_CODE
    assert "resource.RLIMIT_AS" in worker
    assert "resource.setrlimit" in worker
    assert worker.index("install_memory_budget()") < worker.index("import jsonschema")


def test_json_schema_worker_missing_memory_authority_is_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        contracts,
        "run_bounded_subprocess",
        lambda *args, **kwargs: _result("memory_budget_unavailable"),
    )

    result = contracts.validate_json_schema(12, {"type": "integer"})

    assert result.status is ValidationStatus.BLOCKED
    assert result.details == {"memory_limit_bytes": contracts._MAX_JSON_SCHEMA_WORKER_MEMORY_BYTES}


def test_json_schema_worker_memory_exhaustion_is_not_verified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        contracts,
        "run_bounded_subprocess",
        lambda *args, **kwargs: _result("memory_exhausted"),
    )

    result = contracts.validate_json_schema(12, {"type": "integer"})

    assert result.status is ValidationStatus.NOT_VERIFIED
    assert result.details == {"memory_limit_bytes": contracts._MAX_JSON_SCHEMA_WORKER_MEMORY_BYTES}
