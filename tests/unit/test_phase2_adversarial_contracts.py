from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import ValidationError

from ai_qa_automation.agent import _final_response, configuration_fingerprint, sdk_exception_outcome
from ai_qa_automation.config import Settings
from ai_qa_automation.models import (
    AgentRunState,
    TerminalStatus,
    ValidationResult,
    ValidationStatus,
)
from ai_qa_automation.runtime.budget import ExecutionBudget
from ai_qa_automation.runtime.internal_tools import RuntimeServices, _change_revision_closed
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.run_control import RuntimeControl
from ai_qa_automation.runtime.validation_truth import evaluate_revision_closure


def _settings(tmp_path: Path, *, suffix: str) -> Settings:
    return Settings(
        control_root=tmp_path / f"control-{suffix}",
        artifact_root=tmp_path / f"artifacts-{suffix}",
    )


def test_configuration_fingerprint_binds_trust_and_artifact_roots(tmp_path: Path) -> None:
    first = configuration_fingerprint(_settings(tmp_path, suffix="a"))
    second = configuration_fingerprint(_settings(tmp_path, suffix="b"))

    assert first.startswith("sha256:")
    assert second.startswith("sha256:")
    assert first != second


def test_objective_gate_id_is_bounded_and_nonempty(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="objective_gate_id"):
        AgentRunState(objective="bounded", workspace=str(tmp_path), objective_gate_id="   ")

    with pytest.raises(ValidationError, match="objective_gate_id"):
        AgentRunState(objective="bounded", workspace=str(tmp_path), objective_gate_id="x" * 257)


def test_final_response_always_carries_verification_boundaries(tmp_path: Path) -> None:
    state = AgentRunState(objective="report truth", workspace=str(tmp_path))
    state.terminal_status = TerminalStatus.NOT_VERIFIED
    state.terminal_reason = "No deterministic gate closed the objective."

    response = _final_response(state, agent_result="model text")
    limitations = response["report"]["limitations"]

    assert any("model response is not a test result" in item.lower() for item in limitations)
    assert any(
        "external mcp capability remains not_verified" in item.lower() for item in limitations
    )
    assert any("does not replay a prior conversation" in item.lower() for item in limitations)


@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (RuntimeError("401 invalid api key"), TerminalStatus.BLOCKED),
        (ConnectionError("provider connection reset"), TerminalStatus.INFRASTRUCTURE_FAILURE),
        (RuntimeError("schema contract violated"), TerminalStatus.FAILURE),
    ],
)
def test_sdk_terminal_classification_is_explicit(
    exc: BaseException,
    expected: TerminalStatus,
) -> None:
    status, reason = sdk_exception_outcome(exc)

    assert status is expected
    assert type(exc).__name__ in reason


def _validation(
    name: str,
    *,
    status: ValidationStatus = ValidationStatus.PASS,
    revision: int = 1,
    gate_id: str | None = None,
    details: dict[str, object] | None = None,
) -> ValidationResult:
    return ValidationResult(
        name=name,
        status=status,
        revision=revision,
        gate_id=gate_id,
        summary=name,
        details=details or {},
    )


def _closed_checks(path: str = "tests/test_x.py") -> list[ValidationResult]:
    return [
        _validation(
            "test_patch_safety",
            gate_id=f"test_patch_safety:{path}",
            details={"path": path},
        ),
        _validation(
            "pytest",
            gate_id="pytest:targeted",
            details={
                "scope": "targeted",
                "mutation_target_bound": True,
                "mutation_target": path,
            },
        ),
        _validation("pytest", gate_id="pytest:regression", details={"scope": "regression"}),
    ]


def _services(
    tmp_path: Path, checks: list[ValidationResult], *, revision: int = 1
) -> RuntimeServices:
    state = AgentRunState(objective="closure", workspace=str(tmp_path), change_revision=revision)
    state.validation_results = checks
    return RuntimeServices(
        workspace=tmp_path,
        state=state,
        evidence=cast(Any, object()),
        policy=cast(Any, object()),
        test_runner=cast(Any, object()),
    )


@pytest.mark.parametrize(
    "checks",
    [
        _closed_checks(),
        _closed_checks()[:-1],
        [*_closed_checks(), _validation("extra", status=ValidationStatus.FAIL, gate_id="extra")],
        [
            *_closed_checks(),
            _validation("extra", status=ValidationStatus.NOT_VERIFIED, gate_id="extra"),
        ],
        [
            *_closed_checks(),
            _validation(
                "test_patch_safety",
                gate_id="test_patch_safety:tests/test_y.py",
                details={"path": "tests/test_y.py"},
            ),
        ],
        [
            _closed_checks()[0],
            _validation(
                "pytest",
                gate_id="pytest:targeted",
                details={
                    "scope": "targeted",
                    "mutation_target_bound": False,
                    "mutation_target": "tests/test_x.py",
                },
            ),
            _closed_checks()[2],
        ],
        [
            _closed_checks()[0],
            _validation(
                "pytest",
                gate_id="pytest:targeted",
                details={
                    "scope": "targeted",
                    "mutation_target_bound": True,
                    "mutation_target": "tests/test_other.py",
                },
            ),
            _closed_checks()[2],
        ],
    ],
)
def test_internal_mutation_guard_conforms_to_authoritative_closure(
    tmp_path: Path,
    checks: list[ValidationResult],
) -> None:
    services = _services(tmp_path, checks)
    expected = evaluate_revision_closure(checks, current_revision=1).closed

    assert _change_revision_closed(services.state) is expected


def test_internal_mutation_guard_and_shared_closure_agree_for_revision_zero(tmp_path: Path) -> None:
    services = _services(tmp_path, [], revision=0)

    assert _change_revision_closed(services.state) is True
    assert evaluate_revision_closure([], current_revision=0).closed is True


@pytest.mark.parametrize("value", [0, -1, True])
def test_runtime_control_rejects_invalid_repetition_limit(tmp_path: Path, value: object) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    with pytest.raises(ValueError, match="max_repeated_action"):
        RuntimeControl(
            workspace=workspace,
            budget=ExecutionBudget(
                max_tool_calls=2,
                max_network_calls=2,
                max_mutations=1,
                max_wall_seconds=60,
            ),
            journal=RunJournal(tmp_path / "run" / "journal.jsonl"),
            metadata_path=tmp_path / "run" / "runtime.json",
            lease_id="lease",
            max_repeated_action=cast(Any, value),
        )
