from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

import ai_qa_automation.runtime.internal_tool_domains.testing as testing_domain
from ai_qa_automation.models import AgentRunState, ValidationStatus
from ai_qa_automation.runtime.internal_tool_domains.common import RuntimeServices
from ai_qa_automation.tools.pytest_regression import _parse_collection, _parse_execution_nodes
from ai_qa_automation.tools.test_execution import TestExecutionResult


class _FakeRunner:
    pass


class _DiagnosticSuite:
    suite_id = "sha256:" + "a" * 64
    pre_post_collection_match = True
    execution_nodes_match = True

    def details(self) -> dict[str, object]:
        return {
            "suite_id": self.suite_id,
            "pre_post_collection_match": True,
            "execution_nodes_match": True,
            "node_count": 1,
            "execution_subject_digest": "sha256:" + "b" * 64,
        }


def _decorator(
    _name: str,
    _description: str,
    _schema: dict[str, Any],
):
    def register(handler: Any) -> Any:
        return handler

    return register


def test_target_owned_terminal_transcript_is_parseable_but_not_execution_proof() -> None:
    node = "tests/test_demo.py::test_must_execute"

    collection = _parse_collection(node + "\n", truncated=False)
    execution = _parse_execution_nodes(node + " PASSED\n", truncated=False)

    assert collection.nodeids == (node,)
    assert execution == collection.nodeids
    # A hostile pytest_runtestloop can emit this exact line without executing the
    # test body. Parser reconciliation is therefore diagnostic, never semantic authority.


@pytest.mark.asyncio
async def test_zero_exit_reconciled_regression_remains_not_verified(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = AgentRunState(
        run_id="run-regression-forged-transcript",
        objective="reject target-forgeable regression semantics",
        workspace=str(tmp_path),
        change_revision=1,
    )
    services = RuntimeServices(
        workspace=tmp_path,
        state=state,
        evidence=cast(Any, object()),
        policy=cast(Any, object()),
        test_runner=cast(Any, _FakeRunner()),
        max_tool_calls=5,
        max_repeated_action=3,
    )
    monkeypatch.setattr(testing_domain, "TestRunner", _FakeRunner)
    forged_result = TestExecutionResult(
        command=("python", "-m", "pytest"),
        exit_code=0,
        stdout="tests/test_demo.py::test_must_execute PASSED\nno tests ran\n",
        stderr="",
        duration_seconds=0.1,
        evidence_ids=("ev-forged-regression",),
        execution_started=True,
        block_reason=None,
    )
    monkeypatch.setattr(
        testing_domain,
        "run_regression_pytest",
        lambda _runner, _args: (forged_result, _DiagnosticSuite()),
    )

    tools = testing_domain.register_testing_tools(services, _decorator)
    response = await tools["run_pytest"]({"args": []})

    assert response["is_error"] is True
    assert len(state.validation_results) == 1
    validation = state.validation_results[0]
    assert validation.status is ValidationStatus.NOT_VERIFIED
    assert validation.details["regression_suite_verified"] is False
    assert validation.details["regression_suite_id"] is None
    assert validation.details["regression_execution_authority"] == "unavailable"
    assert validation.details["regression_outcome_report_verified"] is False
    assert validation.details["regression_execution"] is None
    assert "cannot prove trusted executed-test semantics" in validation.summary
