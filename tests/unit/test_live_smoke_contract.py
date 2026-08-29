from __future__ import annotations

from copy import deepcopy

import pytest

from tests.evaluations.live_smoke_contract import (
    EXPECTED_GATE_ID,
    assert_live_agent_smoke_contract,
)


def _valid_result() -> dict[str, object]:
    return {
        "report": {
            "terminal_status": "NOT_VERIFIED",
            "summary": (
                "Agent completed with passing deterministic checks, but the operator did not supply "
                "an exact objective-validation gate contract."
            ),
            "files_modified": [],
            "provenance": {"objective_gate_id": "NOT_SUPPLIED"},
            "validation_results": [
                {
                    "name": "json_schema",
                    "gate_id": EXPECTED_GATE_ID,
                    "revision": 0,
                    "status": "PASS",
                    "summary": "Payload matches JSON Schema.",
                    "evidence_ids": [],
                    "details": {},
                }
            ],
        }
    }


def test_live_smoke_contract_accepts_exact_expected_validation() -> None:
    assert_live_agent_smoke_contract(_valid_result())


def test_live_smoke_contract_rejects_terminal_success_without_objective_gate() -> None:
    result = _valid_result()
    result["report"]["terminal_status"] = "SUCCESS"  # type: ignore[index]

    with pytest.raises(AssertionError):
        assert_live_agent_smoke_contract(result)  # type: ignore[arg-type]


def test_live_smoke_contract_rejects_unrelated_validation() -> None:
    result = _valid_result()
    validation = result["report"]["validation_results"][0]  # type: ignore[index]
    validation["name"] = "pytest"  # type: ignore[index]

    with pytest.raises(AssertionError):
        assert_live_agent_smoke_contract(result)  # type: ignore[arg-type]


def test_live_smoke_contract_rejects_wrong_json_subject() -> None:
    result = _valid_result()
    validation = result["report"]["validation_results"][0]  # type: ignore[index]
    validation["gate_id"] = "json_schema:wrong-subject"  # type: ignore[index]

    with pytest.raises(AssertionError):
        assert_live_agent_smoke_contract(result)  # type: ignore[arg-type]


def test_live_smoke_contract_rejects_mutation() -> None:
    result = _valid_result()
    result["report"]["files_modified"] = ["test_sample.py"]  # type: ignore[index]

    with pytest.raises(AssertionError):
        assert_live_agent_smoke_contract(result)  # type: ignore[arg-type]


def test_live_smoke_contract_rejects_extra_validation() -> None:
    result = _valid_result()
    report = result["report"]  # type: ignore[assignment]
    validations = report["validation_results"]  # type: ignore[index]
    validations.append(deepcopy(validations[0]))  # type: ignore[union-attr,index]

    with pytest.raises(AssertionError):
        assert_live_agent_smoke_contract(result)  # type: ignore[arg-type]
