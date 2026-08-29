from __future__ import annotations

import json

import pytest

from ai_qa_automation.intelligence.contract_drift import (
    ContractDriftSeverity,
    OpenAPIContractDriftAnalyzer,
)


def _encode(document: dict[str, object]) -> bytes:
    return json.dumps(document, separators=(",", ":"), sort_keys=True).encode()


def _analyze(baseline: dict[str, object], current: dict[str, object]):
    return OpenAPIContractDriftAnalyzer().analyze(
        path="openapi.json",
        baseline=_encode(baseline),
        current=_encode(current),
    )


def _schema_document(schema: dict[str, object], *, version: str = "3.1.0") -> dict[str, object]:
    return {
        "openapi": version,
        "paths": {},
        "components": {"schemas": {"Subject": schema}},
    }


def test_enum_boolean_and_integer_values_do_not_collapse() -> None:
    result = _analyze(
        _schema_document({"enum": [True]}),
        _schema_document({"enum": [1]}),
    )

    assert result.severity is ContractDriftSeverity.BREAKING
    assert result.analyzed is True
    assert any(change.rule_id == "OAS-ENUM-NARROWED" for change in result.changes)


def test_new_enum_constraint_is_breaking() -> None:
    result = _analyze(
        _schema_document({}),
        _schema_document({"enum": ["active"]}),
    )

    assert result.severity is ContractDriftSeverity.BREAKING
    assert any(change.rule_id == "OAS-ENUM-CONSTRAINT-ADDED" for change in result.changes)


def test_new_type_constraint_is_breaking() -> None:
    result = _analyze(
        _schema_document({}),
        _schema_document({"type": "string"}),
    )

    assert result.severity is ContractDriftSeverity.BREAKING
    assert any(change.rule_id == "OAS-TYPE-CONSTRAINT-ADDED" for change in result.changes)


def test_type_set_widening_is_risky() -> None:
    result = _analyze(
        _schema_document({"type": "string"}),
        _schema_document({"type": ["string", "null"]}),
    )

    assert result.severity is ContractDriftSeverity.RISKY
    assert result.analyzed is True
    assert any(change.rule_id == "OAS-TYPE-WIDENED" for change in result.changes)


def test_schema_reference_target_change_is_breaking() -> None:
    baseline = _schema_document({"$ref": "#/components/schemas/Old"})
    current = _schema_document({"$ref": "#/components/schemas/New"})
    baseline["components"]["schemas"].update({"Old": {}, "New": {}})  # type: ignore[index]
    current["components"]["schemas"].update({"Old": {}, "New": {}})  # type: ignore[index]

    result = _analyze(baseline, current)

    assert result.severity is ContractDriftSeverity.BREAKING
    assert any(change.rule_id == "OAS-SCHEMA-REF-CHANGED" for change in result.changes)


def test_unmodeled_schema_constraint_change_cannot_be_non_breaking() -> None:
    result = _analyze(
        _schema_document({"type": "number", "minimum": 0}),
        _schema_document({"type": "number", "minimum": 1}),
    )

    assert result.severity is ContractDriftSeverity.NOT_ANALYZED
    assert result.analyzed is False
    assert any(change.rule_id == "OAS-SCHEMA-SEMANTICS-UNMODELED" for change in result.changes)


def test_response_content_change_cannot_be_non_breaking() -> None:
    baseline = {
        "openapi": "3.1.0",
        "paths": {
            "/orders": {
                "get": {
                    "responses": {
                        "200": {
                            "description": "ok",
                            "content": {"application/json": {"schema": {"type": "string"}}},
                        }
                    }
                }
            }
        },
    }
    current = json.loads(json.dumps(baseline))
    current["paths"]["/orders"]["get"]["responses"]["200"]["content"]["application/json"]["schema"][
        "type"
    ] = "integer"

    result = _analyze(baseline, current)

    assert result.severity is ContractDriftSeverity.NOT_ANALYZED
    assert result.analyzed is False
    assert any(change.rule_id == "OAS-RESPONSE-SEMANTICS-UNMODELED" for change in result.changes)


@pytest.mark.parametrize("version", ["3.1.1", "4.0.0"])
def test_cross_or_unsupported_openapi_version_fails_closed(version: str) -> None:
    result = _analyze(
        {"openapi": "3.1.0", "paths": {}},
        {"openapi": version, "paths": {}},
    )

    assert result.severity is ContractDriftSeverity.NOT_ANALYZED
    assert result.analyzed is False


@pytest.mark.parametrize(
    "current",
    [
        {"openapi": "3.1.0", "paths": {"/x": {"get": {"responses": {"200": []}}}}},
        {"openapi": "3.1.0", "paths": {"/x": {"GET": {"responses": {}}}}},
        {"openapi": "3.1.0", "paths": {"extension": {}}},
        {"openapi": "3.1.0", "paths": {"/x": {"get": {"responses": {"20": {}}}}}},
        {
            "openapi": "3.1.0",
            "paths": {},
            "components": {"schemas": {"Subject": {"$ref": "https://example.test/schema.json"}}},
        },
    ],
)
def test_unsupported_consumed_contract_shapes_fail_closed(
    current: dict[str, object],
) -> None:
    result = _analyze({"openapi": "3.1.0", "paths": {}}, current)

    assert result.severity is ContractDriftSeverity.NOT_ANALYZED
    assert result.analyzed is False
