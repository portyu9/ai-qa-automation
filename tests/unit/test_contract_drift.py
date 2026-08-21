from __future__ import annotations

import json

from ai_qa_automation.intelligence.contract_drift import (
    ContractDriftSeverity,
    OpenAPIContractDriftAnalyzer,
)


def encode(document: dict[str, object]) -> bytes:
    return json.dumps(document, sort_keys=True).encode("utf-8")


def openapi(paths: dict[str, object], *, schemas: dict[str, object] | None = None) -> dict[str, object]:
    document: dict[str, object] = {
        "openapi": "3.1.0",
        "info": {"title": "test", "version": "1"},
        "paths": paths,
    }
    if schemas is not None:
        document["components"] = {"schemas": schemas}
    return document


def test_removed_operation_is_breaking() -> None:
    baseline = openapi(
        {
            "/orders": {
                "get": {"responses": {"200": {"description": "ok"}}},
                "post": {"responses": {"201": {"description": "created"}}},
            }
        }
    )
    current = openapi(
        {"/orders": {"get": {"responses": {"200": {"description": "ok"}}}}}
    )

    result = OpenAPIContractDriftAnalyzer().analyze(
        path="openapi.json", baseline=encode(baseline), current=encode(current)
    )

    assert result.analyzed is True
    assert result.severity is ContractDriftSeverity.BREAKING
    assert any(change.rule_id == "OAS-OPERATION-REMOVED" for change in result.changes)


def test_required_parameter_addition_is_breaking() -> None:
    baseline = openapi(
        {"/orders": {"get": {"responses": {"200": {"description": "ok"}}}}}
    )
    current = openapi(
        {
            "/orders": {
                "get": {
                    "parameters": [
                        {"name": "tenant", "in": "header", "required": True, "schema": {"type": "string"}}
                    ],
                    "responses": {"200": {"description": "ok"}},
                }
            }
        }
    )

    result = OpenAPIContractDriftAnalyzer().analyze(
        path="openapi.json", baseline=encode(baseline), current=encode(current)
    )

    assert result.severity is ContractDriftSeverity.BREAKING
    assert any(change.rule_id == "OAS-REQUIRED-PARAMETER-ADDED" for change in result.changes)


def test_enum_narrowing_is_breaking() -> None:
    baseline = openapi(
        {},
        schemas={
            "Order": {
                "type": "object",
                "properties": {"status": {"type": "string", "enum": ["NEW", "PAID", "CANCELLED"]}},
            }
        },
    )
    current = openapi(
        {},
        schemas={
            "Order": {
                "type": "object",
                "properties": {"status": {"type": "string", "enum": ["NEW", "PAID"]}},
            }
        },
    )

    result = OpenAPIContractDriftAnalyzer().analyze(
        path="openapi.json", baseline=encode(baseline), current=encode(current)
    )

    assert result.severity is ContractDriftSeverity.BREAKING
    assert any(change.rule_id == "OAS-ENUM-NARROWED" for change in result.changes)


def test_additive_path_is_non_breaking() -> None:
    baseline = openapi({})
    current = openapi(
        {"/health": {"get": {"responses": {"200": {"description": "ok"}}}}}
    )

    result = OpenAPIContractDriftAnalyzer().analyze(
        path="openapi.json", baseline=encode(baseline), current=encode(current)
    )

    assert result.analyzed is True
    assert result.severity is ContractDriftSeverity.NON_BREAKING
    assert any(change.rule_id == "OAS-PATH-ADDED" for change in result.changes)


def test_non_openapi_document_is_not_analyzed() -> None:
    result = OpenAPIContractDriftAnalyzer().analyze(
        path="document.json",
        baseline=encode({"hello": "world"}),
        current=encode({"hello": "again"}),
    )

    assert result.analyzed is False
    assert result.severity is ContractDriftSeverity.NOT_ANALYZED
    assert result.reason == "document is not recognized as OpenAPI/Swagger"
