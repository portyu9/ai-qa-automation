import json

import pytest

from ai_qa_automation.intelligence.contract_drift import (
    ContractDriftSeverity,
    OpenAPIContractDriftAnalyzer,
)


def analyze(baseline: dict[str, object], current: dict[str, object]):
    return OpenAPIContractDriftAnalyzer().analyze(
        path="openapi.json",
        baseline=json.dumps(baseline, separators=(",", ":"), sort_keys=True).encode(),
        current=json.dumps(current, separators=(",", ":"), sort_keys=True).encode(),
    )


def openapi_operation(parameters: list[dict[str, object]]) -> dict[str, object]:
    return {
        "openapi": "3.1.0",
        "paths": {
            "/items/{id}": {
                "get": {
                    "parameters": parameters,
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
    }


@pytest.mark.parametrize(
    ("baseline", "current"),
    [
        ({"swagger": "2.0", "paths": {}}, {"swagger": "2.0", "openapi": 3, "paths": {}}),
        ({"openapi": "3.1.0", "paths": {}}, {"openapi": "3.1.0", "swagger": 2, "paths": {}}),
    ],
)
def test_mixed_dialect_marker_presence_fails_closed(
    baseline: dict[str, object], current: dict[str, object]
) -> None:
    result = analyze(baseline, current)

    assert result.severity is ContractDriftSeverity.NOT_ANALYZED
    assert result.analyzed is False
    assert result.reason is not None
    assert "mix" in result.reason.casefold()


@pytest.mark.parametrize(
    "parameter",
    [
        {"name": "id", "in": "path", "required": False, "schema": {"type": "string"}},
        {"name": "payload", "in": "body", "required": False, "schema": {"type": "string"}},
        {"name": "q", "in": "query", "required": False},
        {
            "name": "q",
            "in": "query",
            "required": False,
            "schema": {"type": "string"},
            "content": {"text/plain": {}},
        },
        {
            "name": "q",
            "in": "query",
            "required": False,
            "content": {"text/plain": {}, "application/json": {}},
        },
    ],
)
def test_malformed_openapi_parameter_shapes_fail_closed(
    parameter: dict[str, object],
) -> None:
    result = analyze(openapi_operation([]), openapi_operation([parameter]))

    assert result.severity is ContractDriftSeverity.NOT_ANALYZED
    assert result.analyzed is False


def test_valid_optional_openapi_schema_parameter_remains_analyzable() -> None:
    parameter = {"name": "q", "in": "query", "required": False, "schema": {"type": "string"}}

    result = analyze(openapi_operation([]), openapi_operation([parameter]))

    assert result.severity is ContractDriftSeverity.NON_BREAKING
    assert result.analyzed is True


def test_valid_optional_openapi_content_parameter_remains_analyzable() -> None:
    parameter = {
        "name": "q",
        "in": "query",
        "required": False,
        "content": {"text/plain": {"schema": {"type": "string"}}},
    }

    result = analyze(openapi_operation([]), openapi_operation([parameter]))

    assert result.severity is ContractDriftSeverity.NON_BREAKING
    assert result.analyzed is True


def swagger_operation(parameters: list[dict[str, object]]) -> dict[str, object]:
    return {
        "swagger": "2.0",
        "paths": {
            "/items/{id}": {
                "get": {
                    "parameters": parameters,
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
    }


@pytest.mark.parametrize(
    "parameter",
    [
        {"name": "id", "in": "path", "required": False, "type": "string"},
        {"name": "q", "in": "cookie", "required": False, "type": "string"},
        {"name": "q", "in": "query", "required": False},
        {"name": "q", "in": "query", "required": False, "schema": {"type": "string"}},
        {"name": "upload", "in": "query", "required": False, "type": "file"},
        {"name": "values", "in": "query", "required": False, "type": "array"},
        {"name": "body", "in": "body", "required": False},
    ],
)
def test_malformed_swagger_parameter_shapes_fail_closed(
    parameter: dict[str, object],
) -> None:
    result = analyze(swagger_operation([]), swagger_operation([parameter]))

    assert result.severity is ContractDriftSeverity.NOT_ANALYZED
    assert result.analyzed is False


def test_valid_optional_swagger_parameter_remains_analyzable() -> None:
    parameter = {"name": "q", "in": "query", "required": False, "type": "string"}

    result = analyze(swagger_operation([]), swagger_operation([parameter]))

    assert result.severity is ContractDriftSeverity.NON_BREAKING
    assert result.analyzed is True
