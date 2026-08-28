import json
import pytest
from ai_qa_automation.intelligence.contract_drift import ContractDriftSeverity, OpenAPIContractDriftAnalyzer


def analyze(baseline, current):
    return OpenAPIContractDriftAnalyzer().analyze(
        path="openapi.json",
        baseline=json.dumps(baseline, separators=(",", ":"), sort_keys=True).encode(),
        current=json.dumps(current, separators=(",", ":"), sort_keys=True).encode(),
    )


def openapi_operation(parameters, *, path="/items"):
    return {
        "openapi": "3.1.0",
        "paths": {path: {"get": {"parameters": parameters, "responses": {"200": {"description": "ok"}}}}},
    }


def swagger_operation(parameters, *, path="/items"):
    return {
        "swagger": "2.0",
        "paths": {path: {"get": {"parameters": parameters, "responses": {"200": {"description": "ok"}}}}},
    }


@pytest.mark.parametrize(
    ("baseline", "current"),
    [
        ({"swagger": "2.0", "paths": {}}, {"swagger": "2.0", "openapi": 3, "paths": {}}),
        ({"openapi": "3.1.0", "paths": {}}, {"openapi": "3.1.0", "swagger": 2, "paths": {}}),
    ],
)
def test_mixed_dialect_marker_presence_fails_closed(baseline, current):
    result = analyze(baseline, current)
    assert result.severity is ContractDriftSeverity.NOT_ANALYZED
    assert result.analyzed is False
    assert result.reason and "mix" in result.reason.casefold()


@pytest.mark.parametrize(
    "parameter",
    [
        {"name": "payload", "in": "body", "required": False, "schema": {"type": "string"}},
        {"name": "q", "in": "query", "required": False},
        {"name": "q", "in": "query", "required": False, "schema": {"type": "string"}, "content": {"text/plain": {}}},
        {"name": "q", "in": "query", "required": False, "content": {"text/plain": {}, "application/json": {}}},
        {"name": "q", "in": "query", "required": False, "type": "string", "schema": {"type": "string"}},
    ],
)
def test_malformed_openapi_parameter_shapes_fail_closed(parameter):
    result = analyze(openapi_operation([]), openapi_operation([parameter]))
    assert result.severity is ContractDriftSeverity.NOT_ANALYZED
    assert result.analyzed is False


@pytest.mark.parametrize(
    ("path", "parameters"),
    [
        ("/items/{id}", []),
        ("/items/{id}", [{"name": "other", "in": "path", "required": True, "schema": {"type": "string"}}]),
        ("/items/{id", [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}]),
        ("/items?id={id}", [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}]),
    ],
)
def test_openapi_path_template_authority_fails_closed(path, parameters):
    result = analyze({"openapi": "3.1.0", "paths": {}}, openapi_operation(parameters, path=path))
    assert result.severity is ContractDriftSeverity.NOT_ANALYZED
    assert result.analyzed is False


def test_valid_required_openapi_path_parameter_remains_analyzable():
    parameter = {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}
    doc = openapi_operation([parameter], path="/items/{id}")
    result = analyze(doc, json.loads(json.dumps(doc)))
    assert result.severity is ContractDriftSeverity.NON_BREAKING
    assert result.analyzed is True


def test_valid_optional_openapi_schema_parameter_remains_analyzable():
    parameter = {"name": "q", "in": "query", "required": False, "schema": {"type": "string"}}
    result = analyze(openapi_operation([]), openapi_operation([parameter]))
    assert result.severity is ContractDriftSeverity.NON_BREAKING
    assert result.analyzed is True


def test_valid_optional_openapi_content_parameter_remains_analyzable():
    parameter = {"name": "q", "in": "query", "required": False, "content": {"text/plain": {"schema": {"type": "string"}}}}
    result = analyze(openapi_operation([]), openapi_operation([parameter]))
    assert result.severity is ContractDriftSeverity.NON_BREAKING
    assert result.analyzed is True


@pytest.mark.parametrize(
    "parameter",
    [
        {"name": "q", "in": "cookie", "required": False, "type": "string"},
        {"name": "q", "in": "query", "required": False},
        {"name": "q", "in": "query", "required": False, "schema": {"type": "string"}},
        {"name": "upload", "in": "query", "required": False, "type": "file"},
        {"name": "values", "in": "query", "required": False, "type": "array"},
        {"name": "values", "in": "query", "required": False, "type": "array", "items": {}},
        {"name": "q", "in": "query", "required": False, "type": "string", "items": {"type": "string"}},
        {"name": "body", "in": "body", "required": False},
        {"name": "body", "in": "body", "required": False, "type": "object", "schema": {"type": "object"}},
    ],
)
def test_malformed_swagger_parameter_shapes_fail_closed(parameter):
    result = analyze(swagger_operation([]), swagger_operation([parameter]))
    assert result.severity is ContractDriftSeverity.NOT_ANALYZED
    assert result.analyzed is False


def test_swagger_multiple_body_parameters_fail_closed():
    parameters = [
        {"name": "a", "in": "body", "schema": {"type": "object"}},
        {"name": "b", "in": "body", "schema": {"type": "object"}},
    ]
    result = analyze(swagger_operation([]), swagger_operation(parameters))
    assert result.severity is ContractDriftSeverity.NOT_ANALYZED
    assert result.analyzed is False


def test_swagger_body_and_form_data_cannot_mix():
    parameters = [
        {"name": "body", "in": "body", "schema": {"type": "object"}},
        {"name": "file", "in": "formData", "type": "file"},
    ]
    result = analyze(swagger_operation([]), swagger_operation(parameters))
    assert result.severity is ContractDriftSeverity.NOT_ANALYZED
    assert result.analyzed is False


@pytest.mark.parametrize(
    ("path", "parameters"),
    [
        ("/items/{id}", []),
        ("/items/{id}", [{"name": "other", "in": "path", "required": True, "type": "string"}]),
        ("/items/{id", [{"name": "id", "in": "path", "required": True, "type": "string"}]),
    ],
)
def test_swagger_path_template_authority_fails_closed(path, parameters):
    result = analyze({"swagger": "2.0", "paths": {}}, swagger_operation(parameters, path=path))
    assert result.severity is ContractDriftSeverity.NOT_ANALYZED
    assert result.analyzed is False


def test_valid_required_swagger_path_parameter_remains_analyzable():
    parameter = {"name": "id", "in": "path", "required": True, "type": "string"}
    doc = swagger_operation([parameter], path="/items/{id}")
    result = analyze(doc, json.loads(json.dumps(doc)))
    assert result.severity is ContractDriftSeverity.NON_BREAKING
    assert result.analyzed is True


def test_valid_optional_swagger_parameter_remains_analyzable():
    parameter = {"name": "q", "in": "query", "required": False, "type": "string"}
    result = analyze(swagger_operation([]), swagger_operation([parameter]))
    assert result.severity is ContractDriftSeverity.NON_BREAKING
    assert result.analyzed is True


def test_valid_swagger_array_parameter_remains_analyzable():
    parameter = {"name": "q", "in": "query", "required": False, "type": "array", "items": {"type": "string"}}
    result = analyze(swagger_operation([]), swagger_operation([parameter]))
    assert result.severity is ContractDriftSeverity.NON_BREAKING
    assert result.analyzed is True
