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


def test_required_property_removal_is_risky() -> None:
    baseline = _schema_document(
        {
            "type": "object",
            "properties": {"tenant": {"type": "string"}},
            "required": ["tenant"],
        }
    )
    current = _schema_document(
        {
            "type": "object",
            "properties": {"tenant": {"type": "string"}},
            "required": [],
        }
    )

    result = _analyze(baseline, current)

    assert result.severity is ContractDriftSeverity.RISKY
    assert result.analyzed is True
    assert any(change.rule_id == "OAS-REQUIRED-PROPERTY-REMOVED" for change in result.changes)


def test_optional_schema_property_addition_is_risky() -> None:
    result = _analyze(
        _schema_document({"type": "object", "properties": {}}),
        _schema_document(
            {
                "type": "object",
                "properties": {"trace_id": {"type": "string"}},
            }
        ),
    )

    assert result.severity is ContractDriftSeverity.RISKY
    assert result.analyzed is True
    assert any(change.rule_id == "OAS-PROPERTY-ADDED" for change in result.changes)


def test_added_response_status_is_risky() -> None:
    baseline = {
        "openapi": "3.1.0",
        "paths": {"/orders": {"get": {"responses": {"200": {"description": "ok"}}}}},
    }
    current = json.loads(json.dumps(baseline))
    current["paths"]["/orders"]["get"]["responses"]["404"] = {"description": "not found"}

    result = _analyze(baseline, current)

    assert result.severity is ContractDriftSeverity.RISKY
    assert result.analyzed is True
    assert any(change.rule_id == "OAS-RESPONSE-ADDED" for change in result.changes)


@pytest.mark.parametrize(
    "schema",
    [
        {"enum": []},
        {"enum": [True, True]},
        {"enum": [1, 1.0]},
        {"type": ["string", "string"]},
        {"type": "unsupported"},
    ],
)
def test_ambiguous_or_unsupported_schema_constraints_fail_closed(
    schema: dict[str, object],
) -> None:
    result = _analyze(
        {"openapi": "3.1.0", "paths": {}},
        _schema_document(schema),
    )

    assert result.severity is ContractDriftSeverity.NOT_ANALYZED
    assert result.analyzed is False


def test_openapi_30_type_array_fails_closed() -> None:
    result = _analyze(
        {"openapi": "3.0.3", "paths": {}},
        _schema_document({"type": ["string", "null"]}, version="3.0.3"),
    )

    assert result.severity is ContractDriftSeverity.NOT_ANALYZED
    assert result.analyzed is False


def test_unresolved_local_schema_reference_fails_closed() -> None:
    result = _analyze(
        {"openapi": "3.1.0", "paths": {}},
        _schema_document({"$ref": "#/components/schemas/Missing"}),
    )

    assert result.severity is ContractDriftSeverity.NOT_ANALYZED
    assert result.analyzed is False
    assert result.reason is not None
    assert "resolve" in result.reason


@pytest.mark.parametrize(
    "current",
    [
        {"openapi": "3.1.0", "paths": {}, "definitions": {}},
        {"swagger": "2.0", "paths": {}, "components": {}},
        {
            "swagger": "2.0",
            "paths": {"/orders": {"post": {"requestBody": {}}}},
        },
    ],
)
def test_cross_dialect_consumed_shapes_fail_closed(
    current: dict[str, object],
) -> None:
    baseline = (
        {"swagger": "2.0", "paths": {}}
        if "swagger" in current
        else {"openapi": "3.1.0", "paths": {}}
    )

    result = _analyze(baseline, current)

    assert result.severity is ContractDriftSeverity.NOT_ANALYZED
    assert result.analyzed is False


def test_non_openapi_reason_remains_backward_compatible() -> None:
    result = _analyze({"hello": "world"}, {"hello": "again"})

    assert result.severity is ContractDriftSeverity.NOT_ANALYZED
    assert result.analyzed is False
    assert result.reason == "document is not recognized as OpenAPI/Swagger"


@pytest.mark.parametrize(
    "current",
    [
        {
            "openapi": "3.1.0",
            "paths": {
                "/orders": {
                    "post": {
                        "requestBody": {"$ref": "#/components/requestBodies/Order"},
                        "responses": {"200": {"description": "ok"}},
                    }
                }
            },
            "components": {"requestBodies": {"Order": {"required": True, "content": {}}}},
        },
        {
            "openapi": "3.1.0",
            "paths": {
                "/orders": {
                    "get": {"responses": {"200": {"$ref": "#/components/responses/Order"}}}
                }
            },
            "components": {"responses": {"Order": {"description": "ok"}}},
        },
        {"openapi": "3.1.0", "paths": {"/orders": {"get": {}}}},
        {
            "openapi": "3.1.0",
            "paths": {"/orders": {"get": {"responses": {}}}},
        },
        {
            "openapi": "3.1.0",
            "paths": {"/orders": {"get": {"responses": {"200": {}}}}},
        },
        {
            "swagger": "2.0",
            "paths": {"/orders": {"get": {"responses": {"2XX": {"description": "ok"}}}}},
        },
        {
            "openapi": "3.1.0",
            "paths": {
                "/orders": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {"schema": {"$ref": "https://example.test/order.json"}}
                            }
                        },
                        "responses": {"200": {"description": "ok"}},
                    }
                }
            },
        },
    ],
)
def test_indirect_or_incomplete_consumed_payload_shapes_fail_closed(
    current: dict[str, object],
) -> None:
    baseline = (
        {"swagger": "2.0", "paths": {}}
        if "swagger" in current
        else {"openapi": "3.1.0", "paths": {}}
    )

    result = _analyze(baseline, current)

    assert result.severity is ContractDriftSeverity.NOT_ANALYZED
    assert result.analyzed is False


def test_self_contained_request_and_response_payload_schemas_remain_analyzable() -> None:
    document = {
        "openapi": "3.1.0",
        "paths": {
            "/orders": {
                "post": {
                    "requestBody": {
                        "required": False,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Order"}
                            }
                        },
                    },
                    "responses": {
                        "2XX": {
                            "description": "ok",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/Order"}
                                }
                            },
                        }
                    },
                }
            }
        },
        "components": {"schemas": {"Order": {"type": "object", "properties": {}}}},
    }

    result = _analyze(document, json.loads(json.dumps(document)))

    assert result.severity is ContractDriftSeverity.NON_BREAKING
    assert result.analyzed is True
