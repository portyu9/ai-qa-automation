from __future__ import annotations

from pathlib import Path

import json
import pytest

from ai_qa_automation.cli import contract_diff_command
from ai_qa_automation.intelligence import contract_document
from ai_qa_automation.intelligence.contract_document import (
    MAX_CONTRACT_DOCUMENT_BYTES,
    load_contract_document,
)
from ai_qa_automation.intelligence.contract_drift import (
    ContractDriftSeverity,
    OpenAPIContractDriftAnalyzer,
)


def _baseline_yaml() -> bytes:
    return b"""openapi: 3.1.0
info: {title: test, version: '1'}
paths:
  /orders:
    get:
      responses:
        '200': {description: ok}
"""


def _nested_schema(depth: int) -> dict[str, object]:
    schema: dict[str, object] = {"type": "string"}
    for _ in range(depth):
        schema = {"type": "array", "items": schema}
    return schema


def _assert_not_analyzed(current: bytes, *, path: str = "openapi.yaml") -> str:
    result = OpenAPIContractDriftAnalyzer().analyze(
        path=path,
        baseline=_baseline_yaml() if path.endswith((".yaml", ".yml")) else b'{"openapi":"3.1.0","paths":{}}',
        current=current,
    )
    assert result.analyzed is False
    assert result.severity is ContractDriftSeverity.NOT_ANALYZED
    assert result.reason is not None
    return result.reason


def test_valid_yaml_contract_remains_analyzable() -> None:
    current = b"""openapi: 3.1.0
info: {title: test, version: '1'}
paths: {}
"""

    result = OpenAPIContractDriftAnalyzer().analyze(
        path="openapi.yaml",
        baseline=_baseline_yaml(),
        current=current,
    )

    assert result.analyzed is True
    assert result.severity is ContractDriftSeverity.BREAKING
    assert any(change.rule_id == "OAS-PATH-REMOVED" for change in result.changes)


def test_duplicate_json_keys_are_not_reinterpreted() -> None:
    reason = _assert_not_analyzed(
        b'{"openapi":"3.1.0","paths":{},"paths":{"/hidden":{}}}',
        path="openapi.json",
    )

    assert "duplicate object key" in reason


def test_duplicate_yaml_keys_are_not_reinterpreted() -> None:
    reason = _assert_not_analyzed(
        b"openapi: 3.1.0\npaths: {}\npaths: {'/hidden': {}}\n"
    )

    assert "duplicate mapping key" in reason


def test_yaml_merge_keys_are_not_flattened_before_bounds() -> None:
    reason = _assert_not_analyzed(
        b"base: &base {'/orders': {}}\nopenapi: 3.1.0\npaths:\n  <<: *base\n"
    )

    assert "merge keys" in reason


def test_yaml_shared_container_aliases_are_not_promoted_to_json_tree() -> None:
    reason = _assert_not_analyzed(
        b"openapi: 3.1.0\ncommon: &shared {description: ok}\npaths:\n  /a: *shared\n  /b: *shared\n"
    )

    assert "shared or circular container graph" in reason


def test_yaml_explicit_non_json_scalar_is_not_analyzed() -> None:
    reason = _assert_not_analyzed(
        b"openapi: 3.1.0\ninfo: {title: test, version: !!timestamp 2026-08-28}\npaths: {}\n"
    )

    assert "non-JSON value type" in reason


def test_yaml_non_string_mapping_key_is_not_analyzed() -> None:
    reason = _assert_not_analyzed(
        b"openapi: 3.1.0\npaths:\n  1: {}\n"
    )

    assert "mapping keys must be strings" in reason


def test_yaml_12_plain_on_key_remains_a_string() -> None:
    document = load_contract_document(
        "openapi.yaml",
        b"""openapi: 3.1.0
components:
  schemas:
    Switch:
      type: object
      properties:
        on: {type: string}
      required: [on]
paths: {}
""",
    )

    schema = document["components"]["schemas"]["Switch"]
    assert "on" in schema["properties"]
    assert schema["required"] == ["on"]


def test_json_nesting_limit_is_enforced_before_parser_recursion() -> None:
    deep = '{"openapi":"3.1.0","nested":' + "[" * 65 + "0" + "]" * 65 + "}"

    reason = _assert_not_analyzed(deep.encode(), path="openapi.json")

    assert "nesting-depth limit" in reason


def test_malformed_yaml_is_not_analyzed_instead_of_escaping() -> None:
    reason = _assert_not_analyzed(b"openapi: [\n")

    assert "invalid contract YAML" in reason


def test_nonstandard_json_numbers_are_not_analyzed() -> None:
    reason = _assert_not_analyzed(
        b'{"openapi":"3.1.0","x":NaN,"paths":{}}',
        path="openapi.json",
    )

    assert "non-standard numeric constant" in reason


def test_yaml_alias_limit_is_enforced_during_token_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(contract_document, "_MAX_YAML_ALIASES", 1)
    current = b"""openapi: 3.1.0
shared: &value {description: ok}
paths:
  /a: *value
  /b: *value
"""

    reason = _assert_not_analyzed(current)

    assert "alias limit" in reason


def test_structural_node_limit_is_enforced_after_parse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(contract_document, "_MAX_CONTRACT_NODES", 8)

    reason = _assert_not_analyzed(
        b"openapi: 3.1.0\npaths: {'/a': {}, '/b': {}, '/c': {}, '/d': {}}\n"
    )

    assert "structural-node limit" in reason


def test_standalone_contract_diff_rejects_oversized_document(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline.json"
    current = tmp_path / "current.json"
    baseline.write_bytes(b"x" * (MAX_CONTRACT_DOCUMENT_BYTES + 1))
    current.write_text('{"openapi":"3.1.0","paths":{}}', encoding="utf-8")

    with pytest.raises(ValueError, match="ingestion limit"):
        contract_diff_command(baseline, current)


def test_duplicate_key_diagnostic_does_not_echo_untrusted_key() -> None:
    secret_key = "token-super-secret-value"
    result = OpenAPIContractDriftAnalyzer().analyze(
        path="openapi.json",
        baseline=b'{"openapi":"3.1.0","paths":{}}',
        current=(
            '{"openapi":"3.1.0","paths":{},"'
            + secret_key
            + '":1,"'
            + secret_key
            + '":2}'
        ).encode(),
    )

    assert result.severity is ContractDriftSeverity.NOT_ANALYZED
    assert result.reason is not None
    assert secret_key not in result.reason


def test_invalid_explicit_numeric_diagnostic_does_not_echo_scalar() -> None:
    secret_value = "super-secret-numeric-value"
    reason = _assert_not_analyzed(
        f"openapi: 3.1.0\nx: !!float {secret_value}\npaths: {{}}\n".encode()
    )

    assert secret_value not in reason
    assert "invalid explicit number" in reason


def test_schema_comparison_depth_limit_cannot_be_non_breaking() -> None:
    document = {
        "openapi": "3.1.0",
        "paths": {},
        "components": {"schemas": {"Deep": _nested_schema(14)}},
    }
    payload = json.dumps(document).encode()

    result = OpenAPIContractDriftAnalyzer().analyze(
        path="openapi.json",
        baseline=payload,
        current=payload,
    )

    assert result.severity is ContractDriftSeverity.NOT_ANALYZED
    assert result.analyzed is False
    assert result.reason == "contract comparison exceeded a deterministic analysis bound"
    assert any(change.rule_id == "OAS-SCHEMA-DEPTH-LIMIT" for change in result.changes)


def test_known_breaking_fact_is_retained_when_other_comparison_is_incomplete() -> None:
    deep = _nested_schema(14)
    baseline = {
        "openapi": "3.1.0",
        "paths": {"/removed": {"get": {"responses": {"200": {"description": "ok"}}}}},
        "components": {"schemas": {"Deep": deep}},
    }
    current = {
        "openapi": "3.1.0",
        "paths": {},
        "components": {"schemas": {"Deep": deep}},
    }

    result = OpenAPIContractDriftAnalyzer().analyze(
        path="openapi.json",
        baseline=json.dumps(baseline).encode(),
        current=json.dumps(current).encode(),
    )

    assert result.severity is ContractDriftSeverity.BREAKING
    assert result.analyzed is False
    assert result.reason == "contract comparison exceeded a deterministic analysis bound"
    assert any(change.rule_id == "OAS-PATH-REMOVED" for change in result.changes)
    assert any(change.rule_id == "OAS-SCHEMA-DEPTH-LIMIT" for change in result.changes)
