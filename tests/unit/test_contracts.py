from __future__ import annotations

import json
import signal
import threading
import time
from pathlib import Path

import pytest

from ai_qa_automation.models import ValidationStatus
from ai_qa_automation.tools import contracts
from ai_qa_automation.tools.contracts import validate_json_schema


def test_schema_validation_never_uses_model_opinion() -> None:
    schema = {
        "type": "object",
        "required": ["id"],
        "properties": {"id": {"type": "integer"}},
    }
    assert validate_json_schema({"id": 12}, schema).status is ValidationStatus.PASS


def test_invalid_schema_is_not_mislabeled_as_payload_failure() -> None:
    result = validate_json_schema({"id": 12}, {"type": "definitely-not-a-json-schema-type"})
    assert result.status is ValidationStatus.NOT_VERIFIED
    assert "schema itself is invalid" in result.summary.lower()


def test_valid_schema_mismatch_is_a_real_failure() -> None:
    result = validate_json_schema(
        {"id": "wrong"},
        {"type": "object", "properties": {"id": {"type": "integer"}}},
    )
    assert result.status is ValidationStatus.FAIL


def test_boolean_schemas_remain_valid_json_schema() -> None:
    assert validate_json_schema(12, True).status is ValidationStatus.PASS
    assert validate_json_schema(12, False).status is ValidationStatus.FAIL


def test_unknown_explicit_schema_dialect_is_not_reinterpreted() -> None:
    result = validate_json_schema(
        12,
        {"$schema": "https://unknown.example/schema", "type": "integer"},
    )
    assert result.status is ValidationStatus.NOT_VERIFIED
    assert "dialect" in result.summary.lower()


def test_malformed_schema_dialect_identifier_is_not_verified() -> None:
    result = validate_json_schema(12, {"$schema": 202012, "type": "integer"})
    assert result.status is ValidationStatus.NOT_VERIFIED
    assert "dialect" in result.summary.lower()


def test_supported_legacy_draft_remains_explicitly_supported() -> None:
    result = validate_json_schema(
        12,
        {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "definitions": {"integer": {"type": "integer"}},
            "$ref": "#/definitions/integer",
        },
    )
    assert result.status is ValidationStatus.PASS


def test_unmarked_schema_uses_project_owned_draft_2020_12_default() -> None:
    schema = {"prefixItems": [{"const": 1}], "items": False}
    assert validate_json_schema([1], schema).status is ValidationStatus.PASS
    assert validate_json_schema([1, 2], schema).status is ValidationStatus.FAIL


def test_unknown_embedded_resource_dialect_is_not_reinterpreted() -> None:
    result = validate_json_schema(
        12,
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$defs": {
                "integer": {
                    "$id": "urn:aiqa:integer",
                    "$schema": "https://unknown.example/schema",
                    "type": "integer",
                }
            },
            "$ref": "urn:aiqa:integer",
        },
    )
    assert result.status is ValidationStatus.NOT_VERIFIED
    assert "dialect" in result.summary.lower()


def test_cross_dialect_embedded_resource_is_not_reinterpreted() -> None:
    result = validate_json_schema(
        12,
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$defs": {
                "integer": {
                    "$id": "urn:aiqa:integer",
                    "$schema": "http://json-schema.org/draft-07/schema#",
                    "type": "integer",
                }
            },
            "$ref": "urn:aiqa:integer",
        },
    )
    assert result.status is ValidationStatus.NOT_VERIFIED
    assert "dialect" in result.summary.lower()


def test_same_dialect_embedded_resource_remains_deterministic() -> None:
    result = validate_json_schema(
        12,
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$defs": {
                "integer": {
                    "$id": "urn:aiqa:integer",
                    "$schema": "https://json-schema.org/draft/2020-12/schema",
                    "type": "integer",
                }
            },
            "$ref": "urn:aiqa:integer",
        },
    )
    assert result.status is ValidationStatus.PASS


def test_same_document_reference_remains_deterministic() -> None:
    result = validate_json_schema(
        12,
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$defs": {"integer": {"type": "integer"}},
            "$ref": "#/$defs/integer",
        },
    )
    assert result.status is ValidationStatus.PASS


def test_embedded_resource_reference_remains_deterministic() -> None:
    result = validate_json_schema(
        12,
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$defs": {"integer": {"$id": "urn:aiqa:integer", "type": "integer"}},
            "$ref": "urn:aiqa:integer",
        },
    )
    assert result.status is ValidationStatus.PASS


def test_duplicate_resource_identifiers_fail_closed() -> None:
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$defs": {
            "first": {"$id": "urn:aiqa:duplicate", "const": 1},
            "second": {"$id": "urn:aiqa:duplicate", "const": 2},
        },
        "$ref": "urn:aiqa:duplicate",
    }
    assert validate_json_schema(1, schema).status is ValidationStatus.NOT_VERIFIED
    assert validate_json_schema(2, schema).status is ValidationStatus.NOT_VERIFIED


def test_duplicate_legacy_resource_identifiers_fail_closed() -> None:
    schema = {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "definitions": {
            "first": {"id": "urn:aiqa:duplicate", "enum": [1]},
            "second": {"id": "urn:aiqa:duplicate", "enum": [2]},
        },
        "$ref": "urn:aiqa:duplicate",
    }
    assert validate_json_schema(1, schema).status is ValidationStatus.NOT_VERIFIED
    assert validate_json_schema(2, schema).status is ValidationStatus.NOT_VERIFIED


def test_duplicate_plain_anchors_fail_closed() -> None:
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$defs": {
            "first": {"$anchor": "duplicate", "const": 1},
            "second": {"$anchor": "duplicate", "const": 2},
        },
        "$ref": "#duplicate",
    }
    assert validate_json_schema(1, schema).status is ValidationStatus.NOT_VERIFIED
    assert validate_json_schema(2, schema).status is ValidationStatus.NOT_VERIFIED


def test_plain_and_dynamic_anchor_collision_fails_closed() -> None:
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$defs": {
            "first": {"$anchor": "duplicate", "const": 1},
            "second": {"$dynamicAnchor": "duplicate", "const": 2},
        },
        "$ref": "#duplicate",
    }
    assert validate_json_schema(1, schema).status is ValidationStatus.NOT_VERIFIED
    assert validate_json_schema(2, schema).status is ValidationStatus.NOT_VERIFIED


def test_same_anchor_name_in_distinct_resources_remains_valid() -> None:
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://example.invalid/root",
        "$defs": {
            "first": {
                "$id": "first",
                "$anchor": "shared",
                "const": 1,
            },
            "second": {
                "$id": "second",
                "$anchor": "shared",
                "const": 2,
            },
        },
        "$ref": "first#shared",
    }
    assert validate_json_schema(1, schema).status is ValidationStatus.PASS
    assert validate_json_schema(2, schema).status is ValidationStatus.FAIL


def test_schema_shaped_literal_data_does_not_trigger_schema_policy() -> None:
    literal = {
        "$schema": "https://unknown.example/literal",
        "$ref": "https://example.invalid/not-a-schema-reference",
    }
    result = validate_json_schema(
        literal,
        {"$schema": "https://json-schema.org/draft/2020-12/schema", "const": literal},
    )
    assert result.status is ValidationStatus.PASS


def test_file_reference_cannot_read_local_schema_resource(tmp_path: Path) -> None:
    external = tmp_path / "external-schema.json"
    external.write_text(json.dumps({"const": "outside-resource"}), encoding="utf-8")
    result = validate_json_schema(
        "outside-resource",
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": external.as_uri(),
        },
    )
    assert result.status is ValidationStatus.BLOCKED
    assert result.details == {"reference_scheme": "file"}


def test_remote_reference_is_blocked_without_persisting_untrusted_uri() -> None:
    untrusted_marker = "opaque-query-marker"
    result = validate_json_schema(
        12,
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": f"https://example.invalid/schema.json?opaque={untrusted_marker}",
        },
    )
    assert result.status is ValidationStatus.BLOCKED
    assert result.details == {"reference_scheme": "https"}
    assert untrusted_marker not in result.model_dump_json()


def test_unknown_reference_scheme_is_minimized() -> None:
    untrusted_scheme = "opaque-scheme-marker"
    result = validate_json_schema(
        12,
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": f"{untrusted_scheme}:payload",
        },
    )
    assert result.status is ValidationStatus.BLOCKED
    assert result.details == {"reference_scheme": "other"}
    assert untrusted_scheme not in result.model_dump_json()


def test_relative_external_reference_is_blocked() -> None:
    result = validate_json_schema(
        12,
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": "other-schema.json",
        },
    )
    assert result.status is ValidationStatus.BLOCKED
    assert result.details == {"reference_scheme": "relative"}


def test_external_dynamic_reference_is_blocked() -> None:
    result = validate_json_schema(
        12,
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$dynamicRef": "https://example.invalid/dynamic-schema.json",
        },
    )
    assert result.status is ValidationStatus.BLOCKED
    assert result.details == {"reference_scheme": "https"}


def test_unresolved_same_document_reference_is_not_verified() -> None:
    result = validate_json_schema(
        12,
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": "#/$defs/missing",
        },
    )
    assert result.status is ValidationStatus.NOT_VERIFIED
    assert "cannot be resolved" in result.summary


def test_failure_diagnostics_do_not_echo_untrusted_property_names() -> None:
    untrusted_name = "opaque-property-marker"
    mismatch = validate_json_schema(
        {untrusted_name: "wrong"},
        {"type": "object", "properties": {untrusted_name: {"type": "integer"}}},
    )
    invalid = validate_json_schema(
        12,
        {
            "$defs": {untrusted_name: {"type": "not-a-real-type"}},
            "$ref": f"#/$defs/{untrusted_name}",
        },
    )
    assert mismatch.status is ValidationStatus.FAIL
    assert invalid.status is ValidationStatus.NOT_VERIFIED
    assert untrusted_name not in mismatch.model_dump_json()
    assert untrusted_name not in invalid.model_dump_json()


def test_parent_interval_timer_is_not_claimed() -> None:
    if not all(hasattr(signal, name) for name in ("setitimer", "getitimer", "ITIMER_REAL")):
        return
    before = signal.getitimer(signal.ITIMER_REAL)
    if before[0] > 0 or before[1] > 0:
        result = validate_json_schema(12, {"type": "integer"})
        after = signal.getitimer(signal.ITIMER_REAL)
        assert result.status is ValidationStatus.PASS
        assert after[0] > 0
        assert after[1] == before[1]
        return
    signal.setitimer(signal.ITIMER_REAL, 10.0)
    try:
        result = validate_json_schema(12, {"type": "integer"})
        remaining, interval = signal.getitimer(signal.ITIMER_REAL)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
    assert result.status is ValidationStatus.PASS
    assert remaining > 5.0
    assert interval == 0


def test_parent_alarm_handler_is_not_replaced() -> None:
    if not hasattr(signal, "SIGALRM"):
        return
    previous_handler = signal.getsignal(signal.SIGALRM)

    def custom_handler(_signum: int, _frame: object) -> None:
        return None

    installed_handler = previous_handler
    if previous_handler == signal.SIG_DFL:
        signal.signal(signal.SIGALRM, custom_handler)
        installed_handler = custom_handler
    try:
        result = validate_json_schema(12, {"type": "integer"})
        observed_handler = signal.getsignal(signal.SIGALRM)
    finally:
        if previous_handler == signal.SIG_DFL:
            signal.signal(signal.SIGALRM, previous_handler)
    assert result.status is ValidationStatus.PASS
    assert observed_handler is installed_handler


def test_validation_can_run_from_a_background_thread() -> None:
    observed: list[ValidationStatus] = []

    def validate() -> None:
        observed.append(validate_json_schema(12, {"type": "integer"}).status)

    thread = threading.Thread(target=validate)
    thread.start()
    thread.join(timeout=10)
    assert not thread.is_alive()
    assert observed == [ValidationStatus.PASS]


def test_pathological_pattern_cannot_run_unbounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(contracts, "_JSON_SCHEMA_VALIDATION_TIMEOUT_SECONDS", 0.05)
    started = time.monotonic()
    result = validate_json_schema(
        "a" * 30 + "!",
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "string",
            "pattern": "(a+)+$",
        },
    )
    assert time.monotonic() - started < 3.0
    assert result.status is ValidationStatus.NOT_VERIFIED
    assert result.details == {"timeout_seconds": 0.05}


def test_combinatorial_schema_cannot_run_unbounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(contracts, "_JSON_SCHEMA_VALIDATION_TIMEOUT_SECONDS", 0.05)
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "anyOf": [{"const": value} for value in range(5_000)],
    }
    started = time.monotonic()
    result = validate_json_schema(-1, schema)
    assert time.monotonic() - started < 3.0
    assert result.status is ValidationStatus.NOT_VERIFIED
    assert result.details == {"timeout_seconds": 0.05}


@pytest.mark.parametrize(
    ("invalid_key", "encoded_key"),
    [(1, "1"), (True, "true"), (None, "null"), (1.5, "1.5")],
)
def test_non_string_mapping_keys_are_not_reinterpreted(
    invalid_key: object, encoded_key: str
) -> None:
    result = validate_json_schema(
        {invalid_key: "value"},
        {
            "type": "object",
            "required": [encoded_key],
            "properties": {encoded_key: {"const": "value"}},
            "additionalProperties": False,
        },
    )
    assert result.status is ValidationStatus.NOT_VERIFIED


def test_python_tuple_is_not_reinterpreted_as_json_array() -> None:
    result = validate_json_schema((1, 2), {"type": "array", "items": {"type": "integer"}})
    assert result.status is ValidationStatus.NOT_VERIFIED


def test_worker_payload_replacement_cannot_change_validated_subject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_worker = contracts.run_bounded_subprocess

    def replace_payload(command: list[str], **kwargs: object):
        payload_path = Path(command[5])
        payload_path.write_text(
            json.dumps({"instance": 12, "schema": {"const": 12}}),
            encoding="utf-8",
        )
        return run_worker(command, **kwargs)

    monkeypatch.setattr(contracts, "run_bounded_subprocess", replace_payload)
    result = validate_json_schema("wrong", {"const": "wrong"})

    assert result.status is ValidationStatus.BLOCKED
    assert "serialized subject" in result.summary.lower()


def test_direct_worker_input_enforces_integer_magnitude_bound() -> None:
    result = validate_json_schema(1 << 4096, {"type": "integer"})
    assert result.status is ValidationStatus.NOT_VERIFIED


def test_direct_worker_input_enforces_nesting_depth_bound() -> None:
    at_limit: object = 0
    for _ in range(64):
        at_limit = [at_limit]
    beyond_limit = [at_limit]

    assert validate_json_schema(at_limit, {}).status is ValidationStatus.PASS
    assert validate_json_schema(beyond_limit, {}).status is ValidationStatus.NOT_VERIFIED


def test_direct_worker_input_enforces_container_item_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(contracts, "_MAX_JSON_SCHEMA_WORKER_CONTAINER_ITEMS", 2)
    result = validate_json_schema([1, 2, 3], {"type": "array"})
    assert result.status is ValidationStatus.NOT_VERIFIED


def test_direct_worker_input_enforces_structural_node_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(contracts, "_MAX_JSON_SCHEMA_WORKER_NODES", 2)
    result = validate_json_schema([1, 2], {})
    assert result.status is ValidationStatus.NOT_VERIFIED


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_direct_worker_input_rejects_non_finite_numbers(value: float) -> None:
    result = validate_json_schema(value, {"type": "number"})
    assert result.status is ValidationStatus.NOT_VERIFIED


def test_direct_worker_input_enforces_utf8_bound_before_encoding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(contracts, "_MAX_JSON_SCHEMA_WORKER_INPUT_BYTES", 8)

    def unexpected_encode(*_args: object, **_kwargs: object) -> object:
        pytest.fail("worker encoder ran before the UTF-8 preflight bound")

    monkeypatch.setattr(json.JSONEncoder, "iterencode", unexpected_encode)
    result = validate_json_schema(["12345", "6789"], {})
    assert result.status is ValidationStatus.NOT_VERIFIED


def test_shared_container_graph_is_rejected_before_encoding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shared = [1, 2, 3]

    def unexpected_encode(*_args: object, **_kwargs: object) -> object:
        pytest.fail("worker encoder ran for a shared container graph")

    monkeypatch.setattr(json.JSONEncoder, "iterencode", unexpected_encode)
    result = validate_json_schema([shared, shared], {"type": "array"})
    assert result.status is ValidationStatus.NOT_VERIFIED


def test_worker_payload_serialization_is_bounded() -> None:
    result = validate_json_schema("x" * 2_200_000, {"type": "string"})
    assert result.status is ValidationStatus.NOT_VERIFIED
    assert "bounded json worker contract" in result.summary.lower()


def test_cyclic_direct_input_is_not_promoted_to_validation() -> None:
    cyclic: dict[str, object] = {}
    cyclic["self"] = cyclic
    result = validate_json_schema(cyclic, {"type": "object"})
    assert result.status is ValidationStatus.NOT_VERIFIED


def test_dependency_unavailability_is_not_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(contracts, "_isolated_dependency_roots", lambda: None)
    result = validate_json_schema(12, {"type": "integer"})
    assert result.status is ValidationStatus.NOT_VERIFIED


def test_worker_stderr_prevents_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    class Result:
        timed_out = False
        returncode = 0
        stdout = '{"kind":"pass"}'
        stderr = "unexpected worker diagnostic"
        stdout_truncated = False
        stderr_truncated = False

    monkeypatch.setattr(contracts, "run_bounded_subprocess", lambda *_args, **_kwargs: Result())
    result = validate_json_schema(12, {"type": "integer"})
    assert result.status is ValidationStatus.NOT_VERIFIED


def test_worker_spawn_failure_is_blocked_without_leaking_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise OSError("/secret/runtime/path")

    monkeypatch.setattr(contracts, "run_bounded_subprocess", fail)
    result = validate_json_schema(12, {"type": "integer"})
    assert result.status is ValidationStatus.BLOCKED
    assert "/secret/runtime/path" not in result.model_dump_json()


def test_worker_workspace_failure_is_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise OSError("workspace unavailable")

    monkeypatch.setattr(contracts, "TemporaryDirectory", fail)
    result = validate_json_schema(12, {"type": "integer"})
    assert result.status is ValidationStatus.BLOCKED
