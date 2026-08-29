from __future__ import annotations

import pytest

from ai_qa_automation.runtime.internal_tools import _stable_gate_id
from ai_qa_automation.runtime.k6_authority import k6_gate_payload, k6_persisted_subject


def request() -> dict[str, object]:
    return {
        "script": "performance/load.js",
        "target_url": "http://127.0.0.1:8000",
        "environment": "local",
        "max_p95_ms": 500,
        "max_error_rate": 0.01,
        "min_request_rate": 1,
    }


def test_k6_subject_normalizes_exact_six_field_contract() -> None:
    assert k6_gate_payload(request()) == {
        "script": "performance/load.js",
        "target_url": "http://127.0.0.1:8000",
        "environment": "local",
        "max_p95_ms": 500.0,
        "max_error_rate": 0.01,
        "min_request_rate": 1.0,
    }


def test_k6_threshold_change_changes_gate_identity() -> None:
    first = k6_gate_payload(request())
    changed = request()
    changed["max_p95_ms"] = 750

    assert _stable_gate_id("k6", first) != _stable_gate_id("k6", k6_gate_payload(changed))


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("max_p95_ms", -1),
        ("max_error_rate", 1.01),
        ("min_request_rate", -1),
        ("max_p95_ms", True),
        ("max_p95_ms", float("inf")),
        ("max_p95_ms", 10**1000),
    ],
)
def test_invalid_k6_thresholds_fail_before_subject_authority(
    name: str,
    value: object,
) -> None:
    payload = request()
    payload[name] = value

    with pytest.raises(ValueError):
        k6_gate_payload(payload)


def test_k6_persisted_subject_minimizes_untrusted_identity_fields() -> None:
    payload = request()
    principal = "identity-marker"
    verifier = "opaque-auth-marker"
    query_marker = "opaque-query-marker"
    environment_marker = "opaque-environment-marker"
    script_marker = "private-script-marker"
    payload["script"] = f"performance/{script_marker}/load.js"
    payload["target_url"] = (
        "http://"
        + principal
        + ":"
        + verifier
        + "@127.0.0.1:8000/private/path?opaque="
        + query_marker
    )
    payload["environment"] = environment_marker
    raw = k6_gate_payload(payload)
    persisted = k6_persisted_subject(raw)

    assert raw["target_url"] != persisted["target_url"]
    assert set(persisted) == {
        "target_url",
        "max_p95_ms",
        "max_error_rate",
        "min_request_rate",
    }
    rendered = str(persisted)
    assert script_marker not in rendered
    assert verifier not in rendered
    assert query_marker not in rendered
    assert environment_marker not in rendered
    assert "/private/path" not in rendered
    assert "127.0.0.1:8000" in rendered
    assert _stable_gate_id("k6", raw) != _stable_gate_id("k6", persisted)


def test_k6_subject_rejects_empty_text_identity() -> None:
    payload = request()
    payload["environment"] = ""

    with pytest.raises(ValueError, match="environment"):
        k6_gate_payload(payload)
