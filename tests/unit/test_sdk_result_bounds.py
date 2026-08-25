from __future__ import annotations

from types import SimpleNamespace

import pytest

from ai_qa_automation.runtime.sdk_result_bounds import (
    MAX_SDK_RESULT_UTF8_BYTES,
    MAX_SDK_SUBTYPE_UTF8_BYTES,
    MAX_SDK_TOKEN_COUNT,
    MAX_SDK_USAGE_KEYS,
    SDKResultBoundsError,
    validate_sdk_result_message,
)


def _message(**overrides: object) -> SimpleNamespace:
    values: dict[str, object] = {
        "result": "Model advisory summary.",
        "subtype": "success",
        "total_cost_usd": 0.25,
        "usage": {"input_tokens": 10, "output_tokens": 5},
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_sdk_result_boundary_accepts_expected_terminal_shape() -> None:
    bounded = validate_sdk_result_message(_message(), max_cost_usd=0.5)

    assert bounded.result == "Model advisory summary."
    assert bounded.subtype == "success"
    assert bounded.total_cost_usd == 0.25
    assert bounded.token_usage == 15
    assert bounded.budget_exceeded is False


def test_sdk_result_boundary_accepts_documented_optional_fields() -> None:
    bounded = validate_sdk_result_message(
        _message(result=None, total_cost_usd=None, usage=None),
        max_cost_usd=0.5,
    )

    assert bounded.result == ""
    assert bounded.total_cost_usd == 0.0
    assert bounded.token_usage == 0


def test_sdk_result_boundary_measures_result_in_utf8_bytes() -> None:
    exact = "é" * (MAX_SDK_RESULT_UTF8_BYTES // 2)
    assert validate_sdk_result_message(_message(result=exact), max_cost_usd=0.5).result == exact

    with pytest.raises(SDKResultBoundsError) as caught:
        validate_sdk_result_message(_message(result=exact + "a"), max_cost_usd=0.5)

    assert caught.value.code == "result_bytes"


def test_sdk_result_boundary_rejects_invalid_unicode_before_retention() -> None:
    with pytest.raises(SDKResultBoundsError) as caught:
        validate_sdk_result_message(_message(result="\ud800"), max_cost_usd=0.5)

    assert caught.value.code == "result_unicode"


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"result": 123}, "result_type"),
        ({"subtype": None}, "subtype_type"),
        ({"subtype": "x" * (MAX_SDK_SUBTYPE_UTF8_BYTES + 1)}, "subtype_bytes"),
        ({"total_cost_usd": float("nan")}, "cost_non_finite"),
        ({"total_cost_usd": float("inf")}, "cost_non_finite"),
        ({"total_cost_usd": -0.01}, "cost_negative"),
        ({"total_cost_usd": True}, "cost_type"),
        ({"total_cost_usd": "0.01"}, "cost_type"),
        ({"usage": []}, "usage_type"),
        ({"usage": {str(index): 0 for index in range(MAX_SDK_USAGE_KEYS + 1)}}, "usage_keys"),
        ({"usage": {"input_tokens": True, "output_tokens": 0}}, "usage_token_type"),
        ({"usage": {"input_tokens": "1", "output_tokens": 0}}, "usage_token_type"),
        ({"usage": {"input_tokens": -1, "output_tokens": 0}}, "usage_token_negative"),
        (
            {"usage": {"input_tokens": MAX_SDK_TOKEN_COUNT + 1, "output_tokens": 0}},
            "usage_token_bound",
        ),
        (
            {
                "usage": {
                    "input_tokens": MAX_SDK_TOKEN_COUNT,
                    "output_tokens": 1,
                }
            },
            "usage_total_bound",
        ),
    ],
)
def test_sdk_result_boundary_rejects_malformed_provider_fields(
    overrides: dict[str, object],
    code: str,
) -> None:
    with pytest.raises(SDKResultBoundsError) as caught:
        validate_sdk_result_message(_message(**overrides), max_cost_usd=0.5)

    assert caught.value.code == code


def test_sdk_result_boundary_reports_runtime_budget_overrun_without_coercion() -> None:
    bounded = validate_sdk_result_message(
        _message(total_cost_usd=0.5001),
        max_cost_usd=0.5,
    )

    assert bounded.total_cost_usd == 0.5001
    assert bounded.budget_exceeded is True
