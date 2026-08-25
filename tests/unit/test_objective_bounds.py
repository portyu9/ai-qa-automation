from __future__ import annotations

import pytest

from ai_qa_automation.runtime.objective_bounds import (
    MAX_OBJECTIVE_UTF8_BYTES,
    ObjectiveBoundsError,
    validate_objective,
)


def test_objective_boundary_preserves_valid_text_exactly() -> None:
    objective = "  Inspect the target exactly as supplied.  \n"

    assert validate_objective(objective) is objective


def test_objective_boundary_accepts_exact_ascii_byte_limit() -> None:
    objective = "x" * MAX_OBJECTIVE_UTF8_BYTES

    assert validate_objective(objective) == objective


def test_objective_boundary_measures_multibyte_utf8_incrementally() -> None:
    exact = "é" * (MAX_OBJECTIVE_UTF8_BYTES // 2)

    assert validate_objective(exact) == exact

    with pytest.raises(ObjectiveBoundsError) as caught:
        validate_objective(exact + "a")

    assert caught.value.code == "objective_bytes"


def test_objective_boundary_rejects_invalid_unicode() -> None:
    with pytest.raises(ObjectiveBoundsError) as caught:
        validate_objective("inspect\ud800target")

    assert caught.value.code == "objective_unicode"


@pytest.mark.parametrize("objective", ["", " ", "\t\n\r"])
def test_objective_boundary_rejects_empty_or_whitespace_only_text(objective: str) -> None:
    with pytest.raises(ObjectiveBoundsError) as caught:
        validate_objective(objective)

    assert caught.value.code == "objective_empty"


@pytest.mark.parametrize("objective", [None, 1, b"inspect", True])
def test_objective_boundary_rejects_coercible_non_strings(objective: object) -> None:
    with pytest.raises(ObjectiveBoundsError) as caught:
        validate_objective(objective)

    assert caught.value.code == "objective_type"


def test_objective_boundary_rejects_string_subclasses() -> None:
    class ObjectiveString(str):
        pass

    with pytest.raises(ObjectiveBoundsError) as caught:
        validate_objective(ObjectiveString("inspect"))

    assert caught.value.code == "objective_type"


@pytest.mark.parametrize("limit", [0, -1, True, 1.5])
def test_objective_boundary_rejects_invalid_internal_limits(limit: object) -> None:
    with pytest.raises(ValueError, match="positive integer"):
        validate_objective("inspect", max_utf8_bytes=limit)  # type: ignore[arg-type]
