from __future__ import annotations

import pytest

from ai_qa_automation.runtime.budget import BudgetExceededError, ExecutionBudget


def make_budget(**overrides: int | float) -> ExecutionBudget:
    values: dict[str, int | float] = {
        "max_tool_calls": 2,
        "max_network_calls": 2,
        "max_mutations": 1,
        "max_wall_seconds": 60.0,
    }
    values.update(overrides)
    return ExecutionBudget(
        max_tool_calls=int(values["max_tool_calls"]),
        max_network_calls=int(values["max_network_calls"]),
        max_mutations=int(values["max_mutations"]),
        max_wall_seconds=float(values["max_wall_seconds"]),
    )


def test_budget_dimensions_are_independent_and_fail_closed() -> None:
    budget = make_budget()

    budget.charge_tool()
    budget.charge_tool()
    budget.charge_network()
    budget.charge_mutation()

    snapshot = budget.snapshot()
    assert snapshot.tool_calls == 2
    assert snapshot.network_calls == 1
    assert snapshot.mutations == 1

    with pytest.raises(BudgetExceededError, match="tool-call budget"):
        budget.charge_tool()
    with pytest.raises(BudgetExceededError, match="mutation budget"):
        budget.charge_mutation()

    # Exhausting one dimension must not silently consume another.
    budget.charge_network()
    assert budget.snapshot().network_calls == 2
    with pytest.raises(BudgetExceededError, match="network-call budget"):
        budget.charge_network()


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("max_tool_calls", 0, "max_tool_calls"),
        ("max_network_calls", 0, "max_network_calls"),
        ("max_mutations", 0, "max_mutations"),
        ("max_wall_seconds", 0.0, "max_wall_seconds"),
    ],
)
def test_budget_rejects_non_positive_limits(field: str, value: int | float, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        make_budget(**{field: value})


def test_wall_clock_budget_is_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    ticks = iter([100.0, 100.1, 101.2])
    monkeypatch.setattr("ai_qa_automation.runtime.budget.time.monotonic", lambda: next(ticks))
    budget = make_budget(max_wall_seconds=1.0)

    budget.charge_tool()
    with pytest.raises(BudgetExceededError, match="wall-clock"):
        budget.charge_tool()

    assert budget.snapshot().tool_calls == 1
