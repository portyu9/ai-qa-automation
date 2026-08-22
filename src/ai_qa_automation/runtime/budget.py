from __future__ import annotations

import math
import threading
import time
from dataclasses import dataclass


class BudgetExceededError(RuntimeError):
    """Raised when a deterministic execution budget is exhausted."""


@dataclass(frozen=True)
class BudgetSnapshot:
    tool_calls: int
    network_calls: int
    mutations: int
    elapsed_seconds: float

    def as_dict(self) -> dict[str, int | float]:
        return {
            "tool_calls": self.tool_calls,
            "network_calls": self.network_calls,
            "mutations": self.mutations,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
        }


class ExecutionBudget:
    """Thread-safe multidimensional circuit breaker for non-model execution."""

    def __init__(
        self,
        *,
        max_tool_calls: int,
        max_network_calls: int,
        max_mutations: int,
        max_wall_seconds: float,
    ) -> None:
        for name, value in {
            "max_tool_calls": max_tool_calls,
            "max_network_calls": max_network_calls,
            "max_mutations": max_mutations,
        }.items():
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if not math.isfinite(max_wall_seconds) or max_wall_seconds <= 0:
            raise ValueError("max_wall_seconds must be a positive finite value")
        self.max_tool_calls = max_tool_calls
        self.max_network_calls = max_network_calls
        self.max_mutations = max_mutations
        self.max_wall_seconds = max_wall_seconds
        self._started = time.monotonic()
        self._tool_calls = 0
        self._network_calls = 0
        self._mutations = 0
        self._lock = threading.Lock()

    def _elapsed(self) -> float:
        return max(0.0, time.monotonic() - self._started)

    def assert_wall_time(self) -> None:
        if self._elapsed() > self.max_wall_seconds:
            raise BudgetExceededError("wall-clock execution budget exhausted")

    def charge_tool(self) -> None:
        with self._lock:
            self.assert_wall_time()
            if self._tool_calls >= self.max_tool_calls:
                raise BudgetExceededError("tool-call budget exhausted")
            self._tool_calls += 1

    def charge_network(self) -> None:
        with self._lock:
            self.assert_wall_time()
            if self._network_calls >= self.max_network_calls:
                raise BudgetExceededError("network-call budget exhausted")
            self._network_calls += 1

    def charge_mutation(self) -> None:
        with self._lock:
            self.assert_wall_time()
            if self._mutations >= self.max_mutations:
                raise BudgetExceededError("mutation budget exhausted")
            self._mutations += 1

    def snapshot(self) -> BudgetSnapshot:
        with self._lock:
            return BudgetSnapshot(
                tool_calls=self._tool_calls,
                network_calls=self._network_calls,
                mutations=self._mutations,
                elapsed_seconds=self._elapsed(),
            )
