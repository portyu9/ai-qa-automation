from __future__ import annotations

from collections.abc import Callable

from ..models import ValidationResult, ValidationStatus


class ValidationGate:
    """Deterministic release gate. Model opinions cannot override a failed validator."""

    def __init__(self) -> None:
        self._checks: list[tuple[str, Callable[[], tuple[bool, str]]]] = []

    def add(self, name: str, check: Callable[[], tuple[bool, str]]) -> "ValidationGate":
        self._checks.append((name, check))
        return self

    def run(self) -> list[ValidationResult]:
        results: list[ValidationResult] = []
        for name, check in self._checks:
            try:
                passed, summary = check()
                status = ValidationStatus.PASS if passed else ValidationStatus.FAIL
            except Exception as exc:  # deterministic checker failure is itself a failure
                status = ValidationStatus.FAIL
                summary = f"validator raised {type(exc).__name__}: {exc}"
            results.append(ValidationResult(name=name, status=status, summary=summary))
        return results

    @staticmethod
    def all_passed(results: list[ValidationResult]) -> bool:
        return bool(results) and all(item.status == ValidationStatus.PASS for item in results)
