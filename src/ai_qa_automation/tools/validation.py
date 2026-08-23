from __future__ import annotations

from collections.abc import Callable

from ..models import ValidationResult, ValidationStatus


class ValidationGate:
    """Deterministic release gate. Model opinions cannot override a failed validator."""

    def __init__(self) -> None:
        self._checks: list[tuple[str, Callable[[], tuple[bool, str]]]] = []

    def add(self, name: str, check: Callable[[], tuple[bool, str]]) -> ValidationGate:
        if not name.strip():
            raise ValueError("validation gate name must not be empty")
        self._checks.append((name, check))
        return self

    def run(self) -> list[ValidationResult]:
        results: list[ValidationResult] = []
        for name, check in self._checks:
            try:
                passed, summary = check()
                if type(passed) is not bool:
                    raise TypeError("validator outcome must be the literal boolean True or False")
                if not isinstance(summary, str) or not summary.strip():
                    raise TypeError("validator summary must be a non-empty string")
                status = ValidationStatus.PASS if passed else ValidationStatus.FAIL
            except Exception as exc:
                status = ValidationStatus.NOT_VERIFIED
                summary = f"validator could not produce a valid deterministic result: {type(exc).__name__}: {exc}"
            results.append(ValidationResult(name=name, status=status, summary=summary))
        return results

    @staticmethod
    def all_passed(results: list[ValidationResult]) -> bool:
        return bool(results) and all(item.status == ValidationStatus.PASS for item in results)
