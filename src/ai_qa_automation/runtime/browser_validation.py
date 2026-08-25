from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Iterable

from ..models import LocatorCandidate, ValidationResult, ValidationStatus
from ..redaction import redact_text


@dataclass(frozen=True, slots=True)
class BrowserValidationSubject:
    """Deterministic browser validation identity plus safe persisted metadata."""

    name: str
    gate_id: str
    details: dict[str, object]


def _subject_gate_id(prefix: str, payload: object) -> str:
    rendered = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    digest = hashlib.sha256(rendered.encode("utf-8")).hexdigest()[:16]
    return f"{prefix}:{digest}"


def browser_inspection_subject(url: str) -> BrowserValidationSubject:
    requested_url = str(url)
    payload = {"operation": "inspect_browser", "url": requested_url}
    return BrowserValidationSubject(
        name="browser_inspection",
        gate_id=_subject_gate_id("browser_inspection", payload),
        details={
            "operation": "inspect_browser",
            "requested_url": redact_text(requested_url),
        },
    )


def browser_locator_verification_subject(
    url: str,
    original_locator: str,
    candidates: Iterable[LocatorCandidate],
) -> BrowserValidationSubject:
    requested_url = str(url)
    original = str(original_locator)
    candidate_pairs = sorted({(item.strategy, item.locator) for item in candidates})
    canonical_candidates = [
        {"strategy": strategy, "locator": locator} for strategy, locator in candidate_pairs
    ]
    payload = {
        "operation": "verify_locator_candidates",
        "url": requested_url,
        "original_locator": original,
        "candidates": canonical_candidates,
    }
    return BrowserValidationSubject(
        name="browser_locator_verification",
        gate_id=_subject_gate_id("browser_locator_verification", payload),
        details={
            "operation": "verify_locator_candidates",
            "requested_url": redact_text(requested_url),
            "original_locator_hash": (
                "sha256:" + hashlib.sha256(original.encode("utf-8")).hexdigest()
            ),
            "candidate_count": len(canonical_candidates),
            "candidate_set_hash": (
                "sha256:"
                + hashlib.sha256(
                    json.dumps(
                        canonical_candidates,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")
                ).hexdigest()
            ),
        },
    )


def browser_validation_result(
    subject: BrowserValidationSubject,
    *,
    revision: int,
    status: ValidationStatus,
    summary: str,
    evidence_ids: Iterable[str] = (),
    details: dict[str, object] | None = None,
) -> ValidationResult:
    return ValidationResult(
        name=subject.name,
        gate_id=subject.gate_id,
        revision=revision,
        status=status,
        summary=summary,
        evidence_ids=list(evidence_ids),
        details={**subject.details, **(details or {})},
    )
