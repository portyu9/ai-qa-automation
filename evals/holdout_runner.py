from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai_qa_automation.integrations.mcp_health import normalize_mcp_failure
from ai_qa_automation.intelligence.failure_analysis import FailureAnalyzer
from ai_qa_automation.intelligence.prioritization import RegressionPrioritizer
from ai_qa_automation.io_safety import read_json_catalog_bounded
from ai_qa_automation.models import (
    EvidenceItem,
    EvidenceKind,
    EvidenceNature,
    RegressionCandidate,
)
from ai_qa_automation.policy import PolicyEngine

ROOT = Path(__file__).resolve().parents[1]
_MAX_SCENARIO_BYTES = 64 * 1024
_MAX_CATALOG_ENTRIES = 16


class ReadinessScenario(BaseModel):
    """Strict contract for one repository-visible sequestered readiness case."""

    model_config = ConfigDict(extra="forbid", strict=True)

    id: str = Field(pattern=r"^H\d{2}$")
    title: str
    evaluator: str
    expected: str
    hard_safety: bool
    holdout: Literal[True]
    repository_visible: Literal[True]

    @field_validator("title", "evaluator", "expected")
    @classmethod
    def non_empty(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("readiness scenario strings must not be empty")
        return normalized


@dataclass(frozen=True, slots=True)
class ReadinessContext:
    root: Path
    target: Path
    policy: PolicyEngine
    analyzer: FailureAnalyzer


ReadinessEvaluator = Callable[[ReadinessContext], str]


@dataclass(frozen=True, slots=True)
class ReadinessSpec:
    case_id: str
    title: str
    function: ReadinessEvaluator
    expected: str
    hard_safety: bool


def _evidence(
    kind: EvidenceKind,
    *,
    nature: EvidenceNature = EvidenceNature.OBSERVED_FACT,
    **data: object,
) -> EvidenceItem:
    return EvidenceItem(
        run_id="readiness",
        kind=kind,
        nature=nature,
        source="readiness-fixture",
        summary="repository-visible sequestered readiness fixture",
        structured_data=data,
    )


def _competing_locator_over_server_error(ctx: ReadinessContext) -> str:
    evidence = [
        _evidence(EvidenceKind.HTTP_RESPONSE, status_code=500),
        _evidence(
            EvidenceKind.ACCESSIBILITY_SNAPSHOT,
            expected_control_present=True,
            locator_failed=True,
        ),
    ]
    return ctx.analyzer.classify(evidence).classification.value


def _model_interpretation_is_not_evidence(ctx: ReadinessContext) -> str:
    evidence = [
        _evidence(
            EvidenceKind.SOURCE_OBSERVATION,
            nature=EvidenceNature.MODEL_INTERPRETATION,
            claim="this looks like a product bug",
        )
    ]
    return ctx.analyzer.classify(evidence).classification.value


def _mcp_rate_limit(_ctx: ReadinessContext) -> str:
    return normalize_mcp_failure(status_code=429).value


def _nested_governance_write(ctx: ReadinessContext) -> str:
    decision = ctx.policy.authorize_path(Path(".claude/settings.json"), write=True)
    return "BLOCKED" if decision.decision.value == "DENY" else "FAIL"


def _security_critical_regression_preserved(_ctx: ReadinessContext) -> str:
    result = RegressionPrioritizer().select(
        [
            RegressionCandidate(
                test_id="security-authz",
                security_critical=True,
                changed_component_overlap=0.0,
            )
        ],
        dependency_confidence=1.0,
        selection_threshold=1.0,
    )
    return "PASS" if result.selected == ["security-authz"] else "FAIL"


def _very_low_dependency_confidence_selects_all(_ctx: ReadinessContext) -> str:
    result = RegressionPrioritizer().select(
        [
            RegressionCandidate(test_id="a", changed_component_overlap=0.0),
            RegressionCandidate(test_id="b", changed_component_overlap=0.0),
            RegressionCandidate(test_id="c", changed_component_overlap=0.0),
        ],
        dependency_confidence=0.2,
        selection_threshold=0.95,
    )
    return "PASS" if result.selected == ["a", "b", "c"] and not result.omitted else "FAIL"


READINESS_EVALUATORS: dict[str, ReadinessSpec] = {
    "competing_locator_over_server_error": ReadinessSpec(
        "H01",
        "competing locator and server-error signals",
        _competing_locator_over_server_error,
        "LOCATOR_UI_CONTRACT_CHANGE",
        False,
    ),
    "model_interpretation_is_not_evidence": ReadinessSpec(
        "H02",
        "model interpretation without observed evidence",
        _model_interpretation_is_not_evidence,
        "INSUFFICIENT_EVIDENCE",
        True,
    ),
    "mcp_rate_limit": ReadinessSpec(
        "H03",
        "MCP rate-limit normalization",
        _mcp_rate_limit,
        "RATE_LIMITED",
        False,
    ),
    "nested_governance_write": ReadinessSpec(
        "H04",
        "nested governance file write is denied",
        _nested_governance_write,
        "BLOCKED",
        True,
    ),
    "security_critical_regression_preserved": ReadinessSpec(
        "H05",
        "security-critical regression cannot be omitted",
        _security_critical_regression_preserved,
        "PASS",
        True,
    ),
    "very_low_dependency_confidence_selects_all": ReadinessSpec(
        "H06",
        "very low dependency confidence broadens to all tests",
        _very_low_dependency_confidence_selects_all,
        "PASS",
        True,
    ),
}


def _validate_evaluator_registry() -> None:
    functions = [spec.function for spec in READINESS_EVALUATORS.values()]
    if len(functions) != len(set(functions)):
        raise ValueError(
            "readiness evaluator registry must not alias one callable under multiple names"
        )


def load_readiness_scenarios(
    scenario_dir: Path | None = None,
) -> list[ReadinessScenario]:
    _validate_evaluator_registry()
    directory = scenario_dir or ROOT / "evals" / "holdout"
    catalog = read_json_catalog_bounded(
        directory,
        max_entries=_MAX_CATALOG_ENTRIES,
        max_bytes_per_file=_MAX_SCENARIO_BYTES,
        label="readiness scenario catalog",
    )
    scenarios: list[ReadinessScenario] = []
    for filename, raw in sorted(catalog.items()):
        scenario = ReadinessScenario.model_validate(raw)
        if scenario.id != Path(filename).stem:
            raise ValueError(
                f"readiness scenario ID {scenario.id} does not match filename {filename}"
            )
        scenarios.append(scenario)

    ids = [scenario.id for scenario in scenarios]
    if len(ids) != len(set(ids)):
        raise ValueError("readiness scenario IDs must be unique")
    expected_ids = {f"H{i:02d}" for i in range(1, 7)}
    if set(ids) != expected_ids:
        raise ValueError("readiness scenario catalog must contain exactly IDs H01 through H06")

    evaluator_names = [scenario.evaluator for scenario in scenarios]
    if len(evaluator_names) != len(set(evaluator_names)):
        raise ValueError("readiness registered evaluator names must be unique")
    if set(evaluator_names) != set(READINESS_EVALUATORS):
        missing = sorted(set(READINESS_EVALUATORS) - set(evaluator_names))
        unknown = sorted(set(evaluator_names) - set(READINESS_EVALUATORS))
        raise ValueError(
            f"readiness scenario registry/catalog mismatch (missing={missing}, unknown={unknown})"
        )
    for scenario in scenarios:
        spec = READINESS_EVALUATORS[scenario.evaluator]
        if scenario.id != spec.case_id:
            raise ValueError(
                f"readiness scenario {scenario.id} does not match evaluator case-id contract"
            )
        if scenario.title != spec.title:
            raise ValueError(
                f"readiness scenario {scenario.id} title does not match evaluator contract"
            )
        if scenario.expected != spec.expected:
            raise ValueError(
                f"readiness scenario {scenario.id} expected outcome does not match evaluator contract"
            )
        if scenario.hard_safety is not spec.hard_safety:
            raise ValueError(
                f"readiness scenario {scenario.id} hard_safety does not match evaluator contract"
            )
    return scenarios


def evaluate_holdout(evaluator: str) -> str:
    """Compatibility entry point for the legacy holdout command/path namespace."""

    spec = READINESS_EVALUATORS.get(evaluator)
    if spec is None:
        raise KeyError(evaluator)
    with TemporaryDirectory() as td:
        root = Path(td)
        target = root / "target"
        target.mkdir()
        context = ReadinessContext(
            root=root,
            target=target,
            policy=PolicyEngine(root, target),
            analyzer=FailureAnalyzer(),
        )
        return spec.function(context)


def main() -> int:
    scenarios = load_readiness_scenarios()
    rows: list[dict[str, object]] = []
    failures = 0
    hard_failures = 0
    for scenario in scenarios:
        actual = evaluate_holdout(scenario.evaluator)
        passed = actual == scenario.expected
        failures += int(not passed)
        hard_failures += int(not passed and scenario.hard_safety)
        rows.append(
            {
                **scenario.model_dump(mode="json"),
                "actual": actual,
                "pass": passed,
            }
        )

    evaluator_names = [scenario.evaluator for scenario in scenarios]
    distinct_registered_evaluators = len(set(evaluator_names))
    output = {
        "suite": "repository_visible_sequestered_readiness",
        "visibility": "repository_visible",
        "tuning_separation": "excluded_from_routine_primary_runner",
        "total": len(rows),
        "distinct_registered_evaluators": distinct_registered_evaluators,
        "duplicate_registered_evaluators": len(rows) - distinct_registered_evaluators,
        "failures": failures,
        "hard_safety_failures": hard_failures,
        "results": rows,
    }
    print(json.dumps(output, indent=2))
    return 1 if failures or hard_failures or distinct_registered_evaluators != len(rows) else 0


if __name__ == "__main__":
    raise SystemExit(main())
