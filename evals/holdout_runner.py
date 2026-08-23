from __future__ import annotations

import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ai_qa_automation.integrations.mcp_health import normalize_mcp_failure
from ai_qa_automation.intelligence.failure_analysis import FailureAnalyzer
from ai_qa_automation.intelligence.prioritization import RegressionPrioritizer
from ai_qa_automation.models import (
    EvidenceItem,
    EvidenceKind,
    EvidenceNature,
    RegressionCandidate,
)
from ai_qa_automation.policy import PolicyEngine


def _evidence(
    kind: EvidenceKind,
    *,
    nature: EvidenceNature = EvidenceNature.OBSERVED_FACT,
    **data: object,
) -> EvidenceItem:
    return EvidenceItem(
        run_id="holdout",
        kind=kind,
        nature=nature,
        source="holdout-fixture",
        summary="unseen controlled holdout fixture",
        structured_data=data,
    )


def evaluate_holdout(evaluator: str) -> str:
    analyzer = FailureAnalyzer()
    with TemporaryDirectory() as td:
        root = Path(td)
        target = root / "target"
        target.mkdir()
        policy = PolicyEngine(root, target)

        if evaluator == "competing_locator_over_server_error":
            evidence = [
                _evidence(EvidenceKind.HTTP_RESPONSE, status_code=500),
                _evidence(
                    EvidenceKind.ACCESSIBILITY_SNAPSHOT,
                    expected_control_present=True,
                    locator_failed=True,
                ),
            ]
            return analyzer.classify(evidence).classification.value

        if evaluator == "model_interpretation_is_not_evidence":
            evidence = [
                _evidence(
                    EvidenceKind.SOURCE_OBSERVATION,
                    nature=EvidenceNature.MODEL_INTERPRETATION,
                    claim="this looks like a product bug",
                )
            ]
            return analyzer.classify(evidence).classification.value

        if evaluator == "mcp_rate_limit":
            return normalize_mcp_failure(status_code=429).value

        if evaluator == "nested_governance_write":
            decision = policy.authorize_path(Path(".claude/settings.json"), write=True)
            return "BLOCKED" if decision.decision.value == "DENY" else "FAIL"

        if evaluator == "security_critical_regression_preserved":
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

        if evaluator == "very_low_dependency_confidence_selects_all":
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

        raise KeyError(evaluator)


def main() -> int:
    scenario_dir = ROOT / "evals" / "holdout"
    rows: list[dict[str, object]] = []
    failures = 0
    hard_failures = 0
    for path in sorted(scenario_dir.glob("*.json")):
        scenario = json.loads(path.read_text(encoding="utf-8"))
        actual = evaluate_holdout(str(scenario["evaluator"]))
        passed = actual == scenario["expected"]
        failures += int(not passed)
        hard_failures += int(not passed and bool(scenario["hard_safety"]))
        rows.append({**scenario, "actual": actual, "pass": passed})
    output = {
        "suite": "holdout",
        "total": len(rows),
        "failures": failures,
        "hard_safety_failures": hard_failures,
        "results": rows,
    }
    print(json.dumps(output, indent=2))
    return 1 if failures or hard_failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
