from __future__ import annotations

import hashlib
import json
from typing import Any

from ..models import RiskLevel, TestGenerationPlan, TestLayer, TestScenario


def _sha256_json(value: Any) -> str:
    rendered = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return f"sha256:{hashlib.sha256(rendered.encode('utf-8')).hexdigest()}"


def _requirement_digest(requirement: str) -> str:
    return f"sha256:{hashlib.sha256(requirement.encode('utf-8')).hexdigest()}"


class TestGenerationPlanner:
    """Conservative coverage-aware planner that prefers the lowest reliable test layer.

    Existing-coverage labels may come from model interpretation of repository
    observations. They are therefore advisory context only and never suppress a
    deterministic candidate scenario. Omission requires stronger observed or
    deterministic evidence than a model-supplied label.

    Scenario identities are content-addressed from the normalized requirement and
    deterministic scenario contract. The selected scenario is therefore stable for
    the same planner inputs, but remains advisory until a deterministic implementation
    gate proves proposed source corresponds to that contract.
    """

    _RISK_RANK = {
        RiskLevel.LOW: 1,
        RiskLevel.MEDIUM: 2,
        RiskLevel.HIGH: 3,
        RiskLevel.CRITICAL: 4,
    }

    def plan(
        self,
        requirement: str,
        *,
        existing_coverage: list[str] | None = None,
    ) -> TestGenerationPlan:
        normalized_requirement = requirement.strip()
        requirement_digest = _requirement_digest(normalized_requirement)
        text = normalized_requirement.lower()
        layer = self._select_layer(text)
        scenarios: list[TestScenario] = []

        candidate_specs = [
            (
                "happy path",
                RiskLevel.MEDIUM,
                "Prove intended behavior",
                ["observable business outcome"],
            ),
            (
                "negative path",
                RiskLevel.HIGH,
                "Prove invalid input/error contract",
                ["deterministic rejection", "stable error contract"],
            ),
            (
                "boundary",
                RiskLevel.HIGH,
                "Prove important boundary behavior",
                ["boundary accepted/rejected as specified"],
            ),
        ]
        if any(token in text for token in ("auth", "permission", "role", "access")):
            candidate_specs.append(
                (
                    "authorization",
                    RiskLevel.CRITICAL,
                    "Prove access-control behavior",
                    ["unauthorized access denied", "authorized access allowed"],
                )
            )

        for name, risk, purpose, assertions in candidate_specs:
            assertion_contract_digest = _sha256_json(assertions)
            scenario_contract = {
                "requirement_digest": requirement_digest,
                "name": name,
                "layer": layer.value,
                "risk": risk.value,
                "purpose": purpose,
                "assertions": assertions,
                "tags": ["generated-plan"],
                "assertion_contract_digest": assertion_contract_digest,
            }
            scenarios.append(
                TestScenario(
                    scenario_id=_sha256_json(scenario_contract),
                    assertion_contract_digest=assertion_contract_digest,
                    name=name,
                    layer=layer,
                    risk=risk,
                    purpose=purpose,
                    assertions=assertions,
                    tags=["generated-plan"],
                )
            )

        selected = max(
            enumerate(scenarios),
            key=lambda item: (self._RISK_RANK[item[1].risk], -item[0]),
        )[1]
        gaps = [f"{scenario.layer.value}:{scenario.name}" for scenario in scenarios]
        duplicate_risk = (
            "REVIEW_REQUIRED — interpreted existing-coverage labels are advisory and cannot "
            "suppress deterministic candidate scenarios"
            if existing_coverage
            else "UNKNOWN — inspect same-run repository coverage evidence before implementation"
        )
        return TestGenerationPlan(
            requirement_summary=normalized_requirement,
            requirement_digest=requirement_digest,
            coverage_gaps=gaps,
            scenarios=scenarios,
            selected_scenario_id=selected.scenario_id,
            duplicate_risk=duplicate_risk,
            validation_plan=[
                "same-run repository coverage evidence review",
                "repository convention check",
                "meaningful assertion review",
                "deterministic execution",
                "controlled sensitivity/mutation check where safe",
            ],
        )

    def validate_identity(self, plan: TestGenerationPlan) -> None:
        """Fail unless a persisted plan is an exact deterministic planner output."""

        expected = self.plan(plan.requirement_summary)
        expected_with_advisory_coverage = self.plan(
            plan.requirement_summary,
            existing_coverage=["advisory-present"],
        )
        if (
            plan.requirement_digest != expected.requirement_digest
            or plan.coverage_gaps != expected.coverage_gaps
            or plan.scenarios != expected.scenarios
            or plan.selected_scenario_id != expected.selected_scenario_id
            or plan.validation_plan != expected.validation_plan
            or plan.duplicate_risk
            not in {expected.duplicate_risk, expected_with_advisory_coverage.duplicate_risk}
        ):
            raise ValueError(
                "test-generation plan identity does not replay from deterministic planner inputs"
            )

    @staticmethod
    def _select_layer(text: str) -> TestLayer:
        if any(
            token in text for token in ("endpoint", "api", "http", "openapi", "status code", "json")
        ):
            return TestLayer.API
        if any(token in text for token in ("button", "page", "browser", "modal", "screen", "ui")):
            return TestLayer.UI
        if any(token in text for token in ("database", "queue", "service", "integration")):
            return TestLayer.INTEGRATION
        if any(token in text for token in ("function", "method", "algorithm", "pure logic")):
            return TestLayer.UNIT
        return TestLayer.COMPONENT
