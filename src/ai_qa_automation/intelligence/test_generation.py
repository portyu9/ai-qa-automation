from __future__ import annotations

from ..models import RiskLevel, TestGenerationPlan, TestLayer, TestScenario


class TestGenerationPlanner:
    """Conservative coverage-aware planner that prefers the lowest reliable test layer.

    Existing-coverage labels may come from model interpretation of repository
    observations. They are therefore advisory context only and never suppress a
    deterministic candidate scenario. Omission requires stronger observed or
    deterministic evidence than a model-supplied label.
    """

    def plan(
        self,
        requirement: str,
        *,
        existing_coverage: list[str] | None = None,
    ) -> TestGenerationPlan:
        text = requirement.lower()
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
            scenarios.append(
                TestScenario(
                    name=name,
                    layer=layer,
                    risk=risk,
                    purpose=purpose,
                    assertions=assertions,
                    tags=["generated-plan"],
                )
            )

        gaps = [f"{scenario.layer.value}:{scenario.name}" for scenario in scenarios]
        duplicate_risk = (
            "REVIEW_REQUIRED — interpreted existing-coverage labels are advisory and cannot "
            "suppress deterministic candidate scenarios"
            if existing_coverage
            else "UNKNOWN — inspect same-run repository coverage evidence before implementation"
        )
        return TestGenerationPlan(
            requirement_summary=requirement.strip(),
            coverage_gaps=gaps,
            scenarios=scenarios,
            duplicate_risk=duplicate_risk,
            validation_plan=[
                "same-run repository coverage evidence review",
                "repository convention check",
                "meaningful assertion review",
                "deterministic execution",
                "controlled sensitivity/mutation check where safe",
            ],
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
