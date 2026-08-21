from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath

from ..models import RiskLevel, TestLayer


@dataclass(frozen=True)
class ChangeImpactAssessment:
    risk: RiskLevel
    changed_files: tuple[str, ...]
    risk_areas: tuple[str, ...]
    recommended_layers: tuple[TestLayer, ...]
    recommended_tags: tuple[str, ...]
    confidence: float
    rationale: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "risk": self.risk.value,
            "changed_files": list(self.changed_files),
            "risk_areas": list(self.risk_areas),
            "recommended_layers": [item.value for item in self.recommended_layers],
            "recommended_tags": list(self.recommended_tags),
            "confidence": self.confidence,
            "rationale": list(self.rationale),
        }


class ChangeImpactAnalyzer:
    """Deterministically converts a changed-file set into regression risk signals."""

    _CRITICAL = {
        "security": ("auth", "oauth", "iam", "rbac", "crypto", "secret", "permission", "policy"),
        "data_integrity": ("migration", "schema", "database", "payment", "billing", "ledger"),
    }
    _HIGH = {
        "api_contract": ("openapi", "swagger", "graphql", "proto", "api/", "routes", "contract"),
        "infrastructure": ("terraform", "k8s", "kubernetes", "helm", "docker", "deployment", "infra/"),
        "dependencies": ("requirements", "pyproject", "package.json", "lock", "pom.xml", "build.gradle"),
    }
    _MEDIUM = {
        "ui": ("frontend", "ui/", "components", "pages", "templates", ".tsx", ".jsx", ".vue"),
        "configuration": ("config", "settings", ".env", "feature_flag", "feature-flag"),
    }

    def assess(self, changed_files: list[str] | tuple[str, ...]) -> ChangeImpactAssessment:
        normalized = tuple(sorted({PurePosixPath(str(path)).as_posix() for path in changed_files if str(path).strip()}))
        if not normalized:
            return ChangeImpactAssessment(
                risk=RiskLevel.LOW,
                changed_files=(),
                risk_areas=(),
                recommended_layers=(TestLayer.UNIT,),
                recommended_tags=("smoke",),
                confidence=0.4,
                rationale=("No changed files were observed; selection should remain conservative.",),
            )

        areas: set[str] = set()
        rationale: list[str] = []
        risk = RiskLevel.LOW
        only_tests = True
        only_docs = True

        for path in normalized:
            lower = path.casefold()
            parts = {part.casefold() for part in PurePosixPath(path).parts}
            is_test = "tests" in parts or "test" in parts or ".spec." in lower or ".test." in lower
            is_doc = lower.endswith((".md", ".rst", ".txt")) or "docs" in parts
            only_tests &= is_test
            only_docs &= is_doc

            critical_match = False
            high_match = False
            medium_match = False
            for area, needles in self._CRITICAL.items():
                if any(needle in lower for needle in needles):
                    areas.add(area)
                    critical_match = True
                    rationale.append(f"{path}: critical {area} surface changed")
            for area, needles in self._HIGH.items():
                if any(needle in lower for needle in needles):
                    areas.add(area)
                    high_match = True
                    rationale.append(f"{path}: high-risk {area} surface changed")
            for area, needles in self._MEDIUM.items():
                if any(needle in lower for needle in needles):
                    areas.add(area)
                    medium_match = True
                    rationale.append(f"{path}: {area} surface changed")
            if critical_match:
                risk = RiskLevel.CRITICAL
            elif high_match and risk != RiskLevel.CRITICAL:
                risk = RiskLevel.HIGH
            elif medium_match and risk == RiskLevel.LOW:
                risk = RiskLevel.MEDIUM

        if only_docs:
            risk = RiskLevel.LOW
            areas.add("documentation")
            rationale.append("All observed changes are documentation-only.")
        elif only_tests and risk == RiskLevel.LOW:
            areas.add("test_automation")
            rationale.append("All observed changes are confined to test code.")

        layers: set[TestLayer] = {TestLayer.UNIT}
        tags: set[str] = {"smoke"}
        if "api_contract" in areas or "data_integrity" in areas:
            layers.update({TestLayer.API, TestLayer.INTEGRATION})
            tags.add("contract")
        if "ui" in areas:
            layers.update({TestLayer.COMPONENT, TestLayer.UI})
            tags.add("ui")
        if "security" in areas:
            layers.add(TestLayer.INTEGRATION)
            tags.add("security")
        if "dependencies" in areas or "infrastructure" in areas or "configuration" in areas:
            layers.add(TestLayer.INTEGRATION)
            tags.add("integration")
        if risk in {RiskLevel.HIGH, RiskLevel.CRITICAL}:
            tags.add("full-regression")

        confidence = min(0.98, 0.62 + min(len(normalized), 12) * 0.02 + len(areas) * 0.04)
        if not rationale:
            rationale.append("No high-risk path heuristic matched; retain baseline smoke and unit coverage.")

        order = {TestLayer.UNIT: 0, TestLayer.COMPONENT: 1, TestLayer.API: 2, TestLayer.INTEGRATION: 3, TestLayer.UI: 4}
        return ChangeImpactAssessment(
            risk=risk,
            changed_files=normalized,
            risk_areas=tuple(sorted(areas)),
            recommended_layers=tuple(sorted(layers, key=order.__getitem__)),
            recommended_tags=tuple(sorted(tags)),
            confidence=round(confidence, 2),
            rationale=tuple(rationale[:20]),
        )
