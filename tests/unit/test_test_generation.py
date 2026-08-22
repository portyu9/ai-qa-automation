from ai_qa_automation.intelligence.test_generation import TestGenerationPlanner
from ai_qa_automation.models import TestLayer


def test_api_requirement_prefers_api_layer() -> None:
    plan = TestGenerationPlanner().plan("POST /orders API must return 403 for unauthorized role")
    assert plan.scenarios
    assert all(item.layer is TestLayer.API for item in plan.scenarios)
    assert any(item.name == "authorization" for item in plan.scenarios)


def test_model_supplied_existing_coverage_cannot_suppress_candidate_scenarios() -> None:
    plan = TestGenerationPlanner().plan(
        "orders API status code contract",
        existing_coverage=["api:happy path", "api:negative path", "api:boundary"],
    )

    assert {item.name for item in plan.scenarios} == {"happy path", "negative path", "boundary"}
    assert "advisory" in plan.duplicate_risk.lower()


def test_generation_plan_requires_same_run_coverage_review_before_implementation() -> None:
    plan = TestGenerationPlanner().plan("checkout component behavior")

    assert "same-run repository coverage evidence review" in plan.validation_plan
    assert "inspect same-run repository coverage evidence" in plan.duplicate_risk.lower()
