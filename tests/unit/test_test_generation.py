from ai_qa_automation.intelligence.test_generation import TestGenerationPlanner
from ai_qa_automation.models import TestLayer


def test_api_requirement_prefers_api_layer() -> None:
    plan = TestGenerationPlanner().plan("POST /orders API must return 403 for unauthorized role")
    assert plan.scenarios
    assert all(item.layer is TestLayer.API for item in plan.scenarios)
    assert any(item.name == "authorization" for item in plan.scenarios)


def test_existing_coverage_is_not_duplicated() -> None:
    plan = TestGenerationPlanner().plan("orders API status code contract", existing_coverage=["api:happy path"])
    assert all(item.name != "happy path" for item in plan.scenarios)
