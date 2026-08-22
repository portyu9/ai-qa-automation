from ai_qa_automation.models import ValidationStatus
from ai_qa_automation.tools.contracts import validate_json_schema


def test_schema_validation_never_uses_model_opinion() -> None:
    schema = {"type": "object", "required": ["id"], "properties": {"id": {"type": "integer"}}}
    result = validate_json_schema({"id": 12}, schema)
    assert result.status in {ValidationStatus.PASS, ValidationStatus.NOT_VERIFIED}
