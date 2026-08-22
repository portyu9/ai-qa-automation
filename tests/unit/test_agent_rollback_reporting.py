from ai_qa_automation.agent import _remove_latest_modified_path
from ai_qa_automation.models import AgentRunState


def test_rollback_removes_only_latest_occurrence_of_same_modified_path(tmp_path) -> None:
    state = AgentRunState(objective="repair", workspace=str(tmp_path))
    state.files_modified = [
        "tests/test_checkout.py",
        "tests/test_other.py",
        "tests/test_checkout.py",
    ]

    _remove_latest_modified_path(state, "tests/test_checkout.py")

    assert state.files_modified == ["tests/test_checkout.py", "tests/test_other.py"]
