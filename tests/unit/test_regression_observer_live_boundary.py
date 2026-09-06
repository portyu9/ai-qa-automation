from ai_qa_automation.runtime.internal_tool_domains.testing import (
    _REGRESSION_EXECUTION_AUTHORITY,
)
from ai_qa_automation.runtime.regression_execution_observer import (
    TRUSTED_REGRESSION_EXECUTION_AUTHORITY,
)


def test_live_regression_pytest_declares_no_authoritative_observer() -> None:
    assert _REGRESSION_EXECUTION_AUTHORITY == "unavailable"
    assert _REGRESSION_EXECUTION_AUTHORITY != TRUSTED_REGRESSION_EXECUTION_AUTHORITY
