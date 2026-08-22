from ai_qa_automation.intelligence.ci_analysis import analyze_ci_failure


def test_ci_auth_failure_is_not_mislabeled_as_product_defect() -> None:
    result = analyze_ci_failure(exit_code=1, log_tail="remote: HTTP 403 permission denied")
    assert result.category == "AUTHENTICATION_FAILURE"


def test_unknown_ci_failure_stays_unknown() -> None:
    result = analyze_ci_failure(exit_code=7, log_tail="process exited unexpectedly")
    assert result.category == "UNKNOWN"
