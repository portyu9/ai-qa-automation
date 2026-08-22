from ai_qa_automation.intelligence.ci_analysis import analyze_ci_failure


def test_ci_auth_failure_is_not_mislabeled_as_product_defect() -> None:
    result = analyze_ci_failure(exit_code=1, log_tail="remote: HTTP 403 permission denied")
    assert result.category == "AUTHENTICATION_FAILURE"


def test_ci_numeric_business_id_is_not_treated_as_http_status() -> None:
    result = analyze_ci_failure(exit_code=1, log_tail="job record 403 failed to deserialize")
    assert result.category == "TEST_FAILURE"


def test_ci_numeric_rate_id_is_not_treated_as_rate_limit() -> None:
    result = analyze_ci_failure(exit_code=7, log_tail="build artifact 429 could not be opened")
    assert result.category == "UNKNOWN"


def test_unknown_ci_failure_stays_unknown() -> None:
    result = analyze_ci_failure(exit_code=7, log_tail="process exited unexpectedly")
    assert result.category == "UNKNOWN"
