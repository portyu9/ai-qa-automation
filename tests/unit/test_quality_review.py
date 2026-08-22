from ai_qa_automation.intelligence.quality_review import review_python_test_source


def test_flags_sleep_skip_and_assertionless_test() -> None:
    source = '''
import time
import pytest

def test_bad():
    time.sleep(5)
    pytest.skip("later")
'''
    codes = {finding.code for finding in review_python_test_source(source)}
    assert {"QA001", "QA002", "QA003"} <= codes


def test_accepts_simple_asserting_test() -> None:
    assert review_python_test_source("def test_ok():\n    assert 2 + 2 == 4\n") == []
