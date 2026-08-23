from __future__ import annotations

import pytest

from ai_qa_automation.intelligence.quality_review import review_python_test_source


def codes(source: str) -> set[str]:
    return {finding.code for finding in review_python_test_source(source)}


def test_flags_sleep_skip_and_assertionless_test() -> None:
    source = """
import time
import pytest

def test_bad():
    time.sleep(5)
    pytest.skip("later")
"""
    assert {"QA001", "QA002", "QA003"} <= codes(source)


def test_flags_asyncio_sleep_and_xfail() -> None:
    source = """
import asyncio
import pytest

async def test_bad():
    await asyncio.sleep(1)
    pytest.xfail("unstable")
"""
    assert {"QA001", "QA002", "QA003"} <= codes(source)


@pytest.mark.parametrize(
    "assertion",
    [
        "assert True",
        "assert value == value",
        "assert value is value",
        "assert value >= value",
        "assert value <= value",
    ],
)
def test_tautological_assertions_are_critical(assertion: str) -> None:
    source = f"def test_fake():\n    value = 1\n    {assertion}\n"
    findings = review_python_test_source(source)
    assert any(item.code == "QA004" and item.severity == "CRITICAL" for item in findings)


def test_broad_exception_suppression_is_critical() -> None:
    source = """
def test_suppressed():
    try:
        raise RuntimeError("failure")
    except Exception:
        pass
"""
    findings = review_python_test_source(source)
    assert any(item.code == "QA005" and item.severity == "CRITICAL" for item in findings)
    assert any(item.code == "QA003" for item in findings)


def test_bare_except_suppression_is_critical() -> None:
    source = """
def test_suppressed():
    try:
        raise RuntimeError("failure")
    except:
        pass
"""
    assert "QA005" in codes(source)


def test_specific_exception_with_meaningful_assertion_is_not_suppression() -> None:
    source = """
def test_error():
    try:
        raise ValueError("expected")
    except ValueError as exc:
        assert str(exc) == "expected"
"""
    assert review_python_test_source(source) == []


def test_pytest_raises_counts_as_observable_assertion() -> None:
    source = """
import pytest

def test_error():
    with pytest.raises(ValueError):
        int("not-a-number")
"""
    assert review_python_test_source(source) == []


@pytest.mark.parametrize(
    "body",
    [
        "self.assertEqual(actual, expected)",
        "expect(actual).to_equal(expected)",
        "assert_that(actual).is_equal_to(expected)",
        "verify(actual).matches(expected)",
    ],
)
def test_supported_assertion_call_shapes_count_as_observable(body: str) -> None:
    source = f"def test_behavior(self=None):\n    actual = 1\n    expected = 1\n    {body}\n"
    assert "QA003" not in codes(source)


def test_assertion_like_text_in_string_or_comment_does_not_count() -> None:
    source = """
def test_fake():
    text = "assert actual == expected"
    # assert actual == expected
    value = 1
"""
    assert "QA003" in codes(source)


def test_helper_assertion_outside_test_function_does_not_make_test_observable() -> None:
    source = """
def helper():
    assert 1 == 1

def test_fake():
    value = 1
"""
    assert "QA003" in codes(source)


def test_unused_nested_helper_assertion_does_not_make_outer_test_observable() -> None:
    source = """
def test_fake():
    def helper():
        assert 2 + 2 == 4
    value = 1
"""
    assert "QA003" in codes(source)


def test_nested_class_assertion_does_not_make_outer_test_observable() -> None:
    source = """
def test_fake():
    class LocalVerifier:
        def assert_behavior(self):
            assert 2 + 2 == 4
    value = 1
"""
    assert "QA003" in codes(source)


def test_assertion_after_nested_helper_still_counts_for_outer_test() -> None:
    source = """
def test_real():
    def helper():
        return 4
    assert helper() == 4
"""
    assert "QA003" not in codes(source)


def test_accepts_simple_asserting_test() -> None:
    assert review_python_test_source("def test_ok():\n    assert 2 + 2 == 4\n") == []


def test_non_test_helper_without_assertion_is_not_flagged_as_test() -> None:
    assert review_python_test_source("def helper():\n    return 1\n") == []
