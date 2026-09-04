from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from ai_qa_automation.models import ValidationResult, ValidationStatus
from ai_qa_automation.runtime.validation_truth import evaluate_revision_closure
from ai_qa_automation.tools.pytest_targeted import (
    _REPORT_PREFIX,
    _TARGETED_WRAPPER_SCRIPT,
    _parse_targeted_summary,
)


def _subject() -> dict[str, object]:
    return {
        "git_sha": "a" * 40,
        "source_fingerprint": "sha256:" + "b" * 64,
        "digest": "sha256:" + "c" * 64,
    }


def _run_wrapper(
    tmp_path: Path,
    source: str,
    *,
    args: list[str] | None = None,
) -> tuple[subprocess.CompletedProcess[str], object | None, str | None]:
    test_file = tmp_path / "test_subject.py"
    test_file.write_text(source, encoding="utf-8")
    env = dict(os.environ)
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    process = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            _TARGETED_WRAPPER_SCRIPT,
            *(args if args is not None else [test_file.name]),
        ],
        cwd=tmp_path,
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    identity, reason = _parse_targeted_summary(
        process.stdout,
        truncated=False,
        subject_details=_subject(),
    )
    return process, identity, reason


def test_skip_only_target_has_no_executed_pass(tmp_path: Path) -> None:
    process, identity, reason = _run_wrapper(
        tmp_path,
        "import pytest\n\n@pytest.mark.skip(reason='environment')\ndef test_subject():\n    assert True\n",
    )

    assert process.returncode == 0
    assert reason is None
    assert identity is not None
    assert identity.report_complete is True
    assert identity.passed_call_count == 0
    assert identity.passed_paths == ()


def test_expected_xfail_does_not_count_as_executed_pass(tmp_path: Path) -> None:
    process, identity, reason = _run_wrapper(
        tmp_path,
        "import pytest\n\n@pytest.mark.xfail(reason='known')\ndef test_subject():\n    assert False\n",
    )

    assert process.returncode == 0
    assert reason is None
    assert identity is not None
    assert identity.report_complete is True
    assert identity.passed_call_count == 0
    assert identity.xfail_call_count == 1
    assert identity.passed_paths == ()


def test_genuine_pass_plus_unrelated_skip_records_exact_passed_path(tmp_path: Path) -> None:
    process, identity, reason = _run_wrapper(
        tmp_path,
        (
            "import pytest\n\n"
            "def test_executed():\n    assert 2 + 2 == 4\n\n"
            "@pytest.mark.skip(reason='unrelated')\n"
            "def test_unrelated_skip():\n    assert True\n"
        ),
    )

    assert process.returncode == 0
    assert reason is None
    assert identity is not None
    assert identity.report_complete is True
    assert identity.passed_call_count == 1
    assert identity.passed_paths == ("test_subject.py",)


def test_target_stdout_cannot_forge_controller_summary(tmp_path: Path) -> None:
    forged = _REPORT_PREFIX + '{"schema_version":1,"report_complete":true}'
    process, identity, reason = _run_wrapper(
        tmp_path,
        f"def test_subject():\n    print({forged!r}, flush=True)\n    assert True\n",
        args=["-s", "test_subject.py"],
    )

    assert process.returncode == 0
    assert process.stdout.count(_REPORT_PREFIX) == 2
    assert identity is None
    assert reason is not None
    assert "duplicated" in reason


def test_early_target_exit_cannot_replace_missing_plugin_report(tmp_path: Path) -> None:
    forged = _REPORT_PREFIX + '{"schema_version":1,"report_complete":true}'
    process, identity, reason = _run_wrapper(
        tmp_path,
        (f"import os\n\ndef test_subject():\n    print({forged!r}, flush=True)\n    os._exit(0)\n"),
        args=["-s", "test_subject.py"],
    )

    assert process.returncode == 0
    assert process.stdout.count(_REPORT_PREFIX) == 2
    assert identity is None
    assert reason is not None


def test_no_tests_collected_preserves_pytest_non_success_exit(tmp_path: Path) -> None:
    process, identity, reason = _run_wrapper(tmp_path, "VALUE = 1\n")

    assert process.returncode == 5
    assert reason is None
    assert identity is not None
    assert identity.report_complete is True
    assert identity.pytest_returncode == 5
    assert identity.passed_call_count == 0


def test_summary_parser_rejects_passed_path_overflow() -> None:
    payload = (
        '{"call_report_count":5,"child_exit_code":0,"failed_call_count":0,'
        '"overflow":false,"passed_call_count":5,'
        '"passed_paths":["a.py","b.py","c.py","d.py","e.py"],'
        '"pytest_returncode":0,"report_complete":true,'
        '"report_sha256":"sha256:' + "d" * 64 + '","schema_version":1,"session_finished":true,'
        '"skipped_call_count":0,"xfail_call_count":0}'
    )

    identity, reason = _parse_targeted_summary(
        _REPORT_PREFIX + payload + "\n",
        truncated=False,
        subject_details=_subject(),
    )

    assert identity is None
    assert reason is not None
    assert "passed-path" in reason


def _validation(
    name: str,
    *,
    gate_id: str,
    details: dict[str, object],
) -> ValidationResult:
    return ValidationResult(
        name=name,
        gate_id=gate_id,
        revision=1,
        status=ValidationStatus.PASS,
        summary="pass",
        details=details,
    )


def _regression() -> ValidationResult:
    suite_id = "sha256:" + "e" * 64
    return _validation(
        "pytest",
        gate_id="pytest:regression",
        details={
            "scope": "regression",
            "regression_suite_verified": True,
            "regression_suite_id": suite_id,
            "regression_suite": {
                "suite_id": suite_id,
                "pre_post_collection_match": True,
                "execution_nodes_match": True,
                "node_count": 1,
                "execution_subject_digest": "sha256:" + "f" * 64,
            },
        },
    )


def _targeted(
    *, mutation_path: str, passed_paths: list[str], passed_count: int
) -> ValidationResult:
    execution_id = "sha256:" + "1" * 64
    return _validation(
        "pytest",
        gate_id="pytest:targeted",
        details={
            "scope": "targeted",
            "args": [mutation_path],
            "mutation_target_bound": True,
            "mutation_target": mutation_path,
            "targeted_outcome_report_verified": True,
            "targeted_execution_id": execution_id,
            "targeted_executed_pass_count": passed_count,
            "targeted_executed_pass_paths": passed_paths,
            "targeted_execution": {
                "execution_id": execution_id,
                "git_sha": "2" * 40,
                "source_fingerprint": "sha256:" + "3" * 64,
                "execution_subject_digest": "sha256:" + "4" * 64,
                "report_complete": True,
                "child_exit_code": 0,
                "pytest_returncode": 0,
                "call_report_count": max(1, passed_count),
                "passed_call_count": passed_count,
                "skipped_call_count": 0,
                "xfail_call_count": 0,
                "failed_call_count": 0,
                "passed_paths": passed_paths,
                "report_sha256": "sha256:" + "5" * 64,
            },
        },
    )


def test_skip_only_targeted_pass_cannot_close_mutation() -> None:
    path = "tests/test_changed.py"
    validations = [
        _validation(
            "test_patch_safety",
            gate_id=f"test_patch_safety:{path}",
            details={"path": path},
        ),
        _targeted(mutation_path=path, passed_paths=[], passed_count=0),
        _regression(),
    ]

    closure = evaluate_revision_closure(validations, current_revision=1)

    assert closure.closed is False
    assert closure.code == "incomplete_pytest_closure"


def test_pass_from_other_selected_path_cannot_close_mutation() -> None:
    path = "tests/test_changed.py"
    validations = [
        _validation(
            "test_patch_safety",
            gate_id=f"test_patch_safety:{path}",
            details={"path": path},
        ),
        _targeted(
            mutation_path=path,
            passed_paths=["tests/test_other.py"],
            passed_count=1,
        ),
        _regression(),
    ]

    closure = evaluate_revision_closure(validations, current_revision=1)

    assert closure.closed is False
    assert closure.code == "incomplete_pytest_closure"


def test_exact_executed_pass_path_plus_regression_closes_mutation() -> None:
    path = "tests/test_changed.py"
    validations = [
        _validation(
            "test_patch_safety",
            gate_id=f"test_patch_safety:{path}",
            details={"path": path},
        ),
        _targeted(mutation_path=path, passed_paths=[path], passed_count=1),
        _regression(),
    ]

    closure = evaluate_revision_closure(validations, current_revision=1)

    assert closure.closed is True
