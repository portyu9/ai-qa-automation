from __future__ import annotations

import pytest

from scripts import trusted_pr_control as control

HEAD_SHA = "1" * 40
BASE_SHA = "2" * 40
MERGE_SHA = "3" * 40
RUN_URL = "https://github.com/portyu9/ai-qa-automation/actions/runs/123"


def _workflow_cli_args(command: str = "report") -> list[str]:
    return [
        command,
        "--pr-number",
        "43",
        "--expected-head-sha",
        HEAD_SHA,
        "--expected-base-sha",
        BASE_SHA,
        "--expected-merge-sha",
        MERGE_SHA,
        "--authorized",
        "true",
        "--job-results-json",
        '{"validation":"success"}',
        "--target-url",
        RUN_URL,
    ]


def test_workflow_report_command_parses_exact_cli_shape() -> None:
    args = control._parser().parse_args(_workflow_cli_args())

    assert args.command == "report"
    assert args.pr_number == "43"
    assert args.expected_head_sha == HEAD_SHA
    assert args.expected_base_sha == BASE_SHA
    assert args.expected_merge_sha == MERGE_SHA
    assert args.authorized == "true"
    assert args.job_results_json == '{"validation":"success"}'
    assert args.target_url == RUN_URL


def test_trusted_reporter_rejects_unknown_command() -> None:
    with pytest.raises(SystemExit):
        control._parser().parse_args(_workflow_cli_args("dispatch"))
