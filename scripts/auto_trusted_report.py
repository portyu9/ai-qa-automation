from __future__ import annotations

import argparse
import json
import os
from collections.abc import Mapping
from typing import Any

from scripts.trusted_pr_control import (
    EXPECTED_WORKFLOW_REF,
    GitHubApi,
    PullRequestSubject,
    TRUSTED_STATUS_CONTEXT,
    _require_positive_int,
    _require_sha,
    parse_job_results,
    resolve_current_subject,
)

EXPECTED_WORKFLOW_EVENT = "workflow_run"


def report_automatic_result(
    *,
    repository: str,
    token: str,
    workflow_event: str,
    workflow_ref: str,
    expected: PullRequestSubject,
    job_results: Mapping[str, str],
    target_url: str,
) -> dict[str, Any]:
    if workflow_event != EXPECTED_WORKFLOW_EVENT:
        raise PermissionError("automatic trusted status publication requires workflow_run")
    if workflow_ref != EXPECTED_WORKFLOW_REF:
        raise PermissionError("automatic trusted status publication requires refs/heads/main")
    if set(job_results) != {"validation"}:
        raise ValueError("trusted validation results must contain exactly the validation job")
    validation_result = job_results["validation"]
    if validation_result not in {"cancelled", "failure", "skipped", "success"}:
        raise ValueError("trusted validation job has an invalid terminal result")

    api = GitHubApi(repository=repository, token=token)
    current = resolve_current_subject(api, expected)
    if validation_result == "success":
        state = "success"
        description = "Automatic exact-subject trusted validation passed"
    else:
        state = "failure"
        description = f"Automatic trusted validation ended {validation_result}"
    api.post_status(
        sha=current.head_sha,
        state=state,
        description=description,
        target_url=target_url,
    )
    return {
        "result": state.upper(),
        "status_posted": True,
        "status_context": TRUSTED_STATUS_CONTEXT,
        "status_subject": current.head_sha,
        "validation_result": validation_result,
        "authorization_mode": "automatic-default-branch",
    }


def _subject_from_args(args: argparse.Namespace) -> PullRequestSubject:
    return PullRequestSubject(
        number=_require_positive_int(args.pr_number, label="pull-request number"),
        head_sha=_require_sha(args.expected_head_sha, label="expected head SHA"),
        base_sha=_require_sha(args.expected_base_sha, label="expected base SHA"),
        merge_sha=_require_sha(args.expected_merge_sha, label="expected merge SHA"),
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Automatic trusted PR status reporter")
    parser.add_argument("--pr-number", required=True)
    parser.add_argument("--expected-head-sha", required=True)
    parser.add_argument("--expected-base-sha", required=True)
    parser.add_argument("--expected-merge-sha", required=True)
    parser.add_argument("--job-results-json", required=True)
    parser.add_argument("--target-url", required=True)
    return parser


def main() -> None:
    args = _parser().parse_args()
    result = report_automatic_result(
        repository=os.environ.get("GITHUB_REPOSITORY", ""),
        token=os.environ.get("GITHUB_TOKEN", ""),
        workflow_event=os.environ.get("GITHUB_EVENT_NAME", ""),
        workflow_ref=os.environ.get("GITHUB_REF", ""),
        expected=_subject_from_args(args),
        job_results=parse_job_results(args.job_results_json),
        target_url=args.target_url,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    if result["result"] == "FAILURE":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
