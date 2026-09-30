from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

_CONTROL_PATH = Path(__file__).with_name("trusted_pr_control.py")
_CONTROL_SPEC = importlib.util.spec_from_file_location("aiqa_trusted_pr_control", _CONTROL_PATH)
if _CONTROL_SPEC is None or _CONTROL_SPEC.loader is None:
    raise RuntimeError("unable to load trusted PR control module")
_control = importlib.util.module_from_spec(_CONTROL_SPEC)
sys.modules[_CONTROL_SPEC.name] = _control
_CONTROL_SPEC.loader.exec_module(_control)

_PREFLIGHT_PATH = Path(__file__).with_name("auto_trusted_preflight.py")
_PREFLIGHT_SPEC = importlib.util.spec_from_file_location(
    "aiqa_auto_trusted_preflight", _PREFLIGHT_PATH
)
if _PREFLIGHT_SPEC is None or _PREFLIGHT_SPEC.loader is None:
    raise RuntimeError("unable to load trusted admission preflight")
_preflight = importlib.util.module_from_spec(_PREFLIGHT_SPEC)
sys.modules[_PREFLIGHT_SPEC.name] = _preflight
_PREFLIGHT_SPEC.loader.exec_module(_preflight)

EXPECTED_WORKFLOW_REF = _control.EXPECTED_WORKFLOW_REF
GitHubApi = _control.GitHubApi
PullRequestSubject = _control.PullRequestSubject
TRUSTED_STATUS_CONTEXT = _control.TRUSTED_STATUS_CONTEXT
_require_positive_int = _control._require_positive_int
_require_sha = _control._require_sha
parse_job_results = _control.parse_job_results
resolve_current_subject = _control.resolve_current_subject

EXPECTED_WORKFLOW_EVENTS = frozenset({"schedule", "workflow_run"})


def _require_protected_owner_authorization(
    *,
    repository: str,
    token: str,
    expected: PullRequestSubject,
) -> dict[str, Any]:
    """Re-prove the exact live owner authorization with the App publication token."""

    api = _preflight.GitHubAPI(
        api_url=os.environ.get("GITHUB_API_URL", ""),
        token=token,
        repository=repository,
    )
    trusted_sha = _preflight._current_main(api)
    if trusted_sha != expected.base_sha:
        raise PermissionError("protected-maintenance current main drifted before publication")
    pr = _preflight._require_dict(
        api.get(f"/repos/{repository}/pulls/{expected.number}"),
        label="protected-maintenance publication pull request",
    )
    admission = _preflight._resolve_subject(
        api,
        lane=_preflight.PROTECTED_OWNER_LANE,
        pr=pr,
        head_sha=expected.head_sha,
        trusted_sha=trusted_sha,
        qualification_ready=True,
    )
    if (
        admission.pr_number != expected.number
        or admission.head_sha != expected.head_sha
        or admission.base_sha != expected.base_sha
        or admission.merge_sha != expected.merge_sha
        or admission.trusted_sha != expected.base_sha
        or not admission.protected_changes
    ):
        raise PermissionError(
            "protected-maintenance authorization is not exact for status publication"
        )
    snapshot = _preflight._protected_owner_authorization(api, admission=admission)
    if snapshot is None:
        raise PermissionError("protected-maintenance exact owner authorization is absent")
    return snapshot

def _require_current_main(api: GitHubApi, expected: PullRequestSubject) -> None:
    payload = api.get_json(f"/repos/{api.repository}/git/ref/heads/main")
    if payload.get("ref") != "refs/heads/main":
        raise ValueError("trusted status current-main ref identity drifted")
    obj = payload.get("object")
    if not isinstance(obj, Mapping) or obj.get("type") != "commit":
        raise ValueError("trusted status current-main ref must point to a commit")
    observed = _require_sha(obj.get("sha"), label="current main SHA")
    if observed != expected.base_sha:
        raise ValueError(
            "current main changed after authorization: "
            f"expected {expected.base_sha}, observed {observed}"
        )


def report_automatic_result(
    *,
    repository: str,
    token: str,
    workflow_event: str,
    workflow_ref: str,
    lane: str,
    workflow_run_id: int | str,
    workflow_run_attempt: int | str,
    expected: PullRequestSubject,
    job_results: Mapping[str, str],
    target_url: str,
) -> dict[str, Any]:
    if workflow_event not in EXPECTED_WORKFLOW_EVENTS:
        raise PermissionError("trusted status publication requires workflow_run or schedule")
    reviewed_lanes = {"owner-routine", _preflight.PROTECTED_OWNER_LANE, *_preflight.BOT_LANES}
    if lane not in reviewed_lanes:
        raise PermissionError("trusted status publication lane is not reviewed")
    maintenance = lane == _preflight.PROTECTED_OWNER_LANE
    if maintenance and workflow_event != "workflow_run":
        raise PermissionError(
            "protected-maintenance status publication requires the accepted-main workflow_run lane"
        )
    if workflow_event == "schedule" and lane not in _preflight.BOT_LANES:
        raise PermissionError("scheduled trusted status publication is restricted to governed bot lanes")
    if workflow_ref != EXPECTED_WORKFLOW_REF:
        raise PermissionError("automatic trusted status publication requires refs/heads/main")
    run_id = _require_positive_int(workflow_run_id, label="trusted reporter workflow run id")
    run_attempt = _require_positive_int(
        workflow_run_attempt,
        label="trusted reporter workflow run attempt",
    )
    if run_attempt != 1:
        raise PermissionError("trusted status publication requires workflow run attempt 1")
    expected_target_url = f"https://github.com/{repository}/actions/runs/{run_id}"
    if target_url != expected_target_url:
        raise PermissionError("trusted status target URL is not the exact reporter workflow run")
    if set(job_results) != {"validation"}:
        raise ValueError("trusted validation results must contain exactly the validation job")
    validation_result = job_results["validation"]
    if validation_result not in {"cancelled", "failure", "skipped", "success"}:
        raise ValueError("trusted validation job has an invalid terminal result")

    authorization_snapshot = (
        _require_protected_owner_authorization(
            repository=repository,
            token=token,
            expected=expected,
        )
        if maintenance
        else None
    )
    api = GitHubApi(repository=repository, token=token)
    _require_current_main(api, expected)
    current = resolve_current_subject(api, expected)
    _require_current_main(api, current)
    if validation_result == "success":
        state = "success"
        description = (
            "Protected-maintenance exact-subject trusted validation passed"
            if maintenance
            else "Automatic exact-subject trusted validation passed"
        )
    else:
        state = "failure"
        description = (
            f"Protected-maintenance trusted validation ended {validation_result}"
            if maintenance
            else f"Automatic trusted validation ended {validation_result}"
        )
    bound_target_url = (
        f"{target_url}?pr={current.number}&base={current.base_sha}"
        f"&head={current.head_sha}&merge={current.merge_sha}"
    )
    publication_authorization_snapshot = (
        _require_protected_owner_authorization(
            repository=repository,
            token=token,
            expected=current,
        )
        if maintenance
        else None
    )
    if maintenance and publication_authorization_snapshot != authorization_snapshot:
        raise PermissionError(
            "protected-maintenance authorization changed before status publication"
        )
    api.post_status(
        sha=current.head_sha,
        state=state,
        description=description,
        target_url=bound_target_url,
    )
    return {
        "result": state.upper(),
        "status_posted": True,
        "status_context": TRUSTED_STATUS_CONTEXT,
        "status_subject": current.head_sha,
        "status_target_url": bound_target_url,
        "validation_result": validation_result,
        "authorization_mode": (
            "explicit-default-branch-protected-maintenance"
            if maintenance
            else "automatic-default-branch"
        ),
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
    parser.add_argument("--lane", required=True)
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
        lane=args.lane,
        workflow_run_id=os.environ.get("GITHUB_RUN_ID", ""),
        workflow_run_attempt=os.environ.get("GITHUB_RUN_ATTEMPT", ""),
        expected=_subject_from_args(args),
        job_results=parse_job_results(args.job_results_json),
        target_url=args.target_url,
    )
    print(json.dumps({"result": result["result"], "reporter": "trusted-pr-gate"}, sort_keys=True))
    if result["result"] == "FAILURE":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
