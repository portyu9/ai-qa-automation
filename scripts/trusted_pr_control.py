from __future__ import annotations

import argparse
import json
import os
import re
import time
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

API_ROOT = "https://api.github.com"
API_VERSION = "2026-03-10"
EXPECTED_BASE_REF = "main"
EXPECTED_WORKFLOW_EVENT = "repository_dispatch"
EXPECTED_WORKFLOW_REF = "refs/heads/main"
TRUSTED_STATUS_CONTEXT = "Trusted PR Gate"
MAX_API_RESPONSE_BYTES = 1024 * 1024
MERGEABILITY_READ_ATTEMPTS = 6
MERGEABILITY_RETRY_SECONDS = 1.0
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
TERMINAL_JOB_RESULTS = {"cancelled", "failure", "skipped", "success"}


@dataclass(frozen=True)
class PullRequestSubject:
    number: int
    head_sha: str
    base_sha: str
    merge_sha: str


class GitHubApi:
    def __init__(self, *, repository: str, token: str) -> None:
        if not REPOSITORY_RE.fullmatch(repository):
            raise ValueError("GITHUB_REPOSITORY must be an owner/name repository identifier")
        if not token:
            raise ValueError("GITHUB_TOKEN is required")
        self.repository = repository
        self._token = token

    def _request(
        self,
        method: str,
        path: str,
        *,
        payload: Mapping[str, Any] | None = None,
    ) -> bytes:
        if not path.startswith("/") or ".." in path:
            raise ValueError("GitHub API path must be an absolute fixed-repository path")
        body = None
        if payload is not None:
            body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        request = urllib.request.Request(
            f"{API_ROOT}{path}",
            data=body,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token}",
                "X-GitHub-Api-Version": API_VERSION,
                "User-Agent": "yp-ai-qa-trusted-pr-control",
                **({"Content-Type": "application/json"} if body is not None else {}),
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                data = response.read(MAX_API_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            detail = exc.read(4096).decode("utf-8", errors="replace")
            raise RuntimeError(
                f"GitHub API {method} {path} failed with HTTP {exc.code}: {detail}"
            ) from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"GitHub API {method} {path} transport failure: {exc}") from exc
        if len(data) > MAX_API_RESPONSE_BYTES:
            raise RuntimeError("GitHub API response exceeds the bounded ingestion limit")
        return data

    def get_json(self, path: str) -> Mapping[str, Any]:
        data = self._request("GET", path)
        parsed = json.loads(data)
        if not isinstance(parsed, dict):
            raise RuntimeError("GitHub API response must be a JSON object")
        return parsed

    def post_json(self, path: str, payload: Mapping[str, Any]) -> Mapping[str, Any] | None:
        data = self._request("POST", path, payload=payload)
        if not data:
            return None
        parsed = json.loads(data)
        if not isinstance(parsed, dict):
            raise RuntimeError("GitHub API response must be a JSON object")
        return parsed

    def fetch_pull_request(self, number: int) -> Mapping[str, Any]:
        if number < 1:
            raise ValueError("pull-request number must be positive")
        return self.get_json(f"/repos/{self.repository}/pulls/{number}")

    def post_status(
        self,
        *,
        sha: str,
        state: str,
        description: str,
        target_url: str,
    ) -> None:
        _require_sha(sha, label="status subject")
        if state not in {"error", "failure", "pending", "success"}:
            raise ValueError("invalid GitHub commit-status state")
        if len(description) > 140:
            raise ValueError("commit-status description exceeds GitHub's 140-character limit")
        target_pattern = re.compile(
            rf"^https://github\.com/{re.escape(self.repository)}/actions/runs/[1-9][0-9]*$"
        )
        if target_pattern.fullmatch(target_url) is None:
            raise ValueError(
                "commit-status target URL must identify one workflow run in this repository"
            )
        self.post_json(
            f"/repos/{self.repository}/statuses/{sha}",
            {
                "state": state,
                "context": TRUSTED_STATUS_CONTEXT,
                "description": description,
                "target_url": target_url,
            },
        )


def _require_sha(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or FULL_SHA_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be a full lowercase 40-character Git object ID")
    return value


def _require_positive_int(value: Any, *, label: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{label} must be a positive integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be a positive integer") from exc
    if parsed < 1 or str(parsed) != str(value):
        raise ValueError(f"{label} must be a canonical positive integer")
    return parsed


def _mapping(value: Any, *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _pull_request_identity(payload: Mapping[str, Any]) -> tuple[int, str, str]:
    if payload.get("state") != "open":
        raise ValueError("pull request must remain open")
    number = _require_positive_int(payload.get("number"), label="pull-request number")
    head = _mapping(payload.get("head"), label="pull-request head")
    base = _mapping(payload.get("base"), label="pull-request base")
    if base.get("ref") != EXPECTED_BASE_REF:
        raise ValueError(f"pull request must target {EXPECTED_BASE_REF!r}")
    return (
        number,
        _require_sha(head.get("sha"), label="pull-request head SHA"),
        _require_sha(base.get("sha"), label="pull-request base SHA"),
    )


def subject_from_pull_request(payload: Mapping[str, Any]) -> PullRequestSubject:
    number, head_sha, base_sha = _pull_request_identity(payload)
    if payload.get("mergeable") is not True:
        raise ValueError("pull request must be currently and definitively mergeable")
    return PullRequestSubject(
        number=number,
        head_sha=head_sha,
        base_sha=base_sha,
        merge_sha=_require_sha(payload.get("merge_commit_sha"), label="pull-request merge SHA"),
    )


def verify_current_subject(
    expected: PullRequestSubject,
    current_payload: Mapping[str, Any],
) -> PullRequestSubject:
    current = subject_from_pull_request(current_payload)
    if current != expected:
        raise ValueError(
            "pull-request subject changed after authorization: "
            f"expected {expected}, observed {current}"
        )
    return current


def _verify_current_identity(
    expected: PullRequestSubject,
    current_payload: Mapping[str, Any],
) -> None:
    number, head_sha, base_sha = _pull_request_identity(current_payload)
    observed = (number, head_sha, base_sha)
    expected_identity = (expected.number, expected.head_sha, expected.base_sha)
    if observed != expected_identity:
        raise ValueError(
            "pull-request subject changed after authorization: "
            f"expected identity {expected_identity}, observed {observed}"
        )


def fetch_stable_current_subject(
    api: GitHubApi,
    expected: PullRequestSubject,
) -> PullRequestSubject:
    for attempt in range(MERGEABILITY_READ_ATTEMPTS):
        payload = api.fetch_pull_request(expected.number)
        _verify_current_identity(expected, payload)
        if "mergeable" not in payload:
            raise ValueError("pull-request mergeable field is required")
        if "merge_commit_sha" not in payload:
            raise ValueError("pull-request merge SHA field is required")
        mergeable = payload["mergeable"]
        merge_sha = payload["merge_commit_sha"]

        if mergeable is True and isinstance(merge_sha, str):
            _require_sha(merge_sha, label="pull-request merge SHA")
            return verify_current_subject(expected, payload)
        if mergeable is False:
            raise ValueError("pull request must be currently and definitively mergeable")
        if mergeable is not None and mergeable is not True:
            raise ValueError("pull-request mergeable state must be true, false, or null")
        if merge_sha is not None:
            _require_sha(merge_sha, label="pull-request merge SHA")

        if attempt + 1 == MERGEABILITY_READ_ATTEMPTS:
            raise RuntimeError(
                "pull-request mergeability did not stabilize within the bounded read window"
            )
        time.sleep(MERGEABILITY_RETRY_SECONDS)

    raise AssertionError("bounded mergeability loop exhausted unexpectedly")


def parse_job_results(raw: str) -> dict[str, str]:
    parsed = json.loads(raw)
    if not isinstance(parsed, dict) or set(parsed) != {"validation"}:
        raise ValueError("trusted validation results must contain exactly the validation job")
    result = parsed["validation"]
    if result not in TERMINAL_JOB_RESULTS:
        raise ValueError("trusted validation job has an invalid terminal result")
    return {"validation": result}


def _parse_bool(value: str) -> bool:
    if value == "true":
        return True
    if value == "false":
        return False
    raise ValueError("authorization value must be exactly 'true' or 'false'")


def report_authorized_result(
    *,
    repository: str,
    token: str,
    actor: str,
    repository_owner: str,
    workflow_event: str,
    workflow_ref: str,
    expected: PullRequestSubject,
    authorized: bool,
    job_results: Mapping[str, str],
    target_url: str,
) -> dict[str, Any]:
    if workflow_event != EXPECTED_WORKFLOW_EVENT:
        raise PermissionError("trusted status publication requires repository_dispatch")
    if workflow_ref != EXPECTED_WORKFLOW_REF:
        raise PermissionError("trusted status publication requires refs/heads/main")
    if not repository_owner or actor != repository_owner:
        raise PermissionError("trusted merge authorization must be dispatched by repository owner")

    api = GitHubApi(repository=repository, token=token)
    current = fetch_stable_current_subject(api, expected)
    if not authorized:
        return {
            "result": "DIAGNOSTIC_ONLY",
            "status_posted": False,
            "subject": {
                "pr_number": str(current.number),
                "expected_head_sha": current.head_sha,
                "expected_base_sha": current.base_sha,
                "expected_merge_sha": current.merge_sha,
            },
        }
    if set(job_results) != {"validation"}:
        raise ValueError("trusted validation results must contain exactly the validation job")
    validation_result = job_results["validation"]
    if validation_result not in TERMINAL_JOB_RESULTS:
        raise ValueError("trusted validation job has an invalid terminal result")
    if validation_result == "success":
        state = "success"
        description = "Owner-authorized exact-subject validation passed"
    else:
        state = "failure"
        description = f"Owner-authorized validation ended {validation_result}"
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
    }


def _subject_from_args(args: argparse.Namespace) -> PullRequestSubject:
    return PullRequestSubject(
        number=_require_positive_int(args.pr_number, label="pull-request number"),
        head_sha=_require_sha(args.expected_head_sha, label="expected head SHA"),
        base_sha=_require_sha(args.expected_base_sha, label="expected base SHA"),
        merge_sha=_require_sha(args.expected_merge_sha, label="expected merge SHA"),
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Trusted PR status reporter")
    parser.add_argument("command", nargs="?", default="report", choices=("report",))
    parser.add_argument("--pr-number", required=True)
    parser.add_argument("--expected-head-sha", required=True)
    parser.add_argument("--expected-base-sha", required=True)
    parser.add_argument("--expected-merge-sha", required=True)
    parser.add_argument("--authorized", required=True)
    parser.add_argument("--job-results-json", required=True)
    parser.add_argument("--target-url", required=True)
    return parser


def main() -> None:
    args = _parser().parse_args()
    result = report_authorized_result(
        repository=os.environ.get("GITHUB_REPOSITORY", ""),
        token=os.environ.get("GITHUB_TOKEN", ""),
        actor=os.environ.get("GITHUB_ACTOR", ""),
        repository_owner=os.environ.get("GITHUB_REPOSITORY_OWNER", ""),
        workflow_event=os.environ.get("GITHUB_EVENT_NAME", ""),
        workflow_ref=os.environ.get("GITHUB_REF", ""),
        expected=_subject_from_args(args),
        authorized=_parse_bool(args.authorized),
        job_results=parse_job_results(args.job_results_json),
        target_url=args.target_url,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    if result["result"] == "FAILURE":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
