from __future__ import annotations

import argparse
import json
import os
import re
import stat
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

API_ROOT = "https://api.github.com"
API_VERSION = "2026-03-10"
EXPECTED_BASE_REF = "main"
TRUSTED_VALIDATION_REF = "main"
TRUSTED_VALIDATION_WORKFLOW = "trusted-pr-validation.yml"
TRUSTED_STATUS_CONTEXT = "Trusted PR Gate"
MAX_API_RESPONSE_BYTES = 1024 * 1024
MAX_EVENT_BYTES = 1024 * 1024
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
AUTOMATIC_PR_ACTIONS = {
    "edited",
    "opened",
    "ready_for_review",
    "reopened",
    "synchronize",
}
TERMINAL_JOB_RESULTS = {"cancelled", "failure", "skipped", "success"}


@dataclass(frozen=True)
class PullRequestEventIdentity:
    number: int
    head_sha: str
    base_sha: str


@dataclass(frozen=True)
class PullRequestSubject:
    number: int
    head_sha: str
    base_sha: str
    merge_sha: str

    def as_dispatch_inputs(self, *, authorized: bool) -> dict[str, str]:
        return {
            "pr_number": str(self.number),
            "expected_head_sha": self.head_sha,
            "expected_base_sha": self.base_sha,
            "expected_merge_sha": self.merge_sha,
            "authorized": "true" if authorized else "false",
        }


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
            with urllib.request.urlopen(request, timeout=15) as response:  # noqa: S310
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

    def dispatch_validation(self, subject: PullRequestSubject) -> Mapping[str, Any] | None:
        return self.post_json(
            f"/repos/{self.repository}/actions/workflows/{TRUSTED_VALIDATION_WORKFLOW}/dispatches",
            {
                "ref": TRUSTED_VALIDATION_REF,
                "inputs": subject.as_dispatch_inputs(authorized=False),
            },
        )

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
        expected_target_prefix = f"https://github.com/{self.repository}/actions/runs/"
        if not target_url.startswith(expected_target_prefix):
            raise ValueError("commit-status target URL must identify a workflow run in this repository")
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


def subject_from_pull_request(payload: Mapping[str, Any]) -> PullRequestSubject:
    if payload.get("state") != "open":
        raise ValueError("pull request must remain open")
    number = _require_positive_int(payload.get("number"), label="pull-request number")
    head = _mapping(payload.get("head"), label="pull-request head")
    base = _mapping(payload.get("base"), label="pull-request base")
    if base.get("ref") != EXPECTED_BASE_REF:
        raise ValueError(f"pull request must target {EXPECTED_BASE_REF!r}")
    if payload.get("mergeable") is False:
        raise ValueError("pull request is currently not mergeable")
    return PullRequestSubject(
        number=number,
        head_sha=_require_sha(head.get("sha"), label="pull-request head SHA"),
        base_sha=_require_sha(base.get("sha"), label="pull-request base SHA"),
        merge_sha=_require_sha(payload.get("merge_commit_sha"), label="pull-request merge SHA"),
    )


def _file_signature(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns


def _read_json_file_bounded(path: Path, *, max_bytes: int) -> Mapping[str, Any]:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    if not getattr(os, "O_NOFOLLOW", 0):
        raise RuntimeError("trusted event ingestion requires O_NOFOLLOW")
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"unable to open trusted event payload safely: {path}") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"{path} must be a regular non-symlink file")
        if before.st_size > max_bytes:
            raise ValueError(f"{path} exceeds {max_bytes} byte ingestion limit")
        chunks: list[bytes] = []
        total = 0
        while total <= max_bytes:
            chunk = os.read(fd, min(64 * 1024, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if total > max_bytes:
            raise ValueError(f"{path} exceeds {max_bytes} byte ingestion limit")
        after = os.fstat(fd)
        current = path.stat(follow_symlinks=False)
        if (
            _file_signature(before) != _file_signature(after)
            or before.st_dev != current.st_dev
            or before.st_ino != current.st_ino
            or not stat.S_ISREG(current.st_mode)
        ):
            raise ValueError(f"{path} changed identity or content during ingestion")
    finally:
        os.close(fd)
    parsed = json.loads(b"".join(chunks))
    if not isinstance(parsed, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return parsed


def subject_from_target_event(event: Mapping[str, Any]) -> tuple[str, PullRequestEventIdentity]:
    action = event.get("action")
    if action not in AUTOMATIC_PR_ACTIONS:
        raise ValueError(f"unsupported pull_request_target action: {action!r}")
    repository = _mapping(event.get("repository"), label="event repository")
    repository_name = repository.get("full_name")
    if not isinstance(repository_name, str) or REPOSITORY_RE.fullmatch(repository_name) is None:
        raise ValueError("event repository full_name is invalid")
    pull_request = _mapping(event.get("pull_request"), label="event pull request")
    if pull_request.get("state") != "open":
        raise ValueError("event pull request must remain open")
    number = _require_positive_int(pull_request.get("number"), label="pull-request number")
    head = _mapping(pull_request.get("head"), label="pull-request head")
    base = _mapping(pull_request.get("base"), label="pull-request base")
    if base.get("ref") != EXPECTED_BASE_REF:
        raise ValueError(f"pull request must target {EXPECTED_BASE_REF!r}")
    return repository_name, PullRequestEventIdentity(
        number=number,
        head_sha=_require_sha(head.get("sha"), label="event head SHA"),
        base_sha=_require_sha(base.get("sha"), label="event base SHA"),
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
    raise ValueError("boolean workflow input must be exactly 'true' or 'false'")


def dispatch_from_event(*, event_path: Path, token: str) -> dict[str, Any]:
    event = _read_json_file_bounded(event_path, max_bytes=MAX_EVENT_BYTES)
    repository, event_identity = subject_from_target_event(event)
    api = GitHubApi(repository=repository, token=token)
    current = subject_from_pull_request(api.fetch_pull_request(event_identity.number))
    if (
        current.number != event_identity.number
        or current.head_sha != event_identity.head_sha
        or current.base_sha != event_identity.base_sha
    ):
        raise ValueError("pull-request head/base changed between event delivery and dispatch")
    api.dispatch_validation(current)
    return {
        "result": "DISPATCHED",
        "repository": repository,
        "subject": current.as_dispatch_inputs(authorized=False),
        "workflow": TRUSTED_VALIDATION_WORKFLOW,
        "ref": TRUSTED_VALIDATION_REF,
    }


def report_authorized_result(
    *,
    repository: str,
    token: str,
    actor: str,
    repository_owner: str,
    expected: PullRequestSubject,
    authorized: bool,
    job_results: Mapping[str, str],
    target_url: str,
) -> dict[str, Any]:
    api = GitHubApi(repository=repository, token=token)
    current = verify_current_subject(expected, api.fetch_pull_request(expected.number))
    if not authorized:
        return {
            "result": "DIAGNOSTIC_ONLY",
            "status_posted": False,
            "subject": current.as_dispatch_inputs(authorized=False),
        }
    if not repository_owner or actor != repository_owner:
        raise PermissionError("trusted merge authorization must be dispatched by repository owner")
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
    parser = argparse.ArgumentParser(description="Trusted PR control-plane helper")
    subparsers = parser.add_subparsers(dest="command", required=True)

    dispatch = subparsers.add_parser("dispatch", help="dispatch trusted main-ref PR validation")
    dispatch.add_argument("--event-path", type=Path, required=True)

    report = subparsers.add_parser("report", help="publish owner-authorized terminal PR status")
    report.add_argument("--pr-number", required=True)
    report.add_argument("--expected-head-sha", required=True)
    report.add_argument("--expected-base-sha", required=True)
    report.add_argument("--expected-merge-sha", required=True)
    report.add_argument("--authorized", required=True)
    report.add_argument("--job-results-json", required=True)
    report.add_argument("--target-url", required=True)
    return parser


def main() -> None:
    args = _parser().parse_args()
    token = os.environ.get("GITHUB_TOKEN", "")
    if args.command == "dispatch":
        result = dispatch_from_event(event_path=args.event_path, token=token)
    else:
        repository = os.environ.get("GITHUB_REPOSITORY", "")
        actor = os.environ.get("GITHUB_ACTOR", "")
        repository_owner = os.environ.get("GITHUB_REPOSITORY_OWNER", "")
        result = report_authorized_result(
            repository=repository,
            token=token,
            actor=actor,
            repository_owner=repository_owner,
            expected=_subject_from_args(args),
            authorized=_parse_bool(args.authorized),
            job_results=parse_job_results(args.job_results_json),
            target_url=args.target_url,
        )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
