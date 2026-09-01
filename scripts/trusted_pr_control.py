from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

API_ROOT = "https://api.github.com"
API_VERSION = "2026-03-10"
EXPECTED_BASE_REF = "main"
EXPECTED_WORKFLOW_REF = "refs/heads/main"
TRUSTED_STATUS_CONTEXT = "Trusted PR Gate"
MAX_API_RESPONSE_BYTES = 1024 * 1024
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

    def fetch_pull_request_merge_ref(self, number: int) -> Mapping[str, Any]:
        if number < 1:
            raise ValueError("pull-request number must be positive")
        return self.get_json(f"/repos/{self.repository}/git/ref/pull/{number}/merge")

    def fetch_git_commit(self, sha: str) -> Mapping[str, Any]:
        return self.get_json(
            f"/repos/{self.repository}/git/commits/{_require_sha(sha, label='merge commit SHA')}"
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
    """Parse a complete PR REST response; terminal reporting does not rely on this shape."""
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


def _merge_ref_sha(payload: Mapping[str, Any], *, number: int) -> str:
    expected_ref = f"refs/pull/{number}/merge"
    if payload.get("ref") != expected_ref:
        raise ValueError(f"pull-request merge ref must be exactly {expected_ref!r}")
    obj = _mapping(payload.get("object"), label="pull-request merge ref object")
    if obj.get("type") != "commit":
        raise ValueError("pull-request merge ref must point to a commit")
    return _require_sha(obj.get("sha"), label="pull-request merge-ref SHA")


def _verify_merge_commit(expected: PullRequestSubject, payload: Mapping[str, Any]) -> None:
    commit_sha = _require_sha(payload.get("sha"), label="merge commit SHA")
    if commit_sha != expected.merge_sha:
        raise ValueError(
            "pull-request merge commit changed after authorization: "
            f"expected {expected.merge_sha}, observed {commit_sha}"
        )
    parents = payload.get("parents")
    if not isinstance(parents, list) or len(parents) != 2:
        raise ValueError("pull-request merge commit must have exactly two parents")
    parent_shas = tuple(
        _require_sha(_mapping(parent, label="merge commit parent").get("sha"), label="parent SHA")
        for parent in parents
    )
    expected_parents = (expected.base_sha, expected.head_sha)
    if parent_shas != expected_parents:
        raise ValueError(
            "pull-request merge commit parents changed after authorization: "
            f"expected {expected_parents}, observed {parent_shas}"
        )


def resolve_current_subject(
    api: GitHubApi,
    expected: PullRequestSubject,
) -> PullRequestSubject:
    """Bind status authority to GitHub's live PR identity and simulated merge ref."""
    _verify_current_identity(expected, api.fetch_pull_request(expected.number))

    merge_ref = api.fetch_pull_request_merge_ref(expected.number)
    observed_merge_sha = _merge_ref_sha(merge_ref, number=expected.number)
    if observed_merge_sha != expected.merge_sha:
        raise ValueError(
            "pull-request merge ref changed after authorization: "
            f"expected {expected.merge_sha}, observed {observed_merge_sha}"
        )

    _verify_merge_commit(expected, api.fetch_git_commit(expected.merge_sha))

    # Close the largest practical TOCTOU window before status publication. A head/base
    # change invalidates identity; a regenerated/conflicted merge invalidates the merge ref.
    _verify_current_identity(expected, api.fetch_pull_request(expected.number))
    final_merge_sha = _merge_ref_sha(
        api.fetch_pull_request_merge_ref(expected.number),
        number=expected.number,
    )
    if final_merge_sha != expected.merge_sha:
        raise ValueError(
            "pull-request merge ref changed before status publication: "
            f"expected {expected.merge_sha}, observed {final_merge_sha}"
        )
    return expected


def parse_job_results(raw: str) -> dict[str, str]:
    parsed = json.loads(raw)
    if not isinstance(parsed, dict) or set(parsed) != {"validation"}:
        raise ValueError("trusted validation results must contain exactly the validation job")
    result = parsed["validation"]
    if result not in TERMINAL_JOB_RESULTS:
        raise ValueError("trusted validation job has an invalid terminal result")
    return {"validation": result}
