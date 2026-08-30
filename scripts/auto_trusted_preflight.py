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
from typing import Any
from urllib.parse import quote

EXPECTED_REPOSITORY = "portyu9/ai-qa-automation"
EXPECTED_OWNER = "portyu9"
EXPECTED_DEFAULT_BRANCH = "main"
EXPECTED_WORKFLOW_ID = 339754724
EXPECTED_WORKFLOW_NAME = "CI — ƳƤ AI QA Automation Framework"
EXPECTED_WORKFLOW_PATH = ".github/workflows/ci.yml"
MAX_EVENT_BYTES = 2 * 1024 * 1024
MAX_API_BYTES = 8 * 1024 * 1024
MAX_PULL_REQUEST_CANDIDATES = 100
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
PROTECTED_PATHS = (
    ".github",
    ".claude",
    ".dockerignore",
    ".gitattributes",
    ".mcp.json",
    ".pre-commit-config.yaml",
    "CLAUDE.md",
    "Dockerfile",
    "evals",
    "examples",
    "pyproject.toml",
    "requirements",
    "scripts",
    "tests",
    "src/ai_qa_automation/__init__.py",
    "src/ai_qa_automation/io_safety.py",
    "src/ai_qa_automation/tools/__init__.py",
    "src/ai_qa_automation/tools/execution_env.py",
)


@dataclass(frozen=True)
class Admission:
    pr_number: int
    head_sha: str
    base_sha: str
    merge_sha: str
    trusted_sha: str
    protected_changes: tuple[dict[str, str], ...]

    @property
    def eligible(self) -> bool:
        return not self.protected_changes


class GitHubAPI:
    def __init__(self, *, api_url: str, token: str, repository: str) -> None:
        if api_url != "https://api.github.com":
            raise ValueError("automatic trusted admission requires the canonical GitHub API")
        if repository != EXPECTED_REPOSITORY:
            raise ValueError("automatic trusted admission is bound to the expected repository")
        if not token:
            raise ValueError("GITHUB_TOKEN is required for read-only live admission")
        self._api_url = api_url.rstrip("/")
        self._token = token
        self._repository = repository

    def get(self, path: str) -> Any:
        if not path.startswith("/") or ".." in path:
            raise ValueError("GitHub API path must be an absolute fixed-repository path")
        url = f"{self._api_url}{path}"
        request = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {self._token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "yp-ai-qa-trusted-admission",
            },
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                content_length = response.headers.get("Content-Length")
                if content_length is not None and int(content_length) > MAX_API_BYTES:
                    raise ValueError("GitHub API response exceeds bounded ingestion limit")
                payload = response.read(MAX_API_BYTES + 1)
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"GitHub API GET failed with HTTP {exc.code}: {path}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"GitHub API GET failed: {path}") from exc
        if len(payload) > MAX_API_BYTES:
            raise ValueError("GitHub API response exceeds bounded ingestion limit")
        try:
            return json.loads(payload)
        except json.JSONDecodeError as exc:
            raise ValueError("GitHub API returned malformed JSON") from exc


def _require_dict(value: Any, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _require_list(value: Any, *, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be a JSON array")
    return value


def _require_str(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    return value


def _require_sha(value: Any, *, label: str) -> str:
    rendered = _require_str(value, label=label)
    if SHA_RE.fullmatch(rendered) is None:
        raise ValueError(f"{label} must be a full lowercase SHA-1 object ID")
    return rendered


def _require_positive_int(value: Any, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _read_json_file(path: Path, *, max_bytes: int, label: str) -> Any:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise RuntimeError("trusted admission requires no-follow event-file ingestion")
    flags = os.O_RDONLY | nofollow | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"{label} cannot be opened as an owned regular file") from exc
    try:
        initial = os.fstat(fd)
        if not stat.S_ISREG(initial.st_mode) or initial.st_size > max_bytes:
            raise ValueError(f"{label} is not a bounded regular file")
        payload = bytearray()
        while len(payload) <= max_bytes:
            chunk = os.read(fd, min(1024 * 1024, max_bytes + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) > max_bytes:
            raise ValueError(f"{label} exceeds bounded ingestion limit")
        final = os.fstat(fd)
        initial_signature = (
            initial.st_dev,
            initial.st_ino,
            initial.st_size,
            initial.st_mtime_ns,
            initial.st_ctime_ns,
        )
        final_signature = (
            final.st_dev,
            final.st_ino,
            final.st_size,
            final.st_mtime_ns,
            final.st_ctime_ns,
        )
        if final_signature != initial_signature:
            raise ValueError(f"{label} changed during ingestion")
    finally:
        os.close(fd)
    try:
        return json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} is malformed JSON") from exc


def _validate_live_run(run: dict[str, Any], *, expected_run_id: int) -> str:
    if _require_positive_int(run.get("id"), label="workflow run id") != expected_run_id:
        raise ValueError("workflow run identity drifted")
    if _require_positive_int(run.get("workflow_id"), label="workflow id") != EXPECTED_WORKFLOW_ID:
        raise ValueError("workflow run is not the reviewed CI workflow")
    if run.get("name") != EXPECTED_WORKFLOW_NAME or run.get("path") != EXPECTED_WORKFLOW_PATH:
        raise ValueError("workflow run name/path differs from the reviewed CI workflow")
    if run.get("event") != "pull_request":
        raise ValueError("automatic trusted admission only accepts pull_request CI")
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        raise ValueError("automatic trusted admission requires a completed successful CI run")
    repository = _require_dict(run.get("repository"), label="workflow repository")
    head_repository = _require_dict(run.get("head_repository"), label="workflow head repository")
    if repository.get("full_name") != EXPECTED_REPOSITORY:
        raise ValueError("workflow run repository identity mismatch")
    if head_repository.get("full_name") != EXPECTED_REPOSITORY:
        raise ValueError("fork/external-head workflow runs are not auto-authorized")
    actor = _require_dict(run.get("actor"), label="workflow actor")
    triggering_actor = _require_dict(run.get("triggering_actor"), label="workflow triggering actor")
    if actor.get("login") != EXPECTED_OWNER or triggering_actor.get("login") != EXPECTED_OWNER:
        raise ValueError("automatic trusted admission requires the repository owner workflow actor")
    return _require_sha(run.get("head_sha"), label="workflow head SHA")


def _select_pull_request(candidates: Any, *, head_sha: str) -> int:
    rows = _require_list(candidates, label="commit pull requests")
    if len(rows) >= MAX_PULL_REQUEST_CANDIDATES:
        raise ValueError("commit pull-request resolution reached the bounded pagination limit")
    matching: list[int] = []
    for raw in rows:
        row = _require_dict(raw, label="pull request candidate")
        head = _require_dict(row.get("head"), label="pull request candidate head")
        base = _require_dict(row.get("base"), label="pull request candidate base")
        head_repo = _require_dict(head.get("repo"), label="pull request candidate head repository")
        base_repo = _require_dict(base.get("repo"), label="pull request candidate base repository")
        if (
            row.get("state") == "open"
            and head.get("sha") == head_sha
            and head_repo.get("full_name") == EXPECTED_REPOSITORY
            and base.get("ref") == EXPECTED_DEFAULT_BRANCH
            and base_repo.get("full_name") == EXPECTED_REPOSITORY
        ):
            matching.append(_require_positive_int(row.get("number"), label="pull request number"))
    if len(matching) != 1:
        raise ValueError(
            "workflow head must resolve to exactly one open same-repository pull request targeting main"
        )
    return matching[0]


def _validate_pull_request(
    pr: dict[str, Any],
    *,
    expected_number: int,
    head_sha: str,
    current_main_sha: str,
) -> str:
    if _require_positive_int(pr.get("number"), label="live pull request number") != expected_number:
        raise ValueError("live pull request number drifted")
    if pr.get("state") != "open" or pr.get("draft") is not False:
        raise ValueError("automatic trusted admission requires an open non-draft pull request")
    head = _require_dict(pr.get("head"), label="live pull request head")
    base = _require_dict(pr.get("base"), label="live pull request base")
    head_repo = _require_dict(head.get("repo"), label="live pull request head repository")
    base_repo = _require_dict(base.get("repo"), label="live pull request base repository")
    if head.get("sha") != head_sha or head_repo.get("full_name") != EXPECTED_REPOSITORY:
        raise ValueError("live pull request head identity drifted")
    if (
        base.get("ref") != EXPECTED_DEFAULT_BRANCH
        or base_repo.get("full_name") != EXPECTED_REPOSITORY
    ):
        raise ValueError("live pull request no longer targets the expected repository main branch")
    base_sha = _require_sha(base.get("sha"), label="live pull request base SHA")
    if base_sha != current_main_sha:
        raise ValueError("pull request base is stale relative to current main")
    return base_sha


def _ref_commit_sha(payload: Any, *, expected_ref: str, label: str) -> str:
    ref = _require_dict(payload, label=label)
    if ref.get("ref") != expected_ref:
        raise ValueError(f"{label} must identify exactly {expected_ref}")
    obj = _require_dict(ref.get("object"), label=f"{label} object")
    if obj.get("type") != "commit":
        raise ValueError(f"{label} must point to a commit")
    return _require_sha(obj.get("sha"), label=f"{label} SHA")


def _validate_git_commit(payload: Any, *, expected_sha: str, label: str) -> dict[str, Any]:
    commit = _require_dict(payload, label=label)
    observed_sha = _require_sha(commit.get("sha"), label=f"{label} SHA")
    if observed_sha != expected_sha:
        raise ValueError(f"{label} identity drifted")
    return commit


def _tree_index(payload: Any, *, label: str) -> dict[str, str]:
    data = _require_dict(payload, label=label)
    if data.get("truncated") is not False:
        raise ValueError(f"{label} is truncated or missing truncation truth")
    rows = _require_list(data.get("tree"), label=f"{label} entries")
    index: dict[str, str] = {}
    for raw in rows:
        row = _require_dict(raw, label=f"{label} entry")
        path = _require_str(row.get("path"), label=f"{label} path")
        if path in index:
            raise ValueError(f"{label} contains duplicate path entries")
        index[path] = _require_sha(row.get("sha"), label=f"{label} object ID")
    return index


def _protected_changes(
    base_tree: dict[str, str], subject_tree: dict[str, str]
) -> tuple[dict[str, str], ...]:
    rows: list[dict[str, str]] = []
    for path in PROTECTED_PATHS:
        base_oid = base_tree.get(path, "MISSING")
        subject_oid = subject_tree.get(path, "MISSING")
        if base_oid != subject_oid:
            rows.append({"path": path, "base_oid": base_oid, "subject_oid": subject_oid})
    return tuple(rows)


def evaluate_admission(api: GitHubAPI, *, event: dict[str, Any]) -> Admission:
    if event.get("action") != "completed":
        raise ValueError("workflow_run event action must be completed")
    event_run = _require_dict(event.get("workflow_run"), label="workflow_run event")
    run_id = _require_positive_int(event_run.get("id"), label="event workflow run id")

    live_run = _require_dict(
        api.get(f"/repos/{EXPECTED_REPOSITORY}/actions/runs/{run_id}"),
        label="live workflow run",
    )
    head_sha = _validate_live_run(live_run, expected_run_id=run_id)
    if event_run.get("head_sha") != head_sha:
        raise ValueError("workflow_run event head SHA differs from live run")

    pulls = api.get(
        f"/repos/{EXPECTED_REPOSITORY}/commits/{head_sha}/pulls"
        f"?per_page={MAX_PULL_REQUEST_CANDIDATES}"
    )
    pr_number = _select_pull_request(pulls, head_sha=head_sha)

    expected_main_ref = f"refs/heads/{EXPECTED_DEFAULT_BRANCH}"
    trusted_sha = _ref_commit_sha(
        api.get(
            f"/repos/{EXPECTED_REPOSITORY}/git/ref/heads/{quote(EXPECTED_DEFAULT_BRANCH, safe='')}"
        ),
        expected_ref=expected_main_ref,
        label="main ref",
    )

    pr = _require_dict(
        api.get(f"/repos/{EXPECTED_REPOSITORY}/pulls/{pr_number}"),
        label="live pull request",
    )
    base_sha = _validate_pull_request(
        pr,
        expected_number=pr_number,
        head_sha=head_sha,
        current_main_sha=trusted_sha,
    )

    expected_merge_ref = f"refs/pull/{pr_number}/merge"
    merge_sha = _ref_commit_sha(
        api.get(f"/repos/{EXPECTED_REPOSITORY}/git/ref/pull/{pr_number}/merge"),
        expected_ref=expected_merge_ref,
        label="pull request merge ref",
    )
    merge_commit = _validate_git_commit(
        api.get(f"/repos/{EXPECTED_REPOSITORY}/git/commits/{merge_sha}"),
        expected_sha=merge_sha,
        label="prospective merge commit",
    )
    parents = _require_list(merge_commit.get("parents"), label="prospective merge parents")
    if len(parents) != 2:
        raise ValueError("prospective merge commit must have exactly two parents")
    parent_shas = [
        _require_sha(_require_dict(item, label="merge parent").get("sha"), label="merge parent SHA")
        for item in parents
    ]
    if parent_shas != [base_sha, head_sha]:
        raise ValueError("prospective merge parent order does not match exact base/head")

    base_commit = _validate_git_commit(
        api.get(f"/repos/{EXPECTED_REPOSITORY}/git/commits/{base_sha}"),
        expected_sha=base_sha,
        label="base commit",
    )
    base_tree_ref = _require_dict(base_commit.get("tree"), label="base commit tree")
    merge_tree_ref = _require_dict(merge_commit.get("tree"), label="merge commit tree")
    base_tree_sha = _require_sha(base_tree_ref.get("sha"), label="base tree SHA")
    merge_tree_sha = _require_sha(merge_tree_ref.get("sha"), label="merge tree SHA")
    base_tree = _tree_index(
        api.get(f"/repos/{EXPECTED_REPOSITORY}/git/trees/{base_tree_sha}?recursive=1"),
        label="base recursive tree",
    )
    merge_tree = _tree_index(
        api.get(f"/repos/{EXPECTED_REPOSITORY}/git/trees/{merge_tree_sha}?recursive=1"),
        label="merge recursive tree",
    )

    return Admission(
        pr_number=pr_number,
        head_sha=head_sha,
        base_sha=base_sha,
        merge_sha=merge_sha,
        trusted_sha=trusted_sha,
        protected_changes=_protected_changes(base_tree, merge_tree),
    )


def write_github_outputs(path: Path, admission: Admission) -> None:
    values = {
        "eligible": "true" if admission.eligible else "false",
        "pr_number": str(admission.pr_number),
        "head_sha": admission.head_sha,
        "base_sha": admission.base_sha,
        "merge_sha": admission.merge_sha,
        "trusted_sha": admission.trusted_sha,
        "protected_changes_json": json.dumps(
            admission.protected_changes, separators=(",", ":"), sort_keys=True
        ),
    }
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        for key, value in values.items():
            if "\n" in value or "\r" in value:
                raise ValueError("GitHub output value contains a newline")
            handle.write(f"{key}={value}\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event", type=Path, required=True)
    parser.add_argument("--github-output", type=Path, required=True)
    args = parser.parse_args()

    repository = os.environ.get("GITHUB_REPOSITORY", "")
    api_url = os.environ.get("GITHUB_API_URL", "")
    token = os.environ.get("GITHUB_TOKEN", "")
    event = _require_dict(
        _read_json_file(args.event, max_bytes=MAX_EVENT_BYTES, label="workflow event"),
        label="workflow event",
    )
    admission = evaluate_admission(
        GitHubAPI(api_url=api_url, token=token, repository=repository),
        event=event,
    )
    write_github_outputs(args.github_output, admission)
    summary = {
        "eligible": admission.eligible,
        "pr_number": admission.pr_number,
        "head_sha": admission.head_sha,
        "base_sha": admission.base_sha,
        "merge_sha": admission.merge_sha,
        "trusted_sha": admission.trusted_sha,
        "protected_changes": admission.protected_changes,
    }
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
