from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote

EXPECTED_REPOSITORY = "portyu9/ai-qa-automation"
EXPECTED_OWNER = "portyu9"
EXPECTED_OWNER_ID = 35150859
EXPECTED_DEFAULT_BRANCH = "main"
EXPECTED_CI_WORKFLOW_ID = 339754724
EXPECTED_CI_WORKFLOW_NAME = "CI — ƳƤ AI QA Automation Framework"
EXPECTED_CI_WORKFLOW_PATH = ".github/workflows/ci.yml"
EXPECTED_CODEQL_WORKFLOW_ID = 359681647
EXPECTED_CODEQL_WORKFLOW_NAME = "CodeQL"
EXPECTED_CODEQL_WORKFLOW_PATH = ".github/workflows/codeql.yml"
GITHUB_ACTIONS_LOGIN = "github-actions[bot]"
GITHUB_ACTIONS_USER_ID = 41898282
DEPENDABOT_LOGIN = "dependabot[bot]"
DEPENDABOT_USER_ID = 49699333
GITHUB_ACTIONS_APP_ID = 15368
MAX_EVENT_BYTES = 2 * 1024 * 1024
MAX_API_BYTES = 8 * 1024 * 1024
MAX_PULL_REQUEST_CANDIDATES = 100
MAX_API_PAGES = 4
TRANSIENT_GET_ATTEMPTS = 3
TRANSIENT_GET_DELAY_SECONDS = 1
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DEPENDABOT_ACTION_REF_RE = re.compile(
    r"^dependabot/github_actions/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*$"
)
PROMOTION_REF_RE = re.compile(r"^automation/dependency-promotion-[1-9][0-9]*-[0-9a-f]{12}$")
AUTOHEAL_REF_RE = re.compile(r"^automation/codeql-autoheal-[1-9][0-9]*-[0-9a-f]{12}$")
PROTECTED_REMEDIATION_REF_RE = re.compile(
    r"^automation/protected-security-remediation-[1-9][0-9]*-[0-9a-f]{64}-a[1-9][0-9]*$"
)
PROTECTED_REMEDIATION_BOT_LOGIN_ENV = "PROTECTED_REMEDIATION_BOT_LOGIN"
PROTECTED_REMEDIATION_BOT_ID_ENV = "PROTECTED_REMEDIATION_BOT_ID"
DEPENDENCY_PROMOTION_BOT_LOGIN_ENV = "DEPENDENCY_PROMOTION_BOT_LOGIN"
DEPENDENCY_PROMOTION_BOT_ID_ENV = "DEPENDENCY_PROMOTION_BOT_ID"
DISALLOWED_PROTECTED_AUTHOR_LOGINS = {
    GITHUB_ACTIONS_LOGIN,
    DEPENDABOT_LOGIN,
    "trusted-pr-gate[bot]",
}
BOT_LANES = {
    "dependabot-actions",
    "dependency-promotion",
    "security-autoheal",
    "protected-security-remediation",
}
BOT_LANE_ORDER = {
    "protected-security-remediation": 0,
    "security-autoheal": 1,
    "dependabot-actions": 2,
    "dependency-promotion": 3,
}
PROTECTED_PATHS = (
    ".github",
    "scripts",
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
    "src/ai_qa_automation/__init__.py",
    "src/ai_qa_automation/io_safety.py",
    "src/ai_qa_automation/tools/__init__.py",
    "src/ai_qa_automation/tools/execution_env.py",
)
ROOT = Path(__file__).resolve().parents[1]
QUALIFICATION_PATH = ROOT / ".github" / "scripts" / "trusted_qualification.py"


@dataclass(frozen=True)
class Wake:
    run_id: int
    run_attempt: int
    kind: str
    head_sha: str


@dataclass(frozen=True)
class Admission:
    lane: str
    pr_number: int
    head_ref: str
    head_sha: str
    base_sha: str
    merge_sha: str
    trusted_sha: str
    protected_changes: tuple[dict[str, str], ...]
    qualification_ready: bool

    @property
    def eligible(self) -> bool:
        if self.lane == "owner-routine":
            return self.qualification_ready and not self.protected_changes
        if self.lane in BOT_LANES:
            return self.qualification_ready
        return False


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
        for attempt in range(TRANSIENT_GET_ATTEMPTS):
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
                break
            except urllib.error.HTTPError as exc:
                if exc.code in {502, 503, 504} and attempt + 1 < TRANSIENT_GET_ATTEMPTS:
                    time.sleep(TRANSIENT_GET_DELAY_SECONDS)
                    continue
                raise RuntimeError(f"GitHub API GET failed with HTTP {exc.code}: {path}") from exc
            except urllib.error.URLError as exc:
                if attempt + 1 < TRANSIENT_GET_ATTEMPTS:
                    time.sleep(TRANSIENT_GET_DELAY_SECONDS)
                    continue
                raise RuntimeError(f"GitHub API GET failed: {path}") from exc
        if len(payload) > MAX_API_BYTES:
            raise ValueError("GitHub API response exceeds bounded ingestion limit")
        try:
            return json.loads(payload)
        except json.JSONDecodeError as exc:
            raise ValueError("GitHub API returned malformed JSON") from exc

    def list_all(self, path: str, *, max_pages: int = MAX_API_PAGES) -> list[dict[str, Any]]:
        if max_pages < 1 or max_pages > MAX_API_PAGES:
            raise ValueError("GitHub pagination bound is outside reviewed limits")
        separator = "&" if "?" in path else "?"
        rows: list[dict[str, Any]] = []
        for page in range(1, max_pages + 1):
            payload = self.get(f"{path}{separator}per_page=100&page={page}")
            if isinstance(payload, list):
                page_rows = payload
            elif isinstance(payload, dict):
                if isinstance(payload.get("check_runs"), list):
                    page_rows = payload["check_runs"]
                elif isinstance(payload.get("workflow_runs"), list):
                    page_rows = payload["workflow_runs"]
                else:
                    raise ValueError("paginated GitHub response has unsupported object shape")
            else:
                raise ValueError("paginated GitHub response must be an array or supported object")
            for row in page_rows:
                if not isinstance(row, dict):
                    raise ValueError("paginated GitHub response contains a non-object row")
                rows.append(row)
            if len(page_rows) < 100:
                return rows
        raise ValueError("GitHub pagination reached the fail-closed page bound")


def _load_qualification_module() -> Any:
    info = QUALIFICATION_PATH.stat(follow_symlinks=False)
    if QUALIFICATION_PATH.is_symlink() or not stat.S_ISREG(info.st_mode):
        raise RuntimeError("trusted qualification verifier must be a regular non-symlink file")
    spec = importlib.util.spec_from_file_location("aiqa_trusted_qualification", QUALIFICATION_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load trusted qualification verifier")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


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
        if (
            initial.st_dev,
            initial.st_ino,
            initial.st_size,
            initial.st_mtime_ns,
            initial.st_ctime_ns,
        ) != (
            final.st_dev,
            final.st_ino,
            final.st_size,
            final.st_mtime_ns,
            final.st_ctime_ns,
        ):
            raise ValueError(f"{label} changed during ingestion")
    finally:
        os.close(fd)
    try:
        return json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} is malformed JSON") from exc


def _current_main(api: GitHubAPI) -> str:
    expected_ref = f"refs/heads/{EXPECTED_DEFAULT_BRANCH}"
    return _ref_commit_sha(
        api.get(
            f"/repos/{EXPECTED_REPOSITORY}/git/ref/heads/{quote(EXPECTED_DEFAULT_BRANCH, safe='')}"
        ),
        expected_ref=expected_ref,
        label="main ref",
    )


def _validate_wake(run: dict[str, Any], *, expected_run_id: int, trusted_sha: str) -> Wake | None:
    if _require_positive_int(run.get("id"), label="workflow run id") != expected_run_id:
        raise ValueError("workflow run identity drifted")
    attempt = _require_positive_int(run.get("run_attempt"), label="workflow run attempt")
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        return None
    repository = _require_dict(run.get("repository"), label="workflow repository")
    head_repository = _require_dict(run.get("head_repository"), label="workflow head repository")
    if (
        repository.get("full_name") != EXPECTED_REPOSITORY
        or head_repository.get("full_name") != EXPECTED_REPOSITORY
    ):
        raise ValueError("workflow run repository identity mismatch")

    workflow_id = _require_positive_int(run.get("workflow_id"), label="workflow id")
    actor = _require_dict(run.get("actor"), label="workflow actor")
    triggering_actor = _require_dict(run.get("triggering_actor"), label="workflow triggering actor")

    if (
        workflow_id == EXPECTED_CI_WORKFLOW_ID
        and run.get("name") == EXPECTED_CI_WORKFLOW_NAME
        and run.get("path") == EXPECTED_CI_WORKFLOW_PATH
        and run.get("event") == "pull_request"
    ):
        if (
            actor.get("login") != EXPECTED_OWNER
            or actor.get("id") != EXPECTED_OWNER_ID
            or triggering_actor.get("login") != EXPECTED_OWNER
            or triggering_actor.get("id") != EXPECTED_OWNER_ID
        ):
            return None
        return Wake(
            run_id=expected_run_id,
            run_attempt=attempt,
            kind="owner-ci",
            head_sha=_require_sha(run.get("head_sha"), label="workflow head SHA"),
        )

    expected_dispatch = {
        EXPECTED_CI_WORKFLOW_ID: (
            EXPECTED_CI_WORKFLOW_NAME,
            EXPECTED_CI_WORKFLOW_PATH,
            "Required PR Gate",
        ),
        EXPECTED_CODEQL_WORKFLOW_ID: (
            EXPECTED_CODEQL_WORKFLOW_NAME,
            EXPECTED_CODEQL_WORKFLOW_PATH,
            "CodeQL",
        ),
    }.get(workflow_id)
    if expected_dispatch is None:
        return None
    workflow_name, workflow_path, check_name = expected_dispatch
    if (
        run.get("name") != workflow_name
        or run.get("path") != workflow_path
        or run.get("event") != "workflow_dispatch"
        or run.get("head_branch") != EXPECTED_DEFAULT_BRANCH
        or _require_sha(run.get("head_sha"), label="trusted dispatch head SHA") != trusted_sha
    ):
        return None
    if (
        actor.get("login") != GITHUB_ACTIONS_LOGIN
        or actor.get("id") != GITHUB_ACTIONS_USER_ID
        or triggering_actor.get("login") != GITHUB_ACTIONS_LOGIN
        or triggering_actor.get("id") != GITHUB_ACTIONS_USER_ID
    ):
        return None
    return Wake(
        run_id=expected_run_id,
        run_attempt=attempt,
        kind=check_name,
        head_sha=trusted_sha,
    )


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


def _protected_remediation_bot_identity() -> tuple[str, int]:
    login = os.environ.get(PROTECTED_REMEDIATION_BOT_LOGIN_ENV, "")
    raw_id = os.environ.get(PROTECTED_REMEDIATION_BOT_ID_ENV, "")
    if (
        not login
        or not login.endswith("[bot]")
        or login in DISALLOWED_PROTECTED_AUTHOR_LOGINS
        or not raw_id.isdigit()
    ):
        raise ValueError("protected remediation author App identity is missing or malformed")
    user_id = int(raw_id)
    if user_id < 1:
        raise ValueError("protected remediation author App user id must be positive")
    return login, user_id


def _dependency_promotion_bot_identity() -> tuple[str, int]:
    login = os.environ.get(DEPENDENCY_PROMOTION_BOT_LOGIN_ENV, "")
    raw_id = os.environ.get(DEPENDENCY_PROMOTION_BOT_ID_ENV, "")
    disallowed = set(DISALLOWED_PROTECTED_AUTHOR_LOGINS)
    disallowed.add("github-advanced-security[bot]")
    protected_login = os.environ.get(PROTECTED_REMEDIATION_BOT_LOGIN_ENV, "")
    if protected_login:
        disallowed.add(protected_login)
    if (
        not login
        or not login.endswith("[bot]")
        or login in disallowed
        or not raw_id.isdigit()
    ):
        raise ValueError("dependency promotion author App identity is missing or malformed")
    user_id = int(raw_id)
    if user_id < 1:
        raise ValueError("dependency promotion author App user id must be positive")
    return login, user_id


def _bot_lane(pr: dict[str, Any]) -> str | None:
    user = _require_dict(pr.get("user"), label="bot pull request user")
    head = _require_dict(pr.get("head"), label="bot pull request head")
    branch = _require_str(head.get("ref"), label="bot pull request head ref")
    if PROTECTED_REMEDIATION_REF_RE.fullmatch(branch) is not None:
        login, user_id = _protected_remediation_bot_identity()
        if user.get("login") == login and user.get("id") == user_id:
            return "protected-security-remediation"
        return None
    if (
        user.get("login") == DEPENDABOT_LOGIN
        and user.get("id") == DEPENDABOT_USER_ID
        and DEPENDABOT_ACTION_REF_RE.fullmatch(branch) is not None
    ):
        return "dependabot-actions"
    if PROMOTION_REF_RE.fullmatch(branch) is not None:
        login, user_id = _dependency_promotion_bot_identity()
        if user.get("login") == login and user.get("id") == user_id:
            return "dependency-promotion"
        return None
    if (
        user.get("login") == GITHUB_ACTIONS_LOGIN
        and user.get("id") == GITHUB_ACTIONS_USER_ID
        and AUTOHEAL_REF_RE.fullmatch(branch) is not None
    ):
        return "security-autoheal"
    return None


def _wake_external_id(wake: Wake, head_sha: str) -> str:
    prefix = {
        "Required PR Gate": "aiqa-ci-qualification",
        "CodeQL": "aiqa-codeql-qualification",
    }.get(wake.kind)
    if prefix is None:
        raise ValueError("bot wake does not identify a qualification check")
    return f"{prefix}:{head_sha}:{wake.run_id}:{wake.run_attempt}"


def _select_bot_pull_request(
    api: GitHubAPI,
    *,
    wake: Wake,
    trusted_sha: str,
) -> tuple[dict[str, Any], str] | None:
    rows = api.list_all(
        f"/repos/{EXPECTED_REPOSITORY}/pulls?state=open&base={EXPECTED_DEFAULT_BRANCH}",
        max_pages=1,
    )
    if len(rows) >= MAX_PULL_REQUEST_CANDIDATES:
        raise ValueError("open pull-request discovery reached the bounded pagination limit")
    matches: list[tuple[dict[str, Any], str]] = []
    for pr in rows:
        lane = _bot_lane(pr)
        if lane is None or pr.get("draft") is not False:
            continue
        head = _require_dict(pr.get("head"), label="bot candidate head")
        base = _require_dict(pr.get("base"), label="bot candidate base")
        head_repo = _require_dict(head.get("repo"), label="bot candidate head repository")
        base_repo = _require_dict(base.get("repo"), label="bot candidate base repository")
        if (
            head_repo.get("full_name") != EXPECTED_REPOSITORY
            or base_repo.get("full_name") != EXPECTED_REPOSITORY
            or base.get("ref") != EXPECTED_DEFAULT_BRANCH
            or base.get("sha") != trusted_sha
        ):
            continue
        head_sha = _require_sha(head.get("sha"), label="bot candidate head SHA")
        expected_external_id = _wake_external_id(wake, head_sha)
        checks = api.list_all(
            f"/repos/{EXPECTED_REPOSITORY}/commits/{head_sha}/check-runs?filter=latest",
            max_pages=2,
        )
        for check in checks:
            app = check.get("app") or {}
            if (
                check.get("name") == wake.kind
                and check.get("head_sha") == head_sha
                and check.get("external_id") == expected_external_id
                and check.get("status") == "completed"
                and check.get("conclusion") == "success"
                and app.get("id") == GITHUB_ACTIONS_APP_ID
                and check.get("details_url")
                == f"https://github.com/{EXPECTED_REPOSITORY}/actions/runs/{wake.run_id}"
            ):
                matches.append((pr, lane))
                break
    if not matches:
        return None
    if len(matches) != 1:
        raise ValueError("trusted workflow wake maps to multiple governed bot pull requests")
    return matches[0]


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
    if pr.get("mergeable") is not True:
        raise ValueError(
            "automatic trusted admission requires a definitively mergeable pull request"
        )
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


def _resolve_subject(
    api: GitHubAPI,
    *,
    lane: str,
    pr: dict[str, Any],
    head_sha: str,
    trusted_sha: str,
    qualification_ready: bool,
) -> Admission:
    pr_number = _require_positive_int(pr.get("number"), label="pull request number")
    live_pr = _require_dict(
        api.get(f"/repos/{EXPECTED_REPOSITORY}/pulls/{pr_number}"),
        label="live pull request",
    )
    observed_lane = _bot_lane(live_pr)
    if lane in BOT_LANES:
        if observed_lane != lane:
            raise ValueError("live governed bot lane drifted before subject resolution")
    elif lane == "owner-routine":
        if observed_lane is not None:
            raise ValueError("owner-routine admission resolved to a governed bot pull request")
    else:
        raise ValueError("automatic trusted admission lane is not reviewed")
    base_sha = _validate_pull_request(
        live_pr,
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
        _require_sha(
            _require_dict(item, label="merge parent").get("sha"),
            label="merge parent SHA",
        )
        for item in parents
    ]
    if parent_shas != [base_sha, head_sha]:
        raise ValueError("prospective merge parent order does not match exact base/head")

    base_commit = _validate_git_commit(
        api.get(f"/repos/{EXPECTED_REPOSITORY}/git/commits/{base_sha}"),
        expected_sha=base_sha,
        label="base commit",
    )
    base_tree_sha = _require_sha(
        _require_dict(base_commit.get("tree"), label="base commit tree").get("sha"),
        label="base tree SHA",
    )
    merge_tree_sha = _require_sha(
        _require_dict(merge_commit.get("tree"), label="merge commit tree").get("sha"),
        label="merge tree SHA",
    )
    base_tree = _tree_index(
        api.get(f"/repos/{EXPECTED_REPOSITORY}/git/trees/{base_tree_sha}?recursive=1"),
        label="base recursive tree",
    )
    merge_tree = _tree_index(
        api.get(f"/repos/{EXPECTED_REPOSITORY}/git/trees/{merge_tree_sha}?recursive=1"),
        label="merge recursive tree",
    )
    head_ref = _require_str(
        _require_dict(live_pr.get("head"), label="live pull request head").get("ref"),
        label="live pull request head ref",
    )
    return Admission(
        lane=lane,
        pr_number=pr_number,
        head_ref=head_ref,
        head_sha=head_sha,
        base_sha=base_sha,
        merge_sha=merge_sha,
        trusted_sha=trusted_sha,
        protected_changes=_protected_changes(base_tree, merge_tree),
        qualification_ready=qualification_ready,
    )


def _select_scheduled_bot_pull_request(
    api: GitHubAPI, *, trusted_sha: str
) -> tuple[dict[str, Any], str] | None:
    rows = api.list_all(
        f"/repos/{EXPECTED_REPOSITORY}/pulls?state=open&base={EXPECTED_DEFAULT_BRANCH}",
        max_pages=1,
    )
    if len(rows) >= MAX_PULL_REQUEST_CANDIDATES:
        raise ValueError("scheduled bot discovery reached the bounded pagination limit")
    candidates: list[tuple[int, int, str]] = []
    for raw in rows:
        pr = _require_dict(raw, label="scheduled bot pull request")
        lane = _bot_lane(pr)
        if lane is None or pr.get("draft") is not False:
            continue
        head = _require_dict(pr.get("head"), label="scheduled bot head")
        base = _require_dict(pr.get("base"), label="scheduled bot base")
        head_repo = _require_dict(head.get("repo"), label="scheduled bot head repository")
        base_repo = _require_dict(base.get("repo"), label="scheduled bot base repository")
        if (
            head_repo.get("full_name") != EXPECTED_REPOSITORY
            or base_repo.get("full_name") != EXPECTED_REPOSITORY
            or base.get("ref") != EXPECTED_DEFAULT_BRANCH
            or base.get("sha") != trusted_sha
        ):
            continue
        number = _require_positive_int(pr.get("number"), label="scheduled bot PR number")
        _require_sha(head.get("sha"), label="scheduled bot head SHA")
        candidates.append((BOT_LANE_ORDER[lane], number, lane))
    for _, number, lane in sorted(candidates):
        live = _require_dict(
            api.get(f"/repos/{EXPECTED_REPOSITORY}/pulls/{number}"),
            label="live scheduled bot pull request",
        )
        if _bot_lane(live) != lane:
            continue
        if live.get("state") != "open" or live.get("draft") is not False:
            continue
        head = _require_dict(live.get("head"), label="live scheduled bot head")
        base = _require_dict(live.get("base"), label="live scheduled bot base")
        head_repo = _require_dict(head.get("repo"), label="live scheduled bot head repository")
        base_repo = _require_dict(base.get("repo"), label="live scheduled bot base repository")
        if (
            head_repo.get("full_name") != EXPECTED_REPOSITORY
            or base_repo.get("full_name") != EXPECTED_REPOSITORY
            or base.get("ref") != EXPECTED_DEFAULT_BRANCH
            or base.get("sha") != trusted_sha
            or live.get("mergeable") is not True
        ):
            continue
        _require_sha(head.get("sha"), label="live scheduled bot head SHA")
        return live, lane
    return None


def evaluate_admission(
    api: GitHubAPI, *, event: dict[str, Any], event_name: str = "workflow_run"
) -> Admission | None:
    trusted_sha = _current_main(api)
    if event_name == "schedule":
        selected = _select_scheduled_bot_pull_request(api, trusted_sha=trusted_sha)
        if selected is None:
            return None
        pr, lane = selected
        head_sha = _require_sha(
            _require_dict(pr.get("head"), label="scheduled bot candidate head").get("sha"),
            label="scheduled bot candidate head SHA",
        )
        return _resolve_subject(
            api,
            lane=lane,
            pr=pr,
            head_sha=head_sha,
            trusted_sha=trusted_sha,
            qualification_ready=True,
        )
    if event_name != "workflow_run":
        raise ValueError("automatic trusted admission supports workflow_run or schedule only")
    if event.get("action") != "completed":
        raise ValueError("workflow_run event action must be completed")
    event_run = _require_dict(event.get("workflow_run"), label="workflow_run event")
    run_id = _require_positive_int(event_run.get("id"), label="event workflow run id")
    live_run = _require_dict(
        api.get(f"/repos/{EXPECTED_REPOSITORY}/actions/runs/{run_id}"),
        label="live workflow run",
    )
    wake = _validate_wake(live_run, expected_run_id=run_id, trusted_sha=trusted_sha)
    if wake is None:
        return None
    if event_run.get("head_sha") != live_run.get("head_sha"):
        raise ValueError("workflow_run event head SHA differs from live run")

    if wake.kind == "owner-ci":
        pulls = api.get(
            f"/repos/{EXPECTED_REPOSITORY}/commits/{wake.head_sha}/pulls"
            f"?per_page={MAX_PULL_REQUEST_CANDIDATES}"
        )
        pr_number = _select_pull_request(pulls, head_sha=wake.head_sha)
        pr = _require_dict(
            api.get(f"/repos/{EXPECTED_REPOSITORY}/pulls/{pr_number}"),
            label="live pull request",
        )
        if _bot_lane(pr) is not None:
            return None
        return _resolve_subject(
            api,
            lane="owner-routine",
            pr=pr,
            head_sha=wake.head_sha,
            trusted_sha=trusted_sha,
            qualification_ready=True,
        )

    selected = _select_bot_pull_request(api, wake=wake, trusted_sha=trusted_sha)
    if selected is None:
        return None
    pr, lane = selected
    head_sha = _require_sha(
        _require_dict(pr.get("head"), label="bot candidate head").get("sha"),
        label="bot candidate head SHA",
    )
    qualification = _load_qualification_module()
    states = qualification.qualification_states(
        api,
        head_sha,
        trusted_sha,
        required=("Required PR Gate", "CodeQL"),
    )
    ready = all(
        state is not None and state.get("conclusion") == "success" for state in states.values()
    )
    return _resolve_subject(
        api,
        lane=lane,
        pr=pr,
        head_sha=head_sha,
        trusted_sha=trusted_sha,
        qualification_ready=ready,
    )


def write_github_outputs(path: Path, admission: Admission | None) -> None:
    if admission is None:
        values = {
            "eligible": "false",
            "lane": "none",
            "pr_number": "",
            "head_ref": "",
            "head_sha": "",
            "base_sha": "",
            "merge_sha": "",
            "trusted_sha": "",
            "protected_changes_json": "[]",
        }
    else:
        values = {
            "eligible": "true" if admission.eligible else "false",
            "lane": admission.lane,
            "pr_number": str(admission.pr_number),
            "head_ref": admission.head_ref,
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
    parser.add_argument(
        "--event-name", choices=("workflow_run", "schedule"), default="workflow_run"
    )
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
        event_name=args.event_name,
    )
    write_github_outputs(args.github_output, admission)
    summary: dict[str, Any] = {
        "eligible": False if admission is None else admission.eligible,
        "lane": "none" if admission is None else admission.lane,
    }
    if admission is not None:
        summary.update(
            {
                "pr_number": admission.pr_number,
                "head_ref": admission.head_ref,
                "head_sha": admission.head_sha,
                "base_sha": admission.base_sha,
                "merge_sha": admission.merge_sha,
                "trusted_sha": admission.trusted_sha,
                "protected_changes": admission.protected_changes,
            }
        )
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
