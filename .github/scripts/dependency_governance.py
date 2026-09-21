#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = ROOT / ".github" / "dependency-governance.json"
API_ROOT = "https://api.github.com"
API_VERSION = "2022-11-28"
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
BOT_LOGIN = "dependabot[bot]"
BOT_USER_ID = 49699333
BOT_EMAIL = "49699333+dependabot[bot]@users.noreply.github.com"
TRUSTED_COMMITTER_LOGIN = "web-flow"
TRUSTED_COMMITTER_NAME = "GitHub"
TRUSTED_COMMITTER_EMAIL = "noreply@github.com"
SIGNED_OFF_BY = "Signed-off-by: dependabot[bot] <support@github.com>"
ACTION_LINE = re.compile(
    r"^\s*(?:-\s+)?uses:\s+(?P<action>[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+)"
    r"@(?P<sha>[0-9a-f]{40})\s+#\s+v(?P<version>\d+(?:\.\d+){0,2})\s*$"
)
UPDATE_TYPE = re.compile(
    r"^\s*update-type:\s*(?P<kind>(?:version|security)-update:semver-(?:patch|minor|major))\s*$",
    re.MULTILINE,
)
SHA = re.compile(r"^[0-9a-f]{40}$")
POST_MERGE_CI_WORKFLOW = "ci.yml"
POST_MERGE_CI_PATH = ".github/workflows/ci.yml"
POST_MERGE_CI_NAME = "CI — ƳƤ AI QA Automation Framework"
POST_MERGE_CI_EVENTS = {"push", "workflow_dispatch"}
CI_DISPATCH_PROMOTION_REF = re.compile(
    r"^automation/dependency-promotion-[1-9][0-9]*-[0-9a-f]{12}$"
)
POST_MERGE_CI_REGISTRATION_ATTEMPTS = 15
POST_MERGE_CI_REGISTRATION_DELAY_SECONDS = 2


class GovernanceError(RuntimeError):
    """Operational/configuration failure: the workflow must fail."""


class PolicyBlock(RuntimeError):
    """Expected fail-closed decision: leave the pull request open."""


def unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def load_config(path: Path | None = None) -> dict[str, Any]:
    config_path = path or Path(os.environ.get("GOVERNANCE_CONFIG", DEFAULT_CONFIG))
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GovernanceError(f"unable to read governance config {config_path}: {exc}") from exc
    errors = validate_config(config)
    if errors:
        raise GovernanceError("invalid dependency governance config:\n- " + "\n- ".join(errors))
    return config


def validate_config(config: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if config.get("schemaVersion") != 1:
        errors.append("schemaVersion must equal 1")
    repository = config.get("repository")
    if not isinstance(repository, str) or repository.count("/") != 1:
        errors.append("repository must be owner/name")
    if config.get("baseBranch") != "main":
        errors.append("baseBranch must equal main")
    if config.get("mergeMethod") != "merge":
        errors.append("mergeMethod must equal merge")
    if config.get("automergeEnabled") is not True:
        errors.append("automergeEnabled must be true")
    if config.get("pipMode") != "promotion":
        errors.append("pipMode must equal promotion")
    for key, maximum in (("maxChangedFiles", 100), ("maxPullRequestAgeDays", 90)):
        value = config.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or not (1 <= value <= maximum):
            errors.append(f"{key} must be an integer from 1 to {maximum}")
    labels = config.get("manualReviewLabels")
    if (
        not isinstance(labels, list)
        or not labels
        or not all(isinstance(x, str) and x.strip() for x in labels)
    ):
        errors.append("manualReviewLabels must be a non-empty string list")
    paths = config.get("manualReviewPaths")
    if (
        not isinstance(paths, list)
        or not paths
        or not all(isinstance(x, str) and x.strip() for x in paths)
    ):
        errors.append("manualReviewPaths must be a non-empty string list")
        paths = []
    critical = {
        ".github/dependabot.yml",
        ".github/dependency-governance.json",
        ".github/dependency-recovery.json",
        ".github/security-autoheal.json",
        ".github/scripts/dependency_governance.py",
        ".github/scripts/dependency_lock_compiler.py",
        ".github/scripts/dependency_promotion.py",
        ".github/scripts/dependency_governance_selfcheck.py",
        ".github/scripts/dependency_recovery.py",
        ".github/scripts/dependency_recovery_selfcheck.py",
        ".github/scripts/security_autoheal.py",
        ".github/scripts/security_autoheal_selfcheck.py",
        ".github/workflows/dependency-governance.yml",
        ".github/workflows/security-autoheal.yml",
        ".github/workflows/trusted-pr-auto.yml",
        "scripts/auto_trusted_preflight.py",
        "scripts/ci_contract_base.py",
        "scripts/ci_contract_trusted_auto.py",
        "scripts/verify_build_authority.py",
        "scripts/auto_trusted_report.py",
        "scripts/trusted_pr_control.py",
        "scripts/verify_ci_contract.py",
        "scripts/verify_fork_cloud_authority.py",
    }
    for item in sorted(critical):
        if item not in paths:
            errors.append(f"{item} must require manual review")
    checks = config.get("requiredChecks")
    if (
        not isinstance(checks, list)
        or not checks
        or not all(isinstance(x, str) and x.strip() for x in checks)
    ):
        errors.append("requiredChecks must be a non-empty string list")
    elif len(set(checks)) != len(checks):
        errors.append("requiredChecks must not contain duplicates")
    allowed = config.get("allowedActionUpdateTypes")
    expected_allowed = {
        "version-update:semver-patch",
        "version-update:semver-minor",
        "version-update:semver-major",
        "security-update:semver-patch",
        "security-update:semver-minor",
        "security-update:semver-major",
    }
    if not isinstance(allowed, list) or set(allowed) != expected_allowed:
        errors.append(
            "allowedActionUpdateTypes must be exactly patch/minor/major version and security updates"
        )
    publish = config.get("publishTrustedStatus")
    if not isinstance(publish, bool):
        errors.append("publishTrustedStatus must be boolean")
    if publish and config.get("trustedStatusContext") != "Trusted PR Gate":
        errors.append("trustedStatusContext must equal Trusted PR Gate when publication is enabled")
    return unique(errors)


class GitHubApi:
    def __init__(self, token: str, repository: str) -> None:
        if not token:
            raise GovernanceError("GITHUB_TOKEN is required")
        if repository.count("/") != 1:
            raise GovernanceError("repository must be owner/name")
        self.token = token
        self.repository = repository
        self.root = f"{API_ROOT}/repos/{repository}"

    def _urlopen(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        token: str | None = None,
        max_bytes: int = MAX_RESPONSE_BYTES,
    ) -> bytes:
        if not path.startswith("/") or ".." in path:
            raise GovernanceError("GitHub API path must be absolute and repository-local")
        data = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
        request = urllib.request.Request(
            f"{self.root}{path}",
            data=data,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token or self.token}",
                "X-GitHub-Api-Version": API_VERSION,
                "User-Agent": "dependabot-governance",
                **({"Content-Type": "application/json"} if data is not None else {}),
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read(max_bytes + 1)
        except urllib.error.HTTPError as exc:
            detail = exc.read(4096).decode("utf-8", errors="replace")
            raise GovernanceError(
                f"GitHub API {method} {path} failed HTTP {exc.code}: {detail}"
            ) from exc
        except urllib.error.URLError as exc:
            raise GovernanceError(f"GitHub API {method} {path} transport failure: {exc}") from exc
        if len(raw) > max_bytes:
            raise GovernanceError(f"GitHub API {method} {path} exceeded bounded response size")
        return raw

    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        token: str | None = None,
    ) -> Any:
        raw = self._urlopen(method, path, payload, token=token)
        if not raw:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise GovernanceError(f"GitHub API {method} {path} returned malformed JSON") from exc

    def raw(self, method: str, path: str, *, max_bytes: int = 4 * 1024 * 1024) -> bytes:
        return self._urlopen(method, path, max_bytes=max_bytes)

    def get(self, path: str) -> Any:
        return self.request("GET", path)

    def post(
        self, path: str, payload: dict[str, Any] | None = None, *, token: str | None = None
    ) -> Any:
        return self.request("POST", path, payload, token=token)

    def put(self, path: str, payload: dict[str, Any]) -> Any:
        return self.request("PUT", path, payload)

    def list_all(self, path: str, *, max_pages: int = 10) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        separator = "&" if "?" in path else "?"
        for page in range(1, max_pages + 1):
            payload = self.get(f"{path}{separator}per_page=100&page={page}")
            if isinstance(payload, dict):
                rows = None
                for collection_key in ("check_runs", "workflow_runs", "jobs"):
                    if collection_key in payload:
                        rows = payload[collection_key]
                        break
            else:
                rows = payload
            if not isinstance(rows, list):
                raise GovernanceError(f"unexpected paginated response for {path}")
            items.extend(row for row in rows if isinstance(row, dict))
            if len(rows) < 100:
                break
        else:
            raise GovernanceError(f"pagination limit reached for {path}")
        return items


def require_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA.fullmatch(value) is None:
        raise PolicyBlock(f"{label} is not a canonical 40-character SHA")
    return value


def _labels(pr: dict[str, Any]) -> set[str]:
    return {
        str(row.get("name"))
        for row in pr.get("labels", [])
        if isinstance(row, dict) and isinstance(row.get("name"), str)
    }


def path_matches(path: str, protected: str) -> bool:
    protected = protected.rstrip("/")
    return path == protected or path.startswith(protected + "/")


def _parse_time(value: Any) -> datetime:
    if not isinstance(value, str) or not value:
        raise PolicyBlock("pull request creation time is missing")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PolicyBlock("pull request creation time is invalid") from exc
    if dt.tzinfo is None:
        raise PolicyBlock("pull request creation time lacks timezone")
    return dt.astimezone(UTC)


def validate_pr_identity(
    api: GitHubApi,
    pr: dict[str, Any],
    config: dict[str, Any],
    *,
    require_current_base: bool = True,
) -> tuple[str, str, int]:
    number = pr.get("number")
    if not isinstance(number, int) or number < 1:
        raise PolicyBlock("invalid pull request number")
    user = pr.get("user") or {}
    if user.get("login") != BOT_LOGIN or user.get("id") != BOT_USER_ID:
        raise PolicyBlock("pull request is not the exact Dependabot identity")
    if pr.get("state") != "open" or pr.get("draft") is not False:
        raise PolicyBlock("pull request is not open and non-draft")
    if pr.get("mergeable") is not True:
        raise PolicyBlock("pull request is not currently and definitively mergeable")
    head = pr.get("head") or {}
    base = pr.get("base") or {}
    head_repo = head.get("repo") or {}
    base_repo = base.get("repo") or {}
    if (
        head_repo.get("full_name") != config["repository"]
        or base_repo.get("full_name") != config["repository"]
    ):
        raise PolicyBlock("Dependabot pull request must use repository-owned head and base")
    if base.get("ref") != config["baseBranch"]:
        raise PolicyBlock("pull request does not target main")
    head_sha = require_sha(head.get("sha"), "head SHA")
    base_sha = require_sha(base.get("sha"), "base SHA")
    live_branch = api.get(f"/branches/{urllib.parse.quote(config['baseBranch'], safe='')}")
    live_sha = require_sha(((live_branch or {}).get("commit") or {}).get("sha"), "live main SHA")
    if require_current_base and base_sha != live_sha:
        raise PolicyBlock("pull request base is stale; wait for Dependabot native rebase")
    if _labels(pr) & set(config["manualReviewLabels"]):
        raise PolicyBlock("pull request carries a manual-review blocker label")
    age_days = (datetime.now(UTC) - _parse_time(pr.get("created_at"))).total_seconds() / 86400
    if age_days < 0 or age_days > config["maxPullRequestAgeDays"]:
        raise PolicyBlock("pull request is outside the bounded automatic-merge age")
    return head_sha, base_sha, number


def validate_commits(api: GitHubApi, number: int, config: dict[str, Any]) -> None:
    commits = api.list_all(f"/pulls/{number}/commits", max_pages=2)
    if len(commits) != 1:
        raise PolicyBlock(
            f"automatic governance requires exactly one Dependabot commit, found {len(commits)}"
        )
    row = commits[0]
    author = row.get("author") or {}
    committer = row.get("committer") or {}
    commit = row.get("commit") or {}
    raw_author = commit.get("author") or {}
    raw_committer = commit.get("committer") or {}
    verification = commit.get("verification") or {}
    message = commit.get("message")
    if author.get("login") != BOT_LOGIN or author.get("id") != BOT_USER_ID:
        raise PolicyBlock("commit author is not the exact Dependabot identity")
    if raw_author.get("email") != BOT_EMAIL:
        raise PolicyBlock("commit author email does not match canonical Dependabot identity")
    if committer.get("login") != TRUSTED_COMMITTER_LOGIN:
        raise PolicyBlock("commit committer is not GitHub web-flow")
    if (
        raw_committer.get("name") != TRUSTED_COMMITTER_NAME
        or raw_committer.get("email") != TRUSTED_COMMITTER_EMAIL
    ):
        raise PolicyBlock("commit committer metadata is not canonical GitHub metadata")
    if verification.get("verified") is not True or verification.get("reason") != "valid":
        raise PolicyBlock("Dependabot commit signature is not verified-valid")
    if not isinstance(message, str) or SIGNED_OFF_BY not in message:
        raise PolicyBlock("Dependabot Signed-off-by provenance is missing")
    update_types = UPDATE_TYPE.findall(message)
    if not update_types:
        raise PolicyBlock("Dependabot update-type metadata is missing")
    unexpected = sorted(set(update_types) - set(config["allowedActionUpdateTypes"]))
    if unexpected:
        raise PolicyBlock("update type requires manual review: " + ", ".join(unexpected))


def changed_files(api: GitHubApi, number: int, config: dict[str, Any]) -> list[dict[str, Any]]:
    files = api.list_all(f"/pulls/{number}/files", max_pages=2)
    if not files:
        raise PolicyBlock("pull request has no changed files")
    if len(files) > config["maxChangedFiles"]:
        raise PolicyBlock("pull request exceeds the automatic changed-file limit")
    for row in files:
        path = row.get("filename")
        if not isinstance(path, str) or not path:
            raise PolicyBlock("changed file path is invalid")
        for protected in config["manualReviewPaths"]:
            if path_matches(path, protected):
                raise PolicyBlock(f"control-plane path requires manual review: {path}")
    return files


def parse_action_change(line: str) -> tuple[str, str, tuple[int, ...]] | None:
    match = ACTION_LINE.fullmatch(line)
    if match is None:
        return None
    return (
        match.group("action"),
        match.group("sha"),
        tuple(int(part) for part in match.group("version").split(".")),
    )


def validate_action_semantics(files: list[dict[str, Any]]) -> None:
    for row in files:
        path = str(row["filename"])
        if not path.startswith(".github/workflows/") or not path.endswith((".yml", ".yaml")):
            raise PolicyBlock(f"non-workflow change requires manual review: {path}")
        if row.get("status") != "modified":
            raise PolicyBlock(f"workflow creation/deletion/rename requires manual review: {path}")
        patch = row.get("patch")
        if not isinstance(patch, str) or not patch:
            raise PolicyBlock(f"workflow patch is unavailable or too large: {path}")
        removed: list[tuple[str, str, tuple[int, ...]]] = []
        added: list[tuple[str, str, tuple[int, ...]]] = []
        for raw in patch.splitlines():
            if not raw or raw.startswith(("@@", " ", "\\")):
                continue
            if raw[0] not in {"+", "-"}:
                continue
            parsed = parse_action_change(raw[1:])
            if parsed is None:
                raise PolicyBlock(
                    f"non-action semantic change requires manual review in {path}: {raw[:160]}"
                )
            (added if raw[0] == "+" else removed).append(parsed)
        if not removed or len(removed) != len(added):
            raise PolicyBlock(f"workflow update must replace action pins one-for-one: {path}")
        if Counter(item[0] for item in removed) != Counter(item[0] for item in added):
            raise PolicyBlock(f"workflow update changes action identities: {path}")
        for action in sorted(set(item[0] for item in removed)):
            old = [item for item in removed if item[0] == action]
            new = [item for item in added if item[0] == action]
            old_versions = {item[2] for item in old}
            new_versions = {item[2] for item in new}
            old_shas = {item[1] for item in old}
            new_shas = {item[1] for item in new}
            if (
                len(old_versions) != 1
                or len(new_versions) != 1
                or len(old_shas) != 1
                or len(new_shas) != 1
            ):
                raise PolicyBlock(
                    f"ambiguous repeated action update requires manual review: {action}"
                )
            old_v = next(iter(old_versions))
            new_v = next(iter(new_versions))
            if new_v <= old_v:
                raise PolicyBlock(f"action version must advance monotonically: {action}")
            if next(iter(old_shas)) == next(iter(new_shas)):
                raise PolicyBlock(f"action SHA did not change: {action}")


def verify_merge_subject(
    api: GitHubApi, pr: dict[str, Any], number: int, head_sha: str, base_sha: str
) -> str:
    merge_sha = require_sha(pr.get("merge_commit_sha"), "prospective merge SHA")
    ref = api.get(f"/git/ref/pull/{number}/merge")
    if (ref or {}).get("ref") != f"refs/pull/{number}/merge":
        raise PolicyBlock("pull request merge ref identity is invalid")
    observed = require_sha(((ref or {}).get("object") or {}).get("sha"), "merge ref SHA")
    if observed != merge_sha:
        raise PolicyBlock("prospective merge ref changed")
    commit = api.get(f"/git/commits/{merge_sha}")
    parents = (commit or {}).get("parents")
    if not isinstance(parents, list) or len(parents) != 2:
        raise PolicyBlock("prospective merge commit must have exactly two parents")
    parent_shas = [require_sha((parent or {}).get("sha"), "merge parent SHA") for parent in parents]
    if parent_shas != [base_sha, head_sha]:
        raise PolicyBlock("prospective merge parents are not exact current base/head")
    return merge_sha


def latest_checks(api: GitHubApi, head_sha: str) -> dict[str, dict[str, Any]]:
    rows = api.list_all(f"/commits/{head_sha}/check-runs?filter=latest", max_pages=4)
    latest: dict[str, dict[str, Any]] = {}
    for row in rows:
        name = row.get("name")
        if not isinstance(name, str) or not name:
            continue
        stamp = row.get("completed_at") or row.get("started_at") or ""
        prior = latest.get(name)
        prior_stamp = (prior or {}).get("completed_at") or (prior or {}).get("started_at") or ""
        if prior is None or stamp >= prior_stamp:
            latest[name] = row
    return latest


def require_green_checks(api: GitHubApi, head_sha: str, config: dict[str, Any]) -> None:
    checks = latest_checks(api, head_sha)
    for name in config["requiredChecks"]:
        row = checks.get(name)
        if row is None:
            raise PolicyBlock(f"required check has not registered: {name}")
        if row.get("status") != "completed" or row.get("conclusion") != "success":
            raise PolicyBlock(
                f"required check is not green: {name} status={row.get('status')} conclusion={row.get('conclusion')}"
            )


def assess(
    api: GitHubApi, pr: dict[str, Any], config: dict[str, Any], *, require_checks: bool
) -> dict[str, Any]:
    head_sha, base_sha, number = validate_pr_identity(api, pr, config)
    validate_commits(api, number, config)
    files = changed_files(api, number, config)
    validate_action_semantics(files)
    merge_sha = verify_merge_subject(api, pr, number, head_sha, base_sha)
    if require_checks:
        require_green_checks(api, head_sha, config)
    return {
        "number": number,
        "headSha": head_sha,
        "baseSha": base_sha,
        "mergeSha": merge_sha,
        "files": [str(row["filename"]) for row in files],
    }


def open_dependabot_prs(api: GitHubApi) -> list[dict[str, Any]]:
    rows = api.list_all("/pulls?state=open&sort=created&direction=asc", max_pages=4)
    return [
        row
        for row in rows
        if (row.get("user") or {}).get("login") == BOT_LOGIN
        and (row.get("user") or {}).get("id") == BOT_USER_ID
    ]


def _post_trusted_status(api: GitHubApi, subject: dict[str, Any], config: dict[str, Any]) -> None:
    if not config["publishTrustedStatus"]:
        return
    token = os.environ.get("TRUSTED_STATUS_TOKEN", "")
    if not token:
        raise GovernanceError("TRUSTED_STATUS_TOKEN is required for the dedicated Trusted PR Gate")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    if not run_id.isdigit() or int(run_id) < 1:
        raise GovernanceError("GITHUB_RUN_ID is invalid")
    fresh = api.get(f"/pulls/{subject['number']}")
    rebound = assess(api, fresh, config, require_checks=True)
    if rebound != subject:
        raise PolicyBlock("pull request changed before trusted status publication")
    response = api.post(
        f"/statuses/{subject['headSha']}",
        {
            "state": "success",
            "context": config["trustedStatusContext"],
            "description": "Dependabot exact-subject governance passed",
            "target_url": f"https://github.com/{config['repository']}/actions/runs/{run_id}",
        },
        token=token,
    )
    if not isinstance(response, dict) or response.get("state") != "success":
        raise GovernanceError("dedicated Trusted PR Gate status publication was not acknowledged")


def _post_merge_ci_candidates(rows: list[dict[str, Any]], subject_sha: str) -> list[dict[str, Any]]:
    subject_sha = require_sha(subject_sha, "post-merge CI subject SHA")
    candidates: list[dict[str, Any]] = []
    for row in rows:
        if (
            row.get("name") != POST_MERGE_CI_NAME
            or row.get("path") != POST_MERGE_CI_PATH
            or row.get("head_branch") != "main"
            or row.get("head_sha") != subject_sha
            or row.get("event") not in POST_MERGE_CI_EVENTS
        ):
            continue
        attempt = row.get("run_attempt")
        if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1:
            raise GovernanceError("exact-subject CI run has invalid run_attempt")
        run_id = row.get("id")
        if not isinstance(run_id, int) or isinstance(run_id, bool) or run_id < 1:
            raise GovernanceError("exact-subject CI run has invalid run id")
        status = row.get("status")
        conclusion = row.get("conclusion")
        if status not in {"queued", "in_progress", "completed"}:
            raise GovernanceError(f"exact-subject CI run has invalid status: {status}")
        if status == "completed" and conclusion != "success":
            raise GovernanceError(f"exact-subject CI run completed non-successfully: {conclusion}")
        candidates.append(row)
    return candidates


def _select_post_merge_ci_run(
    rows: list[dict[str, Any]], subject_sha: str
) -> dict[str, Any] | None:
    candidates = _post_merge_ci_candidates(rows, subject_sha)
    if len(candidates) > 1:
        run_ids = sorted(int(row["id"]) for row in candidates)
        raise GovernanceError(
            f"ambiguous exact-subject CI evidence for {subject_sha}: run ids {run_ids}"
        )
    return candidates[0] if candidates else None


def _live_main_sha(api: GitHubApi, config: dict[str, Any]) -> str:
    branch = urllib.parse.quote(config["baseBranch"], safe="")
    payload = api.get(f"/branches/{branch}")
    return require_sha(((payload or {}).get("commit") or {}).get("sha"), "live main SHA")


def _post_merge_ci_runs(api: GitHubApi, subject_sha: str) -> list[dict[str, Any]]:
    encoded_sha = urllib.parse.quote(require_sha(subject_sha, "post-merge CI subject SHA"), safe="")
    return api.list_all(f"/actions/runs?head_sha={encoded_sha}", max_pages=2)


def dispatch_exact_ci(api: GitHubApi, ref: str, subject_sha: str) -> None:
    subject_sha = require_sha(subject_sha, "explicit CI dispatch subject SHA")
    if ref != "main" and CI_DISPATCH_PROMOTION_REF.fullmatch(ref) is None:
        raise GovernanceError(f"explicit CI dispatch ref is outside reviewed authority: {ref!r}")
    api.post(
        f"/actions/workflows/{POST_MERGE_CI_WORKFLOW}/dispatches",
        {"ref": ref, "inputs": {"subject_sha": subject_sha}},
    )


def _verify_actual_merge_commit(
    api: GitHubApi, result: dict[str, Any], subject: dict[str, Any], config: dict[str, Any]
) -> str:
    merge_sha = require_sha(result.get("sha"), "actual merge SHA")
    commit = api.get(f"/git/commits/{merge_sha}")
    parents = (commit or {}).get("parents")
    if not isinstance(parents, list) or len(parents) != 2:
        raise GovernanceError("actual governed merge commit must have exactly two parents")
    observed = [
        require_sha((parent or {}).get("sha"), "actual merge parent SHA") for parent in parents
    ]
    expected = [subject["baseSha"], subject["headSha"]]
    if observed != expected:
        raise GovernanceError(
            f"actual governed merge parents changed: expected {expected}, got {observed}"
        )
    live_sha = _live_main_sha(api, config)
    if live_sha != merge_sha:
        raise GovernanceError(
            f"main advanced before exact-subject CI dispatch: expected {merge_sha}, got {live_sha}"
        )
    return merge_sha


def finalize_post_merge_evidence(
    api: GitHubApi, result: dict[str, Any], subject: dict[str, Any], config: dict[str, Any]
) -> dict[str, Any]:
    merge_sha = _verify_actual_merge_commit(api, result, subject, config)
    existing = _select_post_merge_ci_run(_post_merge_ci_runs(api, merge_sha), merge_sha)
    if existing is None:
        dispatch_exact_ci(api, config["baseBranch"], merge_sha)
        for attempt in range(POST_MERGE_CI_REGISTRATION_ATTEMPTS):
            existing = _select_post_merge_ci_run(_post_merge_ci_runs(api, merge_sha), merge_sha)
            if existing is not None:
                if existing.get("event") != "workflow_dispatch":
                    raise GovernanceError(
                        "post-merge CI appeared through an unexpected event after explicit dispatch"
                    )
                break
            if attempt + 1 < POST_MERGE_CI_REGISTRATION_ATTEMPTS:
                time.sleep(POST_MERGE_CI_REGISTRATION_DELAY_SECONDS)
        else:
            raise GovernanceError(
                f"explicit CI dispatch did not register for exact current main {merge_sha}"
            )
    if _live_main_sha(api, config) != merge_sha:
        raise GovernanceError("post-merge CI evidence subject is no longer current main")
    return {
        "mergeSha": merge_sha,
        "ciRunId": int(existing["id"]),
        "ciRunAttempt": int(existing["run_attempt"]),
        "ciEvent": str(existing["event"]),
        "ciStatus": str(existing["status"]),
    }


def _merge(api: GitHubApi, subject: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    fresh = api.get(f"/pulls/{subject['number']}")
    rebound = assess(api, fresh, config, require_checks=True)
    if rebound != subject:
        raise PolicyBlock("pull request changed before merge")
    result = api.put(
        f"/pulls/{subject['number']}/merge",
        {"sha": subject["headSha"], "merge_method": config["mergeMethod"]},
    )
    if not isinstance(result, dict) or result.get("merged") is not True:
        message = result.get("message") if isinstance(result, dict) else result
        raise GovernanceError(f"GitHub declined governed merge: {message}")
    return finalize_post_merge_evidence(api, result, subject, config)


def reconcile(config: dict[str, Any], *, allow_merge: bool) -> int:
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    if repository != config["repository"]:
        raise GovernanceError(f"workflow repository {repository!r} does not match bound config")
    api = GitHubApi(os.environ.get("GITHUB_TOKEN", ""), repository)
    eligible = 0
    for summary in open_dependabot_prs(api):
        number = summary.get("number")
        try:
            subject = assess(api, api.get(f"/pulls/{number}"), config, require_checks=True)
            eligible += 1
            print(json.dumps({"pr": number, "decision": "eligible", **subject}, sort_keys=True))
            if allow_merge and config["automergeEnabled"]:
                _post_trusted_status(api, subject, config)
                merge_evidence = _merge(api, subject, config)
                print(
                    json.dumps(
                        {
                            "pr": number,
                            "decision": "merged",
                            "headSha": subject["headSha"],
                            **merge_evidence,
                        },
                        sort_keys=True,
                    )
                )
        except PolicyBlock as exc:
            print(
                json.dumps(
                    {"pr": number, "decision": "blocked", "reason": str(exc)}, sort_keys=True
                )
            )
    return eligible


def selftest(config: dict[str, Any]) -> None:
    errors = validate_config(config)
    if errors:
        raise GovernanceError("config self-test failed: " + "; ".join(errors))
    good = "      - uses: actions/checkout@" + "a" * 40 + " # v7.0.1"
    named_step = "        uses: github/codeql-action/init@" + "b" * 40 + " # v4.38.1"
    bad_tag = "      - uses: actions/checkout@v7 # v7.0.1"
    if parse_action_change(good) is None:
        raise GovernanceError("immutable action-line parser rejected canonical pinned action")
    if parse_action_change(named_step) is None:
        raise GovernanceError("immutable action-line parser rejected named-step action pin")
    if parse_action_change(bad_tag) is not None:
        raise GovernanceError("immutable action-line parser accepted mutable tag")
    synthetic = [
        {
            "filename": ".github/workflows/ci.yml",
            "status": "modified",
            "patch": "@@ -1 +1 @@\n-        uses: github/codeql-action/init@"
            + "a" * 40
            + " # v4.38.0\n"
            "+        uses: github/codeql-action/init@" + "b" * 40 + " # v4.38.1\n",
        }
    ]
    validate_action_semantics(synthetic)
    try:
        validate_action_semantics(
            [
                {
                    "filename": ".github/workflows/ci.yml",
                    "status": "modified",
                    "patch": "@@ -1 +1 @@\n-run: echo old\n+run: echo new\n",
                }
            ]
        )
    except PolicyBlock:
        pass
    else:
        raise GovernanceError("semantic validator accepted non-action workflow mutation")
    validate_action_semantics(
        [
            {
                "filename": ".github/workflows/ci.yml",
                "status": "modified",
                "patch": "@@ -1 +1 @@\n-      - uses: actions/checkout@" + "a" * 40 + " # v7.0.1\n"
                "+      - uses: actions/checkout@" + "b" * 40 + " # v8.0.0\n",
            }
        ]
    )
    try:
        validate_action_semantics(
            [
                {
                    "filename": ".github/workflows/ci.yml",
                    "status": "modified",
                    "patch": "@@ -1 +1 @@\n-      - uses: actions/checkout@"
                    + "a" * 40
                    + " # v8.0.0\n"
                    "+      - uses: actions/checkout@" + "b" * 40 + " # v7.0.1\n",
                }
            ]
        )
    except PolicyBlock:
        pass
    else:
        raise GovernanceError("semantic validator accepted action version downgrade")
    exact_sha = "1" * 40

    class _EmptyWorkflowRunsApi(GitHubApi):
        def __init__(self) -> None:
            pass

        def get(self, path: str) -> Any:
            if not path.startswith("/actions/runs?"):
                raise GovernanceError(f"unexpected self-test API path: {path}")
            return {"workflow_runs": []}

    if _EmptyWorkflowRunsApi().list_all(f"/actions/runs?head_sha={exact_sha}", max_pages=2) != []:
        raise GovernanceError("pagination rejected canonical empty workflow_runs response")

    class _RecordingDispatchApi(GitHubApi):
        def __init__(self) -> None:
            self.calls: list[tuple[str, dict[str, Any] | None]] = []

        def post(
            self,
            path: str,
            payload: dict[str, Any] | None = None,
            *,
            token: str | None = None,
        ) -> Any:
            if token is not None:
                raise GovernanceError("dispatch self-test received unexpected alternate token")
            self.calls.append((path, payload))
            return None

    dispatch_api = _RecordingDispatchApi()
    dispatch_exact_ci(dispatch_api, "main", exact_sha)
    dispatch_exact_ci(
        dispatch_api,
        "automation/dependency-promotion-170-abcdef123456",
        exact_sha,
    )
    expected_dispatch = (
        "/actions/workflows/ci.yml/dispatches",
        {"ref": "main", "inputs": {"subject_sha": exact_sha}},
    )
    if dispatch_api.calls[0] != expected_dispatch:
        raise GovernanceError("main exact-subject CI dispatch payload drifted")
    if dispatch_api.calls[1][1] != {
        "ref": "automation/dependency-promotion-170-abcdef123456",
        "inputs": {"subject_sha": exact_sha},
    }:
        raise GovernanceError("promotion exact-subject CI dispatch payload drifted")
    for bad_ref in (
        "feature/unreviewed",
        "automation/dependency-promotion-0-abcdef123456",
        "automation/dependency-promotion-170-nothex123456",
        "automation/dependency-promotion-170-abcdef123456-extra",
    ):
        try:
            dispatch_exact_ci(dispatch_api, bad_ref, exact_sha)
        except GovernanceError:
            pass
        else:
            raise GovernanceError(f"unreviewed CI dispatch ref was accepted: {bad_ref}")

    canonical_run = {
        "id": 101,
        "name": POST_MERGE_CI_NAME,
        "path": POST_MERGE_CI_PATH,
        "head_branch": "main",
        "head_sha": exact_sha,
        "event": "workflow_dispatch",
        "run_attempt": 1,
        "status": "queued",
        "conclusion": None,
    }
    if _select_post_merge_ci_run([canonical_run], exact_sha) != canonical_run:
        raise GovernanceError("post-merge CI selector rejected canonical exact-subject dispatch")
    wrong_sha = dict(canonical_run, head_sha="2" * 40)
    wrong_workflow = dict(canonical_run, path=".github/workflows/not-ci.yml")
    wrong_event = dict(canonical_run, event="schedule")
    if any(
        _select_post_merge_ci_run([row], exact_sha) is not None
        for row in (wrong_sha, wrong_workflow, wrong_event)
    ):
        raise GovernanceError("post-merge CI selector accepted mismatched evidence")
    for terminal in ("failure", "cancelled", "timed_out"):
        try:
            _select_post_merge_ci_run(
                [dict(canonical_run, status="completed", conclusion=terminal)], exact_sha
            )
        except GovernanceError:
            pass
        else:
            raise GovernanceError(
                f"post-merge CI selector accepted terminal non-success: {terminal}"
            )
    try:
        _select_post_merge_ci_run([canonical_run, dict(canonical_run, id=102)], exact_sha)
    except GovernanceError:
        pass
    else:
        raise GovernanceError("post-merge CI selector accepted ambiguous duplicate runs")
    completed = dict(canonical_run, status="completed", conclusion="success")
    if _select_post_merge_ci_run([completed], exact_sha) != completed:
        raise GovernanceError("post-merge CI selector rejected successful exact-subject evidence")
    print("dependency-governance self-test: ok")


def main() -> None:
    parser = argparse.ArgumentParser(description="Fail-closed Dependabot governance")
    parser.add_argument("--validate-config", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--reconcile", action="store_true")
    parser.add_argument("--allow-merge", action="store_true")
    args = parser.parse_args()
    config = load_config()
    if args.validate_config:
        print("dependency-governance config: valid")
    if args.self_test:
        selftest(config)
    if args.reconcile:
        reconcile(config, allow_merge=args.allow_merge)
    if not (args.validate_config or args.self_test or args.reconcile):
        parser.error("choose --validate-config, --self-test, or --reconcile")


if __name__ == "__main__":
    main()
