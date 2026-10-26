#!/usr/bin/env python3
"""Independent accepted-main owner-identity approval for protected maintenance.

This job may publish the *owner-bound authorization comment*, never an App-owned
Trusted PR Gate status or a merge. The separate trusted controller still
qualifies the candidate and publishes its own exact-subject verdict.
"""

from __future__ import annotations

import json
import os
import re
import stat
import urllib.request
from typing import Any

from auto_trusted_preflight import (
    EXPECTED_CI_WORKFLOW_ID,
    EXPECTED_CODEQL_WORKFLOW_ID,
    EXPECTED_DEFAULT_BRANCH,
    EXPECTED_OWNER,
    EXPECTED_OWNER_ID,
    EXPECTED_REPOSITORY,
    GITHUB_ACTIONS_APP_ID,
    MAX_EVENT_BYTES,
    MAX_PULL_REQUEST_CANDIDATES,
    PROTECTED_OWNER_LANE,
    PROTECTED_OWNER_REASON,
    GitHubAPI,
    _current_main,
    _has_exact_trusted_terminal_status,
    _require_dict,
    _require_sha,
    _resolve_subject,
)

REVIEW_ENV = "PORTYU9_BOT_REVIEW_TOKEN"
COMMENTS_LIMIT = 100
API_ROOT = "https://api.github.com"


def require_execution_context(trusted_sha: str) -> None:
    if (
        os.environ.get("GITHUB_REPOSITORY") != EXPECTED_REPOSITORY
        or os.environ.get("GITHUB_API_URL") != API_ROOT
        or os.environ.get("GITHUB_REF") != f"refs/heads/{EXPECTED_DEFAULT_BRANCH}"
        or os.environ.get("GITHUB_SHA") != trusted_sha
        or os.environ.get("GITHUB_RUN_ATTEMPT") != "1"
        or os.environ.get("GITHUB_EVENT_NAME") not in {"schedule", "workflow_run"}
        or os.environ.get("GITHUB_WORKFLOW_REF")
        != f"{EXPECTED_REPOSITORY}/.github/workflows/protected-maintenance-authorizer.yml@refs/heads/main"
    ):
        raise ValueError("protected owner authorization must execute on fresh accepted main")


OWNER_WAKE_WORKFLOWS = {
    339754724: ("ci", ".github/workflows/ci.yml"),
    359681647: ("CodeQL", ".github/workflows/codeql.yml"),
    377768728: ("security", ".github/workflows/security.yml"),
}


def require_verified_owner_wake(api: GitHubAPI) -> None:
    """An event only wakes trusted main; live API, not event bytes, proves provenance."""
    if os.environ.get("GITHUB_EVENT_NAME") == "schedule":
        return
    path = os.environ.get("GITHUB_EVENT_PATH", "")
    if not path:
        raise ValueError("owner wake must have a GitHub event payload")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_EVENT_BYTES:
            raise ValueError("owner wake event is not a bounded regular file")
        raw = os.read(fd, MAX_EVENT_BYTES + 1)
    finally:
        os.close(fd)
    if len(raw) > MAX_EVENT_BYTES:
        raise ValueError("owner wake event exceeds bounded input limit")
    payload = _require_dict(json.loads(raw), label="owner wake payload")
    if payload.get("action") != "completed":
        raise ValueError("owner wake must be a completed GitHub workflow event")
    wake = _require_dict(payload.get("workflow_run"), label="owner workflow wake")
    run_id = wake.get("id")
    if isinstance(run_id, bool) or not isinstance(run_id, int) or run_id < 1:
        raise ValueError("owner wake workflow run id is invalid")
    live = _require_dict(
        api.get(f"/repos/{EXPECTED_REPOSITORY}/actions/runs/{run_id}"),
        label="live owner workflow wake",
    )
    workflow_id = live.get("workflow_id")
    expected = OWNER_WAKE_WORKFLOWS.get(workflow_id)
    repository = _require_dict(live.get("repository"), label="wake repository")
    head_repository = _require_dict(live.get("head_repository"), label="wake head repository")
    actor = _require_dict(live.get("actor"), label="wake actor")
    initiating_actor = _require_dict(live.get("triggering_actor"), label="wake triggering actor")
    if (
        expected is None
        or live.get("id") != run_id
        or live.get("name") != expected[0]
        or live.get("path") != expected[1]
        or live.get("event") != "pull_request"
        or live.get("run_attempt") != 1
        or live.get("status") != "completed"
        or live.get("conclusion") != "success"
        or live.get("head_sha") != wake.get("head_sha")
        or live.get("workflow_id") != wake.get("workflow_id")
        or repository.get("full_name") != EXPECTED_REPOSITORY
        or head_repository.get("full_name") != EXPECTED_REPOSITORY
        or actor.get("login") != EXPECTED_OWNER
        or actor.get("id") != EXPECTED_OWNER_ID
        or initiating_actor.get("login") != EXPECTED_OWNER
        or initiating_actor.get("id") != EXPECTED_OWNER_ID
    ):
        raise ValueError("owner wake is not an exact native successful PR workflow")


def require_owner_token_identity(token: str) -> None:
    if not token:
        raise ValueError("isolated owner-review credential is missing")
    request = urllib.request.Request(
        f"{API_ROOT}/user",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "yp-protected-maintenance-owner-authorizer",
        },
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        raw = response.read(4097)
    if len(raw) > 4096:
        raise ValueError("owner identity response exceeded the reviewed limit")
    payload = _require_dict(json.loads(raw), label="owner credential identity")
    if (
        payload.get("login") != EXPECTED_OWNER
        or payload.get("id") != EXPECTED_OWNER_ID
        or payload.get("type") != "User"
    ):
        raise ValueError("isolated owner-review token did not resolve to the exact owner")


def require_passing_candidate_checks(api: GitHubAPI, head_sha: str) -> bool:
    """Require independent GitHub Actions CI, CodeQL, and Security on exact PR head.

    Native public PR checks may be supplemented by an unrelated neutral
    github-advanced-security CodeQL check. The only accepted evidence is a
    first-attempt successful named workflow *and* its exact GitHub Actions job.
    """
    specs = (
        (
            "Required PR Gate",
            "ci",
            ".github/workflows/ci.yml",
            EXPECTED_CI_WORKFLOW_ID,
        ),
        ("CodeQL", "CodeQL", ".github/workflows/codeql.yml", EXPECTED_CODEQL_WORKFLOW_ID),
        ("security-gate", "security", ".github/workflows/security.yml", None),
    )
    for check_name, workflow_name, workflow_path, workflow_id in specs:
        rows = api.list_all(
            f"/repos/{EXPECTED_REPOSITORY}/commits/{head_sha}/check-runs"
            f"?check_name={check_name.replace(' ', '%20')}&filter=latest",
            max_pages=2,
        )
        # Never treat one older successful check as approval when another
        # canonical Actions check on the exact head is red or ambiguous.
        native = [
            row
            for row in rows
            if isinstance(row.get("app"), dict)
            and row["app"].get("id") == GITHUB_ACTIONS_APP_ID
            and row["app"].get("slug") == "github-actions"
        ]
        # GitHub legitimately retains older check suites on unchanged PR heads.
        # Pick only the newest exact native job; a newer red, pending, rerun,
        # duplicated, or wrong-subject job must never fall back to an older green.
        if not native or len(native) >= 200:
            return False
        ids = [row.get("id") for row in native]
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 1 for value in ids
        ) or len(set(ids)) != len(ids):
            return False
        newest = max(native, key=lambda row: row["id"])
        accepted = []
        for run in (newest,):
            app = _require_dict(run.get("app"), label="candidate check App")
            if app.get("id") != GITHUB_ACTIONS_APP_ID or app.get("slug") != "github-actions":
                return False
            details_url = run.get("details_url")
            expected_url = re.escape(f"https://github.com/{EXPECTED_REPOSITORY}/actions/runs/")
            match = re.fullmatch(
                expected_url + r"(?P<run>[1-9][0-9]*)/job/(?P<job>[1-9][0-9]*)",
                details_url if isinstance(details_url, str) else "",
            )
            if (
                run.get("name") != check_name
                or run.get("head_sha") != head_sha
                or run.get("status") != "completed"
                or run.get("conclusion") != "success"
                or match is None
                or run.get("id") != int(match.group("job"))
            ):
                continue
            workflow = _require_dict(
                api.get(f"/repos/{EXPECTED_REPOSITORY}/actions/runs/{match.group('run')}"),
                label="candidate workflow run",
            )
            repository = _require_dict(workflow.get("repository"), label="workflow repository")
            head_repository = _require_dict(
                workflow.get("head_repository"), label="workflow head repository"
            )
            if (
                workflow.get("name") == workflow_name
                and workflow.get("path") == workflow_path
                and (workflow_id is None or workflow.get("workflow_id") == workflow_id)
                and workflow.get("run_attempt") == 1
                and workflow.get("head_sha") == head_sha
                and workflow.get("event") == "pull_request"
                and workflow.get("status") == "completed"
                and workflow.get("conclusion") == "success"
                and repository.get("full_name") == EXPECTED_REPOSITORY
                and head_repository.get("full_name") == EXPECTED_REPOSITORY
            ):
                accepted.append(run)
        if len(accepted) != 1:
            return False
    return True


def exact_comment(admission: Any) -> str:
    return (
        f"/trusted-maintenance authorization={PROTECTED_OWNER_REASON} "
        f"pr={admission.pr_number} head={admission.head_sha} "
        f"base={admission.base_sha} merge={admission.merge_sha}"
    )


def existing_authorization(api: GitHubAPI, pr: int, body: str) -> int | None:
    comments = api.list_all(
        f"/repos/{EXPECTED_REPOSITORY}/issues/{pr}/comments?per_page=100",
        max_pages=1,
    )
    if len(comments) >= COMMENTS_LIMIT:
        raise ValueError("owner authorization comment inventory exceeded reviewed limit")
    matches: list[int] = []
    for entry in comments:
        comment = _require_dict(entry, label="owner comment")
        if comment.get("body") != body:
            continue
        owner = _require_dict(comment.get("user"), label="owner comment user")
        if (
            owner.get("login") != EXPECTED_OWNER
            or owner.get("id") != EXPECTED_OWNER_ID
            or owner.get("type") != "User"
            or comment.get("created_at") != comment.get("updated_at")
            or not isinstance(comment.get("id"), int)
            or comment["id"] < 1
        ):
            raise ValueError("matching owner authorization has invalid provenance")
        matches.append(comment["id"])
    if len(matches) > 1:
        raise ValueError("ambiguous duplicate exact owner authorizations")
    return matches[0] if matches else None


def require_durable_owner_authorization(
    api: GitHubAPI, *, pr_number: int, comment_id: int, body: str
) -> None:
    """Read back the exact owner comment without borrowing gate-only authority.

    The independent Trusted PR Auto Gate validates this command again, including
    its own immutable accepted-main workflow identity and exact merged subject.
    The issuer must not call that gate-only validator in its different workflow.
    """
    if not isinstance(comment_id, int) or isinstance(comment_id, bool) or comment_id < 1:
        raise ValueError("owner authorization comment identifier is invalid")
    comment = _require_dict(
        api.get(f"/repos/{EXPECTED_REPOSITORY}/issues/comments/{comment_id}"),
        label="persisted owner authorization",
    )
    user = _require_dict(comment.get("user"), label="persisted owner authorization actor")
    created_at = comment.get("created_at")
    if (
        comment.get("id") != comment_id
        or comment.get("body") != body
        or comment.get("issue_url") != f"{API_ROOT}/repos/{EXPECTED_REPOSITORY}/issues/{pr_number}"
        or user.get("login") != EXPECTED_OWNER
        or user.get("id") != EXPECTED_OWNER_ID
        or user.get("type") != "User"
        or not isinstance(created_at, str)
        or not created_at
        or comment.get("updated_at") != created_at
    ):
        raise ValueError("persisted owner authorization is not immutable and exact")


def publish_once(token: str, pr: int, body: str) -> int:
    payload = json.dumps({"body": body}, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        f"{API_ROOT}/repos/{EXPECTED_REPOSITORY}/issues/{pr}/comments",
        data=payload,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "yp-protected-maintenance-owner-authorizer",
        },
        method="POST",
    )
    # Never retry an ambiguous mutating POST. The next scheduled run must
    # independently observe the exact durable comment before doing anything.
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read(8193)
    if len(raw) > 8192:
        raise ValueError("authorization write acknowledgment was oversized")
    result = _require_dict(json.loads(raw), label="owner authorization acknowledgment")
    user = _require_dict(result.get("user"), label="authorization actor")
    if (
        result.get("body") != body
        or user.get("login") != EXPECTED_OWNER
        or user.get("id") != EXPECTED_OWNER_ID
        or user.get("type") != "User"
        or result.get("created_at") != result.get("updated_at")
        or not isinstance(result.get("id"), int)
        or result["id"] < 1
    ):
        raise ValueError("GitHub did not acknowledge the exact owner authorization")
    return result["id"]


def authorize(api: GitHubAPI, token: str) -> dict[str, Any]:
    trusted_sha = _require_sha(_current_main(api), label="current-main revision")
    require_execution_context(trusted_sha)
    require_verified_owner_wake(api)
    rows = api.list_all(
        f"/repos/{EXPECTED_REPOSITORY}/pulls?state=open&base={EXPECTED_DEFAULT_BRANCH}&per_page=100",
        max_pages=1,
    )
    if len(rows) >= MAX_PULL_REQUEST_CANDIDATES:
        raise ValueError("protected authorizer encountered unbounded open PR inventory")
    eligible: list[Any] = []
    for row in rows:
        pr = _require_dict(row, label="maintenance candidate")
        user = _require_dict(pr.get("user"), label="maintenance candidate author")
        if (
            user.get("login") != EXPECTED_OWNER
            or user.get("id") != EXPECTED_OWNER_ID
            or user.get("type") != "User"
            or pr.get("draft") is not False
            or pr.get("state") != "open"
        ):
            continue
        head = _require_dict(pr.get("head"), label="candidate head")
        head_sha = _require_sha(head.get("sha"), label="candidate head revision")
        admission = _resolve_subject(
            api,
            lane=PROTECTED_OWNER_LANE,
            pr=pr,
            head_sha=head_sha,
            trusted_sha=trusted_sha,
            qualification_ready=True,
        )
        if not admission.eligible or not admission.protected_changes:
            continue
        if not require_passing_candidate_checks(api, head_sha):
            continue
        if _has_exact_trusted_terminal_status(api, admission=admission):
            continue
        eligible.append(admission)

    # Never choose an arbitrary candidate in a competing protected-authority lane.
    if not eligible:
        return {"decision": "no-exact-qualified-protected-maintenance", "mainSha": trusted_sha}
    if len(eligible) != 1:
        raise ValueError("multiple independently qualified protected maintenance candidates")
    selected = eligible[0]
    body = exact_comment(selected)
    present = existing_authorization(api, selected.pr_number, body)
    if present is not None:
        require_durable_owner_authorization(
            api, pr_number=selected.pr_number, comment_id=present, body=body
        )
        return {"decision": "exact-authorization-already-present", "pr": selected.pr_number}

    require_owner_token_identity(token)
    # Reprove the exact subject and current-main identity at the mutation boundary.
    if _current_main(api) != trusted_sha:
        raise ValueError("main moved before owner authorization")
    live = _require_dict(
        api.get(f"/repos/{EXPECTED_REPOSITORY}/pulls/{selected.pr_number}"),
        label="revalidated protected maintenance candidate",
    )
    current = _resolve_subject(
        api,
        lane=PROTECTED_OWNER_LANE,
        pr=live,
        head_sha=selected.head_sha,
        trusted_sha=trusted_sha,
        qualification_ready=True,
    )
    if current != selected or not require_passing_candidate_checks(api, selected.head_sha):
        raise ValueError(
            "protected maintenance subject or exact checks changed before authorization"
        )
    if existing_authorization(api, selected.pr_number, body) is not None:
        raise ValueError("authorization appeared during subject revalidation")
    comment_id = publish_once(token, selected.pr_number, body)
    require_durable_owner_authorization(
        api, pr_number=selected.pr_number, comment_id=comment_id, body=body
    )
    return {
        "decision": "exact-owner-authorization-published",
        "pr": selected.pr_number,
        "headSha": selected.head_sha,
        "baseSha": selected.base_sha,
        "mergeSha": selected.merge_sha,
        "commentId": comment_id,
    }


def main() -> None:
    if os.environ.get("GITHUB_API_URL") != API_ROOT:
        raise ValueError("owner authorization requires canonical GitHub API")
    if os.environ.get("GITHUB_REPOSITORY") != EXPECTED_REPOSITORY:
        raise ValueError("owner authorization repository drifted")
    api = GitHubAPI(
        api_url=API_ROOT,
        token=os.environ.get("GITHUB_TOKEN", ""),
        repository=EXPECTED_REPOSITORY,
    )
    result = authorize(api, os.environ.get(REVIEW_ENV, ""))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
