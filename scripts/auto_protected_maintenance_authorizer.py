#!/usr/bin/env python3
"""Independent accepted-main owner-identity approval for protected maintenance.

This job may publish the *owner-bound authorization comment*, never an App-owned
Trusted PR Gate status or a merge. The separate trusted controller still
qualifies the candidate and publishes its own exact-subject verdict.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from auto_trusted_preflight import (
    EXPECTED_DEFAULT_BRANCH,
    EXPECTED_OWNER,
    EXPECTED_OWNER_ID,
    EXPECTED_REPOSITORY,
    GITHUB_ACTIONS_APP_ID,
    MAX_PULL_REQUEST_CANDIDATES,
    PROTECTED_OWNER_LANE,
    PROTECTED_OWNER_REASON,
    GitHubAPI,
    _current_main,
    _has_exact_trusted_terminal_status,
    _load_qualification_module,
    _require_dict,
    _require_sha,
    _resolve_protected_owner_authorization,
    _resolve_subject,
)

SHA_LENGTH = 40
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
        or os.environ.get("GITHUB_EVENT_NAME") != "schedule"
        or os.environ.get("GITHUB_WORKFLOW_REF")
        != f"{EXPECTED_REPOSITORY}/.github/workflows/protected-maintenance-authorizer.yml@refs/heads/main"
    ):
        raise ValueError("protected owner authorization must execute on fresh accepted main")


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


def require_successful_security_gate(api: GitHubAPI, head_sha: str) -> bool:
    rows = api.list_all(
        f"/repos/{EXPECTED_REPOSITORY}/commits/{head_sha}/check-runs"
        "?check_name=security-gate&filter=all&per_page=100",
        max_pages=1,
    )
    if len(rows) != 1:
        return False
    run = _require_dict(rows[0], label="exact-head security check")
    app = _require_dict(run.get("app"), label="security check application")
    return (
        run.get("name") == "security-gate"
        and run.get("head_sha") == head_sha
        and run.get("status") == "completed"
        and run.get("conclusion") == "success"
        and app.get("id") == GITHUB_ACTIONS_APP_ID
        and app.get("slug") == "github-actions"
    )


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
    rows = api.list_all(
        f"/repos/{EXPECTED_REPOSITORY}/pulls?state=open&base={EXPECTED_DEFAULT_BRANCH}&per_page=100",
        max_pages=1,
    )
    if len(rows) >= MAX_PULL_REQUEST_CANDIDATES:
        raise ValueError("protected authorizer encountered unbounded open PR inventory")
    eligible: list[Any] = []
    qualification = _load_qualification_module()
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
        states = qualification.qualification_states(
            api, head_sha, trusted_sha, required=("Required PR Gate", "CodeQL")
        )
        if any(
            state is None or state.get("conclusion") != "success"
            for state in states.values()
        ) or not require_successful_security_gate(api, head_sha):
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
        _resolve_protected_owner_authorization(
            api, pr_number=selected.pr_number, comment_id=present,
            body=body, trusted_sha=trusted_sha,
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
        api, lane=PROTECTED_OWNER_LANE, pr=live,
        head_sha=selected.head_sha, trusted_sha=trusted_sha,
        qualification_ready=True,
    )
    if current != selected:
        raise ValueError("protected maintenance subject moved before authorization")
    if existing_authorization(api, selected.pr_number, body) is not None:
        raise ValueError("authorization appeared during subject revalidation")
    comment_id = publish_once(token, selected.pr_number, body)
    _resolve_protected_owner_authorization(
        api, pr_number=selected.pr_number, comment_id=comment_id,
        body=body, trusted_sha=trusted_sha,
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
