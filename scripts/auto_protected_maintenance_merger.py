#!/usr/bin/env python3
"""Guarded independent merge of exact App-certified protected owner maintenance.

Owner-identity authorization is minted in a separate environment. Only the
independent trusted-pr-gate App may qualify this job for a normal protected merge.
This job never creates approvals, comments, or status checks.
"""

from __future__ import annotations

import json
import os
import stat
import sys
import urllib.request
from pathlib import Path
from typing import Any

from auto_protected_maintenance_authorizer import (
    exact_comment,
    existing_authorization,
    require_passing_candidate_checks,
)
from auto_trusted_preflight import (
    EXPECTED_DEFAULT_BRANCH,
    EXPECTED_OWNER,
    EXPECTED_OWNER_ID,
    EXPECTED_REPOSITORY,
    MAX_EVENT_BYTES,
    MAX_PULL_REQUEST_CANDIDATES,
    PROTECTED_OWNER_LANE,
    GitHubAPI,
    _current_main,
    _require_dict,
    _require_sha,
    _resolve_subject,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / ".github" / "scripts"))
from trusted_status import TrustedStatusError, require_automatic_trusted_gate

API_ROOT = "https://api.github.com"


class RepositoryLocalAdapter:
    """Expose only the canonical repository-relative surface to gate verifier."""

    def __init__(self, api: GitHubAPI) -> None:
        self.api = api

    def get(self, path: str) -> Any:
        if not isinstance(path, str) or not path.startswith("/") or ".." in path:
            raise ValueError("trusted gate verifier requested unsafe path")
        return self.api.get(f"/repos/{EXPECTED_REPOSITORY}{path}")

    def list_all(self, path: str, *, max_pages: int = 4) -> list[dict]:
        if not isinstance(path, str) or not path.startswith("/") or ".." in path:
            raise ValueError("trusted gate verifier requested unsafe inventory")
        return self.api.list_all(f"/repos/{EXPECTED_REPOSITORY}{path}", max_pages=max_pages)


def require_execution_context(trusted_sha: str) -> None:
    expected_workflow = (
        f"{EXPECTED_REPOSITORY}/.github/workflows/protected-maintenance-merge.yml@refs/heads/main"
    )
    if (
        os.environ.get("GITHUB_REPOSITORY") != EXPECTED_REPOSITORY
        or os.environ.get("GITHUB_API_URL") != API_ROOT
        or os.environ.get("GITHUB_REF") != f"refs/heads/{EXPECTED_DEFAULT_BRANCH}"
        or os.environ.get("GITHUB_SHA") != trusted_sha
        or os.environ.get("GITHUB_RUN_ATTEMPT") != "1"
        or os.environ.get("GITHUB_EVENT_NAME") not in {"schedule", "workflow_run"}
        or os.environ.get("GITHUB_WORKFLOW_REF") != expected_workflow
    ):
        raise ValueError("protected merger must execute accepted-main first-attempt controller")


TRUSTED_WAKE_WORKFLOW_ID = 346203190
TRUSTED_WAKE_WORKFLOW_NAME = "Trusted PR Auto Gate — ƳƤ AI QA Automation Framework"
TRUSTED_WAKE_WORKFLOW_PATH = ".github/workflows/trusted-pr-auto.yml"


def require_verified_merger_wake(api: GitHubAPI, main_sha: str) -> None:
    """Validate event liveness without borrowing the trusted App's merge authority."""
    if os.environ.get("GITHUB_EVENT_NAME") == "schedule":
        return
    path = os.environ.get("GITHUB_EVENT_PATH", "")
    if not path:
        raise ValueError("protected merger wake lacks native GitHub event payload")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_EVENT_BYTES:
            raise ValueError("protected merger wake must be a bounded regular file")
        raw = os.read(fd, MAX_EVENT_BYTES + 1)
    finally:
        os.close(fd)
    if len(raw) > MAX_EVENT_BYTES:
        raise ValueError("protected merger wake exceeds ingestion bound")
    event = _require_dict(json.loads(raw), label="protected merger event")
    if event.get("action") != "completed":
        raise ValueError("protected merger wake is not a completed workflow event")
    wake = _require_dict(event.get("workflow_run"), label="protected merger wake run")
    run_id = wake.get("id")
    if isinstance(run_id, bool) or not isinstance(run_id, int) or run_id < 1:
        raise ValueError("protected merger wake run id is invalid")
    live = _require_dict(
        api.get(f"/repos/{EXPECTED_REPOSITORY}/actions/runs/{run_id}"),
        label="live trusted gate wake",
    )
    repo = _require_dict(live.get("repository"), label="trusted wake repository")
    head_repo = _require_dict(live.get("head_repository"), label="trusted wake head repository")
    if (
        live.get("id") != run_id
        or live.get("workflow_id") != TRUSTED_WAKE_WORKFLOW_ID
        or wake.get("workflow_id") != TRUSTED_WAKE_WORKFLOW_ID
        or live.get("name") != TRUSTED_WAKE_WORKFLOW_NAME
        or live.get("path") != TRUSTED_WAKE_WORKFLOW_PATH
        or live.get("event") not in {"workflow_run", "schedule"}
        or live.get("run_attempt") != 1
        or live.get("status") != "completed"
        or live.get("conclusion") != "success"
        or live.get("head_branch") != EXPECTED_DEFAULT_BRANCH
        or live.get("head_sha") != main_sha
        or wake.get("head_sha") != main_sha
        or repo.get("full_name") != EXPECTED_REPOSITORY
        or head_repo.get("full_name") != EXPECTED_REPOSITORY
    ):
        raise ValueError("protected merger wake is not the exact trusted-main gate")


def require_no_exact_owner_veto(api: GitHubAPI, number: int, head_sha: str) -> None:
    rows = api.list_all(
        f"/repos/{EXPECTED_REPOSITORY}/pulls/{number}/reviews",
        max_pages=2,
    )
    for item in rows:
        review = _require_dict(item, label="owner review")
        user = _require_dict(review.get("user"), label="review user")
        if (
            user.get("login") == EXPECTED_OWNER
            and user.get("id") == EXPECTED_OWNER_ID
            and review.get("state") == "CHANGES_REQUESTED"
            and review.get("commit_id") == head_sha
        ):
            raise ValueError("owner review veto on exact protected maintenance head")


def qualify(api: GitHubAPI) -> dict[str, Any] | None:
    main_sha = _require_sha(_current_main(api), label="current main SHA")
    require_execution_context(main_sha)
    require_verified_merger_wake(api, main_sha)
    rows = api.list_all(
        f"/repos/{EXPECTED_REPOSITORY}/pulls?state=open&base=main",
        max_pages=1,
    )
    if len(rows) >= MAX_PULL_REQUEST_CANDIDATES:
        raise ValueError("protected merger PR inventory exceeded reviewed bound")
    ready: list[dict[str, Any]] = []
    for candidate in rows:
        pr = _require_dict(candidate, label="owner PR")
        user = _require_dict(pr.get("user"), label="owner PR author")
        if (
            user.get("login") != EXPECTED_OWNER
            or user.get("id") != EXPECTED_OWNER_ID
            or user.get("type") != "User"
            or pr.get("state") != "open"
            or pr.get("draft") is not False
        ):
            continue
        head = _require_dict(pr.get("head"), label="protected head")
        admission = _resolve_subject(
            api,
            lane=PROTECTED_OWNER_LANE,
            pr=pr,
            head_sha=_require_sha(head.get("sha"), label="protected head SHA"),
            trusted_sha=main_sha,
            qualification_ready=True,
        )
        if not admission.eligible or not admission.protected_changes:
            continue
        if existing_authorization(api, admission.pr_number, exact_comment(admission)) is None:
            continue
        if not require_passing_candidate_checks(api, admission.head_sha):
            continue
        require_no_exact_owner_veto(api, admission.pr_number, admission.head_sha)
        try:
            gate = require_automatic_trusted_gate(
                RepositoryLocalAdapter(api),
                admission.pr_number,
                admission.head_sha,
                admission.base_sha,
                protected_maintenance=True,
            )
        except TrustedStatusError:
            # Pending or failed App gate is never merger authority.
            continue
        ready.append({"admission": admission, "gate": gate})

    if not ready:
        return None
    if len(ready) != 1:
        raise ValueError("multiple protected merges are simultaneously eligible")
    return ready[0]


def merge_once(token: str, admission: Any) -> dict[str, Any]:
    if not token:
        raise ValueError("protected merger GITHUB_TOKEN missing")
    payload = json.dumps(
        {"sha": admission.head_sha, "merge_method": "merge"},
        separators=(",", ":"),
    ).encode("utf-8")
    request = urllib.request.Request(
        f"{API_ROOT}/repos/{EXPECTED_REPOSITORY}/pulls/{admission.pr_number}/merge",
        data=payload,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
            "User-Agent": "yp-independent-protected-maintenance-merger",
        },
        method="PUT",
    )
    # Do not replay a merge POST/PUT when network acknowledgement is ambiguous.
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read(8193)
    if len(raw) > 8192:
        raise ValueError("protected merge acknowledgment is oversized")
    result = _require_dict(json.loads(raw), label="merge acknowledgment")
    if result.get("merged") is not True:
        raise ValueError("GitHub did not report protected merge success")
    _require_sha(result.get("sha"), label="protected merge SHA")
    return result


def reconcile(api: GitHubAPI, token: str) -> dict[str, Any]:
    selected = qualify(api)
    if selected is None:
        return {"decision": "no-trusted-protected-maintenance"}
    admission = selected["admission"]
    # Fail on moved head/base/merge and owner-approval veto immediately before merge.
    if _current_main(api) != admission.base_sha:
        raise ValueError("main advanced before protected merge")
    live = _require_dict(
        api.get(f"/repos/{EXPECTED_REPOSITORY}/pulls/{admission.pr_number}"),
        label="live protected PR",
    )
    proof = _resolve_subject(
        api,
        lane=PROTECTED_OWNER_LANE,
        pr=live,
        head_sha=admission.head_sha,
        trusted_sha=admission.base_sha,
        qualification_ready=True,
    )
    if proof != admission or not require_passing_candidate_checks(api, admission.head_sha):
        raise ValueError("protected merge subject or checks changed")
    if existing_authorization(api, admission.pr_number, exact_comment(admission)) is None:
        raise ValueError("exact owner authorization disappeared")
    require_no_exact_owner_veto(api, admission.pr_number, admission.head_sha)
    require_automatic_trusted_gate(
        RepositoryLocalAdapter(api),
        admission.pr_number,
        admission.head_sha,
        admission.base_sha,
        protected_maintenance=True,
    )
    result = merge_once(token, admission)
    merge_sha = result["sha"]
    commit = _require_dict(
        api.get(f"/repos/{EXPECTED_REPOSITORY}/git/commits/{merge_sha}"),
        label="merged protected commit",
    )
    parents = commit.get("parents")
    if (
        commit.get("sha") != merge_sha
        or not isinstance(parents, list)
        or len(parents) != 2
        or [parent.get("sha") for parent in parents] != [admission.base_sha, admission.head_sha]
    ):
        raise ValueError("acknowledged merge does not preserve exact reviewed parent order")
    if _current_main(api) != merge_sha:
        raise ValueError("acknowledged protected merge does not equal live current main")
    return {
        "decision": "exact-trusted-protected-maintenance-merged",
        "pr": admission.pr_number,
        "headSha": admission.head_sha,
        "baseSha": admission.base_sha,
        "mergeSha": merge_sha,
    }


def main() -> None:
    api = GitHubAPI(
        api_url=os.environ.get("GITHUB_API_URL", ""),
        repository=os.environ.get("GITHUB_REPOSITORY", ""),
        token=os.environ.get("GITHUB_TOKEN", ""),
    )
    print(json.dumps(reconcile(api, os.environ.get("GITHUB_TOKEN", "")), sort_keys=True))


if __name__ == "__main__":
    main()
