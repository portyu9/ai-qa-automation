#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import time
import urllib.error
import urllib.request
from typing import Any

from dependency_governance import (
    API_ROOT,
    API_VERSION,
    AUTOMATION_APPROVER_LOGIN,
    AUTOMATION_APPROVER_USER_ID,
    MAX_RESPONSE_BYTES,
    GitHubApi,
    GovernanceError,
    PolicyBlock,
    _approval_positive_int,
    _automation_approval_body,
    _exact_automation_approval,
    _reject_manual_owner_veto,
    load_config,
    require_current_control_revision,
    require_sha,
)
from dependency_trusted_gate import require_action_trusted_gate, require_promotion_trusted_gate
from dependency_trusted_merge import (
    LANE_ACTIONS,
    LANE_PROMOTION,
    resolve_trusted_dependency_target,
)
from trusted_status import EXPECTED_REPOSITORY

REVIEW_TOKEN_ENV = "PORTYU9_BOT_REVIEW_TOKEN"
TRANSIENT_IDENTITY_ATTEMPTS = 3
TRANSIENT_IDENTITY_DELAY_SECONDS = 1


def _review_token_identity(token: str) -> dict[str, Any]:
    if not token:
        raise GovernanceError(f"{REVIEW_TOKEN_ENV} is required for owner-identity approval")
    request = urllib.request.Request(
        f"{API_ROOT}/user",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "aiqa-dependency-owner-review",
        },
        method="GET",
    )
    raw = b""
    for attempt in range(TRANSIENT_IDENTITY_ATTEMPTS):
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                content_length = response.headers.get("Content-Length")
                if content_length is not None and int(content_length) > MAX_RESPONSE_BYTES:
                    raise GovernanceError("owner review identity response exceeds bounded size")
                raw = response.read(MAX_RESPONSE_BYTES + 1)
            break
        except urllib.error.HTTPError as exc:
            detail = exc.read(4096).decode("utf-8", errors="replace")
            if exc.code in {502, 503, 504} and attempt + 1 < TRANSIENT_IDENTITY_ATTEMPTS:
                time.sleep(TRANSIENT_IDENTITY_DELAY_SECONDS)
                continue
            raise GovernanceError(
                f"owner review identity lookup failed HTTP {exc.code}: {detail}"
            ) from exc
        except urllib.error.URLError as exc:
            if attempt + 1 < TRANSIENT_IDENTITY_ATTEMPTS:
                time.sleep(TRANSIENT_IDENTITY_DELAY_SECONDS)
                continue
            raise GovernanceError(f"owner review identity lookup transport failure: {exc}") from exc
    if len(raw) > MAX_RESPONSE_BYTES:
        raise GovernanceError("owner review identity response exceeds bounded size")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise GovernanceError("owner review identity response is malformed JSON") from exc
    if not isinstance(payload, dict):
        raise GovernanceError("owner review identity response must be one object")
    if (
        payload.get("login") != AUTOMATION_APPROVER_LOGIN
        or payload.get("id") != AUTOMATION_APPROVER_USER_ID
        or payload.get("type") != "User"
    ):
        raise GovernanceError("owner review credential identity differs from exact repository owner")
    return payload


def _gate_evidence(
    api: GitHubApi,
    *,
    lane: str,
    pr_number: int,
    head_sha: str,
    base_sha: str,
) -> dict[str, Any]:
    if lane == LANE_ACTIONS:
        return require_action_trusted_gate(api, pr_number, head_sha, base_sha)
    if lane == LANE_PROMOTION:
        return require_promotion_trusted_gate(api, pr_number, head_sha, base_sha)
    raise GovernanceError("owner review lane is outside reviewed dependency authority")


def _resolve_exact_subject(
    api: GitHubApi,
    config: dict[str, Any],
    *,
    lane: str,
    pr_number: int,
    trusted_run_id: int,
    trusted_run_attempt: int,
) -> dict[str, Any]:
    control_sha = require_current_control_revision(api, config)
    observed_lane, observed_pr = resolve_trusted_dependency_target(
        api,
        config,
        trusted_run_id=trusted_run_id,
        trusted_run_attempt=trusted_run_attempt,
    )
    if observed_lane != lane or observed_pr != pr_number:
        raise PolicyBlock("trusted dependency subject changed before owner approval")

    pr = api.get(f"/pulls/{pr_number}")
    if not isinstance(pr, dict) or pr.get("state") != "open" or pr.get("draft") is not False:
        raise PolicyBlock("owner review requires an exact open non-draft dependency pull request")
    head = pr.get("head")
    base = pr.get("base")
    if not isinstance(head, dict) or not isinstance(base, dict):
        raise GovernanceError("owner review pull request identity is malformed")
    head_repo = head.get("repo")
    base_repo = base.get("repo")
    if (
        not isinstance(head_repo, dict)
        or not isinstance(base_repo, dict)
        or head_repo.get("full_name") != EXPECTED_REPOSITORY
        or base_repo.get("full_name") != EXPECTED_REPOSITORY
        or base.get("ref") != "main"
    ):
        raise PolicyBlock("owner review pull request repository/base identity drifted")
    head_sha = require_sha(head.get("sha"), "owner review head SHA")
    base_sha = require_sha(base.get("sha"), "owner review base SHA")
    if base_sha != control_sha:
        raise PolicyBlock("owner review pull request is stale relative to current main")

    gate = _gate_evidence(
        api,
        lane=lane,
        pr_number=pr_number,
        head_sha=head_sha,
        base_sha=base_sha,
    )
    if gate.get("runId") != trusted_run_id or gate.get("runAttempt") != trusted_run_attempt:
        raise GovernanceError("owner review Trusted PR Gate evidence changed upstream run identity")
    body = _automation_approval_body(
        number=pr_number,
        head_sha=head_sha,
        base_sha=base_sha,
        gate_evidence=gate,
    )
    return {
        "lane": lane,
        "prNumber": pr_number,
        "headSha": head_sha,
        "baseSha": base_sha,
        "gate": gate,
        "body": body,
    }


def _review_rows(api: GitHubApi, pr_number: int) -> list[dict[str, Any]]:
    rows = api.list_all(f"/pulls/{pr_number}/reviews", max_pages=2)
    if len(rows) >= 200:
        raise GovernanceError("owner review history reached its bounded pagination limit")
    return rows


def _exact_matches(
    rows: list[dict[str, Any]],
    *,
    body: str,
    head_sha: str,
) -> list[dict[str, Any]]:
    matches = [
        review
        for review in rows
        if _exact_automation_approval(review, body=body, head_sha=head_sha)
    ]
    if len(matches) > 1:
        raise GovernanceError("multiple exact owner automation approvals exist for one head")
    return matches


def publish_exact_owner_approval(
    *,
    lane: str,
    pr_number: int,
    trusted_run_id: int,
    trusted_run_attempt: int,
) -> dict[str, Any]:
    if lane not in {LANE_ACTIONS, LANE_PROMOTION}:
        raise GovernanceError("owner review lane is outside reviewed dependency authority")
    if isinstance(pr_number, bool) or not isinstance(pr_number, int) or pr_number < 1:
        raise GovernanceError("owner review PR number is invalid")
    if (
        isinstance(trusted_run_id, bool)
        or not isinstance(trusted_run_id, int)
        or trusted_run_id < 1
        or trusted_run_attempt != 1
    ):
        raise GovernanceError("owner review requires one exact first-attempt Trusted PR Gate run")

    repository = os.environ.get("GITHUB_REPOSITORY", "")
    if repository != EXPECTED_REPOSITORY:
        raise GovernanceError("owner review workflow repository identity drifted")
    read_token = os.environ.get("GITHUB_TOKEN", "")
    review_token = os.environ.get(REVIEW_TOKEN_ENV, "")
    if not read_token:
        raise GovernanceError("GITHUB_TOKEN is required for owner review revalidation")

    config = load_config()
    api = GitHubApi(read_token, repository)
    subject = _resolve_exact_subject(
        api,
        config,
        lane=lane,
        pr_number=pr_number,
        trusted_run_id=trusted_run_id,
        trusted_run_attempt=trusted_run_attempt,
    )
    rows = _review_rows(api, pr_number)
    matches = _exact_matches(rows, body=subject["body"], head_sha=subject["headSha"])
    _reject_manual_owner_veto(
        rows,
        automation_body=subject["body"],
        head_sha=subject["headSha"],
    )
    if matches:
        review = matches[0]
        return {
            "decision": "exact-owner-approval-already-present",
            "reviewId": _approval_positive_int(review.get("id"), "owner approval review id"),
            "reviewer": AUTOMATION_APPROVER_LOGIN,
            "headSha": subject["headSha"],
        }
    _review_token_identity(review_token)

    before_write = _resolve_exact_subject(
        api,
        config,
        lane=lane,
        pr_number=pr_number,
        trusted_run_id=trusted_run_id,
        trusted_run_attempt=trusted_run_attempt,
    )
    if before_write != subject:
        raise PolicyBlock("trusted dependency subject changed immediately before owner approval")

    payload = {
        "event": "APPROVE",
        "body": subject["body"],
        "commit_id": subject["headSha"],
    }
    response: Any = None
    post_error: GovernanceError | None = None
    try:
        response = api.post(f"/pulls/{pr_number}/reviews", payload, token=review_token)
    except GovernanceError as exc:
        post_error = exc

    rows = _review_rows(api, pr_number)
    matches = _exact_matches(rows, body=subject["body"], head_sha=subject["headSha"])
    if not matches:
        if post_error is not None:
            raise post_error
        raise GovernanceError("exact owner approval is not durably observable after publication")
    review = matches[0]
    if response is not None and (
        not isinstance(response, dict)
        or not _exact_automation_approval(
            response,
            body=subject["body"],
            head_sha=subject["headSha"],
        )
    ):
        raise GovernanceError("GitHub did not acknowledge the exact owner automation approval")

    after_write = _resolve_exact_subject(
        api,
        config,
        lane=lane,
        pr_number=pr_number,
        trusted_run_id=trusted_run_id,
        trusted_run_attempt=trusted_run_attempt,
    )
    if after_write != subject:
        raise PolicyBlock("trusted dependency subject changed after owner approval publication")
    final_rows = _review_rows(api, pr_number)
    final_matches = _exact_matches(
        final_rows,
        body=subject["body"],
        head_sha=subject["headSha"],
    )
    if len(final_matches) != 1:
        raise GovernanceError("exact owner approval disappeared after terminal subject revalidation")
    return {
        "decision": "exact-owner-approval-published",
        "reviewId": _approval_positive_int(review.get("id"), "owner approval review id"),
        "reviewer": AUTOMATION_APPROVER_LOGIN,
        "headSha": subject["headSha"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Publish one exact owner review after App-owned Trusted PR Gate"
    )
    parser.add_argument("--lane", required=True, choices=(LANE_ACTIONS, LANE_PROMOTION))
    parser.add_argument("--pr-number", required=True, type=int)
    parser.add_argument("--trusted-run-id", required=True, type=int)
    parser.add_argument("--trusted-run-attempt", required=True, type=int)
    args = parser.parse_args()
    result = publish_exact_owner_approval(
        lane=args.lane,
        pr_number=args.pr_number,
        trusted_run_id=args.trusted_run_id,
        trusted_run_attempt=args.trusted_run_attempt,
    )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
