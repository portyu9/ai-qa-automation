#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from collections.abc import Callable
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
    _exact_automation_approval,
    _reject_manual_owner_veto,
    _validate_owner_review_rows,
)
from trusted_status import (
    EXPECTED_REPOSITORY,
    TARGET_URL_RE,
    TRUSTED_STATUS_BOT_ID,
    TRUSTED_STATUS_BOT_LOGIN,
    TRUSTED_STATUS_CONTEXT,
    TRUSTED_STATUS_DESCRIPTION,
)

REVIEW_TOKEN_ENV = "PORTYU9_BOT_REVIEW_TOKEN"
SECURITY_AUTOHEAL_LANE = "security-autoheal"
PROTECTED_SECURITY_LANE = "protected-security-remediation"
SECURITY_LANES = frozenset({SECURITY_AUTOHEAL_LANE, PROTECTED_SECURITY_LANE})
AUTOMATION_APPROVAL_TITLE = "## ƳƤ governed security owner approval"
TRANSIENT_IDENTITY_ATTEMPTS = 3
TRANSIENT_IDENTITY_DELAY_SECONDS = 1
SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
ARTIFACT_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")

OwnerReviewError = GovernanceError
OwnerReviewPolicyBlock = PolicyBlock


def _require_lane(lane: str) -> str:
    if lane not in SECURITY_LANES:
        raise GovernanceError("security owner-review lane is outside reviewed authority")
    return lane


def _review_token_identity(token: str) -> dict[str, Any]:
    if not token:
        raise GovernanceError(f"{REVIEW_TOKEN_ENV} is required for security owner approval")
    request = urllib.request.Request(
        f"{API_ROOT}/user",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "aiqa-security-owner-review",
        },
        method="GET",
    )
    raw = b""
    for attempt in range(TRANSIENT_IDENTITY_ATTEMPTS):
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                content_length = response.headers.get("Content-Length")
                if content_length is not None and int(content_length) > MAX_RESPONSE_BYTES:
                    raise GovernanceError("security owner identity response exceeds bounded size")
                raw = response.read(MAX_RESPONSE_BYTES + 1)
            break
        except urllib.error.HTTPError as exc:
            detail = exc.read(4096).decode("utf-8", errors="replace")
            if exc.code in {502, 503, 504} and attempt + 1 < TRANSIENT_IDENTITY_ATTEMPTS:
                time.sleep(TRANSIENT_IDENTITY_DELAY_SECONDS)
                continue
            raise GovernanceError(
                f"security owner identity lookup failed HTTP {exc.code}: {detail}"
            ) from exc
        except urllib.error.URLError as exc:
            if attempt + 1 < TRANSIENT_IDENTITY_ATTEMPTS:
                time.sleep(TRANSIENT_IDENTITY_DELAY_SECONDS)
                continue
            raise GovernanceError(
                f"security owner identity lookup transport failure: {exc}"
            ) from exc
    if len(raw) > MAX_RESPONSE_BYTES:
        raise GovernanceError("security owner identity response exceeds bounded size")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise GovernanceError("security owner identity response is malformed JSON") from exc
    if not isinstance(payload, dict):
        raise GovernanceError("security owner identity response must be one object")
    if (
        payload.get("login") != AUTOMATION_APPROVER_LOGIN
        or payload.get("id") != AUTOMATION_APPROVER_USER_ID
        or payload.get("type") != "User"
    ):
        raise GovernanceError(
            "security owner-review credential identity differs from exact repository owner"
        )
    return payload


def _gate_evidence(gate_status: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(gate_status, dict):
        raise GovernanceError("security owner approval gate evidence must be one object")
    creator = gate_status.get("creator")
    if (
        gate_status.get("context") != TRUSTED_STATUS_CONTEXT
        or gate_status.get("state") != "success"
        or gate_status.get("description") != TRUSTED_STATUS_DESCRIPTION
        or not isinstance(creator, dict)
        or creator.get("login") != TRUSTED_STATUS_BOT_LOGIN
        or creator.get("id") != TRUSTED_STATUS_BOT_ID
        or creator.get("type") != "Bot"
    ):
        raise GovernanceError("security owner approval gate evidence is not App-owned success")
    status_id = _approval_positive_int(
        gate_status.get("id"), "security owner approval trusted status id"
    )
    target_url = gate_status.get("target_url")
    if not isinstance(target_url, str):
        raise GovernanceError("security owner approval Trusted PR Gate target URL is missing")
    match = TARGET_URL_RE.fullmatch(target_url)
    if match is None:
        raise GovernanceError(
            "security owner approval Trusted PR Gate target URL is not exact-subject-bound"
        )
    return {
        "statusId": status_id,
        "runId": _approval_positive_int(
            int(match.group("run_id")), "security owner approval trusted run id"
        ),
        "runAttempt": 1,
        "mergeSha": match.group("merge"),
        "prNumber": int(match.group("pr")),
        "baseSha": match.group("base"),
        "headSha": match.group("head"),
    }


def _validated_provenance(lane: str, provenance: Any) -> dict[str, Any]:
    lane = _require_lane(lane)
    if not isinstance(provenance, dict):
        raise GovernanceError("security owner approval provenance must be one object")
    if lane == SECURITY_AUTOHEAL_LANE:
        if set(provenance) != {
            "alertNumber",
            "routeRecordDigest",
            "routePlanDigest",
            "routeArtifactDigest",
        }:
            raise GovernanceError("ordinary security owner approval provenance schema drifted")
        alert_number = _approval_positive_int(
            provenance.get("alertNumber"), "ordinary security alert number"
        )
        route_record_digest = provenance.get("routeRecordDigest")
        route_plan_digest = provenance.get("routePlanDigest")
        route_artifact_digest = provenance.get("routeArtifactDigest")
        if (
            not isinstance(route_record_digest, str)
            or DIGEST.fullmatch(route_record_digest) is None
        ):
            raise GovernanceError("ordinary security route record digest is invalid")
        if not isinstance(route_plan_digest, str) or DIGEST.fullmatch(route_plan_digest) is None:
            raise GovernanceError("ordinary security route plan digest is invalid")
        if (
            not isinstance(route_artifact_digest, str)
            or ARTIFACT_DIGEST.fullmatch(route_artifact_digest) is None
        ):
            raise GovernanceError("ordinary security route artifact digest is invalid")
        return {
            "alertNumber": alert_number,
            "routeRecordDigest": route_record_digest,
            "routePlanDigest": route_plan_digest,
            "routeArtifactDigest": route_artifact_digest,
        }

    if set(provenance) != {
        "alertNumber",
        "routeRecordDigest",
        "repairPlanDigest",
        "authorStrategy",
        "authorBotLogin",
        "authorBotId",
    }:
        raise GovernanceError("protected security owner approval provenance schema drifted")
    alert_number = _approval_positive_int(
        provenance.get("alertNumber"), "protected security alert number"
    )
    route_record_digest = provenance.get("routeRecordDigest")
    repair_plan_digest = provenance.get("repairPlanDigest")
    author_strategy = provenance.get("authorStrategy")
    author_bot_login = provenance.get("authorBotLogin")
    author_bot_id = _approval_positive_int(
        provenance.get("authorBotId"), "protected security author bot id"
    )
    if not isinstance(route_record_digest, str) or DIGEST.fullmatch(route_record_digest) is None:
        raise GovernanceError("protected security route record digest is invalid")
    if not isinstance(repair_plan_digest, str) or DIGEST.fullmatch(repair_plan_digest) is None:
        raise GovernanceError("protected security repair plan digest is invalid")
    if not isinstance(author_strategy, str) or not author_strategy:
        raise GovernanceError("protected security author strategy is invalid")
    if (
        not isinstance(author_bot_login, str)
        or not author_bot_login.endswith("[bot]")
        or author_bot_login
        in {
            "github-actions[bot]",
            "dependabot[bot]",
            "trusted-pr-gate[bot]",
        }
    ):
        raise GovernanceError("protected security author bot login is invalid")
    return {
        "alertNumber": alert_number,
        "routeRecordDigest": route_record_digest,
        "repairPlanDigest": repair_plan_digest,
        "authorStrategy": author_strategy,
        "authorBotLogin": author_bot_login,
        "authorBotId": author_bot_id,
    }


def _provenance_lines(lane: str, provenance: dict[str, Any]) -> tuple[str, ...]:
    if lane == SECURITY_AUTOHEAL_LANE:
        return (
            f"- security alert: `{provenance['alertNumber']}`",
            f"- route record digest: `{provenance['routeRecordDigest']}`",
            f"- route plan digest: `{provenance['routePlanDigest']}`",
            f"- route artifact digest: `{provenance['routeArtifactDigest']}`",
        )
    return (
        f"- security alert: `{provenance['alertNumber']}`",
        f"- route record digest: `{provenance['routeRecordDigest']}`",
        f"- repair plan digest: `{provenance['repairPlanDigest']}`",
        f"- protected author strategy: `{provenance['authorStrategy']}`",
        f"- protected author bot: `{provenance['authorBotLogin']}`",
        f"- protected author bot id: `{provenance['authorBotId']}`",
    )


def _approval_body(
    *,
    lane: str,
    number: int,
    head_sha: str,
    base_sha: str,
    gate_status: dict[str, Any],
    provenance: dict[str, Any],
) -> str:
    lane = _require_lane(lane)
    provenance = _validated_provenance(lane, provenance)
    if isinstance(number, bool) or not isinstance(number, int) or number < 1:
        raise GovernanceError("security owner approval PR number is invalid")
    if SHA.fullmatch(head_sha) is None or SHA.fullmatch(base_sha) is None:
        raise GovernanceError("security owner approval subject SHA is invalid")
    gate = _gate_evidence(gate_status)
    if gate["prNumber"] != number or gate["headSha"] != head_sha or gate["baseSha"] != base_sha:
        raise GovernanceError("security owner approval gate is bound to a different subject")
    merge_sha = gate["mergeSha"]
    if not isinstance(merge_sha, str) or SHA.fullmatch(merge_sha) is None:
        raise GovernanceError("security owner approval prospective merge SHA is invalid")
    return (
        f"{AUTOMATION_APPROVAL_TITLE}\n\n"
        "Deterministic Trusted PR Gate evidence was revalidated for this exact governed "
        "security subject.\n\n"
        f"- security lane: `{lane}`\n"
        f"- PR: #{number}\n"
        f"- head: `{head_sha}`\n"
        f"- base: `{base_sha}`\n"
        f"- prospective merge: `{merge_sha}`\n"
        + "\n".join(_provenance_lines(lane, provenance))
        + "\n"
        f"- Trusted PR Gate run: `{gate['runId']}`\n"
        f"- Trusted PR Gate attempt: `{gate['runAttempt']}`\n"
        f"- Trusted PR Gate status id: `{gate['statusId']}`\n\n"
        "Merge remains separately guarded by exact-subject, owner-veto, gate, and "
        "current-main revalidation."
    )


def _review_rows(api: Any, pr_number: int) -> list[dict[str, Any]]:
    rows = api.list_all(f"/pulls/{pr_number}/reviews", max_pages=2)
    if len(rows) >= 200:
        raise GovernanceError("security owner review history reached its bounded pagination limit")
    _validate_owner_review_rows(rows)
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
        raise GovernanceError("multiple exact security owner approvals exist for one head")
    return matches


def _resolved_subject(
    resolver: Callable[[], dict[str, Any]],
    *,
    lane: str,
    expected_pr_number: int | None = None,
) -> dict[str, Any]:
    subject = resolver()
    if not isinstance(subject, dict):
        raise GovernanceError("security owner-review resolver returned malformed evidence")
    number = subject.get("prNumber")
    head_sha = subject.get("headSha")
    base_sha = subject.get("baseSha")
    gate_status = subject.get("gateStatus")
    provenance = _validated_provenance(lane, subject.get("provenance"))
    if isinstance(number, bool) or not isinstance(number, int) or number < 1:
        raise GovernanceError("security owner-review resolved PR number is invalid")
    if expected_pr_number is not None and number != expected_pr_number:
        raise PolicyBlock("security owner-review subject changed pull request identity")
    if not isinstance(head_sha, str) or SHA.fullmatch(head_sha) is None:
        raise GovernanceError("security owner-review resolved head SHA is invalid")
    if not isinstance(base_sha, str) or SHA.fullmatch(base_sha) is None:
        raise GovernanceError("security owner-review resolved base SHA is invalid")
    body = _approval_body(
        lane=lane,
        number=number,
        head_sha=head_sha,
        base_sha=base_sha,
        gate_status=gate_status,
        provenance=provenance,
    )
    return {
        "lane": _require_lane(lane),
        "prNumber": number,
        "headSha": head_sha,
        "baseSha": base_sha,
        "gate": _gate_evidence(gate_status),
        "provenance": provenance,
        "body": body,
    }


def publish_exact_owner_approval(
    *,
    lane: str,
    resolver: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    lane = _require_lane(lane)
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    if repository != EXPECTED_REPOSITORY:
        raise GovernanceError("security owner-review workflow repository identity drifted")
    read_token = os.environ.get("GITHUB_TOKEN", "")
    review_token = os.environ.get(REVIEW_TOKEN_ENV, "")
    if not read_token:
        raise GovernanceError("GITHUB_TOKEN is required for security owner-review revalidation")

    review_api = GitHubApi(read_token, repository)
    subject = _resolved_subject(resolver, lane=lane)
    pr_number = int(subject["prNumber"])
    rows = _review_rows(review_api, pr_number)
    matches = _exact_matches(rows, body=subject["body"], head_sha=subject["headSha"])
    _reject_manual_owner_veto(
        rows,
        automation_body=subject["body"],
        head_sha=subject["headSha"],
    )
    if matches:
        review = matches[0]
        return {
            "decision": "exact-security-owner-approval-already-present",
            "reviewId": _approval_positive_int(
                review.get("id"), "security owner approval review id"
            ),
            "reviewer": AUTOMATION_APPROVER_LOGIN,
            "lane": lane,
            "prNumber": pr_number,
            "headSha": subject["headSha"],
        }

    _review_token_identity(review_token)
    try:
        before_write = _resolved_subject(
            resolver,
            lane=lane,
            expected_pr_number=pr_number,
        )
    except GovernanceError as exc:
        raise PolicyBlock(
            "governed security subject changed immediately before owner approval"
        ) from exc
    if before_write != subject:
        raise PolicyBlock("governed security subject changed immediately before owner approval")

    before_rows = _review_rows(review_api, pr_number)
    before_matches = _exact_matches(
        before_rows,
        body=subject["body"],
        head_sha=subject["headSha"],
    )
    _reject_manual_owner_veto(
        before_rows,
        automation_body=subject["body"],
        head_sha=subject["headSha"],
    )
    if before_matches:
        review = before_matches[0]
        return {
            "decision": "exact-security-owner-approval-already-present",
            "reviewId": _approval_positive_int(
                review.get("id"), "security owner approval review id"
            ),
            "reviewer": AUTOMATION_APPROVER_LOGIN,
            "lane": lane,
            "prNumber": pr_number,
            "headSha": subject["headSha"],
        }

    payload = {
        "event": "APPROVE",
        "body": subject["body"],
        "commit_id": subject["headSha"],
    }
    response: Any = None
    post_error: GovernanceError | None = None
    try:
        response = review_api.post(
            f"/pulls/{pr_number}/reviews",
            payload,
            token=review_token,
        )
    except GovernanceError as exc:
        post_error = exc

    rows = _review_rows(review_api, pr_number)
    matches = _exact_matches(rows, body=subject["body"], head_sha=subject["headSha"])
    if not matches:
        if post_error is not None:
            raise post_error
        raise GovernanceError(
            "exact security owner approval is not durably observable after publication"
        )
    review = matches[0]
    if response is not None and (
        not isinstance(response, dict)
        or not _exact_automation_approval(
            response,
            body=subject["body"],
            head_sha=subject["headSha"],
        )
    ):
        raise GovernanceError("GitHub did not acknowledge exact security owner approval")

    try:
        after_write = _resolved_subject(
            resolver,
            lane=lane,
            expected_pr_number=pr_number,
        )
    except GovernanceError as exc:
        raise PolicyBlock(
            "governed security subject changed after owner approval publication"
        ) from exc
    if after_write != subject:
        raise PolicyBlock("governed security subject changed after owner approval publication")
    final_rows = _review_rows(review_api, pr_number)
    _reject_manual_owner_veto(
        final_rows,
        automation_body=subject["body"],
        head_sha=subject["headSha"],
    )
    final_matches = _exact_matches(
        final_rows,
        body=subject["body"],
        head_sha=subject["headSha"],
    )
    if len(final_matches) != 1:
        raise GovernanceError(
            "exact security owner approval disappeared after terminal subject revalidation"
        )
    return {
        "decision": "exact-security-owner-approval-published",
        "reviewId": _approval_positive_int(review.get("id"), "security owner approval review id"),
        "reviewer": AUTOMATION_APPROVER_LOGIN,
        "lane": lane,
        "prNumber": pr_number,
        "headSha": subject["headSha"],
    }


def require_exact_owner_approval(
    api: Any,
    *,
    lane: str,
    number: int,
    head_sha: str,
    base_sha: str,
    gate_status: dict[str, Any],
    provenance: dict[str, Any],
) -> dict[str, Any]:
    body = _approval_body(
        lane=lane,
        number=number,
        head_sha=head_sha,
        base_sha=base_sha,
        gate_status=gate_status,
        provenance=provenance,
    )
    rows = _review_rows(api, number)
    matches = _exact_matches(rows, body=body, head_sha=head_sha)
    _reject_manual_owner_veto(rows, automation_body=body, head_sha=head_sha)
    if not matches:
        raise PolicyBlock("exact security owner approval is not yet present")
    review = matches[0]
    return {
        "reviewId": _approval_positive_int(review.get("id"), "security owner approval review id"),
        "reviewer": AUTOMATION_APPROVER_LOGIN,
        "lane": _require_lane(lane),
        "headSha": head_sha,
    }
