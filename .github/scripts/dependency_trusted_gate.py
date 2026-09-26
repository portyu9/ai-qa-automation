from __future__ import annotations

from typing import Any

from trusted_status import (
    EXPECTED_GATE_WORKFLOW_NAME,
    EXPECTED_GATE_WORKFLOW_PATH,
    EXPECTED_REPOSITORY,
    TARGET_URL_RE,
    TrustedStatusError,
    require_automatic_trusted_gate,
)

TRUSTED_PR_AUTO_WORKFLOW_ID = 346203190
TRUSTED_PR_AUTO_SCHEDULE_EVENT = "schedule"


def _require_positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise TrustedStatusError(f"{label} must be a positive integer")
    return value


def _require_sha(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 40
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise TrustedStatusError(f"{label} must be a canonical full SHA")
    return value


def _require_trusted_gate(
    api: Any,
    pr_number: int,
    head_sha: str,
    base_sha: str,
    *,
    allowed_events: frozenset[str],
    authority_label: str,
) -> dict[str, Any]:
    status = require_automatic_trusted_gate(
        api,
        pr_number,
        head_sha,
        base_sha,
        allowed_events=allowed_events,
    )
    target_url = status.get("target_url")
    if not isinstance(target_url, str):
        raise TrustedStatusError("dependency Trusted PR Gate target URL is missing")
    match = TARGET_URL_RE.fullmatch(target_url)
    if match is None:
        raise TrustedStatusError("dependency Trusted PR Gate target URL is not exact-subject-bound")

    run_id = int(match.group("run_id"))
    merge_sha = _require_sha(match.group("merge"), "dependency gate merge SHA")
    run = api.get(f"/actions/runs/{run_id}")
    repository = (run or {}).get("repository") if isinstance(run, dict) else None
    head_repository = (run or {}).get("head_repository") if isinstance(run, dict) else None
    if (
        not isinstance(run, dict)
        or _require_positive_int(run.get("id"), "dependency gate run id") != run_id
        or _require_positive_int(run.get("workflow_id"), "dependency gate workflow id")
        != TRUSTED_PR_AUTO_WORKFLOW_ID
        or run.get("name") != EXPECTED_GATE_WORKFLOW_NAME
        or run.get("path") != EXPECTED_GATE_WORKFLOW_PATH
        or run.get("event") not in allowed_events
        or _require_positive_int(run.get("run_attempt"), "dependency gate run attempt") != 1
        or run.get("head_branch") != "main"
        or _require_sha(run.get("head_sha"), "dependency gate run head SHA") != base_sha
        or run.get("status") != "completed"
        or run.get("conclusion") != "success"
        or not isinstance(repository, dict)
        or repository.get("full_name") != EXPECTED_REPOSITORY
        or not isinstance(head_repository, dict)
        or head_repository.get("full_name") != EXPECTED_REPOSITORY
    ):
        raise TrustedStatusError(
            f"dependency Trusted PR Gate run is not exact {authority_label} authority"
        )

    live_main = api.get("/branches/main")
    if (
        _require_sha(
            ((live_main or {}).get("commit") or {}).get("sha"),
            "dependency gate live main SHA",
        )
        != base_sha
    ):
        raise TrustedStatusError("dependency Trusted PR Gate base is not exact current main")

    merge_ref = api.get(f"/git/ref/pull/{pr_number}/merge")
    if (
        not isinstance(merge_ref, dict)
        or merge_ref.get("ref") != f"refs/pull/{pr_number}/merge"
        or ((merge_ref.get("object") or {}).get("type")) != "commit"
        or _require_sha(
            (merge_ref.get("object") or {}).get("sha"),
            "dependency gate merge ref SHA",
        )
        != merge_sha
    ):
        raise TrustedStatusError("dependency Trusted PR Gate merge ref drifted")

    merge_commit = api.get(f"/git/commits/{merge_sha}")
    parents = (merge_commit or {}).get("parents") if isinstance(merge_commit, dict) else None
    if (
        not isinstance(merge_commit, dict)
        or _require_sha(merge_commit.get("sha"), "dependency gate merge commit SHA") != merge_sha
        or not isinstance(parents, list)
        or len(parents) != 2
    ):
        raise TrustedStatusError("dependency Trusted PR Gate merge commit is malformed")
    observed_parents = [
        _require_sha((parent or {}).get("sha"), "dependency gate merge parent SHA")
        for parent in parents
    ]
    if observed_parents != [base_sha, head_sha]:
        raise TrustedStatusError("dependency Trusted PR Gate merge parents drifted")

    merge_tree = _require_sha(
        ((merge_commit.get("tree") or {}).get("sha")),
        "dependency gate merge tree SHA",
    )
    head_commit = api.get(f"/git/commits/{head_sha}")
    if not isinstance(head_commit, dict):
        raise TrustedStatusError("dependency gate head commit is missing")
    head_tree = _require_sha(
        ((head_commit.get("tree") or {}).get("sha")),
        "dependency gate head tree SHA",
    )
    if merge_tree != head_tree:
        raise TrustedStatusError(
            "dependency Trusted PR Gate prospective merge tree differs from validated head tree"
        )

    return {
        "statusId": _require_positive_int(status.get("id"), "dependency gate status id"),
        "runId": run_id,
        "workflowId": TRUSTED_PR_AUTO_WORKFLOW_ID,
        "event": str(run.get("event")),
        "runAttempt": 1,
        "mergeSha": merge_sha,
        "mergeTreeSha": merge_tree,
    }


def require_schedule_trusted_gate(
    api: Any,
    pr_number: int,
    head_sha: str,
    base_sha: str,
) -> dict[str, Any]:
    """Require schedule-owned Trusted PR Gate evidence for ordinary governed dependency merges."""

    return _require_trusted_gate(
        api,
        pr_number,
        head_sha,
        base_sha,
        allowed_events=frozenset({TRUSTED_PR_AUTO_SCHEDULE_EVENT}),
        authority_label="schedule-owned",
    )


def require_promotion_trusted_gate(
    api: Any,
    pr_number: int,
    head_sha: str,
    base_sha: str,
) -> dict[str, Any]:
    """Require exact automatic gate evidence for generated dependency promotions.

    Promotions may converge through the five-minute schedule or through the reviewed
    dependency-governance workflow_run wake. Both events execute the same trusted-main
    workflow and retain exact current-main/head/merge/tree revalidation here.
    """

    return _require_trusted_gate(
        api,
        pr_number,
        head_sha,
        base_sha,
        allowed_events=frozenset({"schedule", "workflow_run"}),
        authority_label="promotion automatic",
    )
