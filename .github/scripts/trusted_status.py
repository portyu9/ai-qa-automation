from __future__ import annotations

import re
from typing import Any

EXPECTED_REPOSITORY = "portyu9/ai-qa-automation"
EXPECTED_GATE_WORKFLOW_NAME = "Trusted PR Auto Gate — ƳƤ AI QA Automation Framework"
EXPECTED_GATE_WORKFLOW_PATH = ".github/workflows/trusted-pr-auto.yml"
TRUSTED_STATUS_CONTEXT = "Trusted PR Gate"
TRUSTED_STATUS_BOT_LOGIN = "trusted-pr-gate[bot]"
TRUSTED_STATUS_BOT_ID = 322661847
TRUSTED_STATUS_DESCRIPTION = "Automatic exact-subject trusted validation passed"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
TARGET_URL_RE = re.compile(
    r"^https://github\.com/portyu9/ai-qa-automation/actions/runs/"
    r"(?P<run_id>[1-9][0-9]*)"
    r"\?pr=(?P<pr>[1-9][0-9]*)&base=(?P<base>[0-9a-f]{40})"
    r"&head=(?P<head>[0-9a-f]{40})&merge=(?P<merge>[0-9a-f]{40})$"
)


class TrustedStatusError(RuntimeError):
    """The exact dedicated-App terminal status is absent or invalid."""


def _require_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA_RE.fullmatch(value) is None:
        raise TrustedStatusError(f"{label} must be a canonical full SHA")
    return value


def _require_positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise TrustedStatusError(f"{label} must be a positive integer")
    return value


def _require_exact_live_subject(
    api: Any,
    *,
    pr_number: int,
    head_sha: str,
    base_sha: str,
    merge_sha: str,
) -> None:
    pr = api.get(f"/pulls/{pr_number}")
    if not isinstance(pr, dict) or pr.get("state") != "open" or pr.get("draft") is not False:
        raise TrustedStatusError("Trusted PR Gate subject is no longer an open non-draft PR")
    head = pr.get("head") or {}
    base = pr.get("base") or {}
    if (
        head.get("sha") != head_sha
        or (head.get("repo") or {}).get("full_name") != EXPECTED_REPOSITORY
        or base.get("sha") != base_sha
        or base.get("ref") != "main"
        or (base.get("repo") or {}).get("full_name") != EXPECTED_REPOSITORY
    ):
        raise TrustedStatusError("Trusted PR Gate subject identity drifted")

    merge_ref = api.get(f"/git/ref/pull/{pr_number}/merge")
    if (
        not isinstance(merge_ref, dict)
        or merge_ref.get("ref") != f"refs/pull/{pr_number}/merge"
        or ((merge_ref.get("object") or {}).get("type")) != "commit"
        or _require_sha((merge_ref.get("object") or {}).get("sha"), "merge ref SHA") != merge_sha
    ):
        raise TrustedStatusError("Trusted PR Gate merge ref drifted")

    merge_commit = api.get(f"/git/commits/{merge_sha}")
    parents = (merge_commit or {}).get("parents") if isinstance(merge_commit, dict) else None
    if (
        not isinstance(merge_commit, dict)
        or _require_sha(merge_commit.get("sha"), "merge commit SHA") != merge_sha
        or not isinstance(parents, list)
        or len(parents) != 2
    ):
        raise TrustedStatusError("Trusted PR Gate merge commit is malformed")
    observed = [
        _require_sha((parent or {}).get("sha"), "merge parent SHA") for parent in parents
    ]
    if observed != [base_sha, head_sha]:
        raise TrustedStatusError("Trusted PR Gate merge parents drifted")


def require_automatic_trusted_gate(
    api: Any,
    pr_number: int,
    head_sha: str,
    base_sha: str,
) -> dict[str, Any]:
    pr_number = _require_positive_int(pr_number, "pull request number")
    head_sha = _require_sha(head_sha, "head SHA")
    base_sha = _require_sha(base_sha, "base SHA")

    rows = api.list_all(f"/commits/{head_sha}/statuses", max_pages=4)
    matches: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict) or row.get("context") != TRUSTED_STATUS_CONTEXT:
            continue
        creator = row.get("creator") or {}
        if (
            creator.get("login") != TRUSTED_STATUS_BOT_LOGIN
            or creator.get("id") != TRUSTED_STATUS_BOT_ID
            or creator.get("type") != "Bot"
        ):
            continue
        status_id = row.get("id")
        if isinstance(status_id, bool) or not isinstance(status_id, int) or status_id < 1:
            raise TrustedStatusError("Trusted PR Gate status has an invalid id")
        matches.append(row)
    if not matches:
        raise TrustedStatusError("automatic Trusted PR Gate status has not registered")

    latest = max(matches, key=lambda row: int(row["id"]))
    if latest.get("state") != "success":
        raise TrustedStatusError(f"automatic Trusted PR Gate is not green: {latest.get('state')}")
    if latest.get("description") != TRUSTED_STATUS_DESCRIPTION:
        raise TrustedStatusError(
            "automatic Trusted PR Gate description does not match reviewed authority"
        )

    target_url = latest.get("target_url")
    if not isinstance(target_url, str):
        raise TrustedStatusError("automatic Trusted PR Gate target URL is missing")
    match = TARGET_URL_RE.fullmatch(target_url)
    if match is None:
        raise TrustedStatusError("automatic Trusted PR Gate target URL is not exact-subject-bound")
    if (
        int(match.group("pr")) != pr_number
        or match.group("base") != base_sha
        or match.group("head") != head_sha
    ):
        raise TrustedStatusError("automatic Trusted PR Gate status is bound to a stale subject")
    merge_sha = _require_sha(match.group("merge"), "status merge SHA")

    _require_exact_live_subject(
        api,
        pr_number=pr_number,
        head_sha=head_sha,
        base_sha=base_sha,
        merge_sha=merge_sha,
    )

    run_id = int(match.group("run_id"))
    run = api.get(f"/actions/runs/{run_id}")
    repository = (run or {}).get("repository") if isinstance(run, dict) else None
    head_repository = (run or {}).get("head_repository") if isinstance(run, dict) else None
    if (
        not isinstance(run, dict)
        or _require_positive_int(run.get("id"), "trusted gate run id") != run_id
        or run.get("name") != EXPECTED_GATE_WORKFLOW_NAME
        or run.get("path") != EXPECTED_GATE_WORKFLOW_PATH
        or run.get("event") != "workflow_run"
        or run.get("head_branch") != "main"
        or _require_sha(run.get("head_sha"), "trusted gate run head SHA") != base_sha
        or run.get("status") != "completed"
        or run.get("conclusion") != "success"
        or not isinstance(repository, dict)
        or repository.get("full_name") != EXPECTED_REPOSITORY
        or not isinstance(head_repository, dict)
        or head_repository.get("full_name") != EXPECTED_REPOSITORY
    ):
        raise TrustedStatusError(
            "automatic Trusted PR Gate target run is not exact-current-main gate evidence"
        )
    return latest
