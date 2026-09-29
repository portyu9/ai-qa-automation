#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sys
from typing import Any

from dependency_governance import (
    BOT_LOGIN,
    BOT_USER_ID,
    DEPENDABOT_ACTION_REF,
    GitHubApi,
    GovernanceError,
    load_config,
    require_current_control_revision,
    require_sha,
)
from dependency_promotion import PROMOTION_BRANCH_RE, _promotion_actor_matches
from dependency_trusted_gate import (
    TRUSTED_PR_AUTO_WORKFLOW_ID,
    require_action_trusted_gate,
    require_promotion_trusted_gate,
)
from trusted_status import (
    EXPECTED_GATE_WORKFLOW_NAME,
    EXPECTED_GATE_WORKFLOW_PATH,
    EXPECTED_REPOSITORY,
    TrustedStatusError,
)

TRUSTED_DEPENDENCY_EVENTS = frozenset({"workflow_run", "schedule"})
LANE_ACTIONS = "dependabot-actions"
LANE_PROMOTION = "dependency-promotion"
LANE_NONE = "none"
MAX_OPEN_PULL_REQUESTS = 400


def _positive_int(value: Any, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise GovernanceError(f"{label} must be a positive integer")
    return value


def _require_upstream_trusted_run(
    api: GitHubApi,
    *,
    run_id: int,
    run_attempt: int,
    control_sha: str,
) -> dict[str, Any]:
    run_id = _positive_int(run_id, label="trusted workflow run id")
    run_attempt = _positive_int(run_attempt, label="trusted workflow run attempt")
    run = api.get(f"/actions/runs/{run_id}")
    repository = (run or {}).get("repository") if isinstance(run, dict) else None
    head_repository = (run or {}).get("head_repository") if isinstance(run, dict) else None
    if (
        not isinstance(run, dict)
        or _positive_int(run.get("id"), label="live trusted workflow run id") != run_id
        or _positive_int(run.get("workflow_id"), label="trusted workflow id")
        != TRUSTED_PR_AUTO_WORKFLOW_ID
        or _positive_int(run.get("run_attempt"), label="live trusted workflow run attempt")
        != run_attempt
        or run_attempt != 1
        or run.get("name") != EXPECTED_GATE_WORKFLOW_NAME
        or run.get("path") != EXPECTED_GATE_WORKFLOW_PATH
        or run.get("event") not in TRUSTED_DEPENDENCY_EVENTS
        or run.get("head_branch") != "main"
        or require_sha(run.get("head_sha"), "trusted workflow control SHA") != control_sha
        or run.get("status") != "completed"
        or run.get("conclusion") != "success"
        or not isinstance(repository, dict)
        or repository.get("full_name") != EXPECTED_REPOSITORY
        or not isinstance(head_repository, dict)
        or head_repository.get("full_name") != EXPECTED_REPOSITORY
    ):
        raise GovernanceError("upstream Trusted PR Auto Gate run is not exact dependency authority")
    return run


def _candidate_lane(pr: dict[str, Any], *, current_main: str) -> tuple[str, int, str, str] | None:
    if pr.get("state") != "open" or pr.get("draft") is not False:
        return None
    number = pr.get("number")
    if isinstance(number, bool) or not isinstance(number, int) or number < 1:
        return None
    user = pr.get("user") or {}
    head = pr.get("head") or {}
    base = pr.get("base") or {}
    head_repo = head.get("repo") or {}
    base_repo = base.get("repo") or {}
    branch = head.get("ref")
    if (
        not isinstance(branch, str)
        or head_repo.get("full_name") != EXPECTED_REPOSITORY
        or base_repo.get("full_name") != EXPECTED_REPOSITORY
        or base.get("ref") != "main"
        or require_sha(base.get("sha"), "candidate dependency base SHA") != current_main
    ):
        return None
    head_sha = require_sha(head.get("sha"), "candidate dependency head SHA")
    if (
        DEPENDABOT_ACTION_REF.fullmatch(branch) is not None
        and user.get("login") == BOT_LOGIN
        and user.get("id") == BOT_USER_ID
    ):
        return LANE_ACTIONS, number, head_sha, current_main
    if PROMOTION_BRANCH_RE.fullmatch(branch) is not None and _promotion_actor_matches(user):
        return LANE_PROMOTION, number, head_sha, current_main
    return None


def resolve_trusted_dependency_target(
    api: GitHubApi,
    config: dict[str, Any],
    *,
    trusted_run_id: int,
    trusted_run_attempt: int,
) -> tuple[str, int | None]:
    if config.get("repository") != EXPECTED_REPOSITORY or config.get("baseBranch") != "main":
        raise GovernanceError("trusted dependency merge config identity drifted")
    control_sha = require_current_control_revision(api, config)
    _require_upstream_trusted_run(
        api,
        run_id=trusted_run_id,
        run_attempt=trusted_run_attempt,
        control_sha=control_sha,
    )
    rows = api.list_all("/pulls?state=open&base=main&sort=created&direction=asc", max_pages=4)
    if len(rows) >= MAX_OPEN_PULL_REQUESTS:
        raise GovernanceError("trusted dependency target discovery reached its bounded limit")

    matches: list[tuple[str, int]] = []
    for raw in rows:
        if not isinstance(raw, dict):
            raise GovernanceError("open dependency pull-request discovery returned a malformed row")
        candidate = _candidate_lane(raw, current_main=control_sha)
        if candidate is None:
            continue
        lane, number, head_sha, base_sha = candidate
        try:
            if lane == LANE_PROMOTION:
                evidence = require_promotion_trusted_gate(api, number, head_sha, base_sha)
            elif lane == LANE_ACTIONS:
                evidence = require_action_trusted_gate(api, number, head_sha, base_sha)
            else:  # pragma: no cover - candidate_lane owns the closed lane set
                raise GovernanceError(
                    "trusted dependency candidate lane is outside reviewed policy"
                )
        except TrustedStatusError:
            continue
        if (
            evidence.get("runId") == trusted_run_id
            and evidence.get("runAttempt") == trusted_run_attempt
        ):
            matches.append((lane, number))

    if len(matches) > 1:
        raise GovernanceError("one Trusted PR Gate run maps to multiple dependency merge subjects")
    if not matches:
        return LANE_NONE, None
    return matches[0]


def _target_output(*, lane: str, pr_number: int | None) -> str:
    if lane not in {LANE_NONE, LANE_ACTIONS, LANE_PROMOTION}:
        raise GovernanceError("trusted dependency target lane is outside reviewed policy")
    if lane == LANE_NONE:
        if pr_number is not None:
            raise GovernanceError("empty trusted dependency target unexpectedly carries a PR")
        pr_value = ""
    else:
        pr_value = str(_positive_int(pr_number, label="trusted dependency target PR"))
    return f"lane={lane}\npr_number={pr_value}\n"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Resolve one exact dependency subject from Trusted PR Gate"
    )
    parser.add_argument("--trusted-run-id", type=int, required=True)
    parser.add_argument("--trusted-run-attempt", type=int, required=True)
    args = parser.parse_args()

    config = load_config()
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    if repository != EXPECTED_REPOSITORY:
        raise GovernanceError("trusted dependency merge workflow repository identity drifted")
    api = GitHubApi(os.environ.get("GITHUB_TOKEN", ""), repository)
    lane, pr_number = resolve_trusted_dependency_target(
        api,
        config,
        trusted_run_id=args.trusted_run_id,
        trusted_run_attempt=args.trusted_run_attempt,
    )
    sys.stdout.write(_target_output(lane=lane, pr_number=pr_number))


if __name__ == "__main__":
    main()
