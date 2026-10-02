#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import stat
from typing import Any

from security_autoheal import (
    AutohealError,
    GitHubApi,
    PolicyBlock,
    _current_main,
    _generated_repairs,
    _parse_marker,
    _require_scheduled_security_trusted_gate,
    _validate_generated_pr,
    load_config,
)
from trusted_status import (
    EXPECTED_GATE_WORKFLOW_ID,
    EXPECTED_GATE_WORKFLOW_NAME,
    EXPECTED_GATE_WORKFLOW_PATH,
    EXPECTED_REPOSITORY,
)

LANE_SECURITY = "security-autoheal"
LANE_NONE = "none"
TRUSTED_SECURITY_EVENTS = frozenset({"workflow_run", "schedule"})
TARGET_OUTPUT_FD = 3
MAX_OPEN_PULL_REQUESTS = 400


def _positive_int(value: Any, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise AutohealError(f"{label} must be a positive integer")
    return value


def _require_upstream_trusted_run(
    api: GitHubApi,
    *,
    run_id: int,
    run_attempt: int,
    control_sha: str,
) -> None:
    run_id = _positive_int(run_id, label="trusted workflow run id")
    run_attempt = _positive_int(run_attempt, label="trusted workflow run attempt")
    run = api.get(f"/actions/runs/{run_id}")
    repository = (run or {}).get("repository") if isinstance(run, dict) else None
    head_repository = (run or {}).get("head_repository") if isinstance(run, dict) else None
    if (
        not isinstance(run, dict)
        or _positive_int(run.get("id"), label="live trusted workflow run id") != run_id
        or _positive_int(run.get("workflow_id"), label="trusted workflow id")
        != EXPECTED_GATE_WORKFLOW_ID
        or _positive_int(run.get("run_attempt"), label="live trusted workflow run attempt")
        != run_attempt
        or run_attempt != 1
        or run.get("name") != EXPECTED_GATE_WORKFLOW_NAME
        or run.get("path") != EXPECTED_GATE_WORKFLOW_PATH
        or run.get("event") not in TRUSTED_SECURITY_EVENTS
        or run.get("head_branch") != "main"
        or run.get("head_sha") != control_sha
        or run.get("status") != "completed"
        or run.get("conclusion") != "success"
        or not isinstance(repository, dict)
        or repository.get("full_name") != EXPECTED_REPOSITORY
        or not isinstance(head_repository, dict)
        or head_repository.get("full_name") != EXPECTED_REPOSITORY
    ):
        raise AutohealError("upstream Trusted PR Auto Gate run is not exact security authority")


def resolve_trusted_security_target(
    api: GitHubApi,
    config: dict[str, Any],
    *,
    trusted_run_id: int,
    trusted_run_attempt: int,
) -> int | None:
    if config.get("repository") != EXPECTED_REPOSITORY or config.get("baseBranch") != "main":
        raise AutohealError("trusted security merge config identity drifted")
    control_sha = _current_main(api, config)
    _require_upstream_trusted_run(
        api,
        run_id=trusted_run_id,
        run_attempt=trusted_run_attempt,
        control_sha=control_sha,
    )
    rows = api.list_all("/pulls?state=open&base=main&sort=created&direction=asc", max_pages=4)
    if len(rows) >= MAX_OPEN_PULL_REQUESTS:
        raise AutohealError("trusted security target discovery reached its bounded limit")

    matches: list[int] = []
    for summary in _generated_repairs(rows):
        number = summary.get("number")
        if isinstance(number, bool) or not isinstance(number, int) or number < 1:
            raise AutohealError("generated security repair has invalid PR identity")
        try:
            live = api.get(f"/pulls/{number}")
            metadata, subject = _validate_generated_pr(api, live, config)
            gate = _require_scheduled_security_trusted_gate(api, number, metadata, subject)
        except (PolicyBlock, AutohealError):
            continue
        if (
            gate.get("runId") == trusted_run_id
            and gate.get("runAttempt") == trusted_run_attempt
        ):
            matches.append(number)

    if len(matches) > 1:
        raise AutohealError("one Trusted PR Gate run maps to multiple security merge subjects")
    return matches[0] if matches else None


def _publish_target(pr_number: int | None) -> None:
    lane = LANE_SECURITY if pr_number is not None else LANE_NONE
    pr_value = "" if pr_number is None else str(_positive_int(pr_number, label="security target PR"))
    payload = f"lane={lane}\npr_number={pr_value}\n".encode()
    try:
        info = os.fstat(TARGET_OUTPUT_FD)
    except OSError as exc:
        raise AutohealError("trusted security target output descriptor is unavailable") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
        raise AutohealError("trusted security target output is not an owned regular file")
    written = os.write(TARGET_OUTPUT_FD, payload)
    if written != len(payload):
        raise AutohealError("trusted security target output write was incomplete")
    os.fsync(TARGET_OUTPUT_FD)


def main() -> None:
    parser = argparse.ArgumentParser(description="Resolve one exact security subject from Trusted PR Gate")
    parser.add_argument("--trusted-run-id", type=int, required=True)
    parser.add_argument("--trusted-run-attempt", type=int, required=True)
    args = parser.parse_args()

    config = load_config()
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    if repository != EXPECTED_REPOSITORY:
        raise AutohealError("trusted security merge workflow repository identity drifted")
    api = GitHubApi(os.environ.get("GITHUB_TOKEN", ""), repository)
    pr_number = resolve_trusted_security_target(
        api,
        config,
        trusted_run_id=args.trusted_run_id,
        trusted_run_attempt=args.trusted_run_attempt,
    )
    _publish_target(pr_number)


if __name__ == "__main__":
    main()
