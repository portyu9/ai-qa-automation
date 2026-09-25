from __future__ import annotations

import re
from typing import Any

EXPECTED_REPOSITORY = "portyu9/ai-qa-automation"
EXPECTED_MAIN = "main"
GITHUB_ACTIONS_APP_ID = 15368
GITHUB_ACTIONS_LOGIN = "github-actions[bot]"
GITHUB_ACTIONS_USER_ID = 41898282

QUALIFICATION_SPECS = {
    "Required PR Gate": {
        "workflow_id": 339754724,
        "workflow_name": "CI — ƳƤ AI QA Automation Framework",
        "workflow_path": ".github/workflows/ci.yml",
        "external_prefix": "aiqa-ci-qualification",
    },
    "CodeQL": {
        "workflow_id": 359681647,
        "workflow_name": "CodeQL",
        "workflow_path": ".github/workflows/codeql.yml",
        "external_prefix": "aiqa-codeql-qualification",
    },
}
RUN_URL_RE = re.compile(
    r"^https://github\.com/portyu9/ai-qa-automation/actions/runs/(?P<run_id>[1-9][0-9]*)$"
)


class TrustedQualificationError(RuntimeError):
    """Exact-subject trusted-main qualification evidence is absent or invalid."""


def _positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise TrustedQualificationError(f"{label} must be a positive integer")
    return value


def _check_candidate(
    api: Any,
    row: dict[str, Any],
    *,
    name: str,
    head_sha: str,
    base_sha: str,
) -> dict[str, Any] | None:
    spec = QUALIFICATION_SPECS[name]
    external_id = row.get("external_id")
    if not isinstance(external_id, str) or not external_id.startswith(
        f"{spec['external_prefix']}:"
    ):
        return None
    match = re.fullmatch(
        re.escape(str(spec["external_prefix"]))
        + r":"
        + re.escape(head_sha)
        + r":(?P<run_id>[1-9][0-9]*):(?P<attempt>[1-9][0-9]*)",
        external_id,
    )
    if match is None:
        raise TrustedQualificationError(f"{name} trusted qualification external_id is malformed")
    run_id = int(match.group("run_id"))
    attempt = int(match.group("attempt"))
    if row.get("name") != name or row.get("head_sha") != head_sha:
        raise TrustedQualificationError(f"{name} trusted qualification subject drifted")
    app = row.get("app") or {}
    if (
        app.get("id") != GITHUB_ACTIONS_APP_ID
        or app.get("slug") != "github-actions"
        or app.get("name") != "GitHub Actions"
    ):
        raise TrustedQualificationError(
            f"{name} trusted qualification writer is not GitHub Actions"
        )
    if row.get("status") != "completed":
        raise TrustedQualificationError(f"{name} trusted qualification is not terminal")
    conclusion = row.get("conclusion")
    if not isinstance(conclusion, str) or not conclusion:
        raise TrustedQualificationError(f"{name} trusted qualification conclusion is invalid")
    details_url = row.get("details_url")
    expected_url = f"https://github.com/{EXPECTED_REPOSITORY}/actions/runs/{run_id}"
    if details_url != expected_url:
        raise TrustedQualificationError(
            f"{name} trusted qualification details URL is not exact-run-bound"
        )

    run = api.get(f"/actions/runs/{run_id}")
    if not isinstance(run, dict):
        raise TrustedQualificationError(f"{name} trusted qualification workflow run is malformed")
    if _positive_int(run.get("id"), "workflow run id") != run_id:
        raise TrustedQualificationError(
            f"{name} trusted qualification workflow run identity drifted"
        )
    if _positive_int(run.get("run_attempt"), "workflow run attempt") != attempt:
        raise TrustedQualificationError(f"{name} trusted qualification workflow attempt drifted")
    if (
        _positive_int(run.get("workflow_id"), "workflow id") != spec["workflow_id"]
        or run.get("name") != spec["workflow_name"]
        or run.get("path") != spec["workflow_path"]
    ):
        raise TrustedQualificationError(
            f"{name} trusted qualification came from an unreviewed workflow"
        )
    if (
        run.get("event") != "workflow_dispatch"
        or run.get("head_branch") != EXPECTED_MAIN
        or run.get("head_sha") != base_sha
        or run.get("status") != "completed"
    ):
        raise TrustedQualificationError(
            f"{name} trusted qualification run is not exact-current-main dispatch evidence"
        )
    repository = run.get("repository") or {}
    head_repository = run.get("head_repository") or {}
    if (
        repository.get("full_name") != EXPECTED_REPOSITORY
        or head_repository.get("full_name") != EXPECTED_REPOSITORY
    ):
        raise TrustedQualificationError(f"{name} trusted qualification repository identity drifted")
    actor = run.get("actor") or {}
    triggering_actor = run.get("triggering_actor") or {}
    if (
        actor.get("login") != GITHUB_ACTIONS_LOGIN
        or actor.get("id") != GITHUB_ACTIONS_USER_ID
        or triggering_actor.get("login") != GITHUB_ACTIONS_LOGIN
        or triggering_actor.get("id") != GITHUB_ACTIONS_USER_ID
    ):
        raise TrustedQualificationError(
            f"{name} trusted qualification was not dispatched by canonical GitHub Actions"
        )
    run_conclusion = run.get("conclusion")
    if conclusion == "success":
        if run_conclusion != "success":
            raise TrustedQualificationError(
                f"{name} check says success but its workflow did not succeed"
            )
    elif run_conclusion == "success":
        raise TrustedQualificationError(f"{name} check says non-success but its workflow succeeded")
    return {
        "check_id": _positive_int(row.get("id"), f"{name} check id"),
        "run_id": run_id,
        "run_attempt": attempt,
        "conclusion": conclusion,
        "details_url": expected_url,
    }


def qualification_states(
    api: Any,
    head_sha: str,
    base_sha: str,
    *,
    required: tuple[str, ...] = ("Required PR Gate", "CodeQL"),
) -> dict[str, dict[str, Any] | None]:
    rows = api.list_all(f"/commits/{head_sha}/check-runs?filter=latest", max_pages=4)
    states: dict[str, dict[str, Any] | None] = {}
    for name in required:
        if name not in QUALIFICATION_SPECS:
            raise TrustedQualificationError(f"unsupported trusted qualification check: {name}")
        candidates: list[dict[str, Any]] = []
        for raw in rows:
            if not isinstance(raw, dict) or raw.get("name") != name:
                continue
            candidate = _check_candidate(
                api,
                raw,
                name=name,
                head_sha=head_sha,
                base_sha=base_sha,
            )
            if candidate is not None:
                candidates.append(candidate)
        if len(candidates) > 1:
            raise TrustedQualificationError(f"{name} trusted qualification evidence is ambiguous")
        states[name] = candidates[0] if candidates else None
    return states


def require_success(
    api: Any,
    head_sha: str,
    base_sha: str,
    *,
    required: tuple[str, ...] = ("Required PR Gate", "CodeQL"),
) -> dict[str, dict[str, Any]]:
    states = qualification_states(api, head_sha, base_sha, required=required)
    accepted: dict[str, dict[str, Any]] = {}
    for name in required:
        state = states[name]
        if state is None:
            raise TrustedQualificationError(
                f"trusted-main qualification has not registered: {name}"
            )
        if state["conclusion"] != "success":
            raise TrustedQualificationError(
                f"trusted-main qualification is not green: {name}={state['conclusion']}"
            )
        accepted[name] = state
    return accepted
