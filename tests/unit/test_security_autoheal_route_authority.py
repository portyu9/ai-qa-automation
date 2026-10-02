from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT_DIR = ROOT / ".github" / "scripts"
SCRIPT = SCRIPT_DIR / "security_autoheal.py"
BASE = "a" * 40
RUN_ID = 7001
RUN_ATTEMPT = 1
ARTIFACT_ID = 8001
ARTIFACT_NAME = f"security-autoheal-route-plan-{RUN_ID}-{RUN_ATTEMPT}"
ARTIFACT_DIGEST = "sha256:" + ("b" * 64)


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("security_autoheal_route_authority_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(SCRIPT_DIR))
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(SCRIPT_DIR))
    return module


autoheal = _load()


def _metadata() -> dict[str, Any]:
    return {
        "routePlanDigest": "c" * 64,
        "routePlanRunId": RUN_ID,
        "routePlanRunAttempt": RUN_ATTEMPT,
        "routeArtifactId": ARTIFACT_ID,
        "routeArtifactName": ARTIFACT_NAME,
        "routeArtifactDigest": ARTIFACT_DIGEST,
    }


def _job(job_id: int, name: str, *, conclusion: str = "success") -> dict[str, Any]:
    return {
        "id": job_id,
        "name": name,
        "run_id": RUN_ID,
        "run_attempt": RUN_ATTEMPT,
        "status": "completed",
        "conclusion": conclusion,
    }


class Api:
    def __init__(
        self,
        *,
        run_status: str = "completed",
        run_conclusion: str | None = "failure",
        reconcile_conclusion: str = "success",
        duplicate_plan: bool = False,
    ) -> None:
        self.run_status = run_status
        self.run_conclusion = run_conclusion
        self.reconcile_conclusion = reconcile_conclusion
        self.duplicate_plan = duplicate_plan

    def get(self, path: str) -> dict[str, Any]:
        if path == f"/actions/artifacts/{ARTIFACT_ID}":
            return {
                "id": ARTIFACT_ID,
                "name": ARTIFACT_NAME,
                "expired": False,
                "digest": ARTIFACT_DIGEST,
                "workflow_run": {
                    "id": RUN_ID,
                    "head_sha": BASE,
                    "head_branch": "main",
                },
            }
        if path == f"/actions/runs/{RUN_ID}":
            return {
                "id": RUN_ID,
                "workflow_id": autoheal.SECURITY_AUTOHEAL_WORKFLOW_ID,
                "path": autoheal.SECURITY_AUTOHEAL_WORKFLOW_PATH,
                "run_attempt": RUN_ATTEMPT,
                "event": "schedule",
                "head_branch": "main",
                "head_sha": BASE,
                "status": self.run_status,
                "conclusion": self.run_conclusion,
            }
        if path == (
            f"/actions/runs/{RUN_ID}/jobs?filter=latest"
            f"&per_page={autoheal.ROUTE_AUTHORITY_MAX_JOBS}"
        ):
            jobs = [
                _job(9001, autoheal.ROUTE_PLAN_JOB_NAME),
                _job(
                    9002,
                    autoheal.RECONCILE_JOB_NAME,
                    conclusion=self.reconcile_conclusion,
                ),
            ]
            if self.duplicate_plan:
                jobs.append(_job(9003, autoheal.ROUTE_PLAN_JOB_NAME))
            return {"total_count": len(jobs), "jobs": jobs}
        raise AssertionError(f"unexpected API path: {path}")


@pytest.mark.parametrize(
    ("run_status", "run_conclusion"),
    [
        ("in_progress", None),
        ("completed", "success"),
        ("completed", "failure"),
    ],
)
def test_route_artifact_authority_is_bound_to_successful_authoring_stages(
    run_status: str,
    run_conclusion: str | None,
) -> None:
    autoheal._require_marker_route_artifact(
        Api(run_status=run_status, run_conclusion=run_conclusion),
        _metadata(),
        BASE,
    )


def test_route_artifact_authority_rejects_failed_reconcile_stage() -> None:
    with pytest.raises(autoheal.PolicyBlock, match="lacks exact success"):
        autoheal._require_marker_route_artifact(
            Api(reconcile_conclusion="failure"),
            _metadata(),
            BASE,
        )


def test_route_artifact_authority_rejects_ambiguous_authoring_stage() -> None:
    with pytest.raises(autoheal.PolicyBlock, match="missing or ambiguous"):
        autoheal._require_marker_route_artifact(
            Api(duplicate_plan=True),
            _metadata(),
            BASE,
        )


def test_route_artifact_authority_rejects_unstarted_controller_run() -> None:
    with pytest.raises(autoheal.PolicyBlock, match="exact controller-run identity"):
        autoheal._require_marker_route_artifact(
            Api(run_status="queued", run_conclusion=None),
            _metadata(),
            BASE,
        )
