from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
SECURITY_SCRIPT = ROOT / ".github" / "scripts" / "security_autoheal.py"
SCRIPT_DIR = SECURITY_SCRIPT.parent


def _load_security_autoheal() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "security_autoheal_terminal_test", SECURITY_SCRIPT
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(SCRIPT_DIR))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(SCRIPT_DIR))
    return module


autoheal = _load_security_autoheal()

BASE = "a" * 40
HEAD = "b" * 40
MERGE = "c" * 40
TREE = "d" * 40
PROSPECTIVE = "f" * 40
PR_NUMBER = 321
BRIDGE_RUN_ID = 7001
BRIDGE_WORKFLOW_ID = 7002
BRIDGE_JOB_ID = 7003
CODEQL_RUN_ID = 7004
AUTOHEAL_RUN_ID = 7005
GATE_RUN_ID = 7006
TRUSTED_STATUS_ID = 7007
ROUTE_PLAN_RUN_ID = 7008
ROUTE_ARTIFACT_ID = 7009
ROUTE_PLAN_DIGEST = "2" * 64
ROUTE_ARTIFACT_DIGEST = "sha256:" + ("3" * 64)


def _route_alert() -> dict[str, Any]:
    return {
        "number": 7,
        "state": "open",
        "tool": {"name": "CodeQL"},
        "rule": {"id": "py/reflective-xss", "security_severity": "7.0"},
        "most_recent_instance": {
            "state": "open",
            "ref": "refs/heads/main",
            "commit_sha": BASE,
            "location": {
                "path": "examples/reference_sut/app.py",
                "start_line": 10,
                "end_line": 10,
                "start_column": 1,
                "end_column": 5,
            },
            "message": {"text": "security finding"},
        },
    }


ROUTE_RECORD = autoheal.route_security_alert(
    _route_alert(),
    main_sha=BASE,
    config=autoheal.load_config(),
    attempts_by_strategy={autoheal.REFERENCE_SUT_REFLECTIVE_XSS_STRATEGY: 0},
    autofix_eligibility="unknown",
)
FINGERPRINT = str(ROUTE_RECORD["fingerprint"])
ROUTE_RECORD_DIGEST = str(ROUTE_RECORD["recordDigest"])


def _metadata() -> dict[str, Any]:
    return {
        "version": 1,
        "alert": 7,
        "attempt": 1,
        "base": BASE,
        "head": HEAD,
        "fingerprint": FINGERPRINT,
        "generator": "deterministic",
        "path": str(ROUTE_RECORD["path"]),
        "rule": str(ROUTE_RECORD["rule"]),
        "severity": float(ROUTE_RECORD["securitySeverity"]),
        "strategy": str(ROUTE_RECORD["strategy"]),
        "routeDecision": str(ROUTE_RECORD["decision"]),
        "routeAuthority": str(ROUTE_RECORD["authority"]),
        "routeRecordDigest": ROUTE_RECORD_DIGEST,
        "routingPolicyVersion": str(ROUTE_RECORD["routingPolicyVersion"]),
        "routeAutofixEligibility": str(ROUTE_RECORD["autofixEligibility"]),
        "routeRecord": dict(ROUTE_RECORD),
        "routePlanDigest": ROUTE_PLAN_DIGEST,
        "routePlanRunId": ROUTE_PLAN_RUN_ID,
        "routePlanRunAttempt": 1,
        "routeArtifactId": ROUTE_ARTIFACT_ID,
        "routeArtifactName": f"{autoheal.ROUTE_PLAN_ARTIFACT_PREFIX}-{ROUTE_PLAN_RUN_ID}-1",
        "routeArtifactDigest": ROUTE_ARTIFACT_DIGEST,
    }


def _repair_pr() -> dict[str, Any]:
    return {
        "number": PR_NUMBER,
        "state": "closed",
        "draft": False,
        "merged_at": "2026-09-23T12:30:00Z",
        "merge_commit_sha": MERGE,
        "user": {
            "login": autoheal.GITHUB_ACTIONS_LOGIN,
            "id": autoheal.GITHUB_ACTIONS_USER_ID,
        },
        "merged_by": {
            "login": autoheal.GITHUB_ACTIONS_LOGIN,
            "id": autoheal.GITHUB_ACTIONS_USER_ID,
        },
        "head": {
            "ref": autoheal._branch_name(autoheal._subject_from_route(ROUTE_RECORD), 1),
            "sha": HEAD,
            "repo": {"full_name": "portyu9/ai-qa-automation"},
        },
        "base": {
            "ref": "main",
            "sha": BASE,
            "repo": {"full_name": "portyu9/ai-qa-automation"},
        },
        "body": autoheal._marker(_metadata()),
    }


def _bridge_run(
    run_id: int = BRIDGE_RUN_ID,
    *,
    workflow_id: int = BRIDGE_WORKFLOW_ID,
    run_attempt: int = 1,
    status: str = "completed",
    conclusion: str | None = "success",
    name: str = autoheal.POST_MERGE_BRIDGE_NAME,
    path: str = autoheal.POST_MERGE_BRIDGE_PATH,
    head_branch: str = "main",
    head_sha: str = MERGE,
    event: str = autoheal.POST_MERGE_BRIDGE_EVENT,
) -> dict[str, Any]:
    return {
        "id": run_id,
        "workflow_id": workflow_id,
        "run_attempt": run_attempt,
        "name": name,
        "path": path,
        "head_branch": head_branch,
        "head_sha": head_sha,
        "event": event,
        "status": status,
        "conclusion": conclusion,
    }


def _bridge_job(
    job_id: int = BRIDGE_JOB_ID,
    *,
    status: str = "completed",
    conclusion: str | None = "success",
    name: str = autoheal.POST_MERGE_REQUIRED_JOB_NAME,
) -> dict[str, Any]:
    return {
        "id": job_id,
        "name": name,
        "status": status,
        "conclusion": conclusion,
    }


def _codeql_run(
    run_id: int = CODEQL_RUN_ID,
    *,
    run_attempt: int = 1,
    status: str = "completed",
    conclusion: str | None = "success",
    event: str = "push",
    workflow_id: int = autoheal.MAIN_CODEQL_WORKFLOW_ID,
) -> dict[str, Any]:
    return {
        "id": run_id,
        "workflow_id": workflow_id,
        "run_attempt": run_attempt,
        "name": autoheal.MAIN_CODEQL_NAME,
        "path": autoheal.MAIN_CODEQL_PATH,
        "head_branch": "main",
        "head_sha": MERGE,
        "event": event,
        "status": status,
        "conclusion": conclusion,
    }


class _TerminalApi:
    def __init__(
        self,
        *,
        bridge_runs: list[dict[str, Any]] | None = None,
        bridge_jobs: dict[int, dict[str, Any] | None] | None = None,
        codeql_runs: list[dict[str, Any]] | None = None,
        alert_state: str = "fixed",
        alert_path: str | None = "examples/reference_sut/app.py",
        autoheal_head_sha: str = MERGE,
        autoheal_run_attempt: int = 1,
        autoheal_status: str = "in_progress",
        autoheal_conclusion: str | None = None,
        gate_run_attempt: int = 1,
        gate_workflow_id: int = autoheal.TRUSTED_PR_GATE_WORKFLOW_ID,
        gate_event: str = "schedule",
    ) -> None:
        self.pr = _repair_pr()
        self.bridge_runs = [_bridge_run()] if bridge_runs is None else list(bridge_runs)
        if bridge_jobs is None:
            self.bridge_jobs = {
                int(run["id"]): _bridge_job(BRIDGE_JOB_ID + index)
                for index, run in enumerate(self.bridge_runs)
            }
        else:
            self.bridge_jobs = dict(bridge_jobs)
        self.codeql_runs = [_codeql_run()] if codeql_runs is None else list(codeql_runs)
        self.alert_state = alert_state
        self.alert_path = alert_path
        self.autoheal_head_sha = autoheal_head_sha
        self.autoheal_run_attempt = autoheal_run_attempt
        self.autoheal_status = autoheal_status
        self.autoheal_conclusion = autoheal_conclusion
        self.gate_run_attempt = gate_run_attempt
        self.gate_workflow_id = gate_workflow_id
        self.gate_event = gate_event
        self.main_sha = MERGE
        self.route_artifact_available = True
        self.route_artifact_reads = 0
        self.comments: list[dict[str, Any]] = []
        self.dispatches: list[tuple[str, dict[str, Any] | None]] = []

    def get(self, path: str) -> Any:
        if path == "/branches/main":
            return {"commit": {"sha": self.main_sha}}
        if path == f"/pulls/{PR_NUMBER}":
            return self.pr
        if path == f"/commits/{HEAD}":
            return {
                "sha": HEAD,
                "author": {
                    "login": autoheal.GITHUB_ACTIONS_LOGIN,
                    "id": autoheal.GITHUB_ACTIONS_USER_ID,
                },
                "commit": {
                    "message": autoheal._route_bound_commit_message(
                        7,
                        ROUTE_RECORD_DIGEST,
                        ROUTE_PLAN_DIGEST,
                        ROUTE_ARTIFACT_DIGEST,
                    )
                },
            }
        if path == f"/git/commits/{MERGE}":
            return {
                "parents": [{"sha": BASE}, {"sha": HEAD}],
                "tree": {"sha": TREE},
            }
        if path == f"/git/commits/{PROSPECTIVE}":
            return {
                "sha": PROSPECTIVE,
                "parents": [{"sha": BASE}, {"sha": HEAD}],
                "tree": {"sha": TREE},
            }
        if path == f"/git/commits/{HEAD}":
            return {"tree": {"sha": TREE}}
        if path == f"/code-scanning/alerts/{_metadata()['alert']}":
            return {
                "number": 7,
                "state": self.alert_state,
                "tool": {"name": "CodeQL"},
                "rule": {"id": _metadata()["rule"]},
                "most_recent_instance": {"location": {"path": self.alert_path}},
            }
        if path == f"/actions/artifacts/{ROUTE_ARTIFACT_ID}":
            self.route_artifact_reads += 1
            if not self.route_artifact_available:
                raise autoheal.AutohealError("GitHub API HTTP 404: route artifact expired")
            return {
                "id": ROUTE_ARTIFACT_ID,
                "name": f"{autoheal.ROUTE_PLAN_ARTIFACT_PREFIX}-{ROUTE_PLAN_RUN_ID}-1",
                "expired": False,
                "digest": ROUTE_ARTIFACT_DIGEST,
                "workflow_run": {
                    "id": ROUTE_PLAN_RUN_ID,
                    "head_sha": BASE,
                    "head_branch": "main",
                },
            }
        expected_bridge_runs = (
            f"/actions/workflows/{autoheal.POST_MERGE_BRIDGE_WORKFLOW}/runs"
            f"?head_sha={MERGE}&event={autoheal.POST_MERGE_BRIDGE_EVENT}"
            f"&per_page={autoheal.POST_MERGE_BRIDGE_PAGE_SIZE}&page=1"
        )
        if path == expected_bridge_runs:
            return {"workflow_runs": self.bridge_runs}
        jobs_suffix = f"/jobs?filter=latest&per_page={autoheal.POST_MERGE_BRIDGE_MAX_JOBS}"
        if path.startswith("/actions/runs/") and path.endswith(jobs_suffix):
            run_id = int(path[len("/actions/runs/") : -len(jobs_suffix)])
            job = self.bridge_jobs.get(run_id)
            jobs = [] if job is None else [job]
            return {"total_count": len(jobs), "jobs": jobs}
        if path.startswith("/actions/runs/"):
            run_id = int(path.rsplit("/", 1)[1])
            if run_id == ROUTE_PLAN_RUN_ID:
                return {
                    "id": ROUTE_PLAN_RUN_ID,
                    "workflow_id": autoheal.SECURITY_AUTOHEAL_WORKFLOW_ID,
                    "path": autoheal.SECURITY_AUTOHEAL_WORKFLOW_PATH,
                    "run_attempt": 1,
                    "event": "schedule",
                    "head_branch": "main",
                    "head_sha": BASE,
                    "status": "completed",
                    "conclusion": "success",
                }
            if run_id == AUTOHEAL_RUN_ID:
                return {
                    "id": AUTOHEAL_RUN_ID,
                    "workflow_id": autoheal.SECURITY_AUTOHEAL_WORKFLOW_ID,
                    "path": autoheal.SECURITY_AUTOHEAL_WORKFLOW_PATH,
                    "run_attempt": self.autoheal_run_attempt,
                    "event": "workflow_run",
                    "head_branch": "main",
                    "head_sha": self.autoheal_head_sha,
                    "status": self.autoheal_status,
                    "conclusion": self.autoheal_conclusion,
                }
            if run_id == GATE_RUN_ID:
                return {
                    "id": GATE_RUN_ID,
                    "workflow_id": self.gate_workflow_id,
                    "name": autoheal.EXPECTED_GATE_WORKFLOW_NAME,
                    "path": autoheal.EXPECTED_GATE_WORKFLOW_PATH,
                    "event": self.gate_event,
                    "run_attempt": self.gate_run_attempt,
                    "head_branch": "main",
                    "head_sha": BASE,
                    "status": "completed",
                    "conclusion": "success",
                    "repository": {"full_name": "portyu9/ai-qa-automation"},
                    "head_repository": {"full_name": "portyu9/ai-qa-automation"},
                }
            for run in [*self.bridge_runs, *self.codeql_runs]:
                if run["id"] == run_id:
                    return run
            raise AssertionError(f"unknown workflow run id: {run_id}")
        raise AssertionError(f"unexpected GET path: {path}")

    def list_all(
        self,
        path: str,
        *,
        max_pages: int = 10,
        max_items: int | None = None,
    ) -> list[dict[str, Any]]:
        if path == "/pulls?state=closed&sort=updated&direction=desc":
            assert max_pages == 10
            return [self.pr]
        if path == (f"/actions/workflows/{autoheal.MAIN_CODEQL_WORKFLOW_ID}/runs?head_sha={MERGE}"):
            assert max_pages == 1
            assert max_items == autoheal.MAIN_CODEQL_MAX_RUNS
            return list(self.codeql_runs)
        if path == f"/issues/{PR_NUMBER}/comments":
            assert max_pages == 2
            return self.comments
        if path == f"/commits/{HEAD}/statuses":
            assert max_pages == 4
            return [
                {
                    "id": TRUSTED_STATUS_ID,
                    "context": autoheal.TRUSTED_STATUS_CONTEXT,
                    "state": "success",
                    "description": autoheal.TRUSTED_STATUS_DESCRIPTION,
                    "target_url": (
                        "https://github.com/portyu9/ai-qa-automation/actions/runs/"
                        f"{GATE_RUN_ID}?pr={PR_NUMBER}&base={BASE}&head={HEAD}"
                        f"&merge={PROSPECTIVE}"
                    ),
                    "creator": {
                        "login": autoheal.TRUSTED_STATUS_BOT_LOGIN,
                        "id": autoheal.TRUSTED_STATUS_BOT_ID,
                        "type": "Bot",
                    },
                }
            ]
        raise AssertionError(f"unexpected list path: {path}")

    def post(
        self,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        token: str | None = None,
    ) -> Any:
        assert token is None
        if path == f"/issues/{PR_NUMBER}/comments":
            assert payload is not None
            created = {
                "body": payload["body"],
                "user": {
                    "login": autoheal.GITHUB_ACTIONS_LOGIN,
                    "id": autoheal.GITHUB_ACTIONS_USER_ID,
                },
                "created_at": "2026-09-23T12:35:00Z",
                "updated_at": "2026-09-23T12:35:00Z",
            }
            self.comments.append(created)
            return created
        self.dispatches.append((path, payload))
        raise AssertionError(f"unexpected POST path: {path}")


@pytest.fixture
def config() -> dict[str, Any]:
    return autoheal.load_config()


@pytest.fixture(autouse=True)
def workflow_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_RUN_ID", str(AUTOHEAL_RUN_ID))
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")


def test_terminal_closure_persists_exact_idempotent_certificate(
    config: dict[str, Any],
) -> None:
    api = _TerminalApi()

    assert autoheal._reconcile_terminal_closure(api, MERGE, config) is True
    assert len(api.comments) == 1
    certificate = autoheal._parse_terminal_closure_comment(api.comments[0]["body"])
    assert certificate is not None
    assert certificate["version"] == 3
    assert certificate["outcome"] == "resolved"
    assert certificate["pr"] == PR_NUMBER
    assert certificate["alert"] == 7
    assert certificate["base"] == BASE
    assert certificate["head"] == HEAD
    assert certificate["mergeSha"] == MERGE
    assert certificate["sourceTreeSha"] == TREE
    assert certificate["routeRecordDigest"] == ROUTE_RECORD_DIGEST
    assert certificate["routeRecord"] == ROUTE_RECORD
    assert certificate["routePlanDigest"] == ROUTE_PLAN_DIGEST
    assert certificate["routePlanRunId"] == ROUTE_PLAN_RUN_ID
    assert certificate["routeArtifactId"] == ROUTE_ARTIFACT_ID
    assert certificate["routeArtifactDigest"] == ROUTE_ARTIFACT_DIGEST
    assert certificate["postMergeWorkflowId"] == BRIDGE_WORKFLOW_ID
    assert certificate["postMergeRunId"] == BRIDGE_RUN_ID
    assert certificate["postMergeRunAttempt"] == 1
    assert certificate["postMergeEvent"] == autoheal.POST_MERGE_BRIDGE_EVENT
    assert certificate["postMergeRequiredJobId"] == BRIDGE_JOB_ID
    assert certificate["postMergeRequiredJobName"] == autoheal.POST_MERGE_REQUIRED_JOB_NAME
    assert certificate["workflowRunId"] == AUTOHEAL_RUN_ID
    assert certificate["trustedStatusId"] == TRUSTED_STATUS_ID
    assert certificate["trustedGateWorkflowId"] == autoheal.TRUSTED_PR_GATE_WORKFLOW_ID
    assert certificate["trustedGateRunId"] == GATE_RUN_ID
    assert certificate["trustedGateRunAttempt"] == 1
    assert certificate["trustedGateEvent"] == "schedule"
    assert certificate["trustedProspectiveMergeSha"] == PROSPECTIVE

    assert autoheal._reconcile_terminal_closure(api, MERGE, config) is False
    assert len(api.comments) == 1


def test_terminal_closure_replay_survives_originating_artifact_expiry(
    config: dict[str, Any],
) -> None:
    api = _TerminalApi()

    assert autoheal._reconcile_terminal_closure(api, MERGE, config) is True
    assert len(api.comments) == 1
    assert api.route_artifact_reads == 1

    api.route_artifact_available = False
    assert autoheal._reconcile_terminal_closure(api, MERGE, config) is False
    assert len(api.comments) == 1
    assert api.route_artifact_reads == 1


def test_terminal_closure_rejects_post_merge_marker_route_field_drift(
    config: dict[str, Any],
) -> None:
    api = _TerminalApi()
    drifted = _metadata()
    drifted["routeAuthority"] = "security-autoheal-autofix"
    api.pr["body"] = autoheal._marker(drifted)

    with pytest.raises(
        autoheal.PolicyBlock,
        match="marker fields drifted from its canonical route record",
    ):
        autoheal._reconcile_terminal_closure(api, MERGE, config)

    assert api.comments == []


def test_terminal_closure_rejects_commit_or_artifact_route_provenance_drift() -> None:
    config = autoheal.load_config()

    commit_drift = _TerminalApi()
    commit_drift.pr["body"] = autoheal._marker(_metadata())
    original_get = commit_drift.get

    def drifted_commit(path: str) -> Any:
        if path == f"/commits/{HEAD}":
            payload = original_get(path)
            payload["commit"]["message"] = autoheal._route_bound_commit_message(
                7,
                "4" * 64,
                ROUTE_PLAN_DIGEST,
                ROUTE_ARTIFACT_DIGEST,
            )
            return payload
        return original_get(path)

    commit_drift.get = drifted_commit  # type: ignore[method-assign]
    with pytest.raises(
        autoheal.PolicyBlock,
        match="not immutably bound to its persisted route evidence",
    ):
        autoheal._reconcile_terminal_closure(commit_drift, MERGE, config)

    artifact_drift = _TerminalApi()
    original_artifact_get = artifact_drift.get

    def drifted_artifact(path: str) -> Any:
        payload = original_artifact_get(path)
        if path == f"/actions/artifacts/{ROUTE_ARTIFACT_ID}":
            payload["digest"] = "sha256:" + ("5" * 64)
        return payload

    artifact_drift.get = drifted_artifact  # type: ignore[method-assign]
    with pytest.raises(
        autoheal.PolicyBlock,
        match="route artifact drifted from its marker",
    ):
        autoheal._reconcile_terminal_closure(artifact_drift, MERGE, config)


@pytest.mark.parametrize("conclusion", ("failure", "cancelled"))
def test_terminal_closure_rejects_certificate_if_certifying_run_later_fails(
    config: dict[str, Any],
    conclusion: str,
) -> None:
    api = _TerminalApi()
    assert autoheal._reconcile_terminal_closure(api, MERGE, config) is True
    assert len(api.comments) == 1

    api.autoheal_status = "completed"
    api.autoheal_conclusion = conclusion

    with pytest.raises(
        autoheal.PolicyBlock,
        match="terminal closure certificate no longer has exact successful workflow evidence",
    ):
        autoheal._reconcile_terminal_closure(api, MERGE, config)
    assert len(api.comments) == 1


def test_terminal_closure_accepts_certificate_after_certifying_run_completes_successfully(
    config: dict[str, Any],
) -> None:
    api = _TerminalApi()
    assert autoheal._reconcile_terminal_closure(api, MERGE, config) is True
    assert len(api.comments) == 1

    api.autoheal_status = "completed"
    api.autoheal_conclusion = "success"

    assert autoheal._reconcile_terminal_closure(api, MERGE, config) is False
    assert len(api.comments) == 1


def test_current_main_codeql_failed_dispatch_is_unavailable_without_replay(
    config: dict[str, Any],
) -> None:
    failed = _codeql_run(
        event="workflow_dispatch",
        status="completed",
        conclusion="startup_failure",
    )
    api = _TerminalApi(codeql_runs=[failed])

    assert autoheal._observe_current_main_codeql(api, MERGE, config) == {"codeqlObserved": False}
    assert api.dispatches == []


def test_current_main_codeql_failed_dispatch_rejects_workflow_identity_drift(
    config: dict[str, Any],
) -> None:
    failed = _codeql_run(
        event="workflow_dispatch",
        status="completed",
        conclusion="startup_failure",
        workflow_id=autoheal.MAIN_CODEQL_WORKFLOW_ID + 1,
    )
    api = _TerminalApi(codeql_runs=[failed])

    with pytest.raises(
        autoheal.AutohealError,
        match="exact-main CodeQL run has mismatched workflow identity",
    ):
        autoheal._observe_current_main_codeql(api, MERGE, config)

    assert api.dispatches == []


def test_current_main_codeql_missing_evidence_does_not_dispatch(
    config: dict[str, Any],
) -> None:
    api = _TerminalApi(codeql_runs=[])

    assert autoheal._observe_current_main_codeql(api, MERGE, config) == {"codeqlObserved": False}
    assert api.dispatches == []


def test_terminal_closure_waits_for_post_merge_bridge_without_dispatch(
    config: dict[str, Any],
) -> None:
    api = _TerminalApi(bridge_runs=[], bridge_jobs={})

    assert autoheal._reconcile_terminal_closure(api, MERGE, config) is True
    assert api.comments == []
    assert api.dispatches == []


def test_terminal_closure_ignores_skipped_post_merge_bridge(
    config: dict[str, Any],
) -> None:
    api = _TerminalApi(
        bridge_jobs={BRIDGE_RUN_ID: _bridge_job(conclusion="skipped")},
    )

    assert autoheal._reconcile_terminal_closure(api, MERGE, config) is True
    assert api.comments == []
    assert api.dispatches == []


def test_terminal_closure_rejects_failed_post_merge_required_gate(
    config: dict[str, Any],
) -> None:
    api = _TerminalApi(
        bridge_jobs={BRIDGE_RUN_ID: _bridge_job(conclusion="failure")},
    )

    with pytest.raises(
        autoheal.AutohealError,
        match="required-gate job completed non-successfully",
    ):
        autoheal._reconcile_terminal_closure(api, MERGE, config)
    assert api.comments == []


def test_terminal_closure_rejects_duplicate_post_merge_bridge_runs(
    config: dict[str, Any],
) -> None:
    second = _bridge_run(BRIDGE_RUN_ID + 10)
    api = _TerminalApi(
        bridge_runs=[_bridge_run(), second],
        bridge_jobs={
            BRIDGE_RUN_ID: _bridge_job(),
            BRIDGE_RUN_ID + 10: _bridge_job(BRIDGE_JOB_ID + 10),
        },
    )

    with pytest.raises(autoheal.AutohealError, match="ambiguous post-merge bridge evidence"):
        autoheal._reconcile_terminal_closure(api, MERGE, config)
    assert api.comments == []


@pytest.mark.parametrize(
    ("bridge_run", "message"),
    (
        (_bridge_run(run_attempt=2), "run_attempt must equal 1"),
        (_bridge_run(name="Different Bridge"), "mismatched workflow identity"),
        (_bridge_run(path=".github/workflows/ci.yml"), "mismatched workflow identity"),
        (_bridge_run(head_sha="8" * 40), "not exact-main workflow_run evidence"),
        (_bridge_run(head_branch="feature"), "not exact-main workflow_run evidence"),
        (_bridge_run(event="schedule"), "not exact-main workflow_run evidence"),
    ),
)
def test_terminal_closure_rejects_malformed_post_merge_bridge(
    config: dict[str, Any],
    bridge_run: dict[str, Any],
    message: str,
) -> None:
    api = _TerminalApi(
        bridge_runs=[bridge_run],
        bridge_jobs={int(bridge_run["id"]): _bridge_job()},
    )

    with pytest.raises(autoheal.AutohealError, match=message):
        autoheal._reconcile_terminal_closure(api, MERGE, config)
    assert api.comments == []


def test_terminal_closure_rejects_bridge_evidence_if_certifying_run_later_fails(
    config: dict[str, Any],
) -> None:
    api = _TerminalApi()
    assert autoheal._reconcile_terminal_closure(api, MERGE, config) is True
    assert len(api.comments) == 1

    api.bridge_runs[0]["conclusion"] = "failure"

    with pytest.raises(
        autoheal.PolicyBlock,
        match="terminal closure certificate no longer has exact successful workflow evidence",
    ):
        autoheal._reconcile_terminal_closure(api, MERGE, config)


def test_terminal_closure_rejects_existing_certificate_if_alert_reopens(
    config: dict[str, Any],
) -> None:
    api = _TerminalApi()
    assert autoheal._reconcile_terminal_closure(api, MERGE, config) is True
    assert len(api.comments) == 1

    api.alert_state = "open"

    with pytest.raises(
        autoheal.PolicyBlock,
        match="terminal closure certificate no longer has exact fixed alert evidence",
    ):
        autoheal._reconcile_terminal_closure(api, MERGE, config)


def test_finalize_post_merge_stops_at_structural_proof(
    config: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    def _verify(*args: Any) -> tuple[str, str]:
        events.append("topology")
        return MERGE, TREE

    monkeypatch.setattr(autoheal, "_verify_actual_merge_commit", _verify)

    evidence = autoheal._finalize_post_merge_evidence(
        _TerminalApi(),
        {"sha": MERGE},
        {"baseSha": BASE, "headSha": HEAD},
        config,
    )

    assert events == ["topology"]
    assert evidence == {
        "mergeSha": MERGE,
        "sourceTreeSha": TREE,
        "postMergeBinding": ("exact-current-main-parents-validated-source-tree-validation-pending"),
    }


def test_terminal_closure_waits_for_unresolved_alert_after_green_post_merge_validation(
    config: dict[str, Any],
) -> None:
    api = _TerminalApi(alert_state="open")

    assert autoheal._reconcile_terminal_closure(api, MERGE, config) is True
    assert api.comments == []


@pytest.mark.parametrize("alert_path", (None, "examples/reference_sut/other.py"))
def test_terminal_closure_rejects_missing_or_moved_alert_path(
    config: dict[str, Any],
    alert_path: str | None,
) -> None:
    api = _TerminalApi(alert_path=alert_path)

    with pytest.raises(
        autoheal.AutohealError,
        match="terminal alert path is missing or drifted from repair provenance",
    ):
        autoheal._reconcile_terminal_closure(api, MERGE, config)
    assert api.comments == []


def test_terminal_closure_rejects_post_merge_bridge_rerun(
    config: dict[str, Any],
) -> None:
    rerun = _bridge_run(run_attempt=2)
    api = _TerminalApi(
        bridge_runs=[rerun],
        bridge_jobs={BRIDGE_RUN_ID: _bridge_job()},
    )

    with pytest.raises(autoheal.AutohealError, match="run_attempt must equal 1"):
        autoheal._reconcile_terminal_closure(api, MERGE, config)
    assert api.comments == []


def test_terminal_closure_rejects_rerun_trusted_gate(
    config: dict[str, Any],
) -> None:
    api = _TerminalApi(gate_run_attempt=2)

    with pytest.raises(
        autoheal.AutohealError,
        match="terminal Trusted PR Gate target run is not exact-main evidence",
    ):
        autoheal._reconcile_terminal_closure(api, MERGE, config)
    assert api.comments == []


def test_security_merge_gate_requires_schedule_event(
    config: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[int, str, str, frozenset[str] | set[str] | None]] = []

    def _generic_gate(
        api: Any,
        number: int,
        head_sha: str,
        base_sha: str,
        *,
        allowed_events: set[str] | frozenset[str] | None = None,
    ) -> dict[str, Any]:
        calls.append((number, head_sha, base_sha, allowed_events))
        return {"id": TRUSTED_STATUS_ID}

    monkeypatch.setattr(autoheal, "require_automatic_trusted_gate", _generic_gate)
    metadata = _metadata()
    live = {"headSha": HEAD, "baseSha": BASE}

    status = autoheal._require_scheduled_security_trusted_gate(
        _TerminalApi(),
        PR_NUMBER,
        metadata,
        live,
    )
    assert status["id"] == TRUSTED_STATUS_ID
    assert calls == [(PR_NUMBER, HEAD, BASE, autoheal.TERMINAL_TRUSTED_GATE_EVENTS)]

    with pytest.raises(
        autoheal.TrustedStatusError,
        match="not schedule-bound security evidence",
    ):
        autoheal._require_scheduled_security_trusted_gate(
            _TerminalApi(gate_event="workflow_run"),
            PR_NUMBER,
            metadata,
            live,
        )


def test_guarded_merge_revalidates_scheduled_gate_after_fresh_subject_rebind(
    config: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    metadata = _metadata()
    live = {"headSha": HEAD, "baseSha": BASE}
    events: list[str] = []

    class _MergeApi:
        def get(self, path: str) -> Any:
            assert path == f"/pulls/{PR_NUMBER}"
            events.append("fresh-pr")
            return {"number": PR_NUMBER}

        def put(
            self,
            path: str,
            payload: dict[str, Any] | None = None,
            *,
            token: str | None = None,
        ) -> dict[str, Any]:
            assert path == f"/pulls/{PR_NUMBER}/merge"
            assert payload == {"sha": HEAD, "merge_method": config["mergeMethod"]}
            assert token is None
            events.append("merge")
            return {"merged": True, "sha": MERGE}

    def _assess(
        api: Any,
        pr: dict[str, Any],
        config_arg: dict[str, Any],
        *,
        require_checks: bool,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        assert pr == {"number": PR_NUMBER}
        assert config_arg is config
        assert require_checks is False
        events.append("rebind")
        return metadata, live

    def _gate(
        api: Any,
        number: int,
        metadata_arg: dict[str, Any],
        live_arg: dict[str, Any],
    ) -> dict[str, Any]:
        assert number == PR_NUMBER
        assert metadata_arg is metadata
        assert live_arg is live
        events.append("gate")
        return {"id": TRUSTED_STATUS_ID}

    def _finalize(
        api: Any,
        result: dict[str, Any],
        live_arg: dict[str, Any],
        config_arg: dict[str, Any],
    ) -> dict[str, Any]:
        assert result == {"merged": True, "sha": MERGE}
        assert live_arg is live
        assert config_arg is config
        events.append("finalize")
        return {"mergeSha": MERGE, "sourceTreeSha": TREE}

    def _owner_review(
        api: Any,
        *,
        lane: str,
        number: int,
        head_sha: str,
        base_sha: str,
        gate_status: dict[str, Any],
    ) -> dict[str, Any]:
        assert lane == autoheal.SECURITY_AUTOHEAL_LANE
        assert number == PR_NUMBER
        assert head_sha == HEAD
        assert base_sha == BASE
        assert gate_status == {"id": TRUSTED_STATUS_ID}
        events.append("owner-review")
        return {"reviewId": 8801, "reviewer": "portyu9", "headSha": HEAD}

    monkeypatch.setattr(autoheal, "assess_trusted_admission", _assess)
    monkeypatch.setattr(autoheal, "_require_scheduled_security_trusted_gate", _gate)
    monkeypatch.setattr(autoheal, "require_exact_owner_approval", _owner_review)
    monkeypatch.setattr(autoheal, "_current_main", lambda api, config_arg: BASE)
    monkeypatch.setattr(autoheal, "_finalize_post_merge_evidence", _finalize)

    evidence = autoheal._merge(
        _MergeApi(),
        PR_NUMBER,
        metadata,
        live,
        config,
    )

    assert evidence == {"mergeSha": MERGE, "sourceTreeSha": TREE}
    assert events == ["fresh-pr", "rebind", "gate", "owner-review", "merge", "finalize"]


def test_reconcile_stops_immediately_after_successful_merge(
    config: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = {
        "number": 501,
        "head": {"ref": "automation/codeql-autoheal-7-aaaaaaaaaaaa", "sha": HEAD},
        "body": autoheal._marker(_metadata()),
    }
    second = {
        "number": 502,
        "head": {"ref": "automation/codeql-autoheal-8-bbbbbbbbbbbb", "sha": "8" * 40},
        "body": autoheal._marker({**_metadata(), "alert": 8, "head": "8" * 40}),
    }
    observed_gets: list[str] = []

    class _AfterMergeApi:
        def get(self, path: str) -> dict[str, Any]:
            observed_gets.append(path)
            if path == "/pulls/501":
                return {"number": 501}
            raise AssertionError(f"reconcile continued after merge: {path}")

        def list_all(self, path: str, *, max_pages: int = 10) -> list[dict[str, Any]]:
            raise AssertionError(f"reconcile performed post-merge pagination: {path}")

    api = _AfterMergeApi()
    monkeypatch.setenv("GITHUB_REPOSITORY", config["repository"])
    monkeypatch.setattr(autoheal, "GitHubApi", lambda token, repository: api)
    monkeypatch.setattr(autoheal, "_current_main", lambda api_arg, config_arg: BASE)
    monkeypatch.setattr(autoheal, "_reconcile_terminal_closure", lambda *args: False)
    monkeypatch.setattr(autoheal, "_open_pulls", lambda api_arg: [first, second])
    monkeypatch.setattr(autoheal, "_prune_orphan_repair_refs", lambda api_arg, pulls: 0)
    monkeypatch.setattr(autoheal, "_generated_repairs", lambda pulls: list(pulls))

    metadata = _metadata()
    live = {"headSha": HEAD, "baseSha": BASE}

    def assess(
        api_arg: object,
        pr: dict[str, Any],
        config_arg: dict[str, Any],
        *,
        require_checks: bool,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        assert pr == {"number": 501}
        assert config_arg is config
        assert require_checks is False
        return metadata, live

    monkeypatch.setattr(autoheal, "assess_trusted_admission", assess)
    monkeypatch.setattr(
        autoheal,
        "_require_scheduled_security_trusted_gate",
        lambda *args: {"id": TRUSTED_STATUS_ID},
    )
    monkeypatch.setattr(
        autoheal,
        "_merge",
        lambda *args: {"mergeSha": MERGE, "sourceTreeSha": TREE},
    )
    route_plan = {
        "mainSha": BASE,
        "planDigest": "e" * 64,
        "workflowRunId": 123,
        "workflowRunAttempt": 1,
    }
    monkeypatch.setattr(autoheal, "_load_route_plan", lambda path, config_arg: route_plan)
    monkeypatch.setattr(
        autoheal,
        "_require_route_plan_artifact",
        lambda *args, **kwargs: {
            "routePlanDigest": route_plan["planDigest"],
            "routePlanRunId": 123,
            "routePlanRunAttempt": 1,
            "routeArtifactId": 456,
            "routeArtifactName": "security-autoheal-route-plan-123-1",
            "routeArtifactDigest": "sha256:" + ("f" * 64),
        },
    )
    monkeypatch.setattr(autoheal, "_rebind_route_plan", lambda *args: {})

    assert (
        autoheal.reconcile(
            config,
            allow_merge=True,
            route_plan_path=Path("route-plan.json"),
            route_artifact_id=456,
            route_artifact_name="security-autoheal-route-plan-123-1",
            route_artifact_digest="sha256:" + ("f" * 64),
        )
        == 1
    )
    assert observed_gets == ["/pulls/501"]


def test_terminal_closure_rejects_wrong_trusted_gate_workflow_identity(
    config: dict[str, Any],
) -> None:
    api = _TerminalApi(gate_workflow_id=autoheal.TRUSTED_PR_GATE_WORKFLOW_ID + 1)

    with pytest.raises(
        autoheal.AutohealError,
        match="terminal Trusted PR Gate target run is not exact-main evidence",
    ):
        autoheal._reconcile_terminal_closure(api, MERGE, config)
    assert api.comments == []


def test_terminal_closure_rejects_rerun_autoheal_workflow_before_publication(
    config: dict[str, Any],
) -> None:
    api = _TerminalApi(autoheal_run_attempt=2)

    with pytest.raises(
        autoheal.PolicyBlock,
        match="terminal closure evidence is not exact autonomous workflow evidence",
    ):
        autoheal._reconcile_terminal_closure(api, MERGE, config)
    assert api.comments == []


def test_terminal_closure_rejects_moved_autoheal_run_before_publication(
    config: dict[str, Any],
) -> None:
    api = _TerminalApi(autoheal_head_sha="9" * 40)

    with pytest.raises(
        autoheal.PolicyBlock,
        match="terminal closure evidence is not exact autonomous workflow evidence",
    ):
        autoheal._reconcile_terminal_closure(api, MERGE, config)
    assert api.comments == []


def test_terminal_closure_rejects_duplicate_certificates(
    config: dict[str, Any],
) -> None:
    api = _TerminalApi()
    assert autoheal._reconcile_terminal_closure(api, MERGE, config) is True
    assert len(api.comments) == 1
    duplicate = dict(api.comments[0])
    duplicate["created_at"] = "2026-09-23T12:35:01Z"
    duplicate["updated_at"] = "2026-09-23T12:35:01Z"
    api.comments.append(duplicate)

    with pytest.raises(
        autoheal.PolicyBlock,
        match="ambiguous GitHub Actions terminal closure certificates",
    ):
        autoheal._reconcile_terminal_closure(api, MERGE, config)


def test_terminal_closure_rejects_edited_certificate(
    config: dict[str, Any],
) -> None:
    api = _TerminalApi()
    assert autoheal._reconcile_terminal_closure(api, MERGE, config) is True
    assert len(api.comments) == 1
    api.comments[0]["updated_at"] = "2026-09-23T12:36:00Z"

    with pytest.raises(autoheal.PolicyBlock, match="edited or malformed"):
        autoheal._reconcile_terminal_closure(api, MERGE, config)
