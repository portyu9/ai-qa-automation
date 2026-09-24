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
FINGERPRINT = "e" * 64
PROSPECTIVE = "f" * 40
PR_NUMBER = 321
CI_RUN_ID = 7001
CODEQL_RUN_ID = 7002
AUTOHEAL_RUN_ID = 7003
GATE_RUN_ID = 7004
TRUSTED_STATUS_ID = 7005


def _metadata() -> dict[str, Any]:
    return {
        "version": 1,
        "alert": 7,
        "attempt": 1,
        "base": BASE,
        "head": HEAD,
        "fingerprint": FINGERPRINT,
        "generator": "deterministic",
        "path": "examples/reference_sut/app.py",
        "rule": "py/reflective-xss",
        "severity": 7.0,
        "strategy": autoheal.REFERENCE_SUT_REFLECTIVE_XSS_STRATEGY,
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
            "ref": "automation/codeql-autoheal-7-eeeeeeeeeeee",
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


def _ci_run(
    run_id: int = CI_RUN_ID,
    *,
    run_attempt: int = 1,
    status: str = "completed",
    conclusion: str | None = "success",
    event: str = "push",
    workflow_id: int = autoheal.POST_MERGE_CI_WORKFLOW_ID,
    name: str = autoheal.POST_MERGE_CI_NAME,
    path: str = autoheal.POST_MERGE_CI_PATH,
    head_branch: str = "main",
    head_sha: str = MERGE,
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


def _codeql_run(
    run_id: int = CODEQL_RUN_ID,
    *,
    run_attempt: int = 1,
    status: str = "completed",
    conclusion: str | None = "success",
) -> dict[str, Any]:
    return {
        "id": run_id,
        "workflow_id": autoheal.MAIN_CODEQL_WORKFLOW_ID,
        "run_attempt": run_attempt,
        "name": autoheal.MAIN_CODEQL_NAME,
        "path": autoheal.MAIN_CODEQL_PATH,
        "head_branch": "main",
        "head_sha": MERGE,
        "event": "push",
        "status": status,
        "conclusion": conclusion,
    }


class _TerminalApi:
    def __init__(
        self,
        *,
        ci_runs: list[dict[str, Any]] | None = None,
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
        self.ci_runs = [_ci_run()] if ci_runs is None else list(ci_runs)
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
                "commit": {"message": "security: auto-heal CodeQL alert #7"},
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
        if path.startswith("/actions/runs/"):
            run_id = int(path.rsplit("/", 1)[1])
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
            for run in [*self.ci_runs, *self.codeql_runs]:
                if run["id"] == run_id:
                    return run
            raise AssertionError(f"unknown workflow run id: {run_id}")
        raise AssertionError(f"unexpected GET path: {path}")

    def list_all(self, path: str, *, max_pages: int = 10) -> list[dict[str, Any]]:
        if path == "/pulls?state=closed&sort=updated&direction=desc":
            assert max_pages == 10
            return [self.pr]
        if path == f"/actions/runs?head_sha={MERGE}":
            assert max_pages == 2
            return [*self.ci_runs, *self.codeql_runs]
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
        if path == f"/actions/workflows/{autoheal.POST_MERGE_CI_WORKFLOW}/dispatches":
            self.dispatches.append((path, payload))
            self.ci_runs.append(
                _ci_run(
                    status="queued",
                    conclusion=None,
                    event="workflow_dispatch",
                )
            )
            return None
        if path == f"/actions/workflows/{autoheal.MAIN_CODEQL_WORKFLOW}/dispatches":
            self.dispatches.append((path, payload))
            self.codeql_runs.append(
                _codeql_run(
                    status="queued",
                    conclusion=None,
                )
            )
            return None
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
    assert certificate["outcome"] == "resolved"
    assert certificate["pr"] == PR_NUMBER
    assert certificate["alert"] == 7
    assert certificate["base"] == BASE
    assert certificate["head"] == HEAD
    assert certificate["mergeSha"] == MERGE
    assert certificate["sourceTreeSha"] == TREE
    assert certificate["ciRunId"] == CI_RUN_ID
    assert certificate["codeqlRunId"] == CODEQL_RUN_ID
    assert certificate["workflowRunId"] == AUTOHEAL_RUN_ID
    assert certificate["trustedStatusId"] == TRUSTED_STATUS_ID
    assert certificate["trustedGateWorkflowId"] == autoheal.TRUSTED_PR_GATE_WORKFLOW_ID
    assert certificate["trustedGateRunId"] == GATE_RUN_ID
    assert certificate["trustedGateRunAttempt"] == 1
    assert certificate["trustedGateEvent"] == "schedule"
    assert certificate["trustedProspectiveMergeSha"] == PROSPECTIVE

    assert autoheal._reconcile_terminal_closure(api, MERGE, config) is False
    assert len(api.comments) == 1


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


def test_terminal_closure_dispatches_liveness_ci_but_waits_for_automatic_push(
    config: dict[str, Any],
) -> None:
    api = _TerminalApi(ci_runs=[])

    assert autoheal._reconcile_terminal_closure(api, MERGE, config) is True
    assert api.dispatches == [
        (
            f"/actions/workflows/{autoheal.POST_MERGE_CI_WORKFLOW}/dispatches",
            {
                "ref": "main",
                "inputs": {"subject_sha": MERGE, "subject_ref": "main"},
            },
        )
    ]
    assert api.ci_runs[0]["event"] == "workflow_dispatch"
    assert api.comments == []


def test_post_merge_ci_reuses_existing_push_without_dispatch(
    config: dict[str, Any],
) -> None:
    api = _TerminalApi()

    evidence = autoheal._ensure_post_merge_ci(api, MERGE, config)

    assert evidence == {
        "postMergeCiWorkflowId": autoheal.POST_MERGE_CI_WORKFLOW_ID,
        "postMergeCiRunId": CI_RUN_ID,
        "postMergeCiRunAttempt": 1,
        "postMergeCiEvent": "push",
        "postMergeCiStatus": "completed",
        "postMergeCiDispatched": False,
    }
    assert api.dispatches == []


def test_post_merge_ci_dispatches_new_exact_subject_run(
    config: dict[str, Any],
) -> None:
    api = _TerminalApi(ci_runs=[])

    evidence = autoheal._ensure_post_merge_ci(api, MERGE, config)

    assert evidence["postMergeCiRunId"] == CI_RUN_ID
    assert evidence["postMergeCiRunAttempt"] == 1
    assert evidence["postMergeCiEvent"] == "workflow_dispatch"
    assert evidence["postMergeCiStatus"] == "queued"
    assert evidence["postMergeCiDispatched"] is True
    assert len(api.dispatches) == 1


@pytest.mark.parametrize(
    ("row", "message"),
    (
        (
            _ci_run(run_attempt=2),
            "exact-subject CI run_attempt must equal 1",
        ),
        (
            _ci_run(workflow_id=autoheal.POST_MERGE_CI_WORKFLOW_ID + 1),
            "mismatched workflow identity",
        ),
        (
            _ci_run(name="Different CI"),
            "mismatched workflow identity",
        ),
        (
            _ci_run(path=".github/workflows/not-ci.yml"),
            "mismatched workflow identity",
        ),
        (
            _ci_run(head_sha="8" * 40),
            "different head SHA",
        ),
        (
            _ci_run(head_branch="feature"),
            "not bound to main",
        ),
        (
            _ci_run(event="workflow_run"),
            "unexpected event",
        ),
        (
            _ci_run(status="completed", conclusion="failure"),
            "completed non-successfully",
        ),
    ),
)
def test_post_merge_ci_rejects_malformed_canonical_evidence(
    config: dict[str, Any],
    row: dict[str, Any],
    message: str,
) -> None:
    api = _TerminalApi(ci_runs=[row])

    with pytest.raises(autoheal.AutohealError, match=message):
        autoheal._ensure_post_merge_ci(api, MERGE, config)


def test_post_merge_ci_rejects_duplicate_canonical_runs(
    config: dict[str, Any],
) -> None:
    api = _TerminalApi(ci_runs=[_ci_run(), _ci_run(7101)])

    with pytest.raises(autoheal.AutohealError, match="ambiguous exact-subject CI evidence"):
        autoheal._ensure_post_merge_ci(api, MERGE, config)


def test_post_merge_ci_rejects_main_drift_after_dispatch_registration(
    config: dict[str, Any],
) -> None:
    class _DriftApi(_TerminalApi):
        def post(
            self,
            path: str,
            payload: dict[str, Any] | None = None,
            *,
            token: str | None = None,
        ) -> Any:
            result = super().post(path, payload, token=token)
            self.main_sha = "9" * 40
            return result

    api = _DriftApi(ci_runs=[])

    with pytest.raises(
        autoheal.AutohealError,
        match="current main changed after post-merge CI registration",
    ):
        autoheal._ensure_post_merge_ci(api, MERGE, config)


def test_post_merge_ci_dispatch_failure_fails_closed(
    config: dict[str, Any],
) -> None:
    class _DispatchFailureApi(_TerminalApi):
        def post(
            self,
            path: str,
            payload: dict[str, Any] | None = None,
            *,
            token: str | None = None,
        ) -> Any:
            assert path == f"/actions/workflows/{autoheal.POST_MERGE_CI_WORKFLOW}/dispatches"
            assert payload == {
                "ref": "main",
                "inputs": {"subject_sha": MERGE, "subject_ref": "main"},
            }
            assert token is None
            raise autoheal.AutohealError("simulated dispatch failure")

    api = _DispatchFailureApi(ci_runs=[])

    with pytest.raises(autoheal.AutohealError, match="simulated dispatch failure"):
        autoheal._ensure_post_merge_ci(api, MERGE, config)


def test_post_merge_ci_registration_exhaustion_fails_closed(
    config: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _NoRegistrationApi(_TerminalApi):
        def post(
            self,
            path: str,
            payload: dict[str, Any] | None = None,
            *,
            token: str | None = None,
        ) -> Any:
            assert token is None
            self.dispatches.append((path, payload))
            return None

    api = _NoRegistrationApi(ci_runs=[])
    monkeypatch.setattr(autoheal, "POST_MERGE_CI_REGISTRATION_ATTEMPTS", 2)
    monkeypatch.setattr(autoheal, "POST_MERGE_CI_REGISTRATION_DELAY_SECONDS", 0)

    with pytest.raises(autoheal.AutohealError, match="explicit CI dispatch did not register"):
        autoheal._ensure_post_merge_ci(api, MERGE, config)


def test_finalize_post_merge_orders_topology_before_ci_registration(
    config: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    def _verify(*args: Any) -> tuple[str, str]:
        events.append("topology")
        return MERGE, TREE

    def _ensure(*args: Any) -> dict[str, Any]:
        assert events == ["topology"]
        events.append("ci-registration")
        return {
            "postMergeCiWorkflowId": autoheal.POST_MERGE_CI_WORKFLOW_ID,
            "postMergeCiRunId": CI_RUN_ID,
            "postMergeCiRunAttempt": 1,
            "postMergeCiEvent": "push",
            "postMergeCiStatus": "completed",
            "postMergeCiDispatched": False,
        }

    monkeypatch.setattr(autoheal, "_verify_actual_merge_commit", _verify)
    monkeypatch.setattr(autoheal, "_ensure_post_merge_ci", _ensure)

    evidence = autoheal._finalize_post_merge_evidence(
        _TerminalApi(),
        {"sha": MERGE},
        {"baseSha": BASE, "headSha": HEAD},
        config,
    )

    assert events == ["topology", "ci-registration"]
    assert evidence["mergeSha"] == MERGE
    assert evidence["sourceTreeSha"] == TREE
    assert evidence["postMergeCiRunId"] == CI_RUN_ID


@pytest.mark.parametrize(
    ("ci_runs", "codeql_runs", "message"),
    (
        ([_ci_run(), _ci_run(7101)], [_codeql_run()], "ambiguous exact-subject CI evidence"),
        (
            [_ci_run()],
            [_codeql_run(), _codeql_run(7102)],
            "ambiguous terminal exact-main CodeQL evidence",
        ),
        (
            [_ci_run(status="completed", conclusion="failure")],
            [_codeql_run()],
            "CI run completed non-successfully",
        ),
        (
            [_ci_run()],
            [_codeql_run(status="completed", conclusion="failure")],
            "CodeQL run completed non-successfully",
        ),
    ),
)
def test_terminal_closure_rejects_failed_or_ambiguous_workflow_evidence(
    config: dict[str, Any],
    ci_runs: list[dict[str, Any]],
    codeql_runs: list[dict[str, Any]],
    message: str,
) -> None:
    api = _TerminalApi(ci_runs=ci_runs, codeql_runs=codeql_runs)

    with pytest.raises(autoheal.AutohealError, match=message):
        autoheal._reconcile_terminal_closure(api, MERGE, config)
    assert api.comments == []


def test_terminal_closure_waits_for_unresolved_alert_after_green_codeql(
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


@pytest.mark.parametrize(
    ("ci_runs", "codeql_runs", "message"),
    (
        (
            [_ci_run(run_attempt=2)],
            [_codeql_run()],
            "exact-subject CI run_attempt must equal 1",
        ),
        (
            [_ci_run()],
            [_codeql_run(run_attempt=2)],
            "terminal exact-main CodeQL run_attempt must equal 1",
        ),
    ),
)
def test_terminal_closure_rejects_manual_rerun_evidence(
    config: dict[str, Any],
    ci_runs: list[dict[str, Any]],
    codeql_runs: list[dict[str, Any]],
    message: str,
) -> None:
    api = _TerminalApi(ci_runs=ci_runs, codeql_runs=codeql_runs)

    with pytest.raises(autoheal.AutohealError, match=message):
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

    monkeypatch.setattr(autoheal, "assess_trusted_admission", _assess)
    monkeypatch.setattr(autoheal, "_require_scheduled_security_trusted_gate", _gate)
    monkeypatch.setattr(autoheal, "_finalize_post_merge_evidence", _finalize)

    evidence = autoheal._merge(
        _MergeApi(),
        PR_NUMBER,
        metadata,
        live,
        config,
    )

    assert evidence == {"mergeSha": MERGE, "sourceTreeSha": TREE}
    assert events == ["fresh-pr", "rebind", "gate", "merge", "finalize"]


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
