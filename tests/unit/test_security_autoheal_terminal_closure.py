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
) -> dict[str, Any]:
    return {
        "id": run_id,
        "workflow_id": autoheal.POST_MERGE_CI_WORKFLOW_ID,
        "run_attempt": run_attempt,
        "name": autoheal.POST_MERGE_CI_NAME,
        "path": autoheal.POST_MERGE_CI_PATH,
        "head_branch": "main",
        "head_sha": MERGE,
        "event": "push",
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
        self.gate_run_attempt = gate_run_attempt
        self.gate_workflow_id = gate_workflow_id
        self.gate_event = gate_event
        self.comments: list[dict[str, Any]] = []
        self.dispatches: list[tuple[str, dict[str, Any] | None]] = []

    def get(self, path: str) -> Any:
        if path == "/branches/main":
            return {"commit": {"sha": MERGE}}
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
                    "status": "in_progress",
                    "conclusion": None,
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

    assert autoheal._reconcile_terminal_closure(api, MERGE, config) is False
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


def test_terminal_closure_dispatches_missing_exact_main_ci(
    config: dict[str, Any],
) -> None:
    api = _TerminalApi(ci_runs=[])

    assert autoheal._reconcile_terminal_closure(api, MERGE, config) is True
    assert api.dispatches == []
    assert api.comments == []


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
    calls: list[tuple[int, str, str]] = []

    def _generic_gate(
        api: Any,
        number: int,
        head_sha: str,
        base_sha: str,
    ) -> dict[str, Any]:
        calls.append((number, head_sha, base_sha))
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
    assert calls == [(PR_NUMBER, HEAD, BASE)]

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
    assert autoheal._reconcile_terminal_closure(api, MERGE, config) is False
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
    assert autoheal._reconcile_terminal_closure(api, MERGE, config) is False
    assert len(api.comments) == 1
    api.comments[0]["updated_at"] = "2026-09-23T12:36:00Z"

    with pytest.raises(autoheal.PolicyBlock, match="edited or malformed"):
        autoheal._reconcile_terminal_closure(api, MERGE, config)
