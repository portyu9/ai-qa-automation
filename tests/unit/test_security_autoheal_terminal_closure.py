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
PR_NUMBER = 321
CI_RUN_ID = 7001
CODEQL_RUN_ID = 7002
AUTOHEAL_RUN_ID = 7003


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
    status: str = "completed",
    conclusion: str | None = "success",
) -> dict[str, Any]:
    return {
        "id": run_id,
        "workflow_id": autoheal.POST_MERGE_CI_WORKFLOW_ID,
        "run_attempt": 1,
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
    status: str = "completed",
    conclusion: str | None = "success",
) -> dict[str, Any]:
    return {
        "id": run_id,
        "workflow_id": autoheal.MAIN_CODEQL_WORKFLOW_ID,
        "run_attempt": 1,
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
    ) -> None:
        self.pr = _repair_pr()
        self.ci_runs = [_ci_run()] if ci_runs is None else list(ci_runs)
        self.codeql_runs = [_codeql_run()] if codeql_runs is None else list(codeql_runs)
        self.alert_state = alert_state
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
        if path == f"/git/commits/{HEAD}":
            return {"tree": {"sha": TREE}}
        if path == f"/code-scanning/alerts/{_metadata()['alert']}":
            return {
                "number": 7,
                "state": self.alert_state,
                "tool": {"name": "CodeQL"},
                "rule": {"id": _metadata()["rule"]},
                "most_recent_instance": {
                    "location": {"path": _metadata()["path"]}
                },
            }
        if path.startswith("/actions/runs/"):
            run_id = int(path.rsplit("/", 1)[1])
            if run_id == AUTOHEAL_RUN_ID:
                return {
                    "id": AUTOHEAL_RUN_ID,
                    "workflow_id": autoheal.SECURITY_AUTOHEAL_WORKFLOW_ID,
                    "path": autoheal.SECURITY_AUTOHEAL_WORKFLOW_PATH,
                    "run_attempt": 1,
                    "event": "workflow_run",
                    "head_branch": "main",
                    "status": "in_progress",
                    "conclusion": None,
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

    assert autoheal._reconcile_terminal_closure(api, MERGE, config) is False
    assert len(api.comments) == 1


def test_terminal_closure_dispatches_missing_exact_main_ci(
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
    assert api.comments == []


@pytest.mark.parametrize(
    ("ci_runs", "codeql_runs", "message"),
    (
        ([_ci_run(), _ci_run(7101)], [_codeql_run()], "ambiguous exact-subject CI evidence"),
        ([_ci_run()], [_codeql_run(), _codeql_run(7102)], "ambiguous terminal exact-main CodeQL evidence"),
        ([_ci_run(status="completed", conclusion="failure")], [_codeql_run()], "CI run completed non-successfully"),
        ([_ci_run()], [_codeql_run(status="completed", conclusion="failure")], "CodeQL run completed non-successfully"),
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


def test_terminal_closure_rejects_unresolved_alert_after_green_codeql(
    config: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(autoheal.time, "sleep", lambda _seconds: None)
    api = _TerminalApi(alert_state="open")

    with pytest.raises(autoheal.AutohealError, match="remains open"):
        autoheal._reconcile_terminal_closure(api, MERGE, config)
    assert api.comments == []


def test_terminal_closure_rejects_edited_certificate(
    config: dict[str, Any],
) -> None:
    api = _TerminalApi()
    assert autoheal._reconcile_terminal_closure(api, MERGE, config) is False
    assert len(api.comments) == 1
    api.comments[0]["updated_at"] = "2026-09-23T12:36:00Z"

    with pytest.raises(autoheal.PolicyBlock, match="edited or malformed"):
        autoheal._reconcile_terminal_closure(api, MERGE, config)
