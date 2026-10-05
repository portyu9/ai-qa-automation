from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / ".github" / "scripts" / "dependency_recovery.py"
SCRIPT_DIR = SCRIPT.parent


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("dependency_recovery_control_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(SCRIPT_DIR))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(SCRIPT_DIR))
    return module


recovery = _load()


def test_recovery_reproves_governance_config_before_rerun(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    posts: list[str] = []
    guarded: list[dict[str, Any]] = []

    class Api:
        def list_all(self, path: str, *, max_pages: int = 3) -> list[dict[str, Any]]:
            assert path == "/actions/runs/17/jobs?filter=latest"
            return [
                {
                    "id": 41,
                    "name": "Quality / Python 3.11.16",
                    "status": "completed",
                    "conclusion": "failure",
                }
            ]

        def post(self, path: str) -> None:
            posts.append(path)

    governance = {"baseBranch": "main"}
    recovery_policy = {
        "maxRunAttempts": 2,
        "aggregateJobs": ["Required PR Gate"],
    }
    monkeypatch.setattr(recovery, "_fetch_job_logs", lambda api, job_id: "transient")
    monkeypatch.setattr(
        recovery,
        "classify_failed_job",
        lambda job, logs, config: {"transient": True, "reason": "network"},
    )

    def guard(api: Any, config: dict[str, Any]) -> str:
        assert config is governance
        guarded.append(config)
        return "a" * 40

    monkeypatch.setattr(recovery, "require_current_control_revision", guard)

    assert recovery._recover_run(
        Api(),
        {"id": 17, "run_attempt": 1},
        recovery_policy,
        governance,
    )
    assert guarded == [governance]
    assert posts == ["/actions/jobs/41/rerun"]


SUBJECT = "1" * 40
CONTROL = "2" * 40
HEAD = "3" * 40
PR_NUMBER = 320
HEAD_REF = "automation/dependency-promotion-319-dd2b61ac082b"
REPOSITORY = "portyu9/ai-qa-automation"


def _branch() -> dict[str, Any]:
    return {"commit": {"sha": SUBJECT}}


def _commit(*, message: str | None = None) -> dict[str, Any]:
    return {
        "sha": SUBJECT,
        "parents": [{"sha": CONTROL}, {"sha": HEAD}],
        "author": {
            "login": recovery.GITHUB_ACTIONS_LOGIN,
            "id": recovery.GITHUB_ACTIONS_USER_ID,
        },
        "committer": {
            "login": recovery.WEB_FLOW_LOGIN,
            "id": recovery.WEB_FLOW_USER_ID,
        },
        "commit": {
            "message": message
            or (
                f"Merge pull request #{PR_NUMBER} from portyu9/{HEAD_REF}\n\n"
                "deps: promote Dependabot PR #319"
            ),
            "verification": {"verified": True, "reason": "valid"},
        },
    }


def _pr() -> dict[str, Any]:
    return {
        "number": PR_NUMBER,
        "state": "closed",
        "merged": True,
        "merge_commit_sha": SUBJECT,
        "merged_by": {
            "login": recovery.GITHUB_ACTIONS_LOGIN,
            "id": recovery.GITHUB_ACTIONS_USER_ID,
        },
        "user": {
            "login": recovery.PROMOTION_AUTHOR_LOGIN,
            "id": recovery.PROMOTION_AUTHOR_USER_ID,
        },
        "head": {
            "ref": HEAD_REF,
            "sha": HEAD,
            "repo": {"full_name": REPOSITORY},
        },
        "base": {
            "ref": "main",
            "sha": CONTROL,
            "repo": {"full_name": REPOSITORY},
        },
    }


def _run(
    *,
    run_id: int = 9001,
    event: str = recovery.POST_MERGE_DISPATCH_EVENT,
    status: str = "completed",
    conclusion: str | None = "success",
    attempt: int = 1,
) -> dict[str, Any]:
    return {
        "id": run_id,
        "workflow_id": recovery.POST_MERGE_WORKFLOW_ID,
        "name": recovery.POST_MERGE_WORKFLOW_NAME,
        "path": recovery.POST_MERGE_WORKFLOW_PATH,
        "head_sha": SUBJECT,
        "head_branch": "main",
        "repository": {"full_name": REPOSITORY},
        "event": event,
        "status": status,
        "conclusion": conclusion,
        "run_attempt": attempt,
    }


def _required_job(
    *,
    run_id: int = 9001,
    status: str = "completed",
    conclusion: str = "success",
) -> dict[str, Any]:
    return {
        "id": 9101,
        "run_id": run_id,
        "name": recovery.POST_MERGE_REQUIRED_JOB_NAME,
        "status": status,
        "conclusion": conclusion,
    }


class PostMergeApi:
    def __init__(
        self,
        *,
        commit: dict[str, Any] | None = None,
        pull: dict[str, Any] | None = None,
        runs: list[dict[str, Any]] | None = None,
        jobs_by_run: dict[int, list[dict[str, Any]]] | None = None,
    ) -> None:
        self.repository = REPOSITORY
        self.commit = commit or _commit()
        self.pull = pull or _pr()
        self.runs = list(runs or [])
        self.jobs_by_run = dict(jobs_by_run or {})
        self.posts: list[tuple[str, dict[str, Any] | None]] = []

    def get(self, path: str) -> dict[str, Any]:
        if path == "/branches/main":
            return _branch()
        if path == f"/commits/{SUBJECT}":
            return self.commit
        if path == f"/pulls/{PR_NUMBER}":
            return self.pull
        raise AssertionError(f"unexpected GET {path}")

    def list_all(self, path: str, *, max_pages: int = 10) -> list[dict[str, Any]]:
        assert max_pages == 3
        if path == f"/actions/runs?head_sha={SUBJECT}":
            return list(self.runs)
        prefix = "/actions/runs/"
        suffix = "/jobs?filter=latest"
        if path.startswith(prefix) and path.endswith(suffix):
            run_id = int(path.removeprefix(prefix).removesuffix(suffix))
            return list(self.jobs_by_run.get(run_id, []))
        raise AssertionError(f"unexpected list path {path}")

    def post(
        self,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        token: str | None = None,
    ) -> None:
        assert token is None
        self.posts.append((path, payload))


def _recover_post_merge(
    monkeypatch: pytest.MonkeyPatch,
    api: PostMergeApi,
    *,
    allow_dispatch: bool = True,
) -> tuple[bool, str]:
    monkeypatch.setenv("GITHUB_REPOSITORY", REPOSITORY)
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    monkeypatch.setattr(recovery, "GitHubApi", lambda token, repository: api)
    guarded: list[dict[str, Any]] = []

    def guard(observed_api: Any, config: dict[str, Any]) -> str:
        assert observed_api is api
        guarded.append(config)
        return SUBJECT

    monkeypatch.setattr(recovery, "require_current_control_revision", guard)
    config = {"repository": REPOSITORY}
    result = recovery.recover_post_merge_validation(config, allow_dispatch=allow_dispatch)
    assert guarded == [config]
    return result


def test_missing_post_merge_validation_dispatches_exact_recovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = PostMergeApi()

    assert _recover_post_merge(monkeypatch, api) == (False, "dispatched")
    assert api.posts == [
        (
            f"/actions/workflows/{recovery.POST_MERGE_WORKFLOW_ID}/dispatches",
            {
                "ref": "main",
                "inputs": {
                    "lane": "dependency-trusted-merge",
                    "control_sha": CONTROL,
                    "subject_sha": SUBJECT,
                },
            },
        )
    ]


def test_missing_post_merge_validation_read_only_barrier_blocks_without_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = PostMergeApi()

    assert _recover_post_merge(monkeypatch, api, allow_dispatch=False) == (False, "missing")
    assert api.posts == []


def test_read_only_barrier_accepts_explicit_current_control_without_governance_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = PostMergeApi()
    monkeypatch.setenv("GITHUB_REPOSITORY", REPOSITORY)
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    monkeypatch.delenv("GOVERNANCE_CONTROL_SHA", raising=False)
    monkeypatch.setattr(recovery, "GitHubApi", lambda token, repository: api)

    def unexpected_guard(observed_api: Any, config: dict[str, Any]) -> str:
        raise AssertionError("read-only barrier must not depend on GOVERNANCE_CONTROL_SHA")

    monkeypatch.setattr(recovery, "require_current_control_revision", unexpected_guard)
    config = {"repository": REPOSITORY, "baseBranch": "main"}

    assert recovery.recover_post_merge_validation(
        config,
        allow_dispatch=False,
        expected_control_sha=SUBJECT,
    ) == (False, "missing")
    assert api.posts == []


def test_read_only_barrier_rejects_stale_explicit_control(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = PostMergeApi()
    monkeypatch.setenv("GITHUB_REPOSITORY", REPOSITORY)
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    monkeypatch.setattr(recovery, "GitHubApi", lambda token, repository: api)
    config = {"repository": REPOSITORY, "baseBranch": "main"}

    with pytest.raises(
        recovery.GovernanceError,
        match="post-merge validation barrier is stale relative to current main",
    ):
        recovery.recover_post_merge_validation(
            config,
            allow_dispatch=False,
            expected_control_sha="f" * 40,
        )
    assert api.posts == []


def test_successful_exact_post_merge_validation_allows_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = PostMergeApi(runs=[_run()], jobs_by_run={9001: [_required_job()]})

    assert _recover_post_merge(monkeypatch, api) == (True, "satisfied")
    assert api.posts == []


def test_successful_noop_workflow_run_does_not_satisfy_post_merge_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = PostMergeApi(
        runs=[_run(event="workflow_run")],
        jobs_by_run={9001: [_required_job(conclusion="skipped")]},
    )

    assert _recover_post_merge(monkeypatch, api) == (False, "dispatched")
    assert len(api.posts) == 1
    assert api.posts[0][0] == f"/actions/workflows/{recovery.POST_MERGE_WORKFLOW_ID}/dispatches"


def test_workflow_dispatch_success_without_required_gate_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = PostMergeApi(runs=[_run()], jobs_by_run={9001: []})

    with pytest.raises(
        recovery.GovernanceError,
        match="completed without a successful required gate",
    ):
        _recover_post_merge(monkeypatch, api)
    assert api.posts == []


def test_pending_exact_recovery_suppresses_new_mutation_and_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = PostMergeApi(runs=[_run(status="in_progress", conclusion=None)])

    assert _recover_post_merge(monkeypatch, api) == (False, "pending")
    assert api.posts == []


def test_failed_exact_recovery_blocks_without_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = PostMergeApi(runs=[_run(conclusion="failure")])

    with pytest.raises(
        recovery.GovernanceError,
        match="post-merge validation failed",
    ):
        _recover_post_merge(monkeypatch, api)
    assert api.posts == []


def test_replayed_exact_recovery_is_not_authoritative(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = PostMergeApi(runs=[_run(attempt=2)])

    with pytest.raises(
        recovery.GovernanceError,
        match="replay is not authoritative",
    ):
        _recover_post_merge(monkeypatch, api)
    assert api.posts == []


def test_non_dependency_current_main_does_not_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = PostMergeApi(commit=_commit(message="Merge pull request #321 from portyu9/fix/control"))

    assert _recover_post_merge(monkeypatch, api) == (True, "not-applicable")
    assert api.posts == []


def test_governed_dependency_merge_identity_drift_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pull = _pr()
    pull["merged_by"] = {"login": "portyu9", "id": 35150859}
    api = PostMergeApi(pull=pull)

    with pytest.raises(
        recovery.GovernanceError,
        match="identity does not match merge commit",
    ):
        _recover_post_merge(monkeypatch, api)
    assert api.posts == []


def test_post_merge_output_is_explicit_and_append_only(tmp_path: Path) -> None:
    output = tmp_path / "github-output"
    recovery._write_post_merge_output(
        output,
        mutation_ready=False,
        state="dispatched",
    )
    recovery._write_post_merge_output(
        output,
        mutation_ready=True,
        state="satisfied",
    )

    assert output.read_text(encoding="utf-8") == (
        "mutation_ready=false\n"
        "post_merge_state=dispatched\n"
        "mutation_ready=true\n"
        "post_merge_state=satisfied\n"
    )
