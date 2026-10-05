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


def _pr(*, merge_hint: str | None = SUBJECT) -> dict[str, Any]:
    return {
        "number": PR_NUMBER,
        "state": "closed",
        "merged": True,
        "merge_commit_sha": merge_hint,
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


def _post_run(
    *,
    run_id: int = 9001,
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
        "head_repository": {"full_name": REPOSITORY},
        "event": "workflow_run",
        "status": status,
        "conclusion": conclusion,
        "run_attempt": attempt,
    }


def _governance_run(
    *,
    run_id: int = 9101,
    status: str = "completed",
    conclusion: str | None = "success",
    attempt: int = 1,
    actor: str = recovery.OWNER_LOGIN,
    actor_id: int = recovery.OWNER_USER_ID,
) -> dict[str, Any]:
    return {
        "id": run_id,
        "workflow_id": recovery.DEPENDENCY_GOVERNANCE_WORKFLOW_ID,
        "name": recovery.DEPENDENCY_GOVERNANCE_WORKFLOW_NAME,
        "path": recovery.DEPENDENCY_GOVERNANCE_WORKFLOW_PATH,
        "head_sha": SUBJECT,
        "head_branch": "main",
        "repository": {"full_name": REPOSITORY},
        "head_repository": {"full_name": REPOSITORY},
        "event": "schedule",
        "status": status,
        "conclusion": conclusion,
        "run_attempt": attempt,
        "actor": {"login": actor, "id": actor_id},
        "triggering_actor": {"login": actor, "id": actor_id},
    }


def _required_job(
    name: str,
    *,
    run_id: int,
    status: str = "completed",
    conclusion: str = "success",
) -> dict[str, Any]:
    return {
        "id": run_id + 100,
        "run_id": run_id,
        "name": name,
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


def _recover_post_merge(
    monkeypatch: pytest.MonkeyPatch,
    api: PostMergeApi,
) -> tuple[bool, str]:
    monkeypatch.setenv("GITHUB_REPOSITORY", REPOSITORY)
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    monkeypatch.delenv("GITHUB_RUN_ID", raising=False)
    monkeypatch.setattr(recovery, "GitHubApi", lambda token, repository: api)
    guarded: list[dict[str, Any]] = []

    def guard(observed_api: Any, config: dict[str, Any]) -> str:
        assert observed_api is api
        guarded.append(config)
        return SUBJECT

    monkeypatch.setattr(recovery, "require_current_control_revision", guard)
    config = {"repository": REPOSITORY}
    result = recovery.recover_post_merge_validation(config)
    assert guarded == [config]
    return result


def test_missing_post_merge_validation_is_read_only_and_blocks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert _recover_post_merge(monkeypatch, PostMergeApi()) == (False, "missing")


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
    assert recovery.recover_post_merge_validation(
        {"repository": REPOSITORY, "baseBranch": "main"},
        expected_control_sha=SUBJECT,
    ) == (False, "missing")


def test_read_only_barrier_rejects_stale_explicit_control(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = PostMergeApi()
    monkeypatch.setenv("GITHUB_REPOSITORY", REPOSITORY)
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    monkeypatch.setattr(recovery, "GitHubApi", lambda token, repository: api)

    with pytest.raises(
        recovery.GovernanceError,
        match="post-merge validation barrier is stale relative to current main",
    ):
        recovery.recover_post_merge_validation(
            {"repository": REPOSITORY, "baseBranch": "main"},
            expected_control_sha="f" * 40,
        )


def test_successful_exact_post_merge_workflow_allows_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _post_run()
    api = PostMergeApi(
        runs=[run],
        jobs_by_run={
            run["id"]: [
                _required_job(
                    recovery.POST_MERGE_REQUIRED_JOB_NAME,
                    run_id=run["id"],
                )
            ]
        },
    )
    assert _recover_post_merge(monkeypatch, api) == (True, "satisfied")


def test_owner_scheduled_dependency_terminal_gate_allows_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _governance_run()
    api = PostMergeApi(
        runs=[run],
        jobs_by_run={
            run["id"]: [
                _required_job(
                    recovery.DEPENDENCY_POST_MERGE_REQUIRED_JOB_NAME,
                    run_id=run["id"],
                )
            ]
        },
    )
    assert _recover_post_merge(monkeypatch, api) == (True, "satisfied")


def test_owner_scheduled_validation_survives_later_reconciliation_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _governance_run(conclusion="failure")
    api = PostMergeApi(
        runs=[run],
        jobs_by_run={
            run["id"]: [
                _required_job(
                    recovery.DEPENDENCY_POST_MERGE_REQUIRED_JOB_NAME,
                    run_id=run["id"],
                )
            ]
        },
    )
    assert _recover_post_merge(monkeypatch, api) == (True, "satisfied")


def test_wrong_schedule_actor_cannot_satisfy_dependency_post_merge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _governance_run(actor="github-actions[bot]", actor_id=41898282)
    api = PostMergeApi(
        runs=[run],
        jobs_by_run={
            run["id"]: [
                _required_job(
                    recovery.DEPENDENCY_POST_MERGE_REQUIRED_JOB_NAME,
                    run_id=run["id"],
                )
            ]
        },
    )
    assert _recover_post_merge(monkeypatch, api) == (False, "missing")


def test_current_governance_run_is_excluded_from_prior_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _governance_run(status="in_progress", conclusion=None)
    api = PostMergeApi(runs=[run])
    monkeypatch.setenv("GITHUB_REPOSITORY", REPOSITORY)
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    monkeypatch.setenv("GITHUB_RUN_ID", str(run["id"]))
    monkeypatch.setattr(recovery, "GitHubApi", lambda token, repository: api)
    monkeypatch.setattr(
        recovery,
        "require_current_control_revision",
        lambda observed_api, config: SUBJECT,
    )
    assert recovery.recover_post_merge_validation({"repository": REPOSITORY}) == (
        False,
        "missing",
    )


def test_pending_owner_schedule_blocks_new_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _governance_run(status="in_progress", conclusion=None)
    assert _recover_post_merge(monkeypatch, PostMergeApi(runs=[run])) == (False, "pending")


def test_failed_owner_scheduled_required_gate_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _governance_run(conclusion="failure")
    api = PostMergeApi(
        runs=[run],
        jobs_by_run={
            run["id"]: [
                _required_job(
                    recovery.DEPENDENCY_POST_MERGE_REQUIRED_JOB_NAME,
                    run_id=run["id"],
                    conclusion="failure",
                )
            ]
        },
    )
    with pytest.raises(
        recovery.GovernanceError,
        match="owner-scheduled dependency post-merge validation failed",
    ):
        _recover_post_merge(monkeypatch, api)


def test_replayed_owner_scheduled_gate_is_not_authoritative(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _governance_run(attempt=2)
    api = PostMergeApi(
        runs=[run],
        jobs_by_run={
            run["id"]: [
                _required_job(
                    recovery.DEPENDENCY_POST_MERGE_REQUIRED_JOB_NAME,
                    run_id=run["id"],
                )
            ]
        },
    )
    with pytest.raises(
        recovery.GovernanceError,
        match="replay is not authoritative",
    ):
        _recover_post_merge(monkeypatch, api)


def test_failed_post_merge_workflow_gate_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _post_run()
    api = PostMergeApi(
        runs=[run],
        jobs_by_run={
            run["id"]: [
                _required_job(
                    recovery.POST_MERGE_REQUIRED_JOB_NAME,
                    run_id=run["id"],
                    conclusion="failure",
                )
            ]
        },
    )
    with pytest.raises(
        recovery.GovernanceError,
        match="post-merge validation failed",
    ):
        _recover_post_merge(monkeypatch, api)


def test_non_dependency_current_main_is_not_applicable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = PostMergeApi(commit=_commit(message="Merge pull request #321 from portyu9/fix/control"))
    assert _recover_post_merge(monkeypatch, api) == (True, "not-applicable")


def test_governed_dependency_merge_identity_drift_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pull = _pr()
    pull["merged_by"] = {"login": "portyu9", "id": 35150859}
    with pytest.raises(
        recovery.GovernanceError,
        match="identity does not match merge commit",
    ):
        _recover_post_merge(monkeypatch, PostMergeApi(pull=pull))


def test_missing_merge_hint_is_not_used_as_merge_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert _recover_post_merge(
        monkeypatch,
        PostMergeApi(pull=_pr(merge_hint=None)),
    ) == (False, "missing")


def test_conflicting_canonical_merge_hint_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(
        recovery.GovernanceError,
        match="hint conflicts with proven merge",
    ):
        _recover_post_merge(
            monkeypatch,
            PostMergeApi(pull=_pr(merge_hint="9" * 40)),
        )


def test_post_merge_output_is_explicit_and_append_only(tmp_path: Path) -> None:
    output = tmp_path / "github-output"
    recovery._write_post_merge_output(
        output,
        {
            "mutationReady": False,
            "state": "missing",
            "merge": {
                "subjectSha": SUBJECT,
                "controlSha": CONTROL,
            },
        },
    )
    recovery._write_post_merge_output(
        output,
        {
            "mutationReady": True,
            "state": "not-applicable",
            "merge": None,
        },
    )

    assert output.read_text(encoding="utf-8") == (
        "mutation_ready=false\n"
        "post_merge_state=missing\n"
        f"subject_sha={SUBJECT}\n"
        f"control_sha={CONTROL}\n"
        "mutation_ready=true\n"
        "post_merge_state=not-applicable\n"
    )
