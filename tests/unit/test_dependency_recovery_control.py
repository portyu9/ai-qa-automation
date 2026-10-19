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


def _trusted_run(
    *,
    run_id: int = 9101,
    status: str = "completed",
    conclusion: str | None = "success",
    attempt: int = 1,
    workflow_id: int | None = None,
) -> dict[str, Any]:
    return {
        "id": run_id,
        "workflow_id": (
            recovery.DEPENDENCY_TRUSTED_MERGE_WORKFLOW_ID if workflow_id is None else workflow_id
        ),
        "name": recovery.DEPENDENCY_TRUSTED_MERGE_WORKFLOW_NAME,
        "path": recovery.DEPENDENCY_TRUSTED_MERGE_WORKFLOW_PATH,
        "head_sha": CONTROL,
        "head_branch": "main",
        "repository": {"full_name": REPOSITORY},
        "head_repository": {"full_name": REPOSITORY},
        "event": "workflow_run",
        "status": status,
        "conclusion": conclusion,
        "run_attempt": attempt,
    }


def _terminal_check(
    *,
    check_id: int = 9201,
    run_id: int = 9101,
    attempt: int = 1,
    external_id: str | None = None,
    app_id: int | None = None,
    canonical_url: bool = False,
) -> dict[str, Any]:
    return {
        "id": check_id,
        "name": recovery.DEPENDENCY_POST_MERGE_CHECK_NAME,
        "head_sha": SUBJECT,
        "status": "completed",
        "conclusion": "success",
        "details_url": (
            f"https://github.com/{REPOSITORY}/runs/{check_id}"
            if canonical_url
            else f"https://github.com/{REPOSITORY}/actions/runs/{run_id}"
        ),
        "external_id": external_id
        or (
            f"{recovery.DEPENDENCY_POST_MERGE_CHECK_PREFIX}:"
            f"{PR_NUMBER}:{CONTROL}:{SUBJECT}:{run_id}:{attempt}"
        ),
        "app": {
            "id": recovery.GITHUB_ACTIONS_APP_ID if app_id is None else app_id,
            "slug": "github-actions",
        },
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
        checks: list[dict[str, Any]] | None = None,
        trusted_runs: dict[int, dict[str, Any]] | None = None,
        live_runs: dict[int, dict[str, Any]] | None = None,
        live_checks: dict[int, dict[str, Any]] | None = None,
        jobs_by_run: dict[int, list[dict[str, Any]]] | None = None,
    ) -> None:
        self.repository = REPOSITORY
        self.commit = commit or _commit()
        self.pull = pull or _pr()
        self.runs = list(runs or [])
        self.checks = list(checks or [])
        self.trusted_runs = dict(trusted_runs or {})
        self.live_runs = dict(live_runs or {})
        self.live_checks = dict(live_checks or {})
        self.jobs_by_run = dict(jobs_by_run or {})

    def get(self, path: str) -> dict[str, Any]:
        if path == "/branches/main":
            return _branch()
        if path == f"/commits/{SUBJECT}":
            return self.commit
        if path == f"/pulls/{PR_NUMBER}":
            return self.pull
        if path.startswith("/actions/runs/"):
            run_id = int(path.removeprefix("/actions/runs/"))
            if run_id in self.live_runs:
                return self.live_runs[run_id]
            if run_id in self.trusted_runs:
                return self.trusted_runs[run_id]
            for run in self.runs:
                if run.get("id") == run_id:
                    return run
        if path.startswith("/check-runs/"):
            check_id = int(path.removeprefix("/check-runs/"))
            if check_id in self.live_checks:
                return self.live_checks[check_id]
            for check in self.checks:
                if check.get("id") == check_id:
                    return check
        raise AssertionError(f"unexpected GET {path}")

    def list_all(self, path: str, *, max_pages: int = 10) -> list[dict[str, Any]]:
        check_query = (
            f"/commits/{SUBJECT}/check-runs"
            "?check_name=Dependency%20Post-Merge%20Gate&filter=all&per_page=100"
        )
        if path == check_query:
            assert max_pages == 1
            return [
                row
                for row in self.checks
                if row.get("name") == recovery.DEPENDENCY_POST_MERGE_CHECK_NAME
            ]
        assert max_pages == 3
        if path == f"/actions/workflows/{recovery.POST_MERGE_WORKFLOW_ID}/runs?head_sha={SUBJECT}":
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


def test_read_only_barrier_denies_mutation_on_proven_stale_explicit_control(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reads: list[str] = []

    class StaleOnlyApi(PostMergeApi):
        def get(self, path: str) -> dict[str, Any]:
            reads.append(path)
            assert path == "/branches/main", "stale control must not read evidence or mutate"
            return _branch()

        def list_all(self, path: str, *, max_pages: int = 10) -> list[dict[str, Any]]:
            raise AssertionError(f"stale control must not scan evidence: {path}")

    api = StaleOnlyApi()
    monkeypatch.setenv("GITHUB_REPOSITORY", REPOSITORY)
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    monkeypatch.setattr(recovery, "GitHubApi", lambda token, repository: api)

    assert recovery.inspect_post_merge_validation(
        {"repository": REPOSITORY, "baseBranch": "main"},
        expected_control_sha="f" * 40,
    ) == {"mutationReady": False, "state": "stale-main-noop", "merge": None}
    assert reads == ["/branches/main"]


@pytest.mark.parametrize(
    "branch",
    [
        {"commit": {"sha": "invalid"}},
        {"commit": {}},
        {"commit": "invalid"},
        {},
    ],
)
def test_read_only_barrier_rejects_malformed_live_main_instead_of_noop(
    monkeypatch: pytest.MonkeyPatch, branch: dict[str, Any]
) -> None:
    class MalformedApi(PostMergeApi):
        def get(self, path: str) -> dict[str, Any]:
            assert path == "/branches/main"
            return branch

    monkeypatch.setenv("GITHUB_REPOSITORY", REPOSITORY)
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    monkeypatch.setattr(recovery, "GitHubApi", lambda token, repository: MalformedApi())
    with pytest.raises(recovery.GovernanceError):
        recovery.inspect_post_merge_validation(
            {"repository": REPOSITORY, "baseBranch": "main"},
            expected_control_sha="f" * 40,
        )


def test_implicit_control_disallows_stale_noop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = PostMergeApi()
    monkeypatch.setenv("GITHUB_REPOSITORY", REPOSITORY)
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    monkeypatch.setattr(recovery, "GitHubApi", lambda token, repository: api)
    monkeypatch.setattr(
        recovery, "require_current_control_revision",
        lambda api, config: "f" * 40,
    )

    with pytest.raises(recovery.StalePostMergeControl):
        recovery.inspect_post_merge_validation(
            {"repository": REPOSITORY, "baseBranch": "main"},
        )


def test_bad_explicit_control_sha_is_never_stale_noop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GITHUB_REPOSITORY", REPOSITORY)
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    class NoReadsApi:
        def get(self, path: str) -> dict[str, Any]:
            raise AssertionError(f"malformed controller SHA must not read {path}")

    monkeypatch.setattr(recovery, "GitHubApi", lambda token, repository: NoReadsApi())
    with pytest.raises(recovery.GovernanceError, match="exact 40-character SHA"):
        recovery.inspect_post_merge_validation(
            {"repository": REPOSITORY, "baseBranch": "main"},
            expected_control_sha="not-a-sha",
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


def test_direct_post_merge_collection_row_cannot_override_live_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row = _post_run()
    live = _post_run()
    live["head_sha"] = "f" * 40
    api = PostMergeApi(
        runs=[row],
        live_runs={row["id"]: live},
    )
    with pytest.raises(
        recovery.GovernanceError,
        match="discovery/live evidence drifted",
    ):
        _recover_post_merge(monkeypatch, api)


def test_trusted_merge_terminal_check_allows_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _trusted_run()
    api = PostMergeApi(
        checks=[_terminal_check(run_id=run["id"])],
        trusted_runs={run["id"]: run},
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


def test_exact_terminal_proof_survives_exhausted_historical_wake_pages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _trusted_run()

    class SaturatedBridgeApi(PostMergeApi):
        def list_all(self, path: str, *, max_pages: int = 10) -> list[dict[str, Any]]:
            if path.startswith(f"/actions/workflows/{recovery.POST_MERGE_WORKFLOW_ID}/runs?"):
                raise recovery.GovernanceError("historical bridge pagination exhausted")
            return super().list_all(path, max_pages=max_pages)

    api = SaturatedBridgeApi(
        checks=[_terminal_check(run_id=run["id"])],
        trusted_runs={run["id"]: run},
        jobs_by_run={
            run["id"]: [
                _required_job(recovery.DEPENDENCY_POST_MERGE_REQUIRED_JOB_NAME, run_id=run["id"])
            ]
        },
    )
    assert _recover_post_merge(monkeypatch, api) == (True, "satisfied")


def test_invalid_terminal_check_cannot_be_masked_by_green_bridge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bridge = _post_run()
    api = PostMergeApi(
        runs=[bridge],
        checks=[_terminal_check(app_id=999)],
        jobs_by_run={
            bridge["id"]: [
                _required_job(recovery.POST_MERGE_REQUIRED_JOB_NAME, run_id=bridge["id"])
            ]
        },
    )
    with pytest.raises(recovery.GovernanceError, match="check provenance is invalid"):
        _recover_post_merge(monkeypatch, api)


def test_named_terminal_check_survives_unrelated_checks_and_github_canonical_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _trusted_run()
    # GitHub returned 342 latest check runs on the real merged SHA; only the
    # one exact terminal name belongs in this bounded evidence query.
    unrelated = [
        {
            "name": f"unrelated-ci-check-{index}",
            "id": 20000 + index,
            "conclusion": "success",
        }
        for index in range(342)
    ]
    api = PostMergeApi(
        checks=[
            *unrelated,
            _terminal_check(run_id=run["id"], canonical_url=True),
        ],
        trusted_runs={run["id"]: run},
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


def test_canonical_terminal_check_url_must_match_exact_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _trusted_run()
    forged = _terminal_check(run_id=run["id"], canonical_url=True)
    forged["details_url"] = f"https://github.com/{REPOSITORY}/runs/123456"
    api = PostMergeApi(
        checks=[forged],
        trusted_runs={run["id"]: run},
    )
    with pytest.raises(recovery.GovernanceError, match="check provenance is invalid"):
        _recover_post_merge(monkeypatch, api)


def test_terminal_check_collection_row_cannot_override_live_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _trusted_run()
    row = _terminal_check(run_id=run["id"])
    live = _terminal_check(run_id=run["id"])
    live["app"] = {"id": 999, "slug": "untrusted"}
    api = PostMergeApi(
        checks=[row],
        live_checks={row["id"]: live},
        trusted_runs={run["id"]: run},
    )
    with pytest.raises(
        recovery.GovernanceError,
        match="check provenance is invalid",
    ):
        _recover_post_merge(monkeypatch, api)


def test_trusted_merge_terminal_check_is_pending_until_run_completes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _trusted_run(status="in_progress", conclusion=None)
    api = PostMergeApi(
        checks=[_terminal_check(run_id=run["id"])],
        trusted_runs={run["id"]: run},
    )
    assert _recover_post_merge(monkeypatch, api) == (False, "pending")


def test_trusted_merge_terminal_check_rejects_replayed_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _trusted_run(attempt=2)
    api = PostMergeApi(
        checks=[_terminal_check(run_id=run["id"], attempt=2)],
        trusted_runs={run["id"]: run},
    )
    with pytest.raises(
        recovery.GovernanceError,
        match="replay is not authoritative",
    ):
        _recover_post_merge(monkeypatch, api)


def test_trusted_merge_terminal_check_rejects_wrong_app(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _trusted_run()
    api = PostMergeApi(
        checks=[_terminal_check(run_id=run["id"], app_id=999)],
        trusted_runs={run["id"]: run},
    )
    with pytest.raises(
        recovery.GovernanceError,
        match="check provenance is invalid",
    ):
        _recover_post_merge(monkeypatch, api)


def test_trusted_merge_terminal_check_rejects_wrong_workflow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _trusted_run(workflow_id=1)
    api = PostMergeApi(
        checks=[_terminal_check(run_id=run["id"])],
        trusted_runs={run["id"]: run},
    )
    with pytest.raises(
        recovery.GovernanceError,
        match="wrong trusted merge run",
    ):
        _recover_post_merge(monkeypatch, api)


def test_trusted_merge_terminal_check_requires_successful_terminal_job(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _trusted_run()
    api = PostMergeApi(
        checks=[_terminal_check(run_id=run["id"])],
        trusted_runs={run["id"]: run},
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
        match="lacks successful terminal post-merge gate",
    ):
        _recover_post_merge(monkeypatch, api)


def test_trusted_merge_terminal_check_rejects_ambiguous_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _trusted_run()
    api = PostMergeApi(
        checks=[
            _terminal_check(check_id=9201, run_id=run["id"]),
            _terminal_check(check_id=9202, run_id=run["id"]),
        ],
        trusted_runs={run["id"]: run},
    )
    with pytest.raises(
        recovery.GovernanceError,
        match="check evidence is ambiguous",
    ):
        _recover_post_merge(monkeypatch, api)


def test_trusted_merge_terminal_check_rejects_subject_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = _trusted_run()
    bad_external = (
        f"{recovery.DEPENDENCY_POST_MERGE_CHECK_PREFIX}:"
        f"{PR_NUMBER}:{'f' * 40}:{SUBJECT}:{run['id']}:1"
    )
    api = PostMergeApi(
        checks=[_terminal_check(run_id=run["id"], external_id=bad_external)],
        trusted_runs={run["id"]: run},
    )
    with pytest.raises(
        recovery.GovernanceError,
        match="subject binding drifted",
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
