from __future__ import annotations

import importlib.util
import sys
import urllib.parse
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / ".github" / "scripts" / "security_autoheal.py"
SCRIPT_DIR = SCRIPT.parent


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("security_autoheal_autofix_recovery_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(SCRIPT_DIR))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(SCRIPT_DIR))
    return module


autoheal = _load()
BASE = "a" * 40
HEAD = "b" * 40
ALERT = 42
ROUTE_DIGEST = "e" * 64
PLAN_DIGEST = "f" * 64
BRANCH = "automation/codeql-autoheal-42-" + ("d" * 64) + "-a1"


def _repo_commit(
    *,
    owner: str = autoheal.GITHUB_ACTIONS_LOGIN,
    owner_id: int = autoheal.GITHUB_ACTIONS_USER_ID,
    committer_login: str = autoheal.GITHUB_WEB_FLOW_LOGIN,
    committer_id: int = autoheal.GITHUB_WEB_FLOW_USER_ID,
    verified: bool = True,
    verification_reason: str = "valid",
    alert: int = ALERT,
    route_digest: str = ROUTE_DIGEST,
    plan_digest: str = PLAN_DIGEST,
) -> dict[str, Any]:
    return {
        "sha": HEAD,
        "author": {"login": owner, "id": owner_id, "type": "Bot"},
        "committer": {"login": committer_login, "id": committer_id, "type": "User"},
        "commit": {
            "message": (
                f"security: auto-heal CodeQL alert #{alert}\n\n"
                f"{autoheal.ROUTE_RECORD_TRAILER_PREFIX}{route_digest}\n"
                f"{autoheal.ROUTE_PLAN_TRAILER_PREFIX}{plan_digest}\n\nAutofix"
            ),
            "author": {
                "name": autoheal.GITHUB_ACTIONS_LOGIN,
                "email": autoheal.GITHUB_ACTIONS_EMAIL,
            },
            "committer": {
                "name": autoheal.GITHUB_COMMITTER_NAME,
                "email": autoheal.GITHUB_COMMITTER_EMAIL,
            },
            "verification": {"verified": verified, "reason": verification_reason},
        },
    }


class _AmbiguousCommitApi:
    def __init__(self, *, branch: str = BRANCH) -> None:
        self.branch = branch
        self.branch_sha: str | None = None
        self.commit_posts = 0
        self.fail_first_commit_response = True
        self.repository_commit = _repo_commit()
        self.parent = BASE

    def get(self, path: str) -> dict[str, Any]:
        encoded = urllib.parse.quote(self.branch, safe="")
        if path == f"/git/ref/heads/{encoded}":
            if self.branch_sha is None:
                raise autoheal.AutohealError("GitHub API HTTP 404: missing ref")
            return {"object": {"sha": self.branch_sha}}
        if path == f"/git/commits/{HEAD}":
            return {"parents": [{"sha": self.parent}]}
        if path == f"/commits/{HEAD}":
            return self.repository_commit
        raise AssertionError(path)

    def post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        if path == "/git/refs":
            assert payload == {"ref": f"refs/heads/{self.branch}", "sha": BASE}
            self.branch_sha = BASE
            return {"ref": f"refs/heads/{self.branch}"}
        if path == f"/code-scanning/alerts/{ALERT}/autofix/commits":
            self.commit_posts += 1
            assert payload["target_ref"] == f"refs/heads/{self.branch}"
            assert payload["message"] == autoheal._route_bound_commit_message(
                ALERT,
                ROUTE_DIGEST,
                PLAN_DIGEST,
            )
            self.branch_sha = HEAD
            if self.fail_first_commit_response:
                self.fail_first_commit_response = False
                raise autoheal.AutohealError("GitHub API HTTP 503 after provider side effect")
            return {"sha": HEAD}
        raise AssertionError(path)

    def delete(self, path: str) -> dict[str, Any]:
        raise AssertionError(f"unexpected delete: {path}")


def test_existing_base_only_attempt_branch_refuses_provider_replay() -> None:
    api = _AmbiguousCommitApi()
    api.branch_sha = BASE
    api.fail_first_commit_response = False

    with pytest.raises(autoheal.PolicyBlock, match="ambiguous provider-submission state"):
        autoheal._commit_copilot_autofix(
            api,
            ALERT,
            BRANCH,
            BASE,
            ROUTE_DIGEST,
            PLAN_DIGEST,
        )

    assert api.branch_sha == BASE
    assert api.commit_posts == 0


def test_ambiguous_autofix_commit_response_is_recovered_without_provider_replay() -> None:
    api = _AmbiguousCommitApi()

    with pytest.raises(autoheal.AutohealError, match="503 after provider side effect"):
        autoheal._commit_copilot_autofix(
            api,
            ALERT,
            BRANCH,
            BASE,
            ROUTE_DIGEST,
            PLAN_DIGEST,
        )

    assert api.branch_sha == HEAD
    assert api.commit_posts == 1

    recovered = autoheal._commit_copilot_autofix(
        api,
        ALERT,
        BRANCH,
        BASE,
        ROUTE_DIGEST,
        PLAN_DIGEST,
    )
    assert recovered == HEAD
    assert api.commit_posts == 1


@pytest.mark.parametrize(
    ("repository_commit", "parent", "message"),
    (
        (_repo_commit(owner="attacker", owner_id=1), BASE, "ownership"),
        (_repo_commit(), "c" * 40, "parented"),
        (
            _repo_commit(committer_login="attacker", committer_id=1),
            BASE,
            "GitHub-signed provider provenance",
        ),
        (
            _repo_commit(verified=False, verification_reason="unsigned"),
            BASE,
            "GitHub-signed provider provenance",
        ),
        (_repo_commit(alert=99), BASE, "different alert"),
        (_repo_commit(route_digest="a" * 64), BASE, "route digest"),
        (_repo_commit(plan_digest="a" * 64), BASE, "plan digest"),
    ),
)
def test_recovered_autofix_commit_fails_closed_on_provenance_drift(
    repository_commit: dict[str, Any],
    parent: str,
    message: str,
) -> None:
    api = _AmbiguousCommitApi()
    api.branch_sha = HEAD
    api.repository_commit = repository_commit
    api.parent = parent
    api.fail_first_commit_response = False

    with pytest.raises(autoheal.PolicyBlock, match=message):
        autoheal._commit_copilot_autofix(
            api,
            ALERT,
            BRANCH,
            BASE,
            ROUTE_DIGEST,
            PLAN_DIGEST,
        )

    assert api.commit_posts == 0
    assert api.branch_sha == HEAD


class _PruneApi:
    def __init__(self) -> None:
        self.deleted: list[str] = []

    def list_all(self, path: str, *, max_pages: int = 10) -> list[dict[str, Any]]:
        assert path == f"/git/matching-refs/heads/{autoheal.BRANCH_PREFIX}"
        assert max_pages == 4
        return [{"ref": f"refs/heads/{BRANCH}", "object": {"type": "commit", "sha": HEAD}}]

    def get(self, path: str) -> dict[str, Any]:
        if path == f"/commits/{HEAD}":
            return _repo_commit()
        encoded = urllib.parse.quote(BRANCH, safe="")
        if path == f"/git/ref/heads/{encoded}":
            if self.deleted:
                raise autoheal.AutohealError("GitHub API HTTP 404: deleted")
            return {"object": {"sha": HEAD}}
        raise AssertionError(path)

    def delete(self, path: str) -> dict[str, Any]:
        self.deleted.append(path)
        return {}


def test_current_subject_orphan_branch_is_preserved_for_recovery() -> None:
    api = _PruneApi()
    assert (
        autoheal._prune_orphan_repair_refs(
            api,
            [],
            preserve_branches={BRANCH},
        )
        == 0
    )
    assert api.deleted == []


def test_unpreserved_owned_orphan_branch_is_cleaned_up() -> None:
    api = _PruneApi()
    assert autoheal._prune_orphan_repair_refs(api, []) == 1
    assert len(api.deleted) == 1


def _alert(path: str, *, sha: str = BASE) -> dict[str, Any]:
    return {
        "number": ALERT,
        "state": "open",
        "tool": {"name": "CodeQL"},
        "rule": {
            "id": "py/incomplete-url-substring-sanitization",
            "security_severity": "8.0",
        },
        "most_recent_instance": {
            "state": "open",
            "ref": "refs/heads/main",
            "commit_sha": sha,
            "location": {
                "path": path,
                "start_line": 10,
                "end_line": 10,
                "start_column": 1,
                "end_column": 5,
            },
            "message": {"text": "unsafe URL check"},
        },
    }


def _model_route(
    config: dict[str, Any],
    *,
    prior: int = 0,
    eligibility: str = "available",
) -> dict[str, Any]:
    return autoheal.route_security_alert(
        _alert("src/ai_qa_automation/example.py"),
        main_sha=BASE,
        config=config,
        attempts_by_strategy={autoheal.MODEL_AUTOFIX_STRATEGY: prior},
        autofix_eligibility=eligibility,
    )


def _route_reconcile_args(
    monkeypatch: pytest.MonkeyPatch,
    records: dict[int, dict[str, Any]],
) -> dict[str, Any]:
    plan = {
        "mainSha": BASE,
        "planDigest": "e" * 64,
        "workflowRunId": 123,
        "workflowRunAttempt": 1,
    }
    monkeypatch.setattr(autoheal, "_load_route_plan", lambda path, config: plan)
    monkeypatch.setattr(
        autoheal,
        "_require_route_plan_artifact",
        lambda *args, **kwargs: {
            "routePlanDigest": plan["planDigest"],
            "routePlanRunId": 123,
            "routePlanRunAttempt": 1,
            "routeArtifactId": 456,
            "routeArtifactName": "security-autoheal-route-plan-123-1",
            "routeArtifactDigest": "sha256:" + ("f" * 64),
        },
    )
    monkeypatch.setattr(
        autoheal,
        "_rebind_route_plan",
        lambda api, loaded, config: records,
    )
    return {
        "route_plan_path": Path("route-plan.json"),
        "route_artifact_id": 456,
        "route_artifact_name": "security-autoheal-route-plan-123-1",
        "route_artifact_digest": "sha256:" + ("f" * 64),
    }


def test_only_current_policy_eligible_model_subjects_preserve_recovery_branches() -> None:
    config = autoheal.load_config()
    model = _alert("src/ai_qa_automation/example.py")
    blocked = _alert(".github/scripts/security_autoheal.py")
    stale = _alert("src/ai_qa_automation/stale.py", sha="c" * 40)

    branches = autoheal._recoverable_model_autofix_branches(
        [model, blocked, stale],
        BASE,
        config,
    )

    record = autoheal.route_security_alert(
        model,
        main_sha=BASE,
        config=config,
        autofix_eligibility="unknown",
    )
    subject = autoheal._subject_from_route(record)
    assert branches == {
        autoheal._branch_name(subject, attempt)
        for attempt in range(1, int(config["maxAttemptsPerAlert"]) + 1)
    }


def test_attempt_scoped_branch_names_are_distinct_and_legacy_compatible() -> None:
    config = autoheal.load_config()
    subject = autoheal._subject_from_route(_model_route(config))
    legacy = autoheal._branch_name(subject)
    branches = [
        autoheal._branch_name(subject, attempt)
        for attempt in range(1, int(config["maxAttemptsPerAlert"]) + 1)
    ]

    assert autoheal.AUTOHEAL_BRANCH_RE.fullmatch(legacy) is not None
    assert len(branches) == len(set(branches))
    assert legacy not in branches
    assert all(autoheal.AUTOHEAL_BRANCH_RE.fullmatch(branch) is not None for branch in branches)
    assert all(subject["fingerprint"] in branch for branch in branches)


def test_branch_binding_accepts_legacy_or_exact_attempt_and_rejects_mismatch() -> None:
    config = autoheal.load_config()
    subject = autoheal._subject_from_route(_model_route(config))
    metadata = {"attempt": 2}

    autoheal._require_repair_branch_binding(
        autoheal._branch_name(subject),
        metadata,
        subject,
    )
    autoheal._require_repair_branch_binding(
        autoheal._branch_name(subject, 2),
        metadata,
        subject,
    )
    with pytest.raises(autoheal.PolicyBlock, match="fingerprint and attempt"):
        autoheal._require_repair_branch_binding(
            autoheal._branch_name(subject, 1),
            metadata,
            subject,
        )


def test_model_repair_uses_attempt_scoped_branch(monkeypatch: pytest.MonkeyPatch) -> None:
    config = autoheal.load_config()
    route_record = _model_route(config, prior=1)
    subject = autoheal._subject_from_route(route_record)
    expected_branch = autoheal._branch_name(subject, 2)
    observed: dict[str, Any] = {}
    route_evidence = {
        "routePlanDigest": "e" * 64,
        "routePlanRunId": 123,
        "routePlanRunAttempt": 1,
        "routeArtifactId": 456,
        "routeArtifactName": "security-autoheal-route-plan-123-1",
        "routeArtifactDigest": "sha256:" + ("f" * 64),
    }

    monkeypatch.setattr(autoheal, "_current_main", lambda api, config: BASE)

    def commit_autofix(
        api: object,
        alert: int,
        branch: str,
        base: str,
        route_record_digest: str,
        route_plan_digest: str,
    ) -> str:
        observed["branch"] = branch
        assert alert == ALERT
        assert base == BASE
        assert route_record_digest == route_record["recordDigest"]
        assert route_plan_digest == "e" * 64
        return HEAD

    monkeypatch.setattr(autoheal, "_commit_copilot_autofix", commit_autofix)
    monkeypatch.setattr(
        autoheal,
        "_changed_files",
        lambda api, base, head: [{"filename": subject["path"]}],
    )

    expected_route_evidence = route_evidence

    def create_pr(
        api: object,
        branch: str,
        head_sha: str,
        live_subject: dict[str, Any],
        attempt: int,
        *,
        deterministic: bool,
        strategy: str,
        route_record: dict[str, Any],
        route_evidence: dict[str, Any],
    ) -> int:
        assert branch == expected_branch
        assert head_sha == HEAD
        assert live_subject == subject
        assert attempt == 2
        assert deterministic is False
        assert strategy == autoheal.MODEL_AUTOFIX_STRATEGY
        assert route_record["recordDigest"] == _model_route(config, prior=1)["recordDigest"]
        assert route_evidence == expected_route_evidence
        return 999

    monkeypatch.setattr(autoheal, "_create_pull_request", create_pr)

    assert (
        autoheal._create_repair(
            object(),
            subject,
            config,
            attempt=2,
            strategy=autoheal.MODEL_AUTOFIX_STRATEGY,
            route_record=route_record,
            route_evidence=route_evidence,
        )
        == 999
    )
    assert observed["branch"] == expected_branch


class _ReconcileRecoveryApi(_AmbiguousCommitApi):
    def __init__(self) -> None:
        config = autoheal.load_config()
        subject = autoheal._subject_from_route(_model_route(config))
        super().__init__(branch=autoheal._branch_name(subject, 1))
        self.created_prs = 0

    def list_all(self, path: str, *, max_pages: int = 10) -> list[dict[str, Any]]:
        if path == "/pulls?state=open&sort=created&direction=asc":
            assert max_pages == 4
            return []
        if path.startswith("/code-scanning/alerts?"):
            assert max_pages == 10
            return [_alert("src/ai_qa_automation/example.py")]
        if path == f"/git/matching-refs/heads/{autoheal.BRANCH_PREFIX}":
            assert max_pages == 4
            if self.branch_sha is None:
                return []
            return [
                {
                    "ref": f"refs/heads/{self.branch}",
                    "object": {"type": "commit", "sha": self.branch_sha},
                }
            ]
        if path == "/pulls?state=closed&sort=updated&direction=desc":
            assert max_pages == 10
            return []
        raise AssertionError(path)

    def get(self, path: str) -> dict[str, Any]:
        if path == "/branches/main":
            return {"commit": {"sha": BASE}}
        if path == f"/compare/{BASE}...{HEAD}":
            return {"files": [{"filename": "src/ai_qa_automation/example.py"}]}
        return super().get(path)

    def request_status(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        token: str | None = None,
    ) -> tuple[int, dict[str, Any]]:
        assert method == "POST"
        assert path == f"/code-scanning/alerts/{ALERT}/autofix"
        assert payload is None
        assert token is None
        return 200, {"status": "success"}


class _StaleAlertRecoveryApi(_ReconcileRecoveryApi):
    def list_all(self, path: str, *, max_pages: int = 10) -> list[dict[str, Any]]:
        if path.startswith("/code-scanning/alerts?"):
            assert max_pages == 10
            return [_alert("src/ai_qa_automation/example.py", sha="c" * 40)]
        return super().list_all(path, max_pages=max_pages)


def test_stale_codeql_evidence_refreshes_before_orphan_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _StaleAlertRecoveryApi()
    api.branch_sha = HEAD
    config = autoheal.load_config()
    monkeypatch.setenv("GITHUB_REPOSITORY", config["repository"])
    monkeypatch.setattr(autoheal, "GitHubApi", lambda token, repository: api)
    refresh_calls: list[str] = []

    def refresh(
        api_arg: object,
        main_sha: str,
        config_arg: dict[str, Any],
    ) -> dict[str, Any]:
        assert api_arg is api
        assert main_sha == BASE
        assert config_arg is config
        refresh_calls.append(main_sha)
        return {
            "codeqlRunId": 123,
            "codeqlRunAttempt": 1,
            "codeqlEvent": "workflow_dispatch",
            "codeqlStatus": "queued",
            "codeqlDispatched": True,
        }

    monkeypatch.setattr(autoheal, "_ensure_current_main_codeql", refresh)
    route_args = _route_reconcile_args(monkeypatch, {})

    assert autoheal.reconcile(config, allow_merge=False, **route_args) == 0
    assert refresh_calls == [BASE]
    assert api.branch_sha == HEAD
    assert api.commit_posts == 0


def test_reconcile_recovers_ambiguous_autofix_commit_without_second_submission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _ReconcileRecoveryApi()
    config = autoheal.load_config()
    monkeypatch.setenv("GITHUB_REPOSITORY", config["repository"])
    monkeypatch.setattr(autoheal, "GitHubApi", lambda token, repository: api)

    def create_pull_request(
        api_arg: object,
        branch: str,
        head_sha: str,
        subject: dict[str, Any],
        attempt: int,
        *,
        deterministic: bool,
        strategy: str,
        route_record: dict[str, Any],
        route_evidence: dict[str, Any],
    ) -> int:
        assert api_arg is api
        assert branch == api.branch
        assert head_sha == HEAD
        assert subject["number"] == ALERT
        assert attempt == 1
        assert deterministic is False
        assert strategy == autoheal.MODEL_AUTOFIX_STRATEGY
        assert route_record["decision"] == "ordinary-bounded-autofix"
        assert route_evidence["routePlanDigest"] == "e" * 64
        api.created_prs += 1
        return 999

    monkeypatch.setattr(autoheal, "_create_pull_request", create_pull_request)
    route_record = _model_route(config)
    route_args = _route_reconcile_args(monkeypatch, {ALERT: route_record})

    with pytest.raises(autoheal.AutohealError, match="503 after provider side effect"):
        autoheal.reconcile(config, allow_merge=False, **route_args)

    assert api.branch_sha == HEAD
    assert api.commit_posts == 1
    assert api.created_prs == 0

    assert autoheal.reconcile(config, allow_merge=False, **route_args) == 1
    assert api.commit_posts == 1
    assert api.created_prs == 1
