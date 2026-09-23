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
BRANCH = "automation/codeql-autoheal-42-abcdef123456-a1"


def _repo_commit(
    *,
    owner: str = autoheal.GITHUB_ACTIONS_LOGIN,
    owner_id: int = autoheal.GITHUB_ACTIONS_USER_ID,
    alert: int = ALERT,
) -> dict[str, Any]:
    return {
        "sha": HEAD,
        "author": {"login": owner, "id": owner_id},
        "commit": {"message": f"security: auto-heal CodeQL alert #{alert}\n\nAutofix"},
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
            self.branch_sha = HEAD
            if self.fail_first_commit_response:
                self.fail_first_commit_response = False
                raise autoheal.AutohealError("GitHub API HTTP 503 after provider side effect")
            return {"sha": HEAD}
        raise AssertionError(path)

    def delete(self, path: str) -> dict[str, Any]:
        raise AssertionError(f"unexpected delete: {path}")


def test_ambiguous_autofix_commit_response_is_recovered_without_provider_replay() -> None:
    api = _AmbiguousCommitApi()

    with pytest.raises(autoheal.AutohealError, match="503 after provider side effect"):
        autoheal._commit_copilot_autofix(api, ALERT, BRANCH, BASE)

    assert api.branch_sha == HEAD
    assert api.commit_posts == 1

    recovered = autoheal._commit_copilot_autofix(api, ALERT, BRANCH, BASE)
    assert recovered == HEAD
    assert api.commit_posts == 1


@pytest.mark.parametrize(
    ("repository_commit", "parent", "message"),
    (
        (_repo_commit(owner="attacker", owner_id=1), BASE, "ownership"),
        (_repo_commit(), "c" * 40, "parented"),
        (_repo_commit(alert=99), BASE, "different alert"),
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
        autoheal._commit_copilot_autofix(api, ALERT, BRANCH, BASE)

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
            "ref": "refs/heads/main",
            "commit_sha": sha,
            "location": {"path": path, "start_line": 10},
            "message": {"text": "unsafe URL check"},
        },
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

    subject = autoheal.validate_alert(model, BASE, config)
    assert branches == {
        autoheal._branch_name(subject, attempt)
        for attempt in range(1, int(config["maxAttemptsPerAlert"]) + 1)
    }


def test_attempt_scoped_branch_names_are_distinct_and_legacy_compatible() -> None:
    config = autoheal.load_config()
    model = _alert("src/ai_qa_automation/example.py")
    subject = autoheal.validate_alert(model, BASE, config)
    legacy = autoheal._branch_name(subject)
    branches = [
        autoheal._branch_name(subject, attempt)
        for attempt in range(1, int(config["maxAttemptsPerAlert"]) + 1)
    ]

    assert autoheal.AUTOHEAL_BRANCH_RE.fullmatch(legacy) is not None
    assert len(branches) == len(set(branches))
    assert legacy not in branches
    assert all(autoheal.AUTOHEAL_BRANCH_RE.fullmatch(branch) is not None for branch in branches)


def test_branch_binding_accepts_legacy_or_exact_attempt_and_rejects_mismatch() -> None:
    config = autoheal.load_config()
    subject = autoheal.validate_alert(_alert("src/ai_qa_automation/example.py"), BASE, config)
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
    subject = autoheal.validate_alert(_alert("src/ai_qa_automation/example.py"), BASE, config)
    expected_branch = autoheal._branch_name(subject, 2)
    observed: dict[str, Any] = {}

    monkeypatch.setattr(autoheal, "_ensure_copilot_autofix", lambda api, alert: None)

    def commit_autofix(api: object, alert: int, branch: str, base: str) -> str:
        observed["branch"] = branch
        assert alert == ALERT
        assert base == BASE
        return HEAD

    monkeypatch.setattr(autoheal, "_commit_copilot_autofix", commit_autofix)
    monkeypatch.setattr(
        autoheal,
        "_changed_files",
        lambda api, base, head: [{"filename": subject["path"]}],
    )

    def create_pr(
        api: object,
        branch: str,
        head_sha: str,
        live_subject: dict[str, Any],
        attempt: int,
        *,
        deterministic: bool,
        strategy: str,
    ) -> int:
        assert branch == expected_branch
        assert head_sha == HEAD
        assert live_subject == subject
        assert attempt == 2
        assert deterministic is False
        assert strategy == autoheal.MODEL_AUTOFIX_STRATEGY
        return 999

    monkeypatch.setattr(autoheal, "_create_pull_request", create_pr)

    assert (
        autoheal._create_repair(
            object(),
            subject,
            config,
            attempt=2,
            strategy=autoheal.MODEL_AUTOFIX_STRATEGY,
        )
        == 999
    )
    assert observed["branch"] == expected_branch


class _ReconcileRecoveryApi(_AmbiguousCommitApi):
    def __init__(self) -> None:
        config = autoheal.load_config()
        subject = autoheal.validate_alert(
            _alert("src/ai_qa_automation/example.py"),
            BASE,
            config,
        )
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
    ) -> int:
        assert api_arg is api
        assert branch == api.branch
        assert head_sha == HEAD
        assert subject["number"] == ALERT
        assert attempt == 1
        assert deterministic is False
        assert strategy == autoheal.MODEL_AUTOFIX_STRATEGY
        api.created_prs += 1
        return 999

    monkeypatch.setattr(autoheal, "_create_pull_request", create_pull_request)

    with pytest.raises(autoheal.AutohealError, match="503 after provider side effect"):
        autoheal.reconcile(config, allow_merge=False)

    assert api.branch_sha == HEAD
    assert api.commit_posts == 1
    assert api.created_prs == 0

    assert autoheal.reconcile(config, allow_merge=False) == 1
    assert api.commit_posts == 1
    assert api.created_prs == 1
