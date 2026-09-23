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
BRANCH = "automation/codeql-autoheal-42-abcdef123456"


def _repo_commit(*, owner: str = autoheal.GITHUB_ACTIONS_LOGIN, owner_id: int = autoheal.GITHUB_ACTIONS_USER_ID, alert: int = ALERT) -> dict[str, Any]:
    return {
        "sha": HEAD,
        "author": {"login": owner, "id": owner_id},
        "commit": {"message": f"security: auto-heal CodeQL alert #{alert}\n\nAutofix"},
    }


class _AmbiguousCommitApi:
    def __init__(self) -> None:
        self.branch_sha: str | None = None
        self.commit_posts = 0
        self.fail_first_commit_response = True
        self.repository_commit = _repo_commit()
        self.parent = BASE

    def get(self, path: str) -> dict[str, Any]:
        encoded = urllib.parse.quote(BRANCH, safe="")
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
            assert payload == {"ref": f"refs/heads/{BRANCH}", "sha": BASE}
            self.branch_sha = BASE
            return {"ref": f"refs/heads/{BRANCH}"}
        if path == f"/code-scanning/alerts/{ALERT}/autofix/commits":
            self.commit_posts += 1
            assert payload["target_ref"] == f"refs/heads/{BRANCH}"
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
    assert autoheal._prune_orphan_repair_refs(
        api,
        [],
        preserve_branches={BRANCH},
    ) == 0
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
    assert branches == {autoheal._branch_name(subject)}
