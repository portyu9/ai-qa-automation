from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
merger = importlib.import_module("auto_protected_maintenance_merger")


class StubApi:
    def __init__(self, reviews: list[dict] | None = None) -> None:
        self.reviews = reviews or []
        self.calls: list[str] = []

    def list_all(self, path: str, *, max_pages: int = 4) -> list[dict]:
        self.calls.append(path)
        return self.reviews

    def get(self, path: str) -> dict:
        self.calls.append(path)
        return {"checked": True}


def test_local_adapter_is_bound_to_reviewed_repository() -> None:
    api = StubApi()
    adapter = merger.RepositoryLocalAdapter(api)
    assert adapter.get("/commits/abc") == {"checked": True}
    assert adapter.list_all("/pulls?state=open") == []
    assert api.calls == [
        "/repos/portyu9/ai-qa-automation/commits/abc",
        "/repos/portyu9/ai-qa-automation/pulls?state=open",
    ]
    for bad in ("../issues", "/../main", "/commits/%2e/..", "https://attacker.invalid"):
        with pytest.raises(ValueError, match="unsafe"):
            adapter.get(bad)


@pytest.fixture()
def main_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for key, value in {
        "GITHUB_REPOSITORY": "portyu9/ai-qa-automation",
        "GITHUB_API_URL": "https://api.github.com",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_SHA": "a" * 40,
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_EVENT_NAME": "schedule",
        "GITHUB_WORKFLOW_REF": (
            "portyu9/ai-qa-automation/.github/workflows/"
            "protected-maintenance-merge.yml@refs/heads/main"
        ),
    }.items():
        monkeypatch.setenv(key, value)


def test_merge_requires_exact_main_and_immutable_first_attempt(
    main_environment: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    merger.require_execution_context("a" * 40)
    for key, bad in (
        ("GITHUB_REF", "refs/heads/release"),
        ("GITHUB_RUN_ATTEMPT", "2"),
        ("GITHUB_SHA", "b" * 40),
        ("GITHUB_EVENT_NAME", "workflow_dispatch"),
    ):
        correct = merger.os.environ[key]
        monkeypatch.setenv(key, bad)
        with pytest.raises(ValueError, match="accepted-main first-attempt"):
            merger.require_execution_context("a" * 40)
        monkeypatch.setenv(key, correct)


def test_exact_owner_veto_blocks_merge_without_changes_requested_bypass() -> None:
    head = "b" * 40
    user = {"login": "portyu9", "id": 35150859}
    api = StubApi([{"user": user, "state": "COMMENTED", "commit_id": head}])
    merger.require_no_exact_owner_veto(api, 403, head)
    api.reviews = [{"user": user, "state": "CHANGES_REQUESTED", "commit_id": head}]
    with pytest.raises(ValueError, match="veto"):
        merger.require_no_exact_owner_veto(api, 403, head)
    api.reviews = [{"user": user, "state": "CHANGES_REQUESTED", "commit_id": "a" * 40}]
    merger.require_no_exact_owner_veto(api, 403, head)


def test_ambiguous_merge_response_never_counts_as_merge(monkeypatch: pytest.MonkeyPatch) -> None:
    subject = SimpleNamespace(pr_number=403, head_sha="b" * 40)

    def response(body: dict) -> Mock:
        output = MagicMock()
        output.read.return_value = json.dumps(body).encode()
        output.__enter__ = Mock(return_value=output)
        output.__exit__ = Mock(return_value=None)
        return output

    writer = Mock(return_value=response({"merged": False, "sha": "c" * 40}))
    monkeypatch.setattr(merger.urllib.request, "urlopen", writer)
    with pytest.raises(ValueError, match="did not report"):
        merger.merge_once("fixture-token", subject)
    assert writer.call_count == 1

    writer.reset_mock()
    writer.return_value = response({"merged": True, "sha": "c" * 40})
    proof = merger.merge_once("fixture-token", subject)
    assert proof["merged"] is True
    assert proof["sha"] == "c" * 40
    assert writer.call_count == 1
