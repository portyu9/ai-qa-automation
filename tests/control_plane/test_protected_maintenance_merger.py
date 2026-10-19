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


def test_scheduled_controller_merges_only_after_independent_gate_and_owner_identity(
    main_environment: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate = {
        "number": 403,
        "state": "open",
        "draft": False,
        "user": {"login": "portyu9", "id": 35150859, "type": "User"},
        "head": {"sha": "b" * 40},
    }
    admission = SimpleNamespace(
        eligible=True,
        protected_changes=({"path": ".github", "base_oid": "a", "subject_oid": "b"},),
        pr_number=403,
        head_sha="b" * 40,
        base_sha="a" * 40,
        merge_sha="c" * 40,
    )

    class ControllerAPI:
        def __init__(self) -> None:
            self.review_state = "COMMENTED"
            self.calls: list[str] = []

        def list_all(self, path: str, *, max_pages: int = 4) -> list[dict]:
            self.calls.append(path)
            if "/pulls?state=open&base=main" in path:
                return [candidate]
            if "/pulls/403/reviews" in path:
                return [
                    {
                        "user": {"login": "portyu9", "id": 35150859},
                        "commit_id": "b" * 40,
                        "state": self.review_state,
                    }
                ]
            raise AssertionError(f"unreviewed controller inventory: {path}")

        def get(self, path: str) -> dict:
            self.calls.append(path)
            if path.endswith("/pulls/403"):
                return candidate
            if path.endswith("/git/commits/" + "c" * 40):
                return {
                    "sha": "c" * 40,
                    "parents": [{"sha": "a" * 40}, {"sha": "b" * 40}],
                }
            raise AssertionError(f"unreviewed controller lookup: {path}")

    api = ControllerAPI()
    monkeypatch.setattr(merger, "_current_main", lambda _: "a" * 40)
    monkeypatch.setattr(merger, "_resolve_subject", lambda *a, **k: admission)
    monkeypatch.setattr(merger, "existing_authorization", lambda *a, **k: 28)
    monkeypatch.setattr(merger, "require_passing_candidate_checks", lambda *a, **k: True)
    gated: list[tuple[int, str, str]] = []

    def trusted(*args: object, **kwargs: object) -> dict:
        assert kwargs == {"protected_maintenance": True}
        gated.append((args[1], args[2], args[3]))
        return {"state": "success"}

    monkeypatch.setattr(merger, "require_automatic_trusted_gate", trusted)
    merged: list[tuple[str, int]] = []
    # The merge callback changes the observed default branch only after mutation.
    monkeypatch.setattr(merger, "_current_main", lambda _: "c" * 40 if merged else "a" * 40)

    def merge(token: str, subject: SimpleNamespace) -> dict:
        merged.append((token, subject.pr_number))
        return {"merged": True, "sha": "c" * 40}

    monkeypatch.setattr(merger, "merge_once", merge)
    result = merger.reconcile(api, "reviewed-merger-test-token")
    assert result == {
        "decision": "exact-trusted-protected-maintenance-merged",
        "pr": 403,
        "headSha": "b" * 40,
        "baseSha": "a" * 40,
        "mergeSha": "c" * 40,
    }
    assert gated == [(403, "b" * 40, "a" * 40)] * 2
    assert merged == [("reviewed-merger-test-token", 403)]

    # An acknowledged API merge without an exact visible main transition is not PASS.
    merged.clear()
    monkeypatch.setattr(merger, "_current_main", lambda _: "a" * 40)
    with pytest.raises(ValueError, match="does not equal live current main"):
        merger.reconcile(api, "reviewed-merger-test-token")
    merged.clear()
    monkeypatch.setattr(merger, "_current_main", lambda _: "c" * 40 if merged else "a" * 40)

    def missing_gate(*args: object, **kwargs: object) -> dict:
        assert kwargs == {"protected_maintenance": True}
        raise merger.TrustedStatusError("independent App status missing")

    monkeypatch.setattr(merger, "require_automatic_trusted_gate", missing_gate)
    assert merger.reconcile(api, "reviewed-merger-test-token") == {
        "decision": "no-trusted-protected-maintenance"
    }
    assert merged == []

    api.review_state = "CHANGES_REQUESTED"
    with pytest.raises(ValueError, match="veto"):
        merger.reconcile(api, "reviewed-merger-test-token")
    assert merged == []

    api.review_state = "COMMENTED"
    monkeypatch.setattr(merger, "require_automatic_trusted_gate", trusted)
    calls = iter(["a" * 40, "d" * 40])
    monkeypatch.setattr(merger, "_current_main", lambda _: next(calls))
    with pytest.raises(ValueError, match="main advanced"):
        merger.reconcile(api, "reviewed-merger-test-token")
    assert merged == []


def test_merger_event_wake_cannot_replace_app_gate(
    main_environment: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_EVENT_NAME", "workflow_run")
    event_file = tmp_path / "event.json"
    wake = {
        "action": "completed",
        "workflow_run": {
            "id": 919,
            "workflow_id": merger.TRUSTED_WAKE_WORKFLOW_ID,
            "head_sha": "a" * 40,
        },
    }
    event_file.write_text(json.dumps(wake), encoding="utf-8")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_file))
    merger.require_execution_context("a" * 40)
    valid = {
        "id": 919,
        "workflow_id": 346203190,
        "name": "Trusted PR Auto Gate — ƳƤ AI QA Automation Framework",
        "path": ".github/workflows/trusted-pr-auto.yml",
        "event": "workflow_run",
        "run_attempt": 1,
        "status": "completed",
        "conclusion": "success",
        "head_branch": "main",
        "head_sha": "a" * 40,
        "repository": {"full_name": "portyu9/ai-qa-automation"},
        "head_repository": {"full_name": "portyu9/ai-qa-automation"},
    }

    class WakeAPI:
        def __init__(self, result: dict) -> None:
            self.result = result

        def get(self, endpoint: str) -> dict:
            assert endpoint == "/repos/portyu9/ai-qa-automation/actions/runs/919"
            return self.result

    api = WakeAPI(valid)
    merger.require_verified_merger_wake(api, "a" * 40)
    for mutation in (
        {"workflow_id": 999},
        {"name": "Other workflow"},
        {"path": ".github/workflows/untrusted.yml"},
        {"head_sha": "b" * 40},
        {"head_branch": "bad"},
        {"event": "pull_request"},
        {"conclusion": "failure"},
        {"run_attempt": 2},
        {"head_repository": {"full_name": "bad/source"}},
    ):
        api.result = {**valid, **mutation}
        with pytest.raises(ValueError, match="not the exact trusted-main gate"):
            merger.require_verified_merger_wake(api, "a" * 40)
    api.result = valid
    wake["workflow_run"]["workflow_id"] = 5
    event_file.write_text(json.dumps(wake), encoding="utf-8")
    with pytest.raises(ValueError, match="not the exact trusted-main gate"):
        merger.require_verified_merger_wake(api, "a" * 40)
    event_file.write_text("x" * (merger.MAX_EVENT_BYTES + 1), encoding="utf-8")
    with pytest.raises(ValueError, match="bounded"):
        merger.require_verified_merger_wake(api, "a" * 40)
