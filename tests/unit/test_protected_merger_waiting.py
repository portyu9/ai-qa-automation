"""Adversarial read-only waiting admission for the independent protected merger."""

from __future__ import annotations

import importlib.util
import sys
from copy import deepcopy
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT_DIR = ROOT / "scripts"
BASE = "b" * 40
HEAD = "a" * 40
MERGE = "c" * 40
NUMBER = 71


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "protected_merger_waiting_test", SCRIPT_DIR / "auto_protected_maintenance_merger.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(SCRIPT_DIR))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(SCRIPT_DIR))
    return module


merger = _load()
REPO = merger.EXPECTED_REPOSITORY


def _pr(mergeable: bool | None = None) -> dict[str, Any]:
    return {
        "number": NUMBER,
        "state": "open",
        "draft": False,
        "user": {
            "login": merger.EXPECTED_OWNER,
            "id": merger.EXPECTED_OWNER_ID,
            "type": "User",
        },
        "head": {
            "ref": "fix/protected-merger-waiting-admission-20261110",
            "sha": HEAD,
            "repo": {"full_name": REPO},
        },
        "base": {
            "ref": "main",
            "sha": BASE,
            "repo": {"full_name": REPO},
        },
        "mergeable": mergeable,
    }


class ReadOnlyApi:
    def __init__(self, *, mergeable: bool | None = None) -> None:
        self.live = _pr(mergeable)
        self.summary = deepcopy(self.live)
        self.summary.pop("mergeable")
        self.comments: list[dict[str, Any]] = []
        self.reads: list[str] = []

    def get(self, path: str) -> dict[str, Any]:
        self.reads.append(path)
        if path == f"/repos/{REPO}/pulls/{NUMBER}":
            return deepcopy(self.live)
        raise AssertionError(f"unexpected privileged or unreviewed API read: {path}")

    def list_all(self, path: str, *, max_pages: int = 1) -> list[dict[str, Any]]:
        self.reads.append(path)
        assert max_pages == 1
        if path == f"/repos/{REPO}/pulls?state=open&base=main":
            return [deepcopy(self.summary)]
        if path == f"/repos/{REPO}/issues/{NUMBER}/comments?per_page=100":
            return deepcopy(self.comments)
        raise AssertionError(f"unexpected inventory: {path}")

    def post(self, *_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("waiting admission must never mutate GitHub")


@pytest.fixture(autouse=True)
def _trusted_main(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(merger, "_current_main", lambda _api: BASE)
    monkeypatch.setattr(merger, "require_execution_context", lambda _sha: None)
    monkeypatch.setattr(merger, "require_verified_merger_wake", lambda _api, _sha: None)


@pytest.mark.parametrize("mergeable", [None, False])
def test_unapproved_pending_owner_is_explicit_wait_not_red_or_merge(
    monkeypatch: pytest.MonkeyPatch, mergeable: bool | None
) -> None:
    api = ReadOnlyApi(mergeable=mergeable)
    monkeypatch.setattr(
        merger,
        "_resolve_subject",
        lambda *_args, **_kwargs: pytest.fail("pending PR must not request merge authority"),
    )
    monkeypatch.setattr(
        merger,
        "merge_once",
        lambda *_args, **_kwargs: pytest.fail("pending PR must not merge"),
    )
    assert merger.reconcile(api, "unused") == {
        "decision": "no-trusted-protected-maintenance",
        "disposition": "waiting-for-unapproved-owner-mergeability",
    }
    assert api.reads == [
        f"/repos/{REPO}/pulls?state=open&base=main",
        f"/repos/{REPO}/pulls/{NUMBER}",
        f"/repos/{REPO}/issues/{NUMBER}/comments?per_page=100",
    ]


@pytest.mark.parametrize(
    ("which", "field", "key", "value"),
    [
        ("summary", "head", "sha", "z" * 40),
        ("summary", "head", "ref", ""),
        ("summary", "head", "repo", {"full_name": "attacker/fork"}),
        ("summary", "base", "sha", "d" * 40),
        ("summary", "base", "ref", "staging"),
        ("live", "head", "sha", "d" * 40),
        ("live", "head", "ref", "fix/unreviewed-rebase"),
        ("live", "base", "sha", "d" * 40),
        ("live", "base", "repo", {"full_name": "attacker/fork"}),
        ("live", "user", "id", -1),
        ("live", "user", "type", "Bot"),
    ],
)
def test_corrupt_or_moved_identity_never_becomes_benign_wait(
    which: str, field: str, key: str, value: Any
) -> None:
    api = ReadOnlyApi(mergeable=False)
    getattr(api, which)[field][key] = value
    with pytest.raises(ValueError):
        merger.qualify(api)


@pytest.mark.parametrize("invalid", [0, "false", "pending"])
def test_invalid_mergeability_types_fail_closed(invalid: Any) -> None:
    api = ReadOnlyApi()
    api.live["mergeable"] = invalid
    with pytest.raises(ValueError, match="invalid GitHub truth"):
        merger.qualify(api)


def test_missing_mergeability_is_not_silently_reclassified() -> None:
    api = ReadOnlyApi()
    api.live.pop("mergeable")
    with pytest.raises(ValueError, match="invalid GitHub truth"):
        merger.qualify(api)


@pytest.mark.parametrize(
    "comments",
    [
        [{"body": "/trusted-maintenance authorization=protected-control-plane-maintenance"}],
        [{"body": "/trusted-maintenance malformed-or-forged"}],
        [{"body": None}],
    ],
)
def test_authorization_or_corrupt_comment_cannot_be_suppressed(
    comments: list[dict[str, Any]]
) -> None:
    api = ReadOnlyApi(mergeable=None)
    api.comments = comments
    with pytest.raises(ValueError, match="authorization|unreadable"):
        merger.qualify(api)


def test_comment_inventory_bound_fail_closed() -> None:
    api = ReadOnlyApi(mergeable=False)
    api.comments = [{"body": "ordinary discussion"} for _ in range(merger.COMMENTS_LIMIT)]
    with pytest.raises(ValueError, match="inventory exceeded"):
        merger.qualify(api)


def test_main_movement_during_read_only_classification_is_not_wait(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = ReadOnlyApi(mergeable=None)
    heads = iter([BASE, "d" * 40])
    monkeypatch.setattr(merger, "_current_main", lambda _api: next(heads))
    with pytest.raises(ValueError, match="main changed"):
        merger.qualify(api)


def test_mergeable_subject_still_requires_exact_authorization_ci_and_app_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = ReadOnlyApi(mergeable=True)
    proof = SimpleNamespace(
        eligible=True,
        protected_changes=({"path": ".github"},),
        pr_number=NUMBER,
        head_sha=HEAD,
        base_sha=BASE,
        merge_sha=MERGE,
    )
    calls: list[str] = []

    def resolver(_api: Any, **kwargs: Any) -> Any:
        assert kwargs == {
            "lane": merger.PROTECTED_OWNER_LANE,
            "pr": api.summary,
            "head_sha": HEAD,
            "trusted_sha": BASE,
            "qualification_ready": True,
        }
        calls.append("resolve")
        return proof

    monkeypatch.setattr(merger, "_resolve_subject", resolver)
    monkeypatch.setattr(merger, "exact_comment", lambda _proof: "exact-owner-authorization")
    monkeypatch.setattr(
        merger,
        "existing_authorization",
        lambda _api, pr, body: (
            calls.append("authorization") or 5
            if pr == NUMBER and body == "exact-owner-authorization"
            else pytest.fail("wrong authorization subject")
        ),
    )
    monkeypatch.setattr(
        merger,
        "require_passing_candidate_checks",
        lambda _api, sha: calls.append("checks") or sha == HEAD,
    )
    monkeypatch.setattr(
        merger, "require_no_exact_owner_veto",
        lambda _api, pr, sha: calls.append("veto"),
    )
    monkeypatch.setattr(
        merger,
        "require_automatic_trusted_gate",
        lambda _adapter, pr, head, base, *, protected_maintenance: (
            calls.append("app-gate")
            or {
                "verified": pr == NUMBER
                and head == HEAD
                and base == BASE
                and protected_maintenance
            }
        ),
    )

    selected = merger.qualify(api)
    assert selected == {"admission": proof, "gate": {"verified": True}}
    assert calls == ["resolve", "authorization", "checks", "veto", "app-gate"]
    assert f"/repos/{REPO}/issues/{NUMBER}/comments?per_page=100" not in api.reads

    calls.clear()
    monkeypatch.setattr(merger, "existing_authorization", lambda *_args: None)
    assert merger.qualify(api) is None
    assert calls == ["resolve"]


def test_pending_wait_never_hides_an_independent_verified_ready_subject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = ReadOnlyApi(mergeable=False)
    second = _pr(True)
    second["number"] = NUMBER + 1
    second["head"]["sha"] = "e" * 40
    api.summary = [api.summary, second]  # type: ignore[assignment]
    # A second eligible PR remains subject to normal positive admission gates.
    def listing(path: str, *, max_pages: int = 1) -> list[dict[str, Any]]:
        if path == f"/repos/{REPO}/pulls?state=open&base=main":
            return deepcopy(api.summary)
        if path == f"/repos/{REPO}/issues/{NUMBER}/comments?per_page=100":
            return []
        raise AssertionError(path)

    monkeypatch.setattr(api, "list_all", listing)
    def get(path: str) -> dict[str, Any]:
        if path == f"/repos/{REPO}/pulls/{NUMBER}":
            return _pr(False)
        if path == f"/repos/{REPO}/pulls/{NUMBER + 1}":
            return second
        raise AssertionError(path)

    monkeypatch.setattr(api, "get", get)
    proof = SimpleNamespace(
        eligible=True, protected_changes=({"path": "scripts"},),
        pr_number=NUMBER + 1, head_sha="e" * 40, base_sha=BASE,
    )
    monkeypatch.setattr(merger, "_resolve_subject", lambda *_args, **_kwargs: proof)
    monkeypatch.setattr(merger, "exact_comment", lambda _proof: "approved")
    monkeypatch.setattr(merger, "existing_authorization", lambda *_args: 9)
    monkeypatch.setattr(merger, "require_passing_candidate_checks", lambda *_args: True)
    monkeypatch.setattr(merger, "require_no_exact_owner_veto", lambda *_args: None)
    monkeypatch.setattr(
        merger, "require_automatic_trusted_gate", lambda *_args, **_kwargs: {"ok": True}
    )
    assert merger.qualify(api)["admission"] is proof
