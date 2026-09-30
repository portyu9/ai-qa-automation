from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / ".github" / "scripts" / "dependency_governance.py"
SCRIPT_DIR = SCRIPT.parent


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("dependency_governance_approval_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(SCRIPT_DIR))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(SCRIPT_DIR))
    return module


governance = _load()
PR_NUMBER = 320
HEAD = "a" * 40
BASE = "b" * 40
MERGE = "c" * 40
GATE = {
    "statusId": 9876,
    "runId": 12345,
    "runAttempt": 1,
    "mergeSha": MERGE,
}


def _body() -> str:
    return governance._automation_approval_body(
        number=PR_NUMBER,
        head_sha=HEAD,
        base_sha=BASE,
        gate_evidence=GATE,
    )


def _review(
    *,
    review_id: int = 7001,
    body: str | None = None,
    login: str = governance.AUTOMATION_APPROVER_LOGIN,
    user_id: int = governance.AUTOMATION_APPROVER_USER_ID,
    state: str = "APPROVED",
    commit_id: str = HEAD,
) -> dict[str, Any]:
    return {
        "id": review_id,
        "body": _body() if body is None else body,
        "state": state,
        "commit_id": commit_id,
        "user": {"login": login, "id": user_id},
    }


class Api:
    def __init__(
        self,
        reviews: list[dict[str, Any]],
        *,
        persist_created: bool = True,
        response: dict[str, Any] | None = None,
    ) -> None:
        self.reviews = list(reviews)
        self.persist_created = persist_created
        self.response = response
        self.posts: list[tuple[str, dict[str, Any]]] = []

    def list_all(self, path: str, *, max_pages: int = 10) -> list[dict[str, Any]]:
        assert path == f"/pulls/{PR_NUMBER}/reviews"
        assert max_pages == 2
        return list(self.reviews)

    def post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        assert path == f"/pulls/{PR_NUMBER}/reviews"
        self.posts.append((path, payload))
        created = self.response or _review()
        if self.persist_created:
            self.reviews.append(created)
        return created


def _approve(api: Api) -> dict[str, Any]:
    return governance.ensure_exact_automation_approval(
        api,
        number=PR_NUMBER,
        head_sha=HEAD,
        base_sha=BASE,
        gate_evidence=GATE,
    )


def test_existing_exact_approval_is_idempotent() -> None:
    api = Api([_review()])
    assert _approve(api) == {
        "reviewId": 7001,
        "reviewer": governance.AUTOMATION_APPROVER_LOGIN,
        "headSha": HEAD,
    }
    assert api.posts == []


def test_publishes_exact_head_approval_and_reloads_it() -> None:
    api = Api([])
    observed = _approve(api)

    assert observed["reviewId"] == 7001
    assert len(api.posts) == 1
    _, payload = api.posts[0]
    assert payload == {
        "event": "APPROVE",
        "body": _body(),
        "commit_id": HEAD,
    }
    assert f"PR: #{PR_NUMBER}" in payload["body"]
    assert HEAD in payload["body"]
    assert BASE in payload["body"]
    assert MERGE in payload["body"]
    assert str(GATE["runId"]) in payload["body"]
    assert str(GATE["statusId"]) in payload["body"]


def test_untrusted_same_body_review_cannot_block_real_approval() -> None:
    api = Api([_review(login="portyu9", user_id=35150859)])
    observed = _approve(api)

    assert observed["reviewId"] == 7001
    assert len(api.posts) == 1
    assert len(api.reviews) == 2


@pytest.mark.parametrize(
    "review",
    (
        _review(state="COMMENTED"),
        _review(commit_id="d" * 40),
    ),
)
def test_exact_bot_audit_body_with_wrong_state_or_head_fails_closed(
    review: dict[str, Any],
) -> None:
    with pytest.raises(governance.GovernanceError):
        _approve(Api([review]))


def test_duplicate_exact_approvals_are_race_safe_and_canonicalized() -> None:
    api = Api([_review(review_id=7001), _review(review_id=7002)])

    assert _approve(api) == {
        "reviewId": 7002,
        "reviewer": governance.AUTOMATION_APPROVER_LOGIN,
        "headSha": HEAD,
    }
    assert api.posts == []


def test_approval_must_be_durably_observable_after_publication() -> None:
    with pytest.raises(
        governance.GovernanceError,
        match="not durably observable",
    ):
        _approve(Api([], persist_created=False))


def test_untrusted_gate_attempt_cannot_produce_approval_body() -> None:
    evidence = dict(GATE)
    evidence["runAttempt"] = 2
    with pytest.raises(
        governance.GovernanceError,
        match="run attempt must equal one",
    ):
        governance._automation_approval_body(
            number=PR_NUMBER,
            head_sha=HEAD,
            base_sha=BASE,
            gate_evidence=evidence,
        )


def _function_merge_and_approval_counts(path: Path) -> dict[str, tuple[int, int]]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    observed: dict[str, tuple[int, int]] = {}
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        merge_calls = 0
        approval_calls = 0
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            if (
                isinstance(child.func, ast.Name)
                and child.func.id == "ensure_exact_automation_approval"
            ):
                approval_calls += 1
            if (
                isinstance(child.func, ast.Attribute)
                and child.func.attr == "put"
                and child.args
                and isinstance(child.args[0], ast.JoinedStr)
                and "/merge"
                in "".join(
                    value.value
                    for value in child.args[0].values
                    if isinstance(value, ast.Constant) and isinstance(value.value, str)
                )
            ):
                merge_calls += 1
        if merge_calls:
            observed[node.name] = (merge_calls, approval_calls)
    return observed


def test_every_dependency_merge_function_has_exact_review_barrier() -> None:
    assert _function_merge_and_approval_counts(
        ROOT / ".github" / "scripts" / "dependency_governance.py"
    ) == {
        "_merge": (1, 1),
        "reconcile_status_target": (1, 1),
    }
    assert _function_merge_and_approval_counts(
        ROOT / ".github" / "scripts" / "dependency_promotion.py"
    ) == {
        "_publish_and_merge": (1, 1),
        "reconcile_status_target": (1, 1),
    }
