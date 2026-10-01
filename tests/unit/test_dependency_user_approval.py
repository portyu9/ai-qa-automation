from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / ".github" / "scripts" / "dependency_user_approval.py"
SCRIPT_DIR = SCRIPT.parent


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("dependency_user_approval_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(SCRIPT_DIR))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(SCRIPT_DIR))
    return module


approval = _load()
PR_NUMBER = 320
HEAD = "a" * 40
BASE = "b" * 40
MERGE = "c" * 40
RUN_ID = 12345
RUN_ATTEMPT = 1
GATE = {
    "statusId": 9876,
    "runId": RUN_ID,
    "runAttempt": RUN_ATTEMPT,
    "mergeSha": MERGE,
}
BODY = approval._automation_approval_body(
    number=PR_NUMBER,
    head_sha=HEAD,
    base_sha=BASE,
    gate_evidence=GATE,
)
SUBJECT = {
    "lane": approval.LANE_ACTIONS,
    "prNumber": PR_NUMBER,
    "headSha": HEAD,
    "baseSha": BASE,
    "gate": GATE,
    "body": BODY,
}


def _review(
    *,
    review_id: int = 7001,
    body: str = BODY,
    state: str = "APPROVED",
    commit_id: str = HEAD,
    login: str = "portyu9",
    user_id: int = 35150859,
) -> dict[str, Any]:
    return {
        "id": review_id,
        "body": body,
        "state": state,
        "commit_id": commit_id,
        "user": {"login": login, "id": user_id, "type": "User"},
    }


class Api:
    def __init__(
        self,
        reviews: list[dict[str, Any]],
        *,
        post_error_after_persist: bool = False,
    ) -> None:
        self.reviews = list(reviews)
        self.post_error_after_persist = post_error_after_persist
        self.posts: list[tuple[str, dict[str, Any], str | None]] = []

    def list_all(self, path: str, *, max_pages: int = 10) -> list[dict[str, Any]]:
        assert path == f"/pulls/{PR_NUMBER}/reviews"
        assert max_pages == 2
        return list(self.reviews)

    def post(
        self,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        token: str | None = None,
    ) -> dict[str, Any]:
        assert path == f"/pulls/{PR_NUMBER}/reviews"
        assert payload is not None
        self.posts.append((path, payload, token))
        created = _review()
        self.reviews.append(created)
        if self.post_error_after_persist:
            raise approval.GovernanceError("simulated ambiguous POST transport failure")
        return created


@pytest.fixture(autouse=True)
def env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_REPOSITORY", approval.EXPECTED_REPOSITORY)
    monkeypatch.setenv("GITHUB_TOKEN", "read-token")
    monkeypatch.setenv(approval.REVIEW_TOKEN_ENV, "owner-token")


def _wire(
    monkeypatch: pytest.MonkeyPatch,
    api: Api,
    *,
    subjects: list[dict[str, Any]] | None = None,
) -> None:
    queue = list(subjects or [dict(SUBJECT), dict(SUBJECT), dict(SUBJECT)])

    monkeypatch.setattr(
        approval, "load_config", lambda: {"repository": approval.EXPECTED_REPOSITORY}
    )
    monkeypatch.setattr(approval, "GitHubApi", lambda token, repository: api)
    monkeypatch.setattr(
        approval,
        "_resolve_exact_subject",
        lambda *args, **kwargs: queue.pop(0),
    )
    monkeypatch.setattr(
        approval,
        "_review_token_identity",
        lambda token: {"login": "portyu9", "id": 35150859, "type": "User"},
    )


def _publish() -> dict[str, Any]:
    return approval.publish_exact_owner_approval(
        lane=approval.LANE_ACTIONS,
        pr_number=PR_NUMBER,
        trusted_run_id=RUN_ID,
        trusted_run_attempt=RUN_ATTEMPT,
    )


def test_existing_exact_owner_approval_converges_without_secret_use(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = Api([_review()])
    _wire(monkeypatch, api)
    monkeypatch.delenv(approval.REVIEW_TOKEN_ENV)

    assert _publish()["decision"] == "exact-owner-approval-already-present"
    assert api.posts == []


def test_publishes_exact_owner_approval_with_isolated_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = Api([])
    _wire(monkeypatch, api)

    observed = _publish()

    assert observed == {
        "decision": "exact-owner-approval-published",
        "reviewId": 7001,
        "reviewer": "portyu9",
        "headSha": HEAD,
    }
    assert api.posts == [
        (
            f"/pulls/{PR_NUMBER}/reviews",
            {"event": "APPROVE", "body": BODY, "commit_id": HEAD},
            "owner-token",
        )
    ]


def test_ambiguous_post_recovers_only_from_durable_exact_review(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = Api([], post_error_after_persist=True)
    _wire(monkeypatch, api)

    assert _publish()["decision"] == "exact-owner-approval-published"
    assert len(api.reviews) == 1


def test_manual_exact_head_changes_requested_veto_blocks_automation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = Api([_review(body="manual veto", state="CHANGES_REQUESTED")])
    _wire(monkeypatch, api)

    with pytest.raises(approval.PolicyBlock, match="CHANGES_REQUESTED veto"):
        _publish()
    assert api.posts == []


def test_late_manual_veto_after_review_publication_blocks_convergence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class LateVetoApi(Api):
        def __init__(self) -> None:
            super().__init__([])
            self.review_reads = 0

        def list_all(self, path: str, *, max_pages: int = 10) -> list[dict[str, Any]]:
            rows = super().list_all(path, max_pages=max_pages)
            self.review_reads += 1
            if self.review_reads >= 3:
                rows.append(
                    _review(
                        review_id=7002,
                        body="manual late veto",
                        state="CHANGES_REQUESTED",
                    )
                )
            return rows

    api = LateVetoApi()
    _wire(monkeypatch, api)

    with pytest.raises(approval.PolicyBlock, match="CHANGES_REQUESTED veto"):
        _publish()
    assert len(api.posts) == 1


def test_multiple_exact_owner_approvals_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = Api([_review(review_id=7001), _review(review_id=7002)])
    _wire(monkeypatch, api)

    with pytest.raises(approval.GovernanceError, match="multiple exact owner"):
        _publish()


def test_subject_change_before_write_blocks_review(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    changed = dict(SUBJECT)
    changed["headSha"] = "d" * 40
    api = Api([])
    _wire(monkeypatch, api, subjects=[dict(SUBJECT), changed])

    with pytest.raises(approval.PolicyBlock, match="immediately before owner approval"):
        _publish()
    assert api.posts == []


def test_only_first_attempt_trusted_run_can_authorize_owner_review() -> None:
    with pytest.raises(approval.GovernanceError, match="first-attempt"):
        approval.publish_exact_owner_approval(
            lane=approval.LANE_ACTIONS,
            pr_number=PR_NUMBER,
            trusted_run_id=RUN_ID,
            trusted_run_attempt=2,
        )


class _Response:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = json.dumps(payload).encode()
        self.headers = {"Content-Length": str(len(self.payload))}

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self, size: int) -> bytes:
        assert size == approval.MAX_RESPONSE_BYTES + 1
        return self.payload


def test_review_token_identity_requires_exact_portyu9_user(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        approval.urllib.request,
        "urlopen",
        lambda request, timeout: _Response(
            {"login": "github-actions[bot]", "id": 41898282, "type": "Bot"}
        ),
    )
    with pytest.raises(approval.GovernanceError, match="differs from exact repository owner"):
        approval._review_token_identity("wrong-token")


def test_review_token_identity_accepts_exact_portyu9_user(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        approval.urllib.request,
        "urlopen",
        lambda request, timeout: _Response({"login": "portyu9", "id": 35150859, "type": "User"}),
    )
    assert approval._review_token_identity("owner-token")["login"] == "portyu9"
