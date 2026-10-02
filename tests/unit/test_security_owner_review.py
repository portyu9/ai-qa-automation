from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / ".github" / "scripts" / "security_owner_review.py"
SCRIPT_DIR = SCRIPT.parent


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("security_owner_review_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(SCRIPT_DIR))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(SCRIPT_DIR))
    return module


review = _load()
PR_NUMBER = 341
HEAD = "a" * 40
BASE = "b" * 40
MERGE = "c" * 40
RUN_ID = 77701
STATUS_ID = 77702
GATE_STATUS = {
    "id": STATUS_ID,
    "context": review.TRUSTED_STATUS_CONTEXT,
    "state": "success",
    "description": review.TRUSTED_STATUS_DESCRIPTION,
    "target_url": (
        f"https://github.com/{review.EXPECTED_REPOSITORY}/actions/runs/{RUN_ID}"
        f"?pr={PR_NUMBER}&base={BASE}&head={HEAD}&merge={MERGE}"
    ),
    "creator": {
        "login": review.TRUSTED_STATUS_BOT_LOGIN,
        "id": review.TRUSTED_STATUS_BOT_ID,
        "type": "Bot",
    },
}
SUBJECT = {
    "prNumber": PR_NUMBER,
    "headSha": HEAD,
    "baseSha": BASE,
    "gateStatus": GATE_STATUS,
}
BODY = review._approval_body(
    lane=review.SECURITY_AUTOHEAL_LANE,
    number=PR_NUMBER,
    head_sha=HEAD,
    base_sha=BASE,
    gate_status=GATE_STATUS,
)


def _review(
    *,
    review_id: int = 8001,
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
        "submitted_at": "2026-10-01T20:30:00Z",
        "user": {"login": login, "id": user_id, "type": "User"},
    }


class Api:
    def __init__(
        self,
        rows: list[dict[str, Any]],
        *,
        ambiguous_post: bool = False,
    ) -> None:
        self.rows = list(rows)
        self.ambiguous_post = ambiguous_post
        self.posts: list[tuple[str, dict[str, Any], str | None]] = []

    def list_all(self, path: str, *, max_pages: int = 10) -> list[dict[str, Any]]:
        assert path == f"/pulls/{PR_NUMBER}/reviews"
        assert max_pages == 2
        return list(self.rows)

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
        self.rows.append(created)
        if self.ambiguous_post:
            raise review.OwnerReviewError("simulated ambiguous owner-review POST")
        return created


@pytest.fixture(autouse=True)
def env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_REPOSITORY", review.EXPECTED_REPOSITORY)
    monkeypatch.setenv("GITHUB_TOKEN", "read-token")
    monkeypatch.setenv(review.REVIEW_TOKEN_ENV, "owner-token")


def _resolver(queue: list[dict[str, Any]] | None = None):
    subjects = list(queue or [dict(SUBJECT), dict(SUBJECT), dict(SUBJECT)])

    def resolve() -> dict[str, Any]:
        return subjects.pop(0)

    return resolve


def _wire(monkeypatch: pytest.MonkeyPatch, api: Api) -> None:
    monkeypatch.setattr(review, "GitHubApi", lambda token, repository: api)
    monkeypatch.setattr(
        review,
        "_review_token_identity",
        lambda token: {"login": "portyu9", "id": 35150859, "type": "User"},
    )


def test_existing_exact_security_owner_approval_converges_without_secret_use(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = Api([_review()])
    _wire(monkeypatch, api)
    monkeypatch.delenv(review.REVIEW_TOKEN_ENV)

    observed = review.publish_exact_owner_approval(
        lane=review.SECURITY_AUTOHEAL_LANE,
        resolver=_resolver([dict(SUBJECT)]),
    )

    assert observed["decision"] == "exact-security-owner-approval-already-present"
    assert observed["prNumber"] == PR_NUMBER
    assert api.posts == []


def test_publishes_one_exact_owner_review_with_isolated_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = Api([])
    _wire(monkeypatch, api)

    observed = review.publish_exact_owner_approval(
        lane=review.SECURITY_AUTOHEAL_LANE,
        resolver=_resolver(),
    )

    assert observed["decision"] == "exact-security-owner-approval-published"
    assert observed["reviewId"] == 8001
    assert api.posts == [
        (
            f"/pulls/{PR_NUMBER}/reviews",
            {"event": "APPROVE", "body": BODY, "commit_id": HEAD},
            "owner-token",
        )
    ]


def test_ambiguous_review_post_converges_only_from_durable_exact_review(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = Api([], ambiguous_post=True)
    _wire(monkeypatch, api)

    observed = review.publish_exact_owner_approval(
        lane=review.SECURITY_AUTOHEAL_LANE,
        resolver=_resolver(),
    )

    assert observed["decision"] == "exact-security-owner-approval-published"
    assert len(api.rows) == 1


def test_latest_manual_exact_head_owner_veto_blocks_security_approval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = Api([_review(body="manual veto", state="CHANGES_REQUESTED")])
    _wire(monkeypatch, api)

    with pytest.raises(review.OwnerReviewPolicyBlock, match="CHANGES_REQUESTED veto"):
        review.publish_exact_owner_approval(
            lane=review.SECURITY_AUTOHEAL_LANE,
            resolver=_resolver([dict(SUBJECT)]),
        )
    assert api.posts == []


def test_subject_drift_immediately_before_review_write_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = Api([])
    _wire(monkeypatch, api)
    changed = dict(SUBJECT)
    changed["headSha"] = "d" * 40

    with pytest.raises(review.OwnerReviewPolicyBlock, match="immediately before owner approval"):
        review.publish_exact_owner_approval(
            lane=review.SECURITY_AUTOHEAL_LANE,
            resolver=_resolver([dict(SUBJECT), changed]),
        )
    assert api.posts == []


def test_exact_approval_is_lane_bound_and_rejects_cross_lane_reuse() -> None:
    protected_body = review._approval_body(
        lane=review.PROTECTED_SECURITY_LANE,
        number=PR_NUMBER,
        head_sha=HEAD,
        base_sha=BASE,
        gate_status=GATE_STATUS,
    )
    assert protected_body != BODY

    api = Api([_review(body=BODY)])
    with pytest.raises(review.OwnerReviewPolicyBlock, match="not yet present"):
        review.require_exact_owner_approval(
            api,
            lane=review.PROTECTED_SECURITY_LANE,
            number=PR_NUMBER,
            head_sha=HEAD,
            base_sha=BASE,
            gate_status=GATE_STATUS,
        )


def test_gate_binding_rejects_wrong_subject_and_non_app_creator() -> None:
    wrong_subject = dict(GATE_STATUS)
    wrong_subject["target_url"] = (
        f"https://github.com/{review.EXPECTED_REPOSITORY}/actions/runs/{RUN_ID}"
        f"?pr={PR_NUMBER}&base={BASE}&head={'d' * 40}&merge={MERGE}"
    )
    with pytest.raises(review.OwnerReviewError, match="different subject"):
        review._approval_body(
            lane=review.SECURITY_AUTOHEAL_LANE,
            number=PR_NUMBER,
            head_sha=HEAD,
            base_sha=BASE,
            gate_status=wrong_subject,
        )

    spoofed = dict(GATE_STATUS)
    spoofed["creator"] = {"login": "github-actions[bot]", "id": 41898282, "type": "Bot"}
    with pytest.raises(review.OwnerReviewError, match="App-owned success"):
        review._gate_evidence(spoofed)
