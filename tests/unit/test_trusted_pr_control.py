from __future__ import annotations

from collections.abc import Mapping
from typing import Any, ClassVar

import pytest

from scripts import trusted_pr_control as control

HEAD_SHA = "1" * 40
BASE_SHA = "2" * 40
MERGE_SHA = "3" * 40
OTHER_SHA = "4" * 40
REPOSITORY = "portyu9/ai-qa-automation"
RUN_URL = f"https://github.com/{REPOSITORY}/actions/runs/123"


def _pull_request_payload(
    *,
    head_sha: str = HEAD_SHA,
    base_sha: str = BASE_SHA,
    merge_sha: str | None = MERGE_SHA,
    state: str = "open",
    base_ref: str = "main",
    mergeable: bool | None = True,
    include_merge_fields: bool = True,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "number": 43,
        "state": state,
        "head": {"sha": head_sha},
        "base": {"ref": base_ref, "sha": base_sha},
    }
    if include_merge_fields:
        payload["merge_commit_sha"] = merge_sha
        payload["mergeable"] = mergeable
    return payload


def _merge_ref_payload(
    *,
    sha: str = MERGE_SHA,
    ref: str = "refs/pull/43/merge",
    object_type: str = "commit",
) -> dict[str, Any]:
    return {
        "ref": ref,
        "object": {
            "sha": sha,
            "type": object_type,
        },
    }


def _merge_commit_payload(
    *,
    sha: str = MERGE_SHA,
    parents: tuple[str, ...] = (BASE_SHA, HEAD_SHA),
) -> dict[str, Any]:
    return {
        "sha": sha,
        "parents": [{"sha": parent} for parent in parents],
        "tree": {"sha": "5" * 40},
    }


class FakeApi:
    current_payload: ClassVar[Mapping[str, Any]] = _pull_request_payload()
    payload_sequence: ClassVar[list[Mapping[str, Any]]] = []
    merge_ref_payload: ClassVar[Mapping[str, Any]] = _merge_ref_payload()
    merge_ref_sequence: ClassVar[list[Mapping[str, Any]]] = []
    merge_commit_payload: ClassVar[Mapping[str, Any]] = _merge_commit_payload()

    def __init__(self) -> None:
        self.pr_fetch_count = 0
        self.merge_ref_fetch_count = 0
        self.merge_commit_fetch_count = 0

    def fetch_pull_request(self, number: int) -> Mapping[str, Any]:
        assert number == 43
        self.pr_fetch_count += 1
        if type(self).payload_sequence:
            return type(self).payload_sequence.pop(0)
        return type(self).current_payload

    def fetch_pull_request_merge_ref(self, number: int) -> Mapping[str, Any]:
        assert number == 43
        self.merge_ref_fetch_count += 1
        if type(self).merge_ref_sequence:
            return type(self).merge_ref_sequence.pop(0)
        return type(self).merge_ref_payload

    def fetch_git_commit(self, sha: str) -> Mapping[str, Any]:
        assert sha == MERGE_SHA
        self.merge_commit_fetch_count += 1
        return type(self).merge_commit_payload


@pytest.fixture(autouse=True)
def _reset_fake_api() -> None:
    FakeApi.current_payload = _pull_request_payload()
    FakeApi.payload_sequence = []
    FakeApi.merge_ref_payload = _merge_ref_payload()
    FakeApi.merge_ref_sequence = []
    FakeApi.merge_commit_payload = _merge_commit_payload()


def _subject() -> control.PullRequestSubject:
    return control.PullRequestSubject(
        number=43,
        head_sha=HEAD_SHA,
        base_sha=BASE_SHA,
        merge_sha=MERGE_SHA,
    )


def _resolve() -> tuple[control.PullRequestSubject, FakeApi]:
    api = FakeApi()
    return control.resolve_current_subject(api, _subject()), api


def test_complete_pr_parser_remains_strict() -> None:
    assert control.subject_from_pull_request(_pull_request_payload()) == _subject()

    with pytest.raises(ValueError, match="remain open"):
        control.subject_from_pull_request(_pull_request_payload(state="closed"))
    with pytest.raises(ValueError, match="target 'main'"):
        control.subject_from_pull_request(_pull_request_payload(base_ref="release"))
    with pytest.raises(ValueError, match="definitively mergeable"):
        control.subject_from_pull_request(_pull_request_payload(mergeable=False))
    with pytest.raises(ValueError, match="definitively mergeable"):
        control.subject_from_pull_request(_pull_request_payload(mergeable=None))
    with pytest.raises(ValueError, match="merge SHA"):
        control.subject_from_pull_request(_pull_request_payload(merge_sha="short"))


def test_shared_resolver_uses_merge_ref_when_pr_merge_fields_are_absent() -> None:
    FakeApi.current_payload = _pull_request_payload(include_merge_fields=False)

    resolved, api = _resolve()

    assert resolved == _subject()
    assert api.pr_fetch_count == 2
    assert api.merge_ref_fetch_count == 2
    assert api.merge_commit_fetch_count == 1


@pytest.mark.parametrize(
    "payload",
    [
        _pull_request_payload(state="closed", include_merge_fields=False),
        _pull_request_payload(base_ref="release", include_merge_fields=False),
        _pull_request_payload(head_sha=OTHER_SHA, include_merge_fields=False),
        _pull_request_payload(base_sha=OTHER_SHA, include_merge_fields=False),
    ],
)
def test_live_pr_identity_drift_fails_closed(payload: Mapping[str, Any]) -> None:
    FakeApi.current_payload = payload
    api = FakeApi()

    with pytest.raises(ValueError):
        control.resolve_current_subject(api, _subject())

    assert api.merge_ref_fetch_count == 0


@pytest.mark.parametrize(
    ("payload", "match"),
    [
        (_merge_ref_payload(sha=OTHER_SHA), "merge ref changed"),
        (_merge_ref_payload(ref="refs/pull/43/head"), "merge ref must be exactly"),
        (_merge_ref_payload(object_type="tag"), "must point to a commit"),
        (_merge_ref_payload(sha="short"), "merge-ref SHA"),
    ],
)
def test_merge_ref_mismatch_or_malformed_fails_closed(
    payload: Mapping[str, Any],
    match: str,
) -> None:
    FakeApi.merge_ref_payload = payload

    with pytest.raises(ValueError, match=match):
        _resolve()


@pytest.mark.parametrize(
    ("payload", "match"),
    [
        (_merge_commit_payload(sha=OTHER_SHA), "merge commit changed"),
        (_merge_commit_payload(parents=(HEAD_SHA, BASE_SHA)), "parents changed"),
        (_merge_commit_payload(parents=(BASE_SHA,)), "exactly two parents"),
        (_merge_commit_payload(parents=(BASE_SHA, HEAD_SHA, OTHER_SHA)), "exactly two parents"),
    ],
)
def test_merge_commit_identity_is_bound_to_expected_parents(
    payload: Mapping[str, Any],
    match: str,
) -> None:
    FakeApi.merge_commit_payload = payload

    with pytest.raises(ValueError, match=match):
        _resolve()


def test_identity_drift_after_merge_verification_fails_closed() -> None:
    FakeApi.payload_sequence = [
        _pull_request_payload(include_merge_fields=False),
        _pull_request_payload(head_sha=OTHER_SHA, include_merge_fields=False),
    ]

    with pytest.raises(ValueError, match="subject changed after authorization"):
        _resolve()


def test_merge_ref_drift_immediately_before_status_boundary_fails_closed() -> None:
    FakeApi.merge_ref_sequence = [
        _merge_ref_payload(),
        _merge_ref_payload(sha=OTHER_SHA),
    ]

    with pytest.raises(ValueError, match="before status publication"):
        _resolve()


def test_job_result_contract_rejects_extra_or_unknown_results() -> None:
    assert control.parse_job_results('{"validation":"success"}') == {"validation": "success"}
    with pytest.raises(ValueError, match="exactly"):
        control.parse_job_results('{"validation":"success","other":"success"}')
    with pytest.raises(ValueError, match="invalid terminal result"):
        control.parse_job_results('{"validation":"green"}')


def test_status_target_url_must_be_exact_repository_run_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = control.GitHubApi(repository=REPOSITORY, token="token")
    monkeypatch.setattr(api, "post_json", lambda *_args, **_kwargs: None)

    api.post_status(
        sha=HEAD_SHA,
        state="success",
        description="ok",
        target_url=RUN_URL,
    )
    for invalid in (
        "https://example.com/forged",
        f"{RUN_URL}/extra",
        f"https://github.com/{REPOSITORY}/actions/runs/0",
        f"https://github.com/{REPOSITORY}/actions/runs/not-a-number",
    ):
        with pytest.raises(ValueError, match="one workflow run"):
            api.post_status(
                sha=HEAD_SHA,
                state="success",
                description="ok",
                target_url=invalid,
            )


def test_legacy_repository_dispatch_reporter_api_is_removed() -> None:
    assert not hasattr(control, "EXPECTED_WORKFLOW_EVENT")
    assert not hasattr(control, "report_authorized_result")
    assert not hasattr(control, "_parser")
    assert not hasattr(control, "main")
