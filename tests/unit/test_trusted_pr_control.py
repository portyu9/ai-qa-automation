from __future__ import annotations

import sys
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
    instances: ClassVar[list[FakeApi]] = []

    def __init__(self, *, repository: str, token: str) -> None:
        self.repository = repository
        self.token = token
        self.statuses: list[dict[str, str]] = []
        self.pr_fetch_count = 0
        self.merge_ref_fetch_count = 0
        self.merge_commit_fetch_count = 0
        type(self).instances.append(self)

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

    def post_status(
        self,
        *,
        sha: str,
        state: str,
        description: str,
        target_url: str,
    ) -> None:
        self.statuses.append(
            {
                "sha": sha,
                "state": state,
                "description": description,
                "target_url": target_url,
            }
        )


@pytest.fixture(autouse=True)
def _reset_fake_api() -> None:
    FakeApi.current_payload = _pull_request_payload()
    FakeApi.payload_sequence = []
    FakeApi.merge_ref_payload = _merge_ref_payload()
    FakeApi.merge_ref_sequence = []
    FakeApi.merge_commit_payload = _merge_commit_payload()
    FakeApi.instances = []


def _subject() -> control.PullRequestSubject:
    return control.PullRequestSubject(
        number=43,
        head_sha=HEAD_SHA,
        base_sha=BASE_SHA,
        merge_sha=MERGE_SHA,
    )


def _report(
    monkeypatch: pytest.MonkeyPatch,
    *,
    actor: str = "portyu9",
    repository_owner: str = "portyu9",
    workflow_event: str = "repository_dispatch",
    workflow_ref: str = "refs/heads/main",
    authorized: bool = True,
    job_result: str = "success",
) -> dict[str, Any]:
    monkeypatch.setattr(control, "GitHubApi", FakeApi)
    return control.report_authorized_result(
        repository=REPOSITORY,
        token="token",
        actor=actor,
        repository_owner=repository_owner,
        workflow_event=workflow_event,
        workflow_ref=workflow_ref,
        expected=_subject(),
        authorized=authorized,
        job_results={"validation": job_result},
        target_url=RUN_URL,
    )


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


@pytest.mark.parametrize(
    ("workflow_event", "workflow_ref", "actor", "match"),
    [
        ("pull_request", "refs/heads/main", "portyu9", "repository_dispatch"),
        ("repository_dispatch", "refs/heads/feature", "portyu9", "refs/heads/main"),
        ("repository_dispatch", "refs/heads/main", "contributor", "repository owner"),
    ],
)
def test_report_admission_denies_before_api_access(
    monkeypatch: pytest.MonkeyPatch,
    workflow_event: str,
    workflow_ref: str,
    actor: str,
    match: str,
) -> None:
    monkeypatch.setattr(control, "GitHubApi", FakeApi)

    with pytest.raises(PermissionError, match=match):
        control.report_authorized_result(
            repository=REPOSITORY,
            token="token",
            actor=actor,
            repository_owner="portyu9",
            workflow_event=workflow_event,
            workflow_ref=workflow_ref,
            expected=_subject(),
            authorized=True,
            job_results={"validation": "success"},
            target_url=RUN_URL,
        )

    assert FakeApi.instances == []


def test_report_uses_merge_ref_when_pr_merge_fields_are_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    FakeApi.current_payload = _pull_request_payload(include_merge_fields=False)

    result = _report(monkeypatch)

    assert result["result"] == "SUCCESS"
    api = FakeApi.instances[0]
    assert api.pr_fetch_count == 2
    assert api.merge_ref_fetch_count == 2
    assert api.merge_commit_fetch_count == 1
    assert api.statuses == [
        {
            "sha": HEAD_SHA,
            "state": "success",
            "description": "Owner-authorized exact-subject validation passed",
            "target_url": RUN_URL,
        }
    ]


def test_diagnostic_owner_run_verifies_exact_subject_without_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _report(monkeypatch, authorized=False)

    assert result == {
        "result": "DIAGNOSTIC_ONLY",
        "status_posted": False,
        "subject": {
            "pr_number": "43",
            "expected_head_sha": HEAD_SHA,
            "expected_base_sha": BASE_SHA,
            "expected_merge_sha": MERGE_SHA,
        },
    }
    assert FakeApi.instances[0].statuses == []


@pytest.mark.parametrize(
    "payload",
    [
        _pull_request_payload(state="closed", include_merge_fields=False),
        _pull_request_payload(base_ref="release", include_merge_fields=False),
        _pull_request_payload(head_sha=OTHER_SHA, include_merge_fields=False),
        _pull_request_payload(base_sha=OTHER_SHA, include_merge_fields=False),
    ],
)
def test_live_pr_identity_drift_fails_before_status(
    monkeypatch: pytest.MonkeyPatch,
    payload: Mapping[str, Any],
) -> None:
    FakeApi.current_payload = payload

    with pytest.raises(ValueError):
        _report(monkeypatch)

    api = FakeApi.instances[0]
    assert api.statuses == []
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
    monkeypatch: pytest.MonkeyPatch,
    payload: Mapping[str, Any],
    match: str,
) -> None:
    FakeApi.merge_ref_payload = payload

    with pytest.raises(ValueError, match=match):
        _report(monkeypatch)

    assert FakeApi.instances[0].statuses == []


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
    monkeypatch: pytest.MonkeyPatch,
    payload: Mapping[str, Any],
    match: str,
) -> None:
    FakeApi.merge_commit_payload = payload

    with pytest.raises(ValueError, match=match):
        _report(monkeypatch)

    assert FakeApi.instances[0].statuses == []


def test_identity_drift_after_merge_verification_fails_before_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    FakeApi.payload_sequence = [
        _pull_request_payload(include_merge_fields=False),
        _pull_request_payload(head_sha=OTHER_SHA, include_merge_fields=False),
    ]

    with pytest.raises(ValueError, match="subject changed after authorization"):
        _report(monkeypatch)

    assert FakeApi.instances[0].statuses == []


def test_merge_ref_drift_immediately_before_status_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    FakeApi.merge_ref_sequence = [
        _merge_ref_payload(),
        _merge_ref_payload(sha=OTHER_SHA),
    ]

    with pytest.raises(ValueError, match="before status publication"):
        _report(monkeypatch)

    assert FakeApi.instances[0].statuses == []


def test_owner_authorized_failed_validation_posts_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _report(monkeypatch, job_result="cancelled")

    assert result["result"] == "FAILURE"
    assert result["validation_result"] == "cancelled"
    assert FakeApi.instances[0].statuses[0]["state"] == "failure"


def test_direct_report_rejects_unknown_validation_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(control, "GitHubApi", FakeApi)

    with pytest.raises(ValueError, match="invalid terminal result"):
        control.report_authorized_result(
            repository=REPOSITORY,
            token="token",
            actor="portyu9",
            repository_owner="portyu9",
            workflow_event="repository_dispatch",
            workflow_ref="refs/heads/main",
            expected=_subject(),
            authorized=True,
            job_results={"validation": "green"},
            target_url=RUN_URL,
        )

    assert FakeApi.instances[0].statuses == []


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


def test_main_exits_nonzero_after_publishing_failure(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        control,
        "report_authorized_result",
        lambda **_kwargs: {"result": "FAILURE", "status_posted": True},
    )
    monkeypatch.setenv("GITHUB_REPOSITORY", REPOSITORY)
    monkeypatch.setenv("GITHUB_TOKEN", "token")
    monkeypatch.setenv("GITHUB_ACTOR", "portyu9")
    monkeypatch.setenv("GITHUB_REPOSITORY_OWNER", "portyu9")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "repository_dispatch")
    monkeypatch.setenv("GITHUB_REF", "refs/heads/main")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "trusted_pr_control.py",
            "--pr-number",
            "43",
            "--expected-head-sha",
            HEAD_SHA,
            "--expected-base-sha",
            BASE_SHA,
            "--expected-merge-sha",
            MERGE_SHA,
            "--authorized",
            "true",
            "--job-results-json",
            '{"validation":"failure"}',
            "--target-url",
            RUN_URL,
        ],
    )

    with pytest.raises(SystemExit) as exc_info:
        control.main()

    assert exc_info.value.code == 1
    assert '"result": "FAILURE"' in capsys.readouterr().out
