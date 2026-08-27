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
    merge_sha: str = MERGE_SHA,
    state: str = "open",
    base_ref: str = "main",
    mergeable: bool | None = True,
) -> dict[str, Any]:
    return {
        "number": 43,
        "state": state,
        "head": {"sha": head_sha},
        "base": {"ref": base_ref, "sha": base_sha},
        "merge_commit_sha": merge_sha,
        "mergeable": mergeable,
    }


class FakeApi:
    current_payload: Mapping[str, Any] = _pull_request_payload()
    instances: ClassVar[list[FakeApi]] = []

    def __init__(self, *, repository: str, token: str) -> None:
        self.repository = repository
        self.token = token
        self.statuses: list[dict[str, str]] = []
        type(self).instances.append(self)

    def fetch_pull_request(self, number: int) -> Mapping[str, Any]:
        assert number == 43
        return type(self).current_payload

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
    workflow_event: str = "workflow_dispatch",
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


def test_subject_requires_open_main_definitively_mergeable_exact_subject() -> None:
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


def test_report_requires_workflow_dispatch_before_api_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(control, "GitHubApi", FakeApi)
    with pytest.raises(PermissionError, match="workflow_dispatch"):
        control.report_authorized_result(
            repository=REPOSITORY,
            token="token",
            actor="portyu9",
            repository_owner="portyu9",
            workflow_event="pull_request",
            workflow_ref="refs/heads/main",
            expected=_subject(),
            authorized=True,
            job_results={"validation": "success"},
            target_url=RUN_URL,
        )
    assert FakeApi.instances == []


def test_report_requires_main_ref_before_api_access(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(control, "GitHubApi", FakeApi)
    with pytest.raises(PermissionError, match="refs/heads/main"):
        control.report_authorized_result(
            repository=REPOSITORY,
            token="token",
            actor="portyu9",
            repository_owner="portyu9",
            workflow_event="workflow_dispatch",
            workflow_ref="refs/heads/feature",
            expected=_subject(),
            authorized=True,
            job_results={"validation": "success"},
            target_url=RUN_URL,
        )
    assert FakeApi.instances == []


def test_non_owner_cannot_report_even_diagnostic(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(control, "GitHubApi", FakeApi)
    with pytest.raises(PermissionError, match="repository owner"):
        control.report_authorized_result(
            repository=REPOSITORY,
            token="token",
            actor="contributor",
            repository_owner="portyu9",
            workflow_event="workflow_dispatch",
            workflow_ref="refs/heads/main",
            expected=_subject(),
            authorized=False,
            job_results={"validation": "success"},
            target_url=RUN_URL,
        )
    assert FakeApi.instances == []


def test_diagnostic_owner_run_refetches_subject_without_posting_status(
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
    assert len(FakeApi.instances) == 1
    assert FakeApi.instances[0].statuses == []


def test_owner_authorized_success_posts_exact_current_head_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _report(monkeypatch)

    assert result == {
        "result": "SUCCESS",
        "status_posted": True,
        "status_context": "Trusted PR Gate",
        "status_subject": HEAD_SHA,
        "validation_result": "success",
    }
    assert FakeApi.instances[0].statuses == [
        {
            "sha": HEAD_SHA,
            "state": "success",
            "description": "Owner-authorized exact-subject validation passed",
            "target_url": RUN_URL,
        }
    ]


def test_stale_subject_cannot_post_status(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeApi.current_payload = _pull_request_payload(merge_sha=OTHER_SHA)
    monkeypatch.setattr(control, "GitHubApi", FakeApi)

    with pytest.raises(ValueError, match="subject changed after authorization"):
        control.report_authorized_result(
            repository=REPOSITORY,
            token="token",
            actor="portyu9",
            repository_owner="portyu9",
            workflow_event="workflow_dispatch",
            workflow_ref="refs/heads/main",
            expected=_subject(),
            authorized=True,
            job_results={"validation": "success"},
            target_url=RUN_URL,
        )
    assert FakeApi.instances[0].statuses == []


def test_owner_authorized_failed_validation_posts_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    result = _report(monkeypatch, job_result="cancelled")

    assert result["result"] == "FAILURE"
    assert result["validation_result"] == "cancelled"
    assert FakeApi.instances[0].statuses[0]["state"] == "failure"


def test_direct_report_rejects_unknown_validation_result(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(control, "GitHubApi", FakeApi)
    with pytest.raises(ValueError, match="invalid terminal result"):
        control.report_authorized_result(
            repository=REPOSITORY,
            token="token",
            actor="portyu9",
            repository_owner="portyu9",
            workflow_event="workflow_dispatch",
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
    monkeypatch.setenv("GITHUB_EVENT_NAME", "workflow_dispatch")
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
