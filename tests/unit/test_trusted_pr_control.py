from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

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


def _event_payload(
    *,
    action: str = "synchronize",
    repository: str = REPOSITORY,
) -> dict[str, Any]:
    pull_request = _pull_request_payload(merge_sha="not-yet-materialized", mergeable=None)
    return {
        "action": action,
        "repository": {"full_name": repository},
        "pull_request": pull_request,
    }


class FakeApi:
    current_payload: Mapping[str, Any] = _pull_request_payload()
    instances: list[FakeApi] = []

    def __init__(self, *, repository: str, token: str) -> None:
        self.repository = repository
        self.token = token
        self.dispatched: list[control.PullRequestSubject] = []
        self.statuses: list[dict[str, str]] = []
        type(self).instances.append(self)

    def fetch_pull_request(self, number: int) -> Mapping[str, Any]:
        assert number == 43
        return type(self).current_payload

    def dispatch_validation(self, subject: control.PullRequestSubject) -> None:
        self.dispatched.append(subject)

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


def test_subject_requires_open_main_mergeable_exact_subject() -> None:
    assert control.subject_from_pull_request(_pull_request_payload()) == _subject()

    with pytest.raises(ValueError, match="remain open"):
        control.subject_from_pull_request(_pull_request_payload(state="closed"))
    with pytest.raises(ValueError, match="target 'main'"):
        control.subject_from_pull_request(_pull_request_payload(base_ref="release"))
    with pytest.raises(ValueError, match="not mergeable"):
        control.subject_from_pull_request(_pull_request_payload(mergeable=False))
    with pytest.raises(ValueError, match="merge SHA"):
        control.subject_from_pull_request(_pull_request_payload(merge_sha="short"))


def test_target_event_does_not_trust_event_merge_subject() -> None:
    repository, identity = control.subject_from_target_event(_event_payload())
    assert repository == REPOSITORY
    assert identity == control.PullRequestEventIdentity(
        number=43,
        head_sha=HEAD_SHA,
        base_sha=BASE_SHA,
    )


def test_target_event_rejects_unreviewed_action() -> None:
    with pytest.raises(ValueError, match="unsupported pull_request_target action"):
        control.subject_from_target_event(_event_payload(action="closed"))


def test_bounded_event_ingestion_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text(json.dumps(_event_payload()), encoding="utf-8")
    link = tmp_path / "event.json"
    link.symlink_to(target)

    with pytest.raises(ValueError, match="open trusted event payload safely"):
        control._read_json_file_bounded(link, max_bytes=control.MAX_EVENT_BYTES)


def test_bounded_event_ingestion_enforces_limit(tmp_path: Path) -> None:
    event_path = tmp_path / "event.json"
    event_path.write_bytes(b"{" + b" " * 32 + b"}")

    with pytest.raises(ValueError, match="ingestion limit"):
        control._read_json_file_bounded(event_path, max_bytes=8)


def test_dispatch_refetches_current_subject_before_main_ref_dispatch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    event_path = tmp_path / "event.json"
    event_path.write_text(json.dumps(_event_payload()), encoding="utf-8")
    monkeypatch.setattr(control, "GitHubApi", FakeApi)

    result = control.dispatch_from_event(
        event_path=event_path,
        token="token",
        expected_repository=REPOSITORY,
    )

    assert result["result"] == "DISPATCHED"
    assert result["ref"] == "main"
    assert result["workflow"] == "trusted-pr-validation.yml"
    assert result["subject"] == _subject().as_dispatch_inputs(authorized=False)
    assert len(FakeApi.instances) == 1
    assert FakeApi.instances[0].dispatched == [_subject()]


def test_dispatch_rejects_event_repository_mismatch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    event_path = tmp_path / "event.json"
    event_path.write_text(
        json.dumps(_event_payload(repository="attacker/other-repo")),
        encoding="utf-8",
    )
    monkeypatch.setattr(control, "GitHubApi", FakeApi)

    with pytest.raises(ValueError, match="does not match trusted GITHUB_REPOSITORY"):
        control.dispatch_from_event(
            event_path=event_path,
            token="token",
            expected_repository=REPOSITORY,
        )

    assert FakeApi.instances == []


def test_dispatch_rejects_event_to_api_head_race(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    event_path = tmp_path / "event.json"
    event_path.write_text(json.dumps(_event_payload()), encoding="utf-8")
    FakeApi.current_payload = _pull_request_payload(head_sha=OTHER_SHA)
    monkeypatch.setattr(control, "GitHubApi", FakeApi)

    with pytest.raises(ValueError, match="changed between event delivery and dispatch"):
        control.dispatch_from_event(
            event_path=event_path,
            token="token",
            expected_repository=REPOSITORY,
        )

    assert FakeApi.instances[0].dispatched == []


def test_actual_dispatch_method_pins_workflow_and_main_ref(monkeypatch: pytest.MonkeyPatch) -> None:
    api = control.GitHubApi(repository=REPOSITORY, token="token")
    observed: dict[str, Any] = {}

    def _post_json(path: str, payload: Mapping[str, Any]) -> None:
        observed["path"] = path
        observed["payload"] = payload

    monkeypatch.setattr(api, "post_json", _post_json)
    api.dispatch_validation(_subject())

    assert observed == {
        "path": f"/repos/{REPOSITORY}/actions/workflows/trusted-pr-validation.yml/dispatches",
        "payload": {
            "ref": "main",
            "inputs": _subject().as_dispatch_inputs(authorized=False),
        },
    }


def test_diagnostic_run_never_posts_merge_status(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(control, "GitHubApi", FakeApi)

    result = control.report_authorized_result(
        repository=REPOSITORY,
        token="token",
        actor="attacker",
        repository_owner="portyu9",
        expected=_subject(),
        authorized=False,
        job_results={"validation": "success"},
        target_url=RUN_URL,
    )

    assert result["result"] == "DIAGNOSTIC_ONLY"
    assert result["status_posted"] is False
    assert FakeApi.instances[0].statuses == []


def test_owner_authorized_success_posts_exact_head_status(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(control, "GitHubApi", FakeApi)

    result = control.report_authorized_result(
        repository=REPOSITORY,
        token="token",
        actor="portyu9",
        repository_owner="portyu9",
        expected=_subject(),
        authorized=True,
        job_results={"validation": "success"},
        target_url=RUN_URL,
    )

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


def test_non_owner_cannot_authorize_status(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(control, "GitHubApi", FakeApi)

    with pytest.raises(PermissionError, match="repository owner"):
        control.report_authorized_result(
            repository=REPOSITORY,
            token="token",
            actor="contributor",
            repository_owner="portyu9",
            expected=_subject(),
            authorized=True,
            job_results={"validation": "success"},
            target_url=RUN_URL,
        )

    assert FakeApi.instances[0].statuses == []


def test_stale_subject_cannot_post_status(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeApi.current_payload = _pull_request_payload(merge_sha=OTHER_SHA)
    monkeypatch.setattr(control, "GitHubApi", FakeApi)

    with pytest.raises(ValueError, match="subject changed after authorization"):
        control.report_authorized_result(
            repository=REPOSITORY,
            token="token",
            actor="portyu9",
            repository_owner="portyu9",
            expected=_subject(),
            authorized=True,
            job_results={"validation": "success"},
            target_url=RUN_URL,
        )

    assert FakeApi.instances[0].statuses == []


def test_owner_authorized_failed_validation_posts_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(control, "GitHubApi", FakeApi)

    result = control.report_authorized_result(
        repository=REPOSITORY,
        token="token",
        actor="portyu9",
        repository_owner="portyu9",
        expected=_subject(),
        authorized=True,
        job_results={"validation": "cancelled"},
        target_url=RUN_URL,
    )

    assert result["result"] == "FAILURE"
    assert FakeApi.instances[0].statuses[0]["state"] == "failure"


def test_direct_report_rejects_unknown_validation_result(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(control, "GitHubApi", FakeApi)

    with pytest.raises(ValueError, match="invalid terminal result"):
        control.report_authorized_result(
            repository=REPOSITORY,
            token="token",
            actor="portyu9",
            repository_owner="portyu9",
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


def test_status_target_url_is_repository_bound() -> None:
    api = control.GitHubApi(repository=REPOSITORY, token="token")
    with pytest.raises(ValueError, match="workflow run in this repository"):
        api.post_status(
            sha=HEAD_SHA,
            state="success",
            description="ok",
            target_url="https://example.com/forged",
        )
