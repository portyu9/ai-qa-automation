from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from fastapi import HTTPException

ROOT = Path(__file__).resolve().parents[2]
SECURITY_SCRIPT = ROOT / ".github" / "scripts" / "security_autoheal.py"
SCRIPT_DIR = SECURITY_SCRIPT.parent


def _load_security_autoheal() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "security_autoheal_strategy_test", SECURITY_SCRIPT
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(SCRIPT_DIR))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(SCRIPT_DIR))
    return module


autoheal = _load_security_autoheal()


def _closed_repair(metadata: dict[str, Any]) -> dict[str, Any]:
    return {
        "user": {
            "login": autoheal.GITHUB_ACTIONS_LOGIN,
            "id": autoheal.GITHUB_ACTIONS_USER_ID,
        },
        "head": {"ref": "automation/codeql-autoheal-7-abcdef123456"},
        "body": autoheal._marker(metadata),
    }


class _ClosedRepairApi:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows = rows
        self.calls: list[tuple[str, int]] = []

    def list_all(self, path: str, *, max_pages: int = 10) -> list[dict[str, Any]]:
        self.calls.append((path, max_pages))
        return self.rows


def test_reflective_xss_uses_literal_only_deterministic_strategy() -> None:
    subject = {
        "number": 7,
        "rule": "py/reflective-xss",
        "path": "examples/reference_sut/app.py",
        "line": 1,
    }

    assert autoheal._repair_strategy(subject) == autoheal.REFERENCE_SUT_REFLECTIVE_XSS_STRATEGY
    repaired = autoheal._deterministic_repair(subject)

    assert repaired is not None
    assert "\nimport json\n" not in repaired
    assert "json.dumps(safe_mode)" not in repaired
    for value in (
        "pass",
        "app-defect",
        "outdated-locator",
        "api-failure",
        "timing",
        "invalid-data",
        "prompt-injection",
    ):
        assert f"mode_js = '\"{value}\"'" in repaired
    compiled = compile(repaired, "examples/reference_sut/app.py", "exec")
    namespace: dict[str, Any] = {}
    exec(compiled, namespace)
    checkout = namespace["checkout"]
    for value in (
        "pass",
        "app-defect",
        "outdated-locator",
        "api-failure",
        "timing",
        "invalid-data",
        "prompt-injection",
    ):
        html = checkout(value)
        assert f'encodeURIComponent("{value}")' in html
    with pytest.raises(HTTPException) as exc_info:
        checkout('</script><script>alert("xss")</script>')
    assert exc_info.value.status_code == 400


def test_legacy_copilot_attempts_do_not_consume_new_deterministic_epoch() -> None:
    legacy = {
        "version": 1,
        "alert": 7,
        "rule": "py/reflective-xss",
        "path": "examples/reference_sut/app.py",
        "generator": "github-codeql-autofix",
    }
    api = _ClosedRepairApi([_closed_repair(legacy), _closed_repair({**legacy, "attempt": 2})])

    current_main = "f" * 40
    assert autoheal._attempt_count(api, 7, autoheal.MODEL_AUTOFIX_STRATEGY, current_main) == 2
    assert (
        autoheal._attempt_count(
            api,
            7,
            autoheal.REFERENCE_SUT_REFLECTIVE_XSS_STRATEGY,
            current_main,
        )
        == 0
    )
    assert api.calls == [
        ("/pulls?state=closed&sort=updated&direction=desc", 10),
        ("/pulls?state=closed&sort=updated&direction=desc", 10),
    ]


def test_explicit_strategy_attempt_is_counted_only_in_its_epoch() -> None:
    deterministic = {
        "version": 1,
        "alert": 7,
        "rule": "py/reflective-xss",
        "path": "examples/reference_sut/app.py",
        "generator": "deterministic",
        "strategy": autoheal.REFERENCE_SUT_REFLECTIVE_XSS_STRATEGY,
    }
    api = _ClosedRepairApi([_closed_repair(deterministic)])

    current_main = "f" * 40
    assert (
        autoheal._attempt_count(
            api,
            7,
            autoheal.REFERENCE_SUT_REFLECTIVE_XSS_STRATEGY,
            current_main,
        )
        == 1
    )
    assert autoheal._attempt_count(api, 7, autoheal.MODEL_AUTOFIX_STRATEGY, current_main) == 0


def test_strategy_binding_rejects_legacy_model_strategy_after_deterministic_upgrade() -> None:
    subject = {
        "number": 7,
        "rule": "py/reflective-xss",
        "path": "examples/reference_sut/app.py",
    }
    legacy_model = {
        "alert": 7,
        "rule": subject["rule"],
        "path": subject["path"],
        "generator": "github-codeql-autofix",
    }

    with pytest.raises(autoheal.PolicyBlock, match="strategy drifted"):
        autoheal._require_strategy_binding(legacy_model, subject)

    deterministic = {
        **legacy_model,
        "generator": "deterministic",
        "strategy": autoheal.REFERENCE_SUT_REFLECTIVE_XSS_STRATEGY,
    }
    assert (
        autoheal._require_strategy_binding(deterministic, subject)
        == autoheal.REFERENCE_SUT_REFLECTIVE_XSS_STRATEGY
    )


def test_legacy_deterministic_marker_infers_code_owned_strategy() -> None:
    metadata = {
        "alert": 9,
        "rule": "py/overly-permissive-file",
        "path": "tests/unit/test_example.py",
        "generator": "deterministic",
    }

    assert autoheal._marker_strategy(metadata) == autoheal.OVERLY_PERMISSIVE_TEST_STRATEGY


def _explicit_stale_attempt_fixture() -> tuple[dict[str, Any], dict[str, Any]]:
    metadata = {
        "version": 1,
        "alert": 7,
        "attempt": 1,
        "base": "a" * 40,
        "head": "b" * 40,
        "fingerprint": "c" * 64,
        "generator": "deterministic",
        "path": "examples/reference_sut/app.py",
        "rule": "py/reflective-xss",
        "severity": 7.0,
        "strategy": autoheal.REFERENCE_SUT_REFLECTIVE_XSS_STRATEGY,
        "supersessionReason": autoheal.STALE_SUPERSESSION_REASON,
        "supersededByMain": "f" * 40,
    }
    row = {
        "number": 101,
        "state": "closed",
        "merged_at": None,
        "closed_at": "2026-09-23T00:20:00Z",
        "user": {
            "login": autoheal.GITHUB_ACTIONS_LOGIN,
            "id": autoheal.GITHUB_ACTIONS_USER_ID,
        },
        "head": {
            "ref": "automation/codeql-autoheal-7-abcdef123456",
            "sha": metadata["head"],
        },
        "base": {"sha": metadata["base"]},
        "body": autoheal._marker(metadata),
    }
    return metadata, row


class _StaleCertificateApi:
    def __init__(
        self,
        row: dict[str, Any],
        comments: list[dict[str, Any]],
        events: list[dict[str, Any]],
    ) -> None:
        self.row = row
        self.comments = comments
        self.events = events

    def get(self, path: str) -> dict[str, Any]:
        if path != "/actions/runs/9001":
            raise AssertionError(f"unexpected GET path: {path}")
        return {
            "id": 9001,
            "workflow_id": autoheal.SECURITY_AUTOHEAL_WORKFLOW_ID,
            "path": autoheal.SECURITY_AUTOHEAL_WORKFLOW_PATH,
            "run_attempt": 1,
            "event": "schedule",
            "head_branch": "main",
            "status": "completed",
            "conclusion": "success",
        }

    def list_all(self, path: str, *, max_pages: int = 10) -> list[dict[str, Any]]:
        if path == "/pulls?state=closed&sort=updated&direction=desc":
            assert max_pages == 10
            return [self.row]
        if path == "/issues/101/comments":
            assert max_pages == 2
            return self.comments
        if path == "/issues/101/events":
            assert max_pages == 2
            return self.events
        raise AssertionError(f"unexpected API path: {path}")


def _stale_certificate_comment(
    metadata: dict[str, Any],
    *,
    login: str = autoheal.GITHUB_ACTIONS_LOGIN,
    user_id: int = autoheal.GITHUB_ACTIONS_USER_ID,
    created_at: str = "2026-09-23T00:19:59Z",
    updated_at: str = "2026-09-23T00:19:59Z",
    main_sha: str = "f" * 40,
) -> dict[str, Any]:
    certificate = autoheal._stale_supersession_certificate(
        metadata,
        101,
        main_sha,
        workflow_run_id=9001,
        workflow_run_attempt=1,
    )
    return {
        "body": autoheal._stale_supersession_comment(certificate),
        "user": {"login": login, "id": user_id},
        "created_at": created_at,
        "updated_at": updated_at,
    }


def _bot_closed_event(created_at: str = "2026-09-23T00:20:00Z") -> dict[str, Any]:
    return {
        "id": 500,
        "event": "closed",
        "created_at": created_at,
        "actor": {
            "login": autoheal.GITHUB_ACTIONS_LOGIN,
            "id": autoheal.GITHUB_ACTIONS_USER_ID,
        },
    }


def test_explicit_stale_supersession_requires_exact_unedited_bot_certificate() -> None:
    metadata, row = _explicit_stale_attempt_fixture()
    exact_api = _StaleCertificateApi(
        row,
        [_stale_certificate_comment(metadata)],
        [_bot_closed_event()],
    )
    assert (
        autoheal._attempt_count(
            exact_api,
            7,
            autoheal.REFERENCE_SUT_REFLECTIVE_XSS_STRATEGY,
            "f" * 40,
        )
        == 0
    )

    human_api = _StaleCertificateApi(
        row,
        [_stale_certificate_comment(metadata, login="portyu9", user_id=35150859)],
        [_bot_closed_event()],
    )
    assert (
        autoheal._attempt_count(
            human_api,
            7,
            autoheal.REFERENCE_SUT_REFLECTIVE_XSS_STRATEGY,
            "f" * 40,
        )
        == 1
    )

    edited_api = _StaleCertificateApi(
        row,
        [
            _stale_certificate_comment(
                metadata,
                updated_at="2026-09-23T00:20:01Z",
            )
        ],
        [_bot_closed_event()],
    )
    assert (
        autoheal._attempt_count(
            edited_api,
            7,
            autoheal.REFERENCE_SUT_REFLECTIVE_XSS_STRATEGY,
            "f" * 40,
        )
        == 1
    )


def test_stale_supersession_certificate_cannot_replay_across_reopen() -> None:
    metadata, row = _explicit_stale_attempt_fixture()
    api = _StaleCertificateApi(
        row,
        [
            _stale_certificate_comment(
                metadata,
                created_at="2026-09-23T00:19:00Z",
                updated_at="2026-09-23T00:19:00Z",
            )
        ],
        [
            {
                "id": 499,
                "event": "reopened",
                "created_at": "2026-09-23T00:19:30Z",
                "actor": {"login": "portyu9", "id": 35150859},
            },
            _bot_closed_event(),
        ],
    )
    assert (
        autoheal._attempt_count(
            api,
            7,
            autoheal.REFERENCE_SUT_REFLECTIVE_XSS_STRATEGY,
            "f" * 40,
        )
        == 1
    )


def test_stale_supersession_certificate_rejects_wrong_workflow_run() -> None:
    metadata, row = _explicit_stale_attempt_fixture()
    comment = _stale_certificate_comment(metadata)

    class _WrongWorkflowApi(_StaleCertificateApi):
        def get(self, path: str) -> dict[str, Any]:
            run = super().get(path)
            return {**run, "workflow_id": autoheal.SECURITY_AUTOHEAL_WORKFLOW_ID + 1}

    api = _WrongWorkflowApi(row, [comment], [_bot_closed_event()])
    assert (
        autoheal._attempt_count(
            api,
            7,
            autoheal.REFERENCE_SUT_REFLECTIVE_XSS_STRATEGY,
            "f" * 40,
        )
        == 1
    )


def test_stale_supersession_certificate_rejects_failed_workflow_run() -> None:
    metadata, row = _explicit_stale_attempt_fixture()
    comment = _stale_certificate_comment(metadata)

    class _FailedWorkflowApi(_StaleCertificateApi):
        def get(self, path: str) -> dict[str, Any]:
            run = super().get(path)
            return {**run, "status": "completed", "conclusion": "failure"}

    api = _FailedWorkflowApi(row, [comment], [_bot_closed_event()])
    assert (
        autoheal._attempt_count(
            api,
            7,
            autoheal.REFERENCE_SUT_REFLECTIVE_XSS_STRATEGY,
            "f" * 40,
        )
        == 1
    )


def test_stale_supersession_ignores_prior_main_certificate_but_rejects_duplicate_match() -> None:
    metadata, row = _explicit_stale_attempt_fixture()
    prior = _stale_certificate_comment(
        metadata,
        main_sha="e" * 40,
        created_at="2026-09-23T00:19:57Z",
        updated_at="2026-09-23T00:19:57Z",
    )
    current = _stale_certificate_comment(metadata)
    api = _StaleCertificateApi(row, [prior, current], [_bot_closed_event()])
    assert (
        autoheal._attempt_count(
            api,
            7,
            autoheal.REFERENCE_SUT_REFLECTIVE_XSS_STRATEGY,
            "f" * 40,
        )
        == 0
    )

    duplicate = _stale_certificate_comment(
        metadata,
        created_at="2026-09-23T00:19:58Z",
        updated_at="2026-09-23T00:19:58Z",
    )
    ambiguous = _StaleCertificateApi(
        row,
        [prior, duplicate, current],
        [_bot_closed_event()],
    )
    assert (
        autoheal._attempt_count(
            ambiguous,
            7,
            autoheal.REFERENCE_SUT_REFLECTIVE_XSS_STRATEGY,
            "f" * 40,
        )
        == 1
    )


def test_stale_certificate_recovery_posts_new_certificate_after_main_moves(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    metadata, _ = _explicit_stale_attempt_fixture()
    metadata = {
        key: value
        for key, value in metadata.items()
        if key not in {"supersessionReason", "supersededByMain"}
    }
    prior = _stale_certificate_comment(
        metadata,
        main_sha="e" * 40,
        created_at="2026-09-23T00:19:57Z",
        updated_at="2026-09-23T00:19:57Z",
    )

    class _CertificateRecoveryApi:
        def __init__(self) -> None:
            self.created: list[dict[str, Any]] = []

        def list_all(self, path: str, *, max_pages: int = 10) -> list[dict[str, Any]]:
            assert path == "/issues/101/comments"
            assert max_pages == 2
            return [prior]

        def post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
            assert path == "/issues/101/comments"
            created = {
                "body": payload["body"],
                "user": {
                    "login": autoheal.GITHUB_ACTIONS_LOGIN,
                    "id": autoheal.GITHUB_ACTIONS_USER_ID,
                },
                "created_at": "2026-09-23T00:20:00Z",
                "updated_at": "2026-09-23T00:20:00Z",
            }
            self.created.append(created)
            return created

    monkeypatch.setenv("GITHUB_RUN_ID", "9001")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    api = _CertificateRecoveryApi()
    certificate = autoheal._ensure_stale_supersession_certificate(
        api,
        101,
        metadata,
        "f" * 40,
    )
    assert certificate["supersededByMain"] == "f" * 40
    assert certificate["workflowRunId"] == 9001
    assert len(api.created) == 1
