from __future__ import annotations

import importlib.util
import sys
from copy import deepcopy
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

import scripts.auto_trusted_preflight as preflight

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / ".github" / "scripts" / "security_autoheal.py"
SCRIPT_DIR = SCRIPT.parent


def _load_autoheal() -> ModuleType:
    spec = importlib.util.spec_from_file_location("security_autoheal_trusted_wake_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(SCRIPT_DIR))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(SCRIPT_DIR))
    return module


autoheal = _load_autoheal()
HEAD = "1" * 40
BASE = "2" * 40
RUN_ID = 42
PR_NUMBER = 65
CONFIG = {
    "repository": "portyu9/ai-qa-automation",
    "baseBranch": "main",
}


def _repair_pr() -> dict[str, Any]:
    return {
        "number": PR_NUMBER,
        "state": "open",
        "draft": False,
        "user": {
            "login": autoheal.AUTOHEAL_AUTHOR_LOGIN,
            "id": autoheal.AUTOHEAL_AUTHOR_USER_ID,
            "type": "Bot",
        },
        "head": {
            "ref": f"automation/codeql-autoheal-9-{'a' * 64}-a1",
            "sha": HEAD,
            "repo": {"full_name": CONFIG["repository"]},
        },
        "base": {
            "ref": "main",
            "sha": BASE,
            "repo": {"full_name": CONFIG["repository"]},
        },
        "body": autoheal._marker(
            {
                "version": 1,
                "alert": 9,
                "head": HEAD,
                "base": BASE,
            }
        ),
    }


def _source_run(
    run_id: int = RUN_ID,
    *,
    run_attempt: int = 1,
    status: str = "in_progress",
    conclusion: str | None = None,
    event: str = "workflow_run",
) -> dict[str, Any]:
    return {
        "id": run_id,
        "run_attempt": run_attempt,
        "workflow_id": autoheal.SECURITY_AUTOHEAL_WORKFLOW_ID,
        "name": autoheal.SECURITY_AUTOHEAL_WORKFLOW_NAME,
        "path": autoheal.SECURITY_AUTOHEAL_WORKFLOW_PATH,
        "event": event,
        "head_branch": "main",
        "head_sha": BASE,
        "status": status,
        "conclusion": conclusion,
        "repository": {"full_name": CONFIG["repository"]},
        "head_repository": {"full_name": CONFIG["repository"]},
    }


def _wake_check(
    run_id: int = RUN_ID,
    *,
    run_attempt: int = 1,
    check_id: int = 77,
) -> dict[str, Any]:
    return {
        "id": check_id,
        "name": autoheal.SECURITY_QUALIFICATION_WAKE_CHECK,
        "head_sha": HEAD,
        "external_id": (
            f"{autoheal.SECURITY_QUALIFICATION_WAKE_PREFIX}:{HEAD}:{BASE}:"
            f"trusted-gate:{run_id}:{run_attempt}"
        ),
        "status": "completed",
        "conclusion": "neutral",
        "details_url": f"https://github.com/{CONFIG['repository']}/actions/runs/{run_id}",
        "app": {
            "id": autoheal.GITHUB_ACTIONS_APP_ID,
            "slug": autoheal.GITHUB_ACTIONS_APP_SLUG,
        },
    }


class WakeProducerAPI:
    def __init__(
        self,
        *,
        checks: list[dict[str, Any]] | None = None,
        source_runs: dict[int, dict[str, Any]] | None = None,
    ) -> None:
        self.checks = [] if checks is None else deepcopy(checks)
        self.source_runs = {RUN_ID: _source_run()} if source_runs is None else deepcopy(source_runs)
        self.posts: list[tuple[str, dict[str, Any]]] = []

    def get(self, path: str) -> Any:
        if path == f"/pulls/{PR_NUMBER}":
            return _repair_pr()
        if path == "/branches/main":
            return {"commit": {"sha": BASE}}
        if path.startswith("/actions/runs/"):
            run_id = int(path.rsplit("/", 1)[1])
            return deepcopy(self.source_runs[run_id])
        raise AssertionError(f"unexpected GET: {path}")

    def list_all(
        self,
        path: str,
        *,
        max_pages: int = 10,
        max_items: int | None = None,
    ) -> list[dict[str, Any]]:
        assert path == f"/commits/{HEAD}/check-runs?filter=all"
        assert max_pages == 2
        assert max_items is None
        return deepcopy(self.checks)

    def post(
        self,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        token: str | None = None,
    ) -> dict[str, Any]:
        assert path == "/check-runs"
        assert payload is not None
        assert token is None
        self.posts.append((path, deepcopy(payload)))
        return {
            "id": 88,
            **payload,
            "details_url": payload["details_url"],
            "app": {
                "id": autoheal.GITHUB_ACTIONS_APP_ID,
                "slug": autoheal.GITHUB_ACTIONS_APP_SLUG,
            },
        }


def test_security_autoheal_publishes_non_authoritative_exact_run_wake(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GITHUB_RUN_ID", str(RUN_ID))
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    api = WakeProducerAPI()

    autoheal._ensure_security_qualification_wake(api, PR_NUMBER, CONFIG)

    assert len(api.posts) == 1
    payload = api.posts[0][1]
    assert payload["name"] == autoheal.SECURITY_QUALIFICATION_WAKE_CHECK
    assert payload["head_sha"] == HEAD
    assert payload["status"] == "completed"
    assert payload["conclusion"] == "neutral"
    assert payload["external_id"] == (
        f"{autoheal.SECURITY_QUALIFICATION_WAKE_PREFIX}:{HEAD}:{BASE}:trusted-gate:{RUN_ID}:1"
    )
    assert "not validation authority" in payload["output"]["summary"]
    assert "owner approval" in payload["output"]["summary"]


def test_successful_prior_security_wake_is_idempotent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GITHUB_RUN_ID", str(RUN_ID))
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    api = WakeProducerAPI(
        checks=[_wake_check()],
        source_runs={
            RUN_ID: _source_run(status="completed", conclusion="success"),
        },
    )

    autoheal._ensure_security_qualification_wake(api, PR_NUMBER, CONFIG)

    assert api.posts == []


def test_current_in_progress_security_wake_is_idempotent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GITHUB_RUN_ID", str(RUN_ID))
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    api = WakeProducerAPI(checks=[_wake_check()])

    autoheal._ensure_security_qualification_wake(api, PR_NUMBER, CONFIG)

    assert api.posts == []


def test_prior_successful_security_wake_does_not_suppress_current_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prior_run_id = RUN_ID - 1
    monkeypatch.setenv("GITHUB_RUN_ID", str(RUN_ID))
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    api = WakeProducerAPI(
        checks=[_wake_check(prior_run_id)],
        source_runs={
            prior_run_id: _source_run(
                prior_run_id,
                status="completed",
                conclusion="success",
            ),
            RUN_ID: _source_run(),
        },
    )

    autoheal._ensure_security_qualification_wake(api, PR_NUMBER, CONFIG)

    assert len(api.posts) == 1
    payload = api.posts[0][1]
    assert payload["external_id"].endswith(f"trusted-gate:{RUN_ID}:1")


def test_prior_attempt_wake_does_not_poison_rerun(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GITHUB_RUN_ID", str(RUN_ID))
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "2")
    api = WakeProducerAPI(
        checks=[_wake_check(run_attempt=1)],
        source_runs={RUN_ID: _source_run(run_attempt=2)},
    )

    autoheal._ensure_security_qualification_wake(api, PR_NUMBER, CONFIG)

    assert len(api.posts) == 1
    payload = api.posts[0][1]
    assert payload["external_id"].endswith(f"trusted-gate:{RUN_ID}:2")


def test_terminal_stage_ignores_stale_rerun_attempt_and_accepts_current_success() -> None:
    api = WakeProducerAPI(
        checks=[
            _wake_check(run_attempt=1, check_id=77),
            _wake_check(run_attempt=2, check_id=78),
        ],
        source_runs={
            RUN_ID: _source_run(
                run_attempt=2,
                status="completed",
                conclusion="success",
            )
        },
    )

    stage = autoheal._security_qualification_wake_stage(
        api,
        {"headSha": HEAD, "baseSha": BASE},
        CONFIG,
    )

    assert stage == "trusted-gate"


def _preflight_run(*, event: str = "workflow_run") -> dict[str, Any]:
    return {
        "id": RUN_ID,
        "run_attempt": 1,
        "workflow_id": preflight.EXPECTED_SECURITY_AUTOHEAL_WORKFLOW_ID,
        "name": preflight.EXPECTED_SECURITY_AUTOHEAL_WORKFLOW_NAME,
        "path": preflight.EXPECTED_SECURITY_AUTOHEAL_WORKFLOW_PATH,
        "event": event,
        "head_branch": "main",
        "head_sha": BASE,
        "status": "completed",
        "conclusion": "success",
        "repository": {"full_name": preflight.EXPECTED_REPOSITORY},
        "head_repository": {"full_name": preflight.EXPECTED_REPOSITORY},
        "actor": {"login": "portyu9", "id": preflight.EXPECTED_OWNER_ID},
        "triggering_actor": {"login": "portyu9", "id": preflight.EXPECTED_OWNER_ID},
    }


def _preflight_pr() -> dict[str, Any]:
    return {
        "number": PR_NUMBER,
        "state": "open",
        "draft": False,
        "user": {
            "login": preflight.PROTECTED_REMEDIATION_BOT_LOGIN,
            "id": preflight.PROTECTED_REMEDIATION_BOT_USER_ID,
            "type": "Bot",
        },
        "head": {
            "ref": f"automation/codeql-autoheal-9-{'a' * 64}-a1",
            "sha": HEAD,
            "repo": {"full_name": preflight.EXPECTED_REPOSITORY},
        },
        "base": {
            "ref": "main",
            "sha": BASE,
            "repo": {"full_name": preflight.EXPECTED_REPOSITORY},
        },
    }


class PreflightWakeAPI:
    def __init__(self, *, conclusion: str = "neutral") -> None:
        self.pr = _preflight_pr()
        self.check = {
            "id": 91,
            "name": preflight.SECURITY_AUTOHEAL_WAKE_CHECK,
            "head_sha": HEAD,
            "external_id": (
                f"{preflight.SECURITY_AUTOHEAL_WAKE_PREFIX}:{HEAD}:{BASE}:trusted-gate:{RUN_ID}:1"
            ),
            "status": "completed",
            "conclusion": conclusion,
            "details_url": (
                f"https://github.com/{preflight.EXPECTED_REPOSITORY}/actions/runs/{RUN_ID}"
            ),
            "app": {"id": preflight.GITHUB_ACTIONS_APP_ID, "slug": "github-actions"},
        }

    def list_all(
        self,
        path: str,
        *,
        max_pages: int = preflight.MAX_API_PAGES,
    ) -> list[dict[str, Any]]:
        pulls_path = (
            f"/repos/{preflight.EXPECTED_REPOSITORY}/pulls"
            f"?state=open&base={preflight.EXPECTED_DEFAULT_BRANCH}"
        )
        if path == pulls_path:
            assert max_pages == 1
            return [deepcopy(self.pr)]
        checks_path = f"/repos/{preflight.EXPECTED_REPOSITORY}/commits/{HEAD}/check-runs?filter=all"
        if path == checks_path:
            assert max_pages == 2
            return [deepcopy(self.check)]
        raise AssertionError(f"unexpected list path: {path}")


@pytest.mark.parametrize("event", ["workflow_run", "schedule", "workflow_dispatch"])
def test_security_autoheal_successful_trusted_main_run_is_valid_liveness_wake(
    event: str,
) -> None:
    wake = preflight._validate_wake(
        _preflight_run(event=event),
        expected_run_id=RUN_ID,
        trusted_sha=BASE,
    )

    assert wake is not None
    assert wake.kind == "security-autoheal-controller"
    assert wake.head_sha == BASE


def test_security_wake_selects_only_exact_neutral_bound_repair() -> None:
    wake = preflight._validate_wake(
        _preflight_run(),
        expected_run_id=RUN_ID,
        trusted_sha=BASE,
    )
    assert wake is not None

    selected = preflight._select_security_autoheal_pull_request(
        PreflightWakeAPI(),
        wake=wake,
        trusted_sha=BASE,
    )

    assert selected is not None
    assert selected["number"] == PR_NUMBER
    assert selected["head"]["sha"] == HEAD


def test_security_wake_check_cannot_be_promoted_to_validation_authority() -> None:
    wake = preflight._validate_wake(
        _preflight_run(),
        expected_run_id=RUN_ID,
        trusted_sha=BASE,
    )
    assert wake is not None

    assert (
        preflight._select_security_autoheal_pull_request(
            PreflightWakeAPI(conclusion="success"),
            wake=wake,
            trusted_sha=BASE,
        )
        is None
    )
