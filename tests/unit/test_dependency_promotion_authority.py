from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / ".github" / "scripts" / "dependency_promotion.py"
SCRIPT_DIR = SCRIPT.parent


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("dependency_promotion_authority_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(SCRIPT_DIR))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(SCRIPT_DIR))
    return module


promotion = _load()
HEAD = "a" * 40
BASE = "b" * 40
SOURCE_HEAD = "c" * 40
SOURCE_BASE = "d" * 40
AUTHOR_LOGIN = "dependency-promotion-author[bot]"
AUTHOR_ID = 434343


class RecordingApi:
    def __init__(self, *, returned_login: str = AUTHOR_LOGIN, returned_id: int = AUTHOR_ID) -> None:
        self.returned_login = returned_login
        self.returned_id = returned_id
        self.calls: list[tuple[str, dict[str, Any], str | None]] = []

    def post(
        self,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        token: str | None = None,
    ) -> dict[str, Any]:
        assert payload is not None
        self.calls.append((path, payload, token))
        return {
            "number": 281,
            "user": {"login": self.returned_login, "id": self.returned_id},
            "head": {"sha": HEAD},
        }


class LiveMainApi:
    def __init__(self, sha: str) -> None:
        self.sha = sha
        self.calls: list[str] = []

    def get(self, path: str) -> dict[str, Any]:
        self.calls.append(path)
        return {"commit": {"sha": self.sha}}


def _source() -> dict[str, Any]:
    return {
        "number": 171,
        "headSha": SOURCE_HEAD,
        "sourceBaseSha": SOURCE_BASE,
        "baseSha": BASE,
        "fingerprint": "e" * 64,
    }


def _configure_author(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(promotion.PROMOTION_AUTHOR_LOGIN_ENV, AUTHOR_LOGIN)
    monkeypatch.setenv(promotion.PROMOTION_AUTHOR_ID_ENV, str(AUTHOR_ID))
    monkeypatch.setenv(promotion.PROMOTION_AUTHOR_TOKEN_ENV, "app-token")


def test_live_main_guard_accepts_only_exact_workflow_revision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GITHUB_SHA", BASE)
    api = LiveMainApi(BASE)

    assert promotion._require_exact_live_main(api, {"baseBranch": "main"}) == BASE
    assert api.calls == ["/branches/main"]


def test_live_main_guard_rejects_stale_workflow_before_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GITHUB_SHA", BASE)
    api = LiveMainApi("f" * 40)

    with pytest.raises(promotion.GovernanceError, match="stale relative to current main"):
        promotion._require_exact_live_main(api, {"baseBranch": "main"})


def test_live_main_guard_rejects_missing_workflow_sha(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GITHUB_SHA", raising=False)

    with pytest.raises(promotion.GovernanceError, match="missing or malformed"):
        promotion._require_exact_live_main(LiveMainApi(BASE), {"baseBranch": "main"})


def test_create_promotion_pr_uses_only_configured_app_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_author(monkeypatch)
    api = RecordingApi()

    number = promotion._create_promotion_pr(
        api,
        _source(),
        "automation/dependency-promotion-171-abcdef123456",
        HEAD,
    )

    assert number == 281
    assert len(api.calls) == 1
    path, payload, token = api.calls[0]
    assert path == "/pulls"
    assert token == "app-token"
    assert payload["head"] == "automation/dependency-promotion-171-abcdef123456"
    assert payload["base"] == "main"
    assert payload["draft"] is False


def test_create_promotion_pr_fails_closed_without_app_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_author(monkeypatch)
    monkeypatch.delenv(promotion.PROMOTION_AUTHOR_TOKEN_ENV)
    api = RecordingApi()

    with pytest.raises(promotion.GovernanceError, match="APP_TOKEN is required"):
        promotion._create_promotion_pr(
            api,
            _source(),
            "automation/dependency-promotion-171-abcdef123456",
            HEAD,
        )

    assert api.calls == []


def test_create_promotion_pr_rejects_wrong_returned_app_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_author(monkeypatch)
    api = RecordingApi(returned_login="github-actions[bot]", returned_id=41898282)

    with pytest.raises(promotion.GovernanceError, match="configured GitHub App"):
        promotion._create_promotion_pr(
            api,
            _source(),
            "automation/dependency-promotion-171-abcdef123456",
            HEAD,
        )


@pytest.mark.parametrize(
    "login",
    [
        "github-actions[bot]",
        "dependabot[bot]",
        "trusted-pr-gate[bot]",
        "github-advanced-security[bot]",
    ],
)
def test_promotion_author_identity_rejects_collapsed_authority(
    monkeypatch: pytest.MonkeyPatch, login: str
) -> None:
    monkeypatch.setenv(promotion.PROMOTION_AUTHOR_LOGIN_ENV, login)
    monkeypatch.setenv(promotion.PROMOTION_AUTHOR_ID_ENV, "42")

    with pytest.raises(promotion.GovernanceError, match="identity is missing or malformed"):
        promotion._promotion_author_identity()


def test_promotion_author_identity_rejects_protected_remediation_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(promotion.PROMOTION_AUTHOR_LOGIN_ENV, AUTHOR_LOGIN)
    monkeypatch.setenv(promotion.PROMOTION_AUTHOR_ID_ENV, str(AUTHOR_ID))
    monkeypatch.setenv("PROTECTED_REMEDIATION_BOT_LOGIN", AUTHOR_LOGIN)

    with pytest.raises(promotion.GovernanceError, match="identity is missing or malformed"):
        promotion._promotion_author_identity()
