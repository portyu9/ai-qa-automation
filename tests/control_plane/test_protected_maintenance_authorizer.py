from __future__ import annotations

import importlib
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
owner = importlib.import_module("auto_protected_maintenance_authorizer")


@pytest.fixture()
def trusted_env(monkeypatch: pytest.MonkeyPatch) -> None:
    values = {
        "GITHUB_REPOSITORY": "portyu9/ai-qa-automation",
        "GITHUB_API_URL": "https://api.github.com",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_SHA": "a" * 40,
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_EVENT_NAME": "schedule",
        "GITHUB_WORKFLOW_REF": (
            "portyu9/ai-qa-automation/.github/workflows/"
            "protected-maintenance-authorizer.yml@refs/heads/main"
        ),
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)


def test_execution_binds_exact_trusted_workflow(
    trusted_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner.require_execution_context("a" * 40)
    for key, bad in (
        ("GITHUB_REF", "refs/heads/evil"),
        ("GITHUB_SHA", "b" * 40),
        ("GITHUB_RUN_ATTEMPT", "2"),
        ("GITHUB_EVENT_NAME", "workflow_dispatch"),
        (
            "GITHUB_WORKFLOW_REF",
            "portyu9/ai-qa-automation/.github/workflows/ci.yml@refs/heads/main",
        ),
    ):
        original = owner.os.environ[key]
        monkeypatch.setenv(key, bad)
        with pytest.raises(ValueError, match="fresh accepted main"):
            owner.require_execution_context("a" * 40)
        monkeypatch.setenv(key, original)


def _subject() -> SimpleNamespace:
    return SimpleNamespace(pr_number=403, head_sha="b" * 40, base_sha="a" * 40, merge_sha="c" * 40)


def test_comment_binds_exact_subject_and_reviewed_reason() -> None:
    assert owner.exact_comment(_subject()) == (
        "/trusted-maintenance authorization=protected-control-plane-maintenance "
        f"pr=403 head={'b' * 40} base={'a' * 40} merge={'c' * 40}"
    )


class FakeAPI:
    def __init__(self, *, bad: str = "") -> None:
        self.bad = bad

    def list_all(self, path: str, *, max_pages: int = 1) -> list[dict]:
        if "issues/403/comments" in path:
            return self.comment_rows()
        for name, workflow_id in (
            ("Required PR Gate", 339754724),
            ("CodeQL", 359681647),
            ("security-gate", 0),
        ):
            if "check_name=" + name.replace(" ", "%20") in path:
                identifier = {"Required PR Gate": 10, "CodeQL": 11, "security-gate": 12}[name]
                return [
                    {
                        "id": identifier,
                        "name": name,
                        "head_sha": "b" * 40 if self.bad != "wrong-head" else "c" * 40,
                        "status": "completed",
                        "conclusion": "failure" if self.bad == "red-check" else "success",
                        "app": {
                            "id": 15368 if self.bad != "wrong-app" else 42,
                            "slug": "github-actions",
                        },
                        "details_url": (
                            f"https://github.com/portyu9/ai-qa-automation/actions/runs/"
                            f"{identifier + 100}/job/{identifier}"
                        ),
                    }
                ]
        raise AssertionError(f"unreviewed query: {path}")

    def get(self, path: str) -> dict:
        suffix = path.split("/")[-1]
        workflow_number = int(suffix)
        record = {
            110: ("CI — ƳƤ AI QA Automation Framework", ".github/workflows/ci.yml", 339754724),
            111: ("CodeQL", ".github/workflows/codeql.yml", 359681647),
            112: ("Security", ".github/workflows/security.yml", 500000000),
        }[workflow_number]
        return {
            "name": record[0],
            "path": record[1],
            "workflow_id": record[2],
            "run_attempt": 2 if self.bad == "manual-rerun" else 1,
            "head_sha": "b" * 40,
            "event": "pull_request",
            "status": "completed",
            "conclusion": "failure" if self.bad == "bad-workflow" else "success",
            "repository": {"full_name": "portyu9/ai-qa-automation"},
            "head_repository": {"full_name": "portyu9/ai-qa-automation"},
        }

    def comment_rows(self) -> list[dict]:
        return [
            {
                "id": 28,
                "body": owner.exact_comment(_subject()),
                "user": {"login": "portyu9", "id": 35150859, "type": "User"},
                "created_at": "2026-10-14T10:00:00Z",
                "updated_at": "2026-10-14T10:00:00Z",
            }
        ]


@pytest.mark.parametrize(
    "bad", ["wrong-head", "red-check", "wrong-app", "manual-rerun", "bad-workflow"]
)
def test_candidate_checks_fail_closed_on_wrong_subject_and_authority(bad: str) -> None:
    assert not owner.require_passing_candidate_checks(FakeAPI(bad=bad), "b" * 40)


def test_exact_native_ci_security_codeql_pass() -> None:
    assert owner.require_passing_candidate_checks(FakeAPI(), "b" * 40)


def test_existing_authorization_is_idempotent_and_rejects_duplicates() -> None:
    api = FakeAPI()
    body = owner.exact_comment(_subject())
    assert owner.existing_authorization(api, 403, body) == 28

    def duplicate(path: str, *, max_pages: int = 1) -> list[dict]:
        row = api.comment_rows()[0]
        return [row, {**row, "id": 29}]

    api.list_all = duplicate  # type: ignore[method-assign]
    with pytest.raises(ValueError, match="ambiguous duplicate"):
        owner.existing_authorization(api, 403, body)


def test_owner_identity_mismatch_does_not_count_as_authorization() -> None:
    api = FakeAPI()

    def malformed(path: str, *, max_pages: int = 1) -> list[dict]:
        row = api.comment_rows()[0]
        return [{**row, "user": {"login": "attacker", "id": 777, "type": "User"}}]

    api.list_all = malformed  # type: ignore[method-assign]
    with pytest.raises(ValueError, match="invalid provenance"):
        owner.existing_authorization(api, 403, owner.exact_comment(_subject()))
