from __future__ import annotations

import importlib
import json
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
        for name, _workflow_id in (
            ("Required PR Gate", 339754724),
            ("CodeQL", 359681647),
            ("security-gate", 0),
        ):
            if "check_name=" + name.replace(" ", "%20") in path:
                assert "&filter=latest" in path
                identifier = {"Required PR Gate": 10, "CodeQL": 11, "security-gate": 12}[name]
                rows = [
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
                if self.bad == "duplicate":
                    rows.append({**rows[0], "id": identifier + 1, "conclusion": "failure"})
                if self.bad == "newer-pending":
                    rows.append({**rows[0], "id": identifier + 1, "status": "in_progress"})
                if self.bad == "duplicate-id":
                    rows.append({**rows[0], "conclusion": "failure"})
                if self.bad == "older-red":
                    rows.insert(0, {**rows[0], "id": identifier - 1, "conclusion": "failure"})
                if self.bad == "older-green":
                    rows.insert(0, {**rows[0], "id": identifier - 1})
                return rows
        raise AssertionError(f"unreviewed query: {path}")

    def get(self, path: str) -> dict:
        suffix = path.split("/")[-1]
        workflow_number = int(suffix)
        record = {
            110: ("ci", ".github/workflows/ci.yml", 339754724),
            111: ("CodeQL", ".github/workflows/codeql.yml", 359681647),
            112: ("security", ".github/workflows/security.yml", 500000000),
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
    "bad",
    [
        "wrong-head",
        "red-check",
        "wrong-app",
        "manual-rerun",
        "bad-workflow",
        "duplicate",
        "newer-pending",
        "duplicate-id",
    ],
)
def test_candidate_checks_fail_closed_on_wrong_subject_and_authority(bad: str) -> None:
    assert not owner.require_passing_candidate_checks(FakeAPI(bad=bad), "b" * 40)


def test_exact_native_ci_security_codeql_pass() -> None:
    assert owner.require_passing_candidate_checks(FakeAPI(), "b" * 40)


@pytest.mark.parametrize("prior", ["older-red", "older-green"])
def test_newest_successful_first_attempt_supersedes_stale_native_check(prior: str) -> None:
    # GitHub check_name/filter=latest legitimately returns older check suites
    # after a PR reopen or natural synchronization of unchanged candidate code.
    assert owner.require_passing_candidate_checks(FakeAPI(bad=prior), "b" * 40)


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


def test_durable_authorization_readback_binds_issue_owner_and_immutable_body() -> None:
    body = owner.exact_comment(_subject())
    reference = {
        "id": 28,
        "body": body,
        "issue_url": "https://api.github.com/repos/portyu9/ai-qa-automation/issues/403",
        "user": {"login": "portyu9", "id": 35150859, "type": "User"},
        "created_at": "2026-10-14T11:00:00Z",
        "updated_at": "2026-10-14T11:00:00Z",
    }

    class Persisted:
        def get(self, path: str) -> dict:
            assert path == "/repos/portyu9/ai-qa-automation/issues/comments/28"
            return reference

    api = Persisted()
    owner.require_durable_owner_authorization(api, pr_number=403, comment_id=28, body=body)
    for field, wrong in (
        ("body", "edited command"),
        ("issue_url", "https://api.github.com/repos/portyu9/ai-qa-automation/issues/397"),
        ("updated_at", "2026-10-14T11:01:00Z"),
        ("id", 29),
        ("user", {"login": "attacker", "id": 1, "type": "User"}),
    ):
        original = reference[field]
        reference[field] = wrong
        with pytest.raises(ValueError, match="immutable and exact"):
            owner.require_durable_owner_authorization(api, pr_number=403, comment_id=28, body=body)
        reference[field] = original

    with pytest.raises(ValueError, match="identifier"):
        owner.require_durable_owner_authorization(api, pr_number=403, comment_id=True, body=body)


def test_issuer_publishes_and_reproves_without_borrowing_gate_workflow_identity(
    trusted_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The owner workflow is deliberately NOT the Trusted PR Auto Gate workflow."""
    candidate = {
        "number": 403,
        "state": "open",
        "draft": False,
        "user": {"login": "portyu9", "id": 35150859, "type": "User"},
        "head": {"sha": "b" * 40},
    }
    admission = SimpleNamespace(
        eligible=True,
        protected_changes=({"path": ".github", "base_oid": "a", "subject_oid": "b"},),
        pr_number=403,
        head_sha="b" * 40,
        base_sha="a" * 40,
        merge_sha="c" * 40,
    )
    saved = {
        "id": 28,
        "body": owner.exact_comment(admission),
        "issue_url": "https://api.github.com/repos/portyu9/ai-qa-automation/issues/403",
        "user": {"login": "portyu9", "id": 35150859, "type": "User"},
        "created_at": "2026-10-14T11:00:00Z",
        "updated_at": "2026-10-14T11:00:00Z",
    }

    class IssuerAPI:
        def list_all(self, path: str, *, max_pages: int = 1) -> list[dict]:
            if "/pulls?state=open" in path:
                return [candidate]
            if "/issues/403/comments" in path:
                return []
            raise AssertionError(f"unreviewed issuer inventory: {path}")

        def get(self, path: str) -> dict:
            if path.endswith("/pulls/403"):
                return candidate
            if path.endswith("/issues/comments/28"):
                return saved
            raise AssertionError(f"unreviewed issuer readback: {path}")

    monkeypatch.setattr(owner, "_current_main", lambda _: "a" * 40)
    monkeypatch.setattr(owner, "_resolve_subject", lambda *args, **kwargs: admission)
    monkeypatch.setattr(owner, "_has_exact_trusted_terminal_status", lambda *a, **k: False)
    monkeypatch.setattr(owner, "require_passing_candidate_checks", lambda *a, **k: True)
    monkeypatch.setattr(owner, "require_owner_token_identity", lambda token: None)
    published: list[tuple[str, int, str]] = []

    def publish(token: str, number: int, body: str) -> int:
        published.append((token, number, body))
        return 28

    monkeypatch.setattr(owner, "publish_once", publish)
    outcome = owner.authorize(IssuerAPI(), "isolated-owner-test-token")
    assert outcome == {
        "decision": "exact-owner-authorization-published",
        "pr": 403,
        "headSha": "b" * 40,
        "baseSha": "a" * 40,
        "mergeSha": "c" * 40,
        "commentId": 28,
    }
    assert published == [("isolated-owner-test-token", 403, saved["body"])]


def test_trusted_owner_authorizer_event_wake_is_exact_and_read_only(
    trusted_env: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_EVENT_NAME", "workflow_run")
    path = tmp_path / "event.json"
    wake = {
        "action": "completed",
        "workflow_run": {
            "id": 817,
            "workflow_id": 339754724,
            "head_sha": "b" * 40,
        },
    }
    path.write_text(json.dumps(wake), encoding="utf-8")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(path))
    owner.require_execution_context("a" * 40)
    valid = {
        "id": 817,
        "workflow_id": 339754724,
        "name": "ci",
        "path": ".github/workflows/ci.yml",
        "event": "pull_request",
        "run_attempt": 1,
        "status": "completed",
        "conclusion": "success",
        "head_sha": "b" * 40,
        "repository": {"full_name": "portyu9/ai-qa-automation"},
        "head_repository": {"full_name": "portyu9/ai-qa-automation"},
        "actor": {"login": "portyu9", "id": 35150859},
        "triggering_actor": {"login": "portyu9", "id": 35150859},
    }

    class WakeAPI:
        def __init__(self, result: dict) -> None:
            self.result = result
            self.calls: list[str] = []

        def get(self, endpoint: str) -> dict:
            self.calls.append(endpoint)
            return self.result

    api = WakeAPI(valid)
    owner.require_verified_owner_wake(api)
    assert api.calls == ["/repos/portyu9/ai-qa-automation/actions/runs/817"]
    for mutation in (
        {"run_attempt": 2},
        {"workflow_id": 1},
        {"conclusion": "failure"},
        {"event": "workflow_dispatch"},
        {"head_sha": "c" * 40},
        {"repository": {"full_name": "evil/other"}},
        {"actor": {"login": "portyu9", "id": 7}},
        {"triggering_actor": {"login": "foreign", "id": 35150859}},
    ):
        api.result = {**valid, **mutation}
        with pytest.raises(ValueError, match="not an exact native successful PR workflow"):
            owner.require_verified_owner_wake(api)
    api.result = valid
    wake["workflow_run"]["workflow_id"] = 1
    path.write_text(json.dumps(wake), encoding="utf-8")
    with pytest.raises(ValueError, match="not an exact native successful PR workflow"):
        owner.require_verified_owner_wake(api)
    path.write_text("x" * (owner.MAX_EVENT_BYTES + 1), encoding="utf-8")
    with pytest.raises(ValueError, match="bounded"):
        owner.require_verified_owner_wake(api)
