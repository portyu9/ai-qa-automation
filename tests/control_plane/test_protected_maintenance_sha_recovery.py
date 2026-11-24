"""Bounded, independently authorized recovery after GitHub regenerates a merge ref."""

from __future__ import annotations

import copy
import importlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
owner = importlib.import_module("auto_protected_maintenance_authorizer")
gate = importlib.import_module("auto_trusted_preflight")

BASE = "a" * 40
HEAD = "b" * 40
CURRENT = "c" * 40
STALE = "d" * 40
TREE = "e" * 40
REPO = "portyu9/ai-qa-automation"
USER = {"login": "portyu9", "id": 35150859, "type": "User"}


def subject(merge: str = CURRENT) -> SimpleNamespace:
    return SimpleNamespace(
        lane="owner-protected-maintenance",
        pr_number=474,
        head_sha=HEAD,
        base_sha=BASE,
        merge_sha=merge,
    )


def comment(merge: str = STALE, **overrides: object) -> dict:
    record = {
        "id": 71,
        "body": owner.exact_comment(subject(merge)),
        "user": USER.copy(),
        "created_at": "2026-11-24T18:40:30Z",
        "updated_at": "2026-11-24T18:40:30Z",
        "issue_url": f"https://api.github.com/repos/{REPO}/issues/474",
    }
    record.update(overrides)
    return record


def merge_object(sha: str, *, tree: str = TREE) -> dict:
    return {
        "sha": sha,
        "parents": [{"sha": BASE}, {"sha": HEAD}],
        "tree": {"sha": tree},
    }


class RecoveryAPI:
    def __init__(self) -> None:
        self.rows = [comment()]
        self.objects = {CURRENT: merge_object(CURRENT), STALE: merge_object(STALE)}

    def list_all(self, path: str, *, max_pages: int = 1) -> list[dict]:
        assert path == f"/repos/{REPO}/issues/474/comments?per_page=100"
        assert max_pages == 1
        return self.rows

    def get(self, path: str) -> dict:
        return self.objects[path.rsplit("/", 1)[-1]]


def test_regenerated_sha_requires_new_authorization_even_with_same_tree() -> None:
    api = RecoveryAPI()
    owner.require_bounded_merge_sha_recovery(
        api, subject(), failed_gate_wake=True
    )
    assert owner.exact_comment(subject()) != api.rows[0]["body"]
    assert owner.MAX_EXACT_OWNER_AUTHORIZATIONS == 4


@pytest.mark.parametrize(
    "mutation",
    [
        "stale-tree",
        "current-tree",
        "stale-parents",
        "current-parents",
        "stale-sha",
        "current-sha",
        "duplicate",
        "wrong-owner",
        "edited",
        "already-current",
        "exhausted",
        "no-previous",
    ],
)
def test_owner_recovery_fails_closed_on_unreviewed_drift(mutation: str) -> None:
    api = RecoveryAPI()
    if mutation == "stale-tree":
        api.objects[STALE]["tree"]["sha"] = "f" * 40
    elif mutation == "current-tree":
        api.objects[CURRENT]["tree"]["sha"] = "f" * 40
    elif mutation == "stale-parents":
        api.objects[STALE]["parents"] = [{"sha": HEAD}, {"sha": BASE}]
    elif mutation == "current-parents":
        api.objects[CURRENT]["parents"] = [{"sha": HEAD}, {"sha": BASE}]
    elif mutation == "stale-sha":
        api.objects[STALE]["sha"] = "f" * 40
    elif mutation == "current-sha":
        api.objects[CURRENT]["sha"] = "f" * 40
    elif mutation == "duplicate":
        api.rows.append({**comment(), "id": 72})
    elif mutation == "wrong-owner":
        api.rows[0]["user"] = {"login": "attacker", "id": 72, "type": "User"}
    elif mutation == "edited":
        api.rows[0]["updated_at"] = "2026-11-24T18:40:31Z"
    elif mutation == "already-current":
        api.rows = [comment(CURRENT)]
    elif mutation == "exhausted":
        merges = [STALE, "1" * 40, "2" * 40, "3" * 40]
        api.rows = [{**comment(sha), "id": index + 20} for index, sha in enumerate(merges)]
        api.objects.update({sha: merge_object(sha) for sha in merges})
    elif mutation == "no-previous":
        api.rows = []
    with pytest.raises(ValueError):
        owner.require_bounded_merge_sha_recovery(
            api, subject(), failed_gate_wake=True
        )


def test_first_authorization_allowed_only_without_failed_gate_wake() -> None:
    api = RecoveryAPI()
    api.rows = []
    owner.require_bounded_merge_sha_recovery(
        api, subject(), failed_gate_wake=False
    )
    with pytest.raises(ValueError, match="no previous exact owner approval"):
        owner.require_bounded_merge_sha_recovery(
            api, subject(), failed_gate_wake=True
        )


def trusted_run() -> dict:
    return {
        "id": 817,
        "workflow_id": owner.TRUSTED_GATE_WORKFLOW_ID,
        "name": owner.TRUSTED_GATE_WORKFLOW_NAME,
        "path": ".github/workflows/trusted-pr-auto.yml",
        "event": "workflow_run",
        "run_attempt": 1,
        "status": "completed",
        "conclusion": "failure",
        "head_branch": "main",
        "head_sha": BASE,
        "repository": {"full_name": REPO},
        "head_repository": {"full_name": REPO},
        "actor": USER.copy(),
        "triggering_actor": USER.copy(),
    }


def trusted_jobs() -> list[dict]:
    return [
        {"name": name, "status": "completed", "conclusion": conclusion}
        for name, conclusion in (
            ("Automatic Trusted Admission", "success"),
            ("Exact Subject + Protected Authority Guard", "success"),
            ("Automatic Trusted Validation Aggregate", "success"),
            ("Automatic Trusted PR Gate Reporter", "failure"),
        )
    ]


class WakeAPI:
    def __init__(self) -> None:
        self.live = trusted_run()
        self.jobs = trusted_jobs()

    def get(self, path: str) -> dict:
        assert path == f"/repos/{REPO}/actions/runs/817"
        return self.live

    def list_all(self, path: str, *, max_pages: int = 1) -> list[dict]:
        assert path == f"/repos/{REPO}/actions/runs/817/jobs?per_page=100"
        assert max_pages == 1
        return self.jobs


def wake_context(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    path = tmp_path / "workflow.json"
    path.write_text(
        json.dumps(
            {"action": "completed", "workflow_run": {"id": 817, "workflow_id": 346203190, "head_sha": BASE}}
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("GITHUB_EVENT_NAME", "workflow_run")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(path))
    monkeypatch.setenv("GITHUB_SHA", BASE)
    return path


def test_failed_trusted_reporter_restarts_only_owner_reauthorization(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    wake_context(monkeypatch, tmp_path)
    assert owner.require_verified_owner_wake(WakeAPI()) == "trusted-gate-failure"


@pytest.mark.parametrize(
    "field,value",
    [
        ("run_attempt", 2),
        ("conclusion", "success"),
        ("head_sha", HEAD),
        ("head_branch", "untrusted"),
        ("event", "pull_request"),
        ("workflow_id", 339754724),
        ("actor", {"login": "attacker", "id": 18}),
        ("triggering_actor", {"login": "attacker", "id": 18}),
    ],
)
def test_trusted_failure_wake_rejects_wrong_live_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, field: str, value: object
) -> None:
    wake_context(monkeypatch, tmp_path)
    api = WakeAPI()
    api.live[field] = value
    with pytest.raises(ValueError, match="not an exact native successful PR workflow"):
        owner.require_verified_owner_wake(api)


@pytest.mark.parametrize("job", [0, 1, 2, 3])
def test_trusted_failure_wake_rejects_missing_or_wrong_terminal_job(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, job: int
) -> None:
    wake_context(monkeypatch, tmp_path)
    api = WakeAPI()
    api.jobs[job]["conclusion"] = "cancelled"
    with pytest.raises(ValueError, match="lacks exact terminal validation evidence"):
        owner.require_verified_owner_wake(api)
    api.jobs = trusted_jobs() + [trusted_jobs()[job]]
    with pytest.raises(ValueError, match="lacks exact terminal validation evidence"):
        owner.require_verified_owner_wake(api)


def issue_event() -> dict:
    return {
        "action": "created",
        "sender": USER.copy(),
        "issue": {"number": 474, "pull_request": {"url": f"https://api.github.com/repos/{REPO}/pulls/474"}},
        "comment": comment(CURRENT),
    }


def test_owner_comment_event_revalidates_exact_current_comment(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_ACTOR", "portyu9")
    monkeypatch.setattr(gate, "_current_main", lambda _: BASE)
    admission = subject()
    seen: list[tuple] = []

    def select(_api, *, trusted_sha: str, expected_pr_number: int):
        seen.append((trusted_sha, expected_pr_number))
        return admission

    def prove(_api, *, pr_number: int, comment_id: int, body: str, trusted_sha: str):
        assert (pr_number, comment_id, trusted_sha) == (474, 71, BASE)
        assert body == owner.exact_comment(admission)
        return admission

    monkeypatch.setattr(gate, "_select_protected_owner_admission", select)
    monkeypatch.setattr(gate, "_resolve_protected_owner_authorization", prove)
    assert gate.evaluate_admission(
        object(), event=issue_event(), event_name="issue_comment"
    ) == admission
    assert seen == [(BASE, 474)]


@pytest.mark.parametrize(
    "mutation",
    [
        "edited-event",
        "wrong-owner",
        "wrong-sender",
        "missing-pr",
        "different-pr",
        "wrong-comment-issue",
        "wrong-action",
        "non-owner-actor",
    ],
)
def test_owner_comment_event_rejects_other_liveness(
    monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    monkeypatch.setenv("GITHUB_ACTOR", "portyu9")
    monkeypatch.setattr(gate, "_current_main", lambda _: BASE)
    event = copy.deepcopy(issue_event())
    if mutation == "edited-event":
        event["comment"]["body"] = "changed"
    elif mutation == "wrong-owner":
        event["comment"]["user"]["id"] = 1
    elif mutation == "wrong-sender":
        event["sender"]["id"] = 1
    elif mutation == "missing-pr":
        event["issue"].pop("pull_request")
    elif mutation == "different-pr":
        event["issue"]["number"] = 403
    elif mutation == "wrong-comment-issue":
        event["comment"]["issue_url"] = "https://api.github.com/repos/other/other/issues/474"
    elif mutation == "wrong-action":
        event["action"] = "edited"
    elif mutation == "non-owner-actor":
        monkeypatch.setenv("GITHUB_ACTOR", "attacker")
    with pytest.raises(ValueError, match="owner comment"):
        gate.evaluate_admission(object(), event=event, event_name="issue_comment")


def test_owner_comment_does_not_authorize_prior_merge_or_different_lane(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_ACTOR", "portyu9")
    monkeypatch.setattr(gate, "_current_main", lambda _: BASE)
    monkeypatch.setattr(
        gate, "_select_protected_owner_admission", lambda *args, **kwargs: subject()
    )
    event = issue_event()
    event["comment"]["body"] = owner.exact_comment(subject(STALE))
    assert gate.evaluate_admission(
        object(), event=event, event_name="issue_comment"
    ) is None
    assert gate.evaluate_admission(
        object(),
        event=issue_event(),
        event_name="issue_comment",
        expected_lane="dependabot-actions",
        expected_pr_number=474,
    ) is None


def test_verified_workflow_requires_exact_new_comment_liveness() -> None:
    verifier = importlib.import_module("verify_ci_contract")
    workflow = (ROOT / ".github/workflows/trusted-pr-auto.yml").read_text()
    verifier._trusted_auto._verify_trusted_auto_workflow(workflow)
    for bad in (
        workflow.replace("types: [created]", "types: [edited]", 1),
        workflow.replace("github.event.sender.id == 35150859", "github.event.sender.id > 0", 1),
    ):
        with pytest.raises(ValueError):
            verifier._trusted_auto._verify_trusted_auto_workflow(bad)
