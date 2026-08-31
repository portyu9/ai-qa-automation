from __future__ import annotations

import hashlib
import hmac
import io
import json
import zipfile
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from scripts.trusted_gate_service.core import (
    EXPECTED_REPOSITORY,
    EXPECTED_REPOSITORY_ID,
    OneShotPolicy,
    ProtectedTransition,
    StrictJsonError,
    Subject,
    parse_workflow_run_wakeup,
    strict_json_loads,
    verify_build_manifest_archive,
    verify_jobs,
    verify_webhook_signature,
)
from scripts.trusted_gate_service.github import GitHubClient, GitHubProtocolError

HEAD = "1" * 40
BASE = "2" * 40
MERGE = "3" * 40
TREE = "4" * 40
BASE_OID = "5" * 40
SUBJECT_OID = "6" * 40
INSTALLATION_ID = 12345
RUN_ID = 918
DELIVERY = "00000000-0000-0000-0000-000000000001"
SECRET = b"webhook-secret"


def _subject(*, head: str = HEAD, merge: str = MERGE) -> Subject:
    return Subject(
        pr_number=70,
        head_sha=head,
        base_sha=BASE,
        merge_sha=merge,
        merge_tree_sha=TREE,
        head_ref="ci-python-314-certification",
        protected_changes=(ProtectedTransition(".github", BASE_OID, SUBJECT_OID),),
    )


def _policy_bytes(*, head: str = HEAD, merge: str = MERGE) -> bytes:
    now = datetime.now(UTC)
    payload = {
        "schema_version": 1,
        "policy_id": "pr70-python314-one-shot-v1",
        "repository": EXPECTED_REPOSITORY,
        "repository_id": EXPECTED_REPOSITORY_ID,
        "pr_number": 70,
        "head_sha": head,
        "base_sha": BASE,
        "merge_sha": merge,
        "protected_changes": [
            {"path": ".github", "base_oid": BASE_OID, "subject_oid": SUBJECT_OID}
        ],
        "not_before": (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
    }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()


def _webhook_body() -> bytes:
    return json.dumps(
        {
            "action": "completed",
            "installation": {"id": INSTALLATION_ID},
            "repository": {"id": EXPECTED_REPOSITORY_ID, "full_name": EXPECTED_REPOSITORY},
            "workflow_run": {"id": RUN_ID, "head_sha": HEAD},
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _manifest_zip(*, commit: str = MERGE, tree: str = TREE, extra_name: str | None = None) -> bytes:
    manifest = {
        "schema_version": 1,
        "kind": "unsigned_reproducible_build_manifest",
        "source": {"commit_sha": commit, "tree_sha": tree, "tracked_worktree_clean": True},
    }
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr("build-manifest.json", json.dumps(manifest))
        if extra_name is not None:
            bundle.writestr(extra_name, "x")
    return buffer.getvalue()


def test_webhook_signature_and_wakeup_identity() -> None:
    body = _webhook_body()
    good = "sha256=" + hmac.new(SECRET, body, hashlib.sha256).hexdigest()
    verify_webhook_signature(secret=SECRET, body=body, signature_header=good)
    wakeup = parse_workflow_run_wakeup(
        event_header="workflow_run",
        delivery_header=DELIVERY,
        body=body,
    )
    assert wakeup.run_id == RUN_ID
    assert wakeup.installation_id == INSTALLATION_ID
    with pytest.raises(PermissionError):
        verify_webhook_signature(
            secret=SECRET,
            body=body,
            signature_header="sha256=" + "0" * 64,
        )
    with pytest.raises(ValueError):
        parse_workflow_run_wakeup(event_header="push", delivery_header=DELIVERY, body=body)


def test_strict_json_rejects_duplicate_keys_and_nonstandard_numbers() -> None:
    with pytest.raises(StrictJsonError):
        strict_json_loads(b'{"a":1,"a":2}', max_bytes=100, label="test")
    with pytest.raises(StrictJsonError):
        strict_json_loads(b'{"a":NaN}', max_bytes=100, label="test")


def test_one_shot_policy_is_exact_and_time_bounded() -> None:
    policy = OneShotPolicy.parse(_policy_bytes())
    policy.admit(
        subject=_subject(),
        repository=EXPECTED_REPOSITORY,
        repository_id=EXPECTED_REPOSITORY_ID,
        now=datetime.now(UTC),
    )
    with pytest.raises(PermissionError):
        policy.admit(
            subject=_subject(head="7" * 40),
            repository=EXPECTED_REPOSITORY,
            repository_id=EXPECTED_REPOSITORY_ID,
            now=datetime.now(UTC),
        )
    raw = json.loads(_policy_bytes())
    now = datetime.now(UTC)
    raw["not_before"] = (now - timedelta(hours=2)).isoformat().replace("+00:00", "Z")
    raw["expires_at"] = (now - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    expired = OneShotPolicy.parse(json.dumps(raw).encode())
    with pytest.raises(PermissionError):
        expired.admit(
            subject=_subject(),
            repository=EXPECTED_REPOSITORY,
            repository_id=EXPECTED_REPOSITORY_ID,
            now=now,
        )


def test_policy_rejects_empty_or_duplicate_protected_transitions() -> None:
    raw = json.loads(_policy_bytes())
    raw["protected_changes"] = []
    with pytest.raises(ValueError):
        OneShotPolicy.parse(json.dumps(raw).encode())
    raw = json.loads(_policy_bytes())
    raw["protected_changes"].append(dict(raw["protected_changes"][0]))
    with pytest.raises(ValueError):
        OneShotPolicy.parse(json.dumps(raw).encode())


def test_real_pr70_five_transition_policy_is_order_independent() -> None:
    transitions = tuple(
        sorted(
            (
                ProtectedTransition(
                    ".github",
                    "1a9711c59b4a48081c7d7132b6a31b8033212161",
                    "d11430b748a01b6dc37e49d1ca48e5eb4570503a",
                ),
                ProtectedTransition(
                    "pyproject.toml",
                    "8e758996b7449c98fc6190337959c2f1dccdfdcd",
                    "1b413f5816d23fc7aeefdb6966bc32bd6042a97f",
                ),
                ProtectedTransition(
                    "requirements",
                    "e0bd1a51482fd9e0a38e8c27322b347cc9c9f713",
                    "d2e0cae51d378696c4b3c4089d65c3ce14c7b4e3",
                ),
                ProtectedTransition(
                    "scripts",
                    "f8e207d3eeb1efde67c3204dfb563f5efd3aa329",
                    "6ff64cbb61418839ac73c6c555e4746e09418e64",
                ),
                ProtectedTransition(
                    "tests",
                    "487ba47fcbc154a3d1cce5e23621182f70e70cf5",
                    "f0c4dc5751e6dd04f56351ad9e8ed27620e51eec",
                ),
            )
        )
    )
    now = datetime.now(UTC)
    raw = {
        "schema_version": 1,
        "policy_id": "pr70-python314-live-one-shot-v1",
        "repository": EXPECTED_REPOSITORY,
        "repository_id": EXPECTED_REPOSITORY_ID,
        "pr_number": 70,
        "head_sha": "eac70f8ded8475d1aa2d4737cd465ef791d44d3d",
        "base_sha": "a9a3d1a52c70a31753ecbaecf645973fcc6cce55",
        "merge_sha": "dc939d35d27da6b668b8dbda83db6a52164c9ba0",
        "protected_changes": [item.as_json() for item in reversed(transitions)],
        "not_before": (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
    }
    policy = OneShotPolicy.parse(json.dumps(raw).encode())
    live = Subject(
        pr_number=70,
        head_sha=raw["head_sha"],
        base_sha=raw["base_sha"],
        merge_sha=raw["merge_sha"],
        merge_tree_sha="bf3c873cbe507cafa338ecb8470047e705ad5832",
        head_ref="ci-python-314-certification",
        protected_changes=transitions,
    )
    policy.admit(
        subject=live,
        repository=EXPECTED_REPOSITORY,
        repository_id=EXPECTED_REPOSITORY_ID,
        now=now,
    )


def test_build_manifest_archive_is_subject_bound_and_traversal_safe() -> None:
    archive = _manifest_zip()
    result = verify_build_manifest_archive(
        archive,
        expected_merge_sha=MERGE,
        expected_tree_sha=TREE,
    )
    assert result == {"commit_sha": MERGE, "tree_sha": TREE}
    with pytest.raises(ValueError):
        verify_build_manifest_archive(
            archive,
            expected_merge_sha="9" * 40,
            expected_tree_sha=TREE,
        )
    with pytest.raises(ValueError):
        verify_build_manifest_archive(
            _manifest_zip(extra_name="../escape"),
            expected_merge_sha=MERGE,
            expected_tree_sha=TREE,
        )


def test_job_contract_requires_all_domains_and_two_quality_lanes() -> None:
    jobs: list[dict[str, Any]] = [
        {
            "name": "Supply Chain / Wheel + SBOM + Container",
            "conclusion": "success",
            "steps": [{"name": "Verify CI authority contract", "conclusion": "success"}],
        },
        {"name": "Security Gates", "conclusion": "success", "steps": []},
        {"name": "Playwright Reference SUT", "conclusion": "success", "steps": []},
        {"name": "34-Case Deterministic Control Evaluation", "conclusion": "success", "steps": []},
        {
            "name": "Required PR Gate",
            "conclusion": "success",
            "steps": [
                {"name": "Require every automatic gate to succeed", "conclusion": "success"}
            ],
        },
        {"name": "Quality / Python 3.11.16", "conclusion": "success", "steps": []},
        {"name": "Quality / Python 3.14.7", "conclusion": "success", "steps": []},
    ]
    result = verify_jobs({"total_count": len(jobs), "jobs": jobs})
    assert result["quality_jobs"] == ["Quality / Python 3.11.16", "Quality / Python 3.14.7"]
    jobs[-1]["conclusion"] = "skipped"
    with pytest.raises(ValueError):
        verify_jobs({"total_count": len(jobs), "jobs": jobs})


class _Provider:
    def installation_token(self) -> str:
        return "unused"


def _run(*, actor: str = "portyu9", triggering_actor: str = "portyu9") -> dict[str, Any]:
    return {
        "id": RUN_ID,
        "workflow_id": 339754724,
        "name": "CI — ƳƤ AI QA Automation Framework",
        "path": ".github/workflows/ci.yml",
        "event": "pull_request",
        "status": "completed",
        "conclusion": "success",
        "repository": {"id": EXPECTED_REPOSITORY_ID, "full_name": EXPECTED_REPOSITORY},
        "head_repository": {"full_name": EXPECTED_REPOSITORY},
        "actor": {"login": actor},
        "triggering_actor": {"login": triggering_actor},
        "head_sha": HEAD,
    }


def test_live_run_requires_owner_actor_and_triggering_actor() -> None:
    client = GitHubClient(token_provider=_Provider(), installation_id=INSTALLATION_ID)  # type: ignore[arg-type]
    client._validate_run(_run(), run_id=RUN_ID, event_head_sha=HEAD)
    with pytest.raises(GitHubProtocolError):
        client._validate_run(_run(actor="attacker"), run_id=RUN_ID, event_head_sha=HEAD)
    with pytest.raises(GitHubProtocolError):
        client._validate_run(_run(triggering_actor="attacker"), run_id=RUN_ID, event_head_sha=HEAD)


def test_live_run_rejects_fork_and_wrong_workflow() -> None:
    client = GitHubClient(token_provider=_Provider(), installation_id=INSTALLATION_ID)  # type: ignore[arg-type]
    forked = _run()
    forked["head_repository"] = {"full_name": "someone/fork"}
    with pytest.raises(GitHubProtocolError):
        client._validate_run(forked, run_id=RUN_ID, event_head_sha=HEAD)
    wrong = _run()
    wrong["workflow_id"] = 999
    with pytest.raises(GitHubProtocolError):
        client._validate_run(wrong, run_id=RUN_ID, event_head_sha=HEAD)
