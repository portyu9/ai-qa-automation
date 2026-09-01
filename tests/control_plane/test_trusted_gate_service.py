from __future__ import annotations

import hashlib
import hmac
import json
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from scripts.trusted_gate_service.core import (
    EXPECTED_REPOSITORY,
    EXPECTED_REPOSITORY_ID,
    OneShotPolicy,
    ProtectedTransition,
    Subject,
)
from scripts.trusted_gate_service.github import GitHubProtocolError, GitHubTransportError
from scripts.trusted_gate_service.service import ServiceConfig, TrustedGateService
from scripts.trusted_gate_service.store import DeliveryStore

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
BOT_LOGIN = "trusted-pr-gate[bot]"


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


def _webhook_body(*, installation_id: int = INSTALLATION_ID) -> bytes:
    return json.dumps(
        {
            "action": "completed",
            "installation": {"id": installation_id},
            "repository": {"id": EXPECTED_REPOSITORY_ID, "full_name": EXPECTED_REPOSITORY},
            "workflow_run": {"id": RUN_ID, "head_sha": HEAD},
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _signature(body: bytes) -> str:
    return "sha256=" + hmac.new(SECRET, body, hashlib.sha256).hexdigest()


class FakeGitHub:
    repository = EXPECTED_REPOSITORY
    repository_id = EXPECTED_REPOSITORY_ID
    installation_id = INSTALLATION_ID

    def __init__(self) -> None:
        self.current_subject = _subject()
        self.transport_failure = False
        self.protocol_failure = False
        self.publish_calls = 0
        self.existing_status = False
        self.evidence = {
            "run_id": RUN_ID,
            "target_url": f"https://github.com/{EXPECTED_REPOSITORY}/actions/runs/{RUN_ID}",
        }

    def resolve_subject(self, *, run_id: int, event_head_sha: str) -> Subject:
        if self.transport_failure:
            raise GitHubTransportError("transport")
        if self.protocol_failure:
            raise GitHubProtocolError("protocol")
        if run_id != RUN_ID or event_head_sha != self.current_subject.head_sha:
            raise GitHubProtocolError("subject mismatch")
        return self.current_subject

    def verify_run_evidence(self, *, run_id: int, subject: Subject) -> dict[str, Any]:
        if self.protocol_failure:
            raise GitHubProtocolError("bad evidence")
        if run_id != RUN_ID or subject != self.current_subject:
            raise GitHubProtocolError("evidence subject mismatch")
        return dict(self.evidence)

    def publish_success(self, *, subject: Subject, target_url: str) -> dict[str, Any]:
        self.publish_calls += 1
        self.existing_status = True
        return {"state": "success", "context": "Trusted PR Gate", "target_url": target_url}

    def latest_matching_success(
        self,
        *,
        subject: Subject,
        target_url: str,
        expected_creator_login: str,
    ) -> bool:
        return self.existing_status and expected_creator_login == BOT_LOGIN


def _service(root: Path, fake: FakeGitHub, *, policy: bytes | None = None) -> TrustedGateService:
    raw = policy or _policy_bytes()
    policy_path = root / "policy.json"
    policy_path.write_bytes(raw)
    return TrustedGateService(
        config=ServiceConfig(
            webhook_secret=SECRET,
            installation_id=INSTALLATION_ID,
            expected_creator_login=BOT_LOGIN,
            policy_path=policy_path,
            policy_sha256=hashlib.sha256(raw).hexdigest(),
        ),
        store=DeliveryStore(root / "store.sqlite3"),
        github=fake,  # type: ignore[arg-type]
    )


def _call(service: TrustedGateService, *, body: bytes | None = None):
    payload = body or _webhook_body()
    return service.handle_delivery(
        event_header="workflow_run",
        delivery_header=DELIVERY,
        signature_header=_signature(payload),
        body=payload,
    )


def test_exact_policy_and_evidence_publish_once() -> None:
    with tempfile.TemporaryDirectory() as td:
        fake = FakeGitHub()
        service = _service(Path(td), fake)
        result = _call(service)
        assert result.outcome == "SUCCESS"
        assert result.status_published
        assert fake.publish_calls == 1
        assert _call(service).outcome == "SUCCESS"
        assert fake.publish_calls == 1


def test_policy_miss_blocks_without_status_side_effect() -> None:
    with tempfile.TemporaryDirectory() as td:
        fake = FakeGitHub()
        service = _service(Path(td), fake, policy=_policy_bytes(head="8" * 40))
        result = _call(service)
        assert result.outcome == "BLOCKED"
        assert fake.publish_calls == 0


def test_live_subject_drift_blocks_before_publication() -> None:
    class DriftGitHub(FakeGitHub):
        def __init__(self) -> None:
            super().__init__()
            self.calls = 0

        def resolve_subject(self, *, run_id: int, event_head_sha: str) -> Subject:
            self.calls += 1
            if self.calls == 1:
                return self.current_subject
            return _subject(merge="9" * 40)

    with tempfile.TemporaryDirectory() as td:
        fake = DriftGitHub()
        result = _call(_service(Path(td), fake))
        assert result.outcome == "BLOCKED"
        assert fake.publish_calls == 0


def test_transport_failure_is_retryable_only_before_publication() -> None:
    with tempfile.TemporaryDirectory() as td:
        fake = FakeGitHub()
        fake.transport_failure = True
        result = _call(_service(Path(td), fake))
        assert result.outcome == "RETRYABLE"
        assert fake.publish_calls == 0


def test_wrong_webhook_installation_is_rejected_before_side_effects() -> None:
    with tempfile.TemporaryDirectory() as td:
        fake = FakeGitHub()
        service = _service(Path(td), fake)
        body = _webhook_body(installation_id=INSTALLATION_ID + 1)
        try:
            _call(service, body=body)
        except PermissionError:
            pass
        else:
            raise AssertionError("wrong installation must be rejected")
        assert fake.publish_calls == 0


def test_uncertain_publication_without_live_status_never_reposts() -> None:
    class UncertainPublisher(FakeGitHub):
        def publish_success(self, *, subject: Subject, target_url: str) -> dict[str, Any]:
            self.publish_calls += 1
            return {"state": "pending", "context": "Trusted PR Gate"}

    with tempfile.TemporaryDirectory() as td:
        fake = UncertainPublisher()
        service = _service(Path(td), fake)
        first = _call(service)
        assert first.outcome == "BLOCKED"
        assert first.reason == "publication_outcome_not_provable"
        assert fake.publish_calls == 1
        assert _call(service).outcome == "BLOCKED"
        assert fake.publish_calls == 1


def test_lost_response_after_write_recovers_without_repost() -> None:
    class LostResponseAfterWrite(FakeGitHub):
        def publish_success(self, *, subject: Subject, target_url: str) -> dict[str, Any]:
            self.publish_calls += 1
            self.existing_status = True
            raise GitHubTransportError("response lost after write")

    with tempfile.TemporaryDirectory() as td:
        fake = LostResponseAfterWrite()
        service = _service(Path(td), fake)
        assert _call(service).outcome == "SUCCESS"
        assert fake.publish_calls == 1
        assert _call(service).outcome == "SUCCESS"
        assert fake.publish_calls == 1


def test_lost_response_without_status_blocks_and_never_reposts() -> None:
    class LostBeforeWrite(FakeGitHub):
        def publish_success(self, *, subject: Subject, target_url: str) -> dict[str, Any]:
            self.publish_calls += 1
            raise GitHubTransportError("write outcome unknown")

    with tempfile.TemporaryDirectory() as td:
        fake = LostBeforeWrite()
        service = _service(Path(td), fake)
        first = _call(service)
        assert first.outcome == "BLOCKED"
        assert first.reason == "publication_outcome_not_provable"
        assert fake.publish_calls == 1
        assert _call(service).outcome == "BLOCKED"
        assert fake.publish_calls == 1


def test_post_publication_subject_drift_is_nonreplayable_blocked_truth() -> None:
    class DriftAfterPublish(FakeGitHub):
        def __init__(self) -> None:
            super().__init__()
            self.resolve_calls = 0

        def resolve_subject(self, *, run_id: int, event_head_sha: str) -> Subject:
            self.resolve_calls += 1
            if self.resolve_calls <= 2:
                return self.current_subject
            return _subject(merge="a" * 40)

    with tempfile.TemporaryDirectory() as td:
        fake = DriftAfterPublish()
        service = _service(Path(td), fake)
        assert _call(service).outcome == "BLOCKED"
        assert fake.publish_calls == 1
        assert _call(service).outcome == "BLOCKED"
        assert fake.publish_calls == 1


def test_ambiguous_response_recovers_existing_exact_status() -> None:
    class AmbiguousPublisher(FakeGitHub):
        def publish_success(self, *, subject: Subject, target_url: str) -> dict[str, Any]:
            self.publish_calls += 1
            self.existing_status = True
            return {"state": "pending", "context": "Trusted PR Gate"}

    with tempfile.TemporaryDirectory() as td:
        fake = AmbiguousPublisher()
        service = _service(Path(td), fake)
        first = _call(service)
        assert first.outcome == "SUCCESS"
        assert fake.publish_calls == 1
        assert _call(service).outcome == "SUCCESS"
        assert fake.publish_calls == 1


def test_policy_parser_rejects_unreviewed_repository_identity() -> None:
    raw = json.loads(_policy_bytes())
    raw["repository"] = "someone/else"
    policy = OneShotPolicy.parse(json.dumps(raw).encode())
    with tempfile.TemporaryDirectory() as td:
        fake = FakeGitHub()
        service = _service(Path(td), fake, policy=json.dumps(raw).encode())
        result = _call(service)
        assert result.outcome == "BLOCKED"
        assert fake.publish_calls == 0
    assert policy.repository == "someone/else"


def test_persisted_subject_recovery_rejects_duplicate_json_keys() -> None:
    rendered = (
        '{"pr_number":70,"pr_number":71,"head_sha":"'
        + HEAD
        + '","base_sha":"'
        + BASE
        + '","merge_sha":"'
        + MERGE
        + '","merge_tree_sha":"'
        + TREE
        + '","head_ref":"branch","protected_changes":'
        + json.dumps([{"path": ".github", "base_oid": BASE_OID, "subject_oid": SUBJECT_OID}])
        + "}"
    )
    with pytest.raises(ValueError):
        TrustedGateService._subject_from_json(rendered)


def test_persisted_subject_recovery_rejects_duplicate_transition_paths() -> None:
    raw = TrustedGateService._subject_json(_subject())
    raw["protected_changes"].append(dict(raw["protected_changes"][0]))
    with pytest.raises(ValueError):
        TrustedGateService._subject_from_json(json.dumps(raw))
