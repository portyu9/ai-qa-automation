from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from scripts.trusted_gate_service.core import EXPECTED_REPOSITORY, EXPECTED_REPOSITORY_ID
from scripts.trusted_gate_service.service import ServiceConfig, TrustedGateService

SECRET = b"service-prefilter-webhook-secret"
INSTALLATION_ID = 12345
DELIVERY = "00000000-0000-0000-0000-000000000092"
EVENT_HEAD = "1" * 40
POLICY_HEAD = "9" * 40


class FailOnAcquireStore:
    def acquire(self, *, delivery_id: str, run_id: int) -> Any:
        del delivery_id, run_id
        raise AssertionError("policy-head mismatch must reject before durable delivery acquisition")


class FailOnGitHubUse:
    repository = EXPECTED_REPOSITORY
    repository_id = EXPECTED_REPOSITORY_ID
    installation_id = INSTALLATION_ID

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(f"policy-head mismatch must reject before GitHub access: {name}")


def _policy_bytes() -> bytes:
    now = datetime.now(UTC)
    return json.dumps(
        {
            "schema_version": 1,
            "policy_id": "service-prefilter-test",
            "repository": EXPECTED_REPOSITORY,
            "repository_id": EXPECTED_REPOSITORY_ID,
            "pr_number": 92,
            "head_sha": POLICY_HEAD,
            "base_sha": "2" * 40,
            "merge_sha": "3" * 40,
            "protected_changes": [
                {"path": "scripts", "base_oid": "4" * 40, "subject_oid": "5" * 40}
            ],
            "not_before": (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
            "expires_at": (now + timedelta(minutes=30)).isoformat().replace("+00:00", "Z"),
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _body() -> bytes:
    return json.dumps(
        {
            "action": "completed",
            "installation": {"id": INSTALLATION_ID},
            "repository": {"id": EXPECTED_REPOSITORY_ID, "full_name": EXPECTED_REPOSITORY},
            "workflow_run": {"id": 9200, "head_sha": EVENT_HEAD},
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def test_authenticated_policy_head_mismatch_is_blocked_before_store_or_github(
    tmp_path: Path,
) -> None:
    policy = _policy_bytes()
    policy_path = tmp_path / "policy.json"
    policy_path.write_bytes(policy)
    service = TrustedGateService(
        config=ServiceConfig(
            webhook_secret=SECRET,
            installation_id=INSTALLATION_ID,
            expected_creator_login="trusted-pr-gate[bot]",
            policy_path=policy_path,
            policy_sha256=hashlib.sha256(policy).hexdigest(),
        ),
        store=FailOnAcquireStore(),  # type: ignore[arg-type]
        github=FailOnGitHubUse(),  # type: ignore[arg-type]
    )
    body = _body()
    signature = "sha256=" + hmac.new(SECRET, body, hashlib.sha256).hexdigest()

    result = service.handle_delivery(
        event_header="workflow_run",
        delivery_header=DELIVERY,
        signature_header=signature,
        body=body,
    )

    assert result.outcome == "BLOCKED"
    assert result.reason == "policy_head_mismatch"
    assert result.status_published is False
