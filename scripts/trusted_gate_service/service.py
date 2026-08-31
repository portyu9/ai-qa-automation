from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .core import (
    EXPECTED_REPOSITORY,
    EXPECTED_REPOSITORY_ID,
    OneShotPolicy,
    Subject,
    parse_workflow_run_wakeup,
    verify_webhook_signature,
)
from .github import GitHubClient, GitHubProtocolError, GitHubTransportError
from .store import DeliveryLease, DeliveryStore


@dataclass(frozen=True)
class ServiceConfig:
    webhook_secret: bytes
    installation_id: int
    expected_creator_login: str
    policy_path: Path
    policy_sha256: str


@dataclass(frozen=True)
class DeliveryResult:
    outcome: str
    delivery_id: str
    reason: str
    status_published: bool


class TrustedGateService:
    def __init__(self, *, config: ServiceConfig, store: DeliveryStore, github: GitHubClient) -> None:
        if github.repository != EXPECTED_REPOSITORY or github.repository_id != EXPECTED_REPOSITORY_ID:
            raise ValueError("GitHub client is not bound to the reviewed repository")
        if github.installation_id != config.installation_id:
            raise ValueError("configured installation id differs from GitHub client")
        if not config.expected_creator_login or len(config.expected_creator_login) > 128:
            raise ValueError("expected App creator login is required")
        self._config = config
        self._store = store
        self._github = github
        self._policy = self._load_policy(config.policy_path, config.policy_sha256)

    @staticmethod
    def _load_policy(path: Path, expected_sha256: str) -> OneShotPolicy:
        if not path.is_absolute():
            raise ValueError("maintenance policy path must be absolute")
        if len(expected_sha256) != 64 or any(ch not in "0123456789abcdef" for ch in expected_sha256):
            raise ValueError("maintenance policy SHA-256 is malformed")
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        if not nofollow:
            raise RuntimeError("maintenance policy requires no-follow file ingestion")
        flags = os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(path, flags)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_size < 1 or before.st_size > 256 * 1024:
                raise ValueError("maintenance policy must be a bounded regular file")
            payload = bytearray()
            while len(payload) <= before.st_size:
                chunk = os.read(fd, min(64 * 1024, before.st_size + 1 - len(payload)))
                if not chunk:
                    break
                payload.extend(chunk)
            data = bytes(payload)
            after = os.fstat(fd)
        finally:
            os.close(fd)
        if len(data) != before.st_size:
            raise ValueError("maintenance policy changed or was incompletely read")
        sig_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        sig_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        if sig_before != sig_after:
            raise ValueError("maintenance policy changed during ingestion")
        observed = hashlib.sha256(data).hexdigest()
        if observed != expected_sha256:
            raise ValueError("maintenance policy digest differs from deployment configuration")
        return OneShotPolicy.parse(data)

    def handle_delivery(
        self,
        *,
        event_header: str | None,
        delivery_header: str | None,
        signature_header: str | None,
        body: bytes,
    ) -> DeliveryResult:
        verify_webhook_signature(
            secret=self._config.webhook_secret,
            body=body,
            signature_header=signature_header,
        )
        wakeup = parse_workflow_run_wakeup(
            event_header=event_header,
            delivery_header=delivery_header,
            body=body,
        )
        if wakeup.repository != EXPECTED_REPOSITORY or wakeup.repository_id != EXPECTED_REPOSITORY_ID:
            raise PermissionError("webhook repository identity is not authorized")
        if wakeup.installation_id != self._config.installation_id:
            raise PermissionError("webhook installation identity is not authorized")

        lease = self._store.acquire(delivery_id=wakeup.delivery_id, run_id=wakeup.run_id)
        if lease.terminal:
            return DeliveryResult(
                outcome=lease.state,
                delivery_id=wakeup.delivery_id,
                reason="duplicate_terminal_delivery",
                status_published=lease.state == "SUCCESS",
            )
        if lease.state == "PUBLISHING":
            return self._recover_publishing(lease)
        if lease.state != "PROCESSING":
            return DeliveryResult(
                outcome=lease.state,
                delivery_id=wakeup.delivery_id,
                reason="delivery_not_retryable_yet",
                status_published=False,
            )

        try:
            subject = self._github.resolve_subject(
                run_id=wakeup.run_id,
                event_head_sha=wakeup.event_head_sha,
            )
            self._policy.admit(
                subject=subject,
                repository=wakeup.repository,
                repository_id=wakeup.repository_id,
                now=datetime.now(UTC),
            )
            evidence = self._github.verify_run_evidence(run_id=wakeup.run_id, subject=subject)
            # Re-resolve after every evidence read and immediately before durable publication intent.
            terminal_subject = self._github.resolve_subject(
                run_id=wakeup.run_id,
                event_head_sha=wakeup.event_head_sha,
            )
            self._assert_same_subject(subject, terminal_subject)
            self._policy.admit(
                subject=terminal_subject,
                repository=wakeup.repository,
                repository_id=wakeup.repository_id,
                now=datetime.now(UTC),
            )
            target_url = str(evidence["target_url"])
            self._store.bind_subject(
                delivery_id=wakeup.delivery_id,
                subject=self._subject_json(terminal_subject),
                policy_id=self._policy.policy_id,
                target_url=target_url,
            )
            self._store.begin_publication(delivery_id=wakeup.delivery_id)
            response = self._github.publish_success(subject=terminal_subject, target_url=target_url)
            if response.get("state") != "success" or response.get("context") != "Trusted PR Gate":
                # Publication was attempted; do not retry automatically. Reconcile the exact live
                # status immediately and leave durable PUBLISHING truth if the side effect cannot
                # be proven.
                publishing = self._store.load(wakeup.delivery_id)
                if publishing is None:
                    raise RuntimeError("publication state disappeared after status attempt")
                return self._recover_publishing(publishing)
            post_publication_subject = self._github.resolve_subject(
                run_id=wakeup.run_id,
                event_head_sha=wakeup.event_head_sha,
            )
            self._assert_same_subject(terminal_subject, post_publication_subject)
            self._policy.admit(
                subject=post_publication_subject,
                repository=wakeup.repository,
                repository_id=wakeup.repository_id,
                now=datetime.now(UTC),
            )
            self._store.complete_publication(delivery_id=wakeup.delivery_id)
            return DeliveryResult(
                outcome="SUCCESS",
                delivery_id=wakeup.delivery_id,
                reason="exact_subject_policy_and_evidence_passed",
                status_published=True,
            )
        except GitHubTransportError:
            latest = self._store.load(wakeup.delivery_id)
            if latest is not None and latest.state == "PUBLISHING":
                return self._recover_publishing(latest)
            self._store.mark_retryable(delivery_id=wakeup.delivery_id, error_code="github_transport")
            return DeliveryResult("RETRYABLE", wakeup.delivery_id, "github_transport", False)
        except (GitHubProtocolError, PermissionError, ValueError, RuntimeError) as exc:
            # No attacker-controlled detail is persisted or returned. If publication began, fail closed
            # into recovery instead of relabeling an uncertain side effect as BLOCKED.
            latest = self._store.load(wakeup.delivery_id)
            if latest is not None and latest.state == "PUBLISHING":
                return self._recover_publishing(latest)
            self._store.mark_blocked(delivery_id=wakeup.delivery_id, error_code=type(exc).__name__)
            return DeliveryResult("BLOCKED", wakeup.delivery_id, type(exc).__name__, False)

    def _recover_publishing(self, lease: DeliveryLease) -> DeliveryResult:
        if not lease.subject_json or not lease.target_url or not lease.policy_id:
            return DeliveryResult("BLOCKED", lease.delivery_id, "incomplete_publication_recovery_state", False)
        try:
            subject = self._subject_from_json(lease.subject_json)
            if lease.policy_id != self._policy.policy_id:
                return DeliveryResult("BLOCKED", lease.delivery_id, "publication_policy_identity_drift", False)
            live_subject = self._github.resolve_subject(
                run_id=lease.run_id,
                event_head_sha=subject.head_sha,
            )
            self._assert_same_subject(subject, live_subject)
            self._policy.admit(
                subject=live_subject,
                repository=EXPECTED_REPOSITORY,
                repository_id=EXPECTED_REPOSITORY_ID,
                now=datetime.now(UTC),
            )
            if self._github.latest_matching_success(
                subject=subject,
                target_url=lease.target_url,
                expected_creator_login=self._config.expected_creator_login,
            ):
                self._store.complete_publication(delivery_id=lease.delivery_id)
                return DeliveryResult("SUCCESS", lease.delivery_id, "recovered_existing_exact_status", True)
        except (GitHubTransportError, GitHubProtocolError, PermissionError, ValueError, RuntimeError):
            pass
        # Never replay a commit-status POST after durable publication intent.
        return DeliveryResult("BLOCKED", lease.delivery_id, "publication_outcome_not_provable", False)

    @staticmethod
    def _assert_same_subject(left: Subject, right: Subject) -> None:
        if left != right:
            raise PermissionError("live subject drifted during evidence admission")

    @staticmethod
    def _subject_json(subject: Subject) -> dict[str, Any]:
        return {
            "pr_number": subject.pr_number,
            "head_sha": subject.head_sha,
            "base_sha": subject.base_sha,
            "merge_sha": subject.merge_sha,
            "merge_tree_sha": subject.merge_tree_sha,
            "head_ref": subject.head_ref,
            "protected_changes": [item.as_json() for item in subject.protected_changes],
        }

    @staticmethod
    def _subject_from_json(rendered: str) -> Subject:
        raw = json.loads(rendered)
        if not isinstance(raw, dict):
            raise ValueError("persisted subject is malformed")
        from .core import ProtectedTransition, require_list, require_positive_int, require_sha, require_str

        expected = {"pr_number", "head_sha", "base_sha", "merge_sha", "merge_tree_sha", "head_ref", "protected_changes"}
        if set(raw) != expected:
            raise ValueError("persisted subject fields are not exact")
        transitions = tuple(ProtectedTransition.from_json(item) for item in require_list(raw["protected_changes"], label="persisted protected changes"))
        return Subject(
            pr_number=require_positive_int(raw["pr_number"], label="persisted PR number"),
            head_sha=require_sha(raw["head_sha"], label="persisted head SHA"),
            base_sha=require_sha(raw["base_sha"], label="persisted base SHA"),
            merge_sha=require_sha(raw["merge_sha"], label="persisted merge SHA"),
            merge_tree_sha=require_sha(raw["merge_tree_sha"], label="persisted merge tree SHA"),
            head_ref=require_str(raw["head_ref"], label="persisted head ref", max_len=255),
            protected_changes=transitions,
        )
