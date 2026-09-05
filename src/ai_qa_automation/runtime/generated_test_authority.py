from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..tools.repository import RepositoryInspector

_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_SUBJECT_KEYS = {
    "git_sha",
    "workspace_fingerprint",
    "workspace_root_identity",
    "change_revision",
}


class GeneratedTestAuthorityError(RuntimeError):
    """Raised when generated-test authority cannot be bound deterministically."""


@dataclass(frozen=True)
class GeneratedTestRepositorySubject:
    git_sha: str | None
    workspace_fingerprint: str
    workspace_root_identity: tuple[int, int]
    change_revision: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "git_sha": self.git_sha,
            "workspace_fingerprint": self.workspace_fingerprint,
            "workspace_root_identity": list(self.workspace_root_identity),
            "change_revision": self.change_revision,
        }


def canonical_sha256(value: Any) -> str:
    rendered = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return f"sha256:{hashlib.sha256(rendered.encode('utf-8')).hexdigest()}"


def text_sha256(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode('utf-8')).hexdigest()}"


def _require_sha256(label: str, value: object) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise GeneratedTestAuthorityError(f"generated-test {label} is invalid")
    return value


def _require_bounded_text(label: str, value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise GeneratedTestAuthorityError(f"generated-test {label} is invalid")
    return value


def capture_generated_test_repository_subject(
    workspace: Path,
    *,
    expected_root_identity: tuple[int, int] | None,
    change_revision: int,
) -> GeneratedTestRepositorySubject:
    if isinstance(change_revision, bool) or not isinstance(change_revision, int) or change_revision < 0:
        raise GeneratedTestAuthorityError("generated-test change revision is invalid")
    try:
        inspector = RepositoryInspector(
            workspace,
            expected_root_identity=expected_root_identity,
        )
        snapshot = inspector.snapshot()
    except (OSError, RuntimeError, ValueError) as exc:
        raise GeneratedTestAuthorityError(
            "generated-test repository subject could not be captured"
        ) from exc
    if not snapshot.fingerprint_complete:
        raise GeneratedTestAuthorityError(
            "generated-test repository fingerprint is incomplete"
        )
    if not _SHA256.fullmatch(snapshot.fingerprint):
        raise GeneratedTestAuthorityError(
            "generated-test repository fingerprint is malformed"
        )
    root_identity = inspector.workspace_root_identity
    if root_identity is None:
        raise GeneratedTestAuthorityError(
            "generated-test repository root identity is unavailable"
        )
    git_sha = snapshot.git_sha
    if git_sha is not None and (
        len(git_sha) not in {40, 64}
        or any(char not in "0123456789abcdef" for char in git_sha)
    ):
        raise GeneratedTestAuthorityError("generated-test Git subject is malformed")
    return GeneratedTestRepositorySubject(
        git_sha=git_sha,
        workspace_fingerprint=snapshot.fingerprint,
        workspace_root_identity=root_identity,
        change_revision=change_revision,
    )


def parse_generated_test_repository_subject(value: object) -> GeneratedTestRepositorySubject:
    if not isinstance(value, dict) or set(value) != _SUBJECT_KEYS:
        raise GeneratedTestAuthorityError("generated-test repository subject structure is invalid")
    git_sha = value.get("git_sha")
    if git_sha is not None and (
        not isinstance(git_sha, str)
        or len(git_sha) not in {40, 64}
        or any(char not in "0123456789abcdef" for char in git_sha)
    ):
        raise GeneratedTestAuthorityError("generated-test repository Git subject is invalid")
    fingerprint = value.get("workspace_fingerprint")
    if not isinstance(fingerprint, str) or not _SHA256.fullmatch(fingerprint):
        raise GeneratedTestAuthorityError(
            "generated-test repository fingerprint is invalid"
        )
    raw_root = value.get("workspace_root_identity")
    if (
        not isinstance(raw_root, list)
        or len(raw_root) != 2
        or any(isinstance(part, bool) or not isinstance(part, int) or part < 0 for part in raw_root)
    ):
        raise GeneratedTestAuthorityError(
            "generated-test repository root identity is invalid"
        )
    revision = value.get("change_revision")
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
        raise GeneratedTestAuthorityError("generated-test repository revision is invalid")
    return GeneratedTestRepositorySubject(
        git_sha=git_sha,
        workspace_fingerprint=fingerprint,
        workspace_root_identity=(raw_root[0], raw_root[1]),
        change_revision=revision,
    )


def require_same_generated_test_repository_subject(
    expected: object,
    current: GeneratedTestRepositorySubject,
) -> None:
    parsed = parse_generated_test_repository_subject(expected)
    if parsed != current:
        raise GeneratedTestAuthorityError(
            "generated-test repository subject changed since the authority evidence was captured"
        )


def generated_test_plan_subject(
    *,
    coverage_evidence_id: str,
    coverage_evidence_digest: str,
    coverage_complete: bool,
    requirement_evidence_id: str,
    requirement_evidence_digest: str,
    requirement_digest: str,
    requirement_provenance: str,
    repository_subject: GeneratedTestRepositorySubject,
    selected_scenario_id: str,
    selected_assertion_contract_digest: str,
    advisory_existing_coverage_digest: str,
    plan: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(coverage_complete, bool):
        raise GeneratedTestAuthorityError("generated-test coverage completeness is invalid")
    for label, value in {
        "coverage_evidence_digest": coverage_evidence_digest,
        "requirement_evidence_digest": requirement_evidence_digest,
        "requirement_digest": requirement_digest,
        "selected_scenario_id": selected_scenario_id,
        "selected_assertion_contract_digest": selected_assertion_contract_digest,
        "advisory_existing_coverage_digest": advisory_existing_coverage_digest,
    }.items():
        _require_sha256(label, value)
    for label, value in {
        "coverage_evidence_id": coverage_evidence_id,
        "requirement_evidence_id": requirement_evidence_id,
        "requirement_provenance": requirement_provenance,
    }.items():
        _require_bounded_text(label, value)
    if not isinstance(plan, dict):
        raise GeneratedTestAuthorityError("generated-test plan payload is invalid")
    payload = {
        "schema_version": 1,
        "coverage_evidence_id": coverage_evidence_id,
        "coverage_evidence_digest": coverage_evidence_digest,
        "coverage_complete": coverage_complete,
        "requirement_evidence_id": requirement_evidence_id,
        "requirement_evidence_digest": requirement_evidence_digest,
        "requirement_digest": requirement_digest,
        "requirement_provenance": requirement_provenance,
        "repository_subject": repository_subject.as_dict(),
        "selected_scenario_id": selected_scenario_id,
        "selected_assertion_contract_digest": selected_assertion_contract_digest,
        "advisory_existing_coverage_digest": advisory_existing_coverage_digest,
        "plan": plan,
    }
    return {**payload, "plan_subject_id": canonical_sha256(payload)}


def generated_test_proposal_subject(
    *,
    coverage_evidence_id: str,
    coverage_evidence_digest: str,
    requirement_evidence_id: str,
    requirement_digest: str,
    plan_evidence_id: str,
    plan_subject_id: str,
    scenario_id: str,
    layer: str,
    assertion_contract_digest: str,
    target_path: str,
    content_sha256: str,
    repository_subject: GeneratedTestRepositorySubject,
) -> dict[str, Any]:
    for label, value in {
        "coverage_evidence_digest": coverage_evidence_digest,
        "requirement_digest": requirement_digest,
        "plan_subject_id": plan_subject_id,
        "scenario_id": scenario_id,
        "assertion_contract_digest": assertion_contract_digest,
        "content_sha256": content_sha256,
    }.items():
        _require_sha256(label, value)
    for label, value in {
        "coverage_evidence_id": coverage_evidence_id,
        "requirement_evidence_id": requirement_evidence_id,
        "plan_evidence_id": plan_evidence_id,
        "layer": layer,
        "target_path": target_path,
    }.items():
        _require_bounded_text(label, value)
    payload = {
        "schema_version": 1,
        "coverage_evidence_id": coverage_evidence_id,
        "coverage_evidence_digest": coverage_evidence_digest,
        "requirement_evidence_id": requirement_evidence_id,
        "requirement_digest": requirement_digest,
        "plan_evidence_id": plan_evidence_id,
        "plan_subject_id": plan_subject_id,
        "scenario_id": scenario_id,
        "layer": layer,
        "assertion_contract_digest": assertion_contract_digest,
        "target_path": target_path,
        "content_sha256": content_sha256,
        "repository_subject": repository_subject.as_dict(),
        "semantic_implementation_verified": False,
    }
    return {
        **payload,
        "proposal_subject_id": canonical_sha256(payload),
    }
