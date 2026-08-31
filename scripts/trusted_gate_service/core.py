from __future__ import annotations

import hashlib
import hmac
import io
import json
import re
import stat
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import PurePosixPath
from typing import Any

EXPECTED_REPOSITORY = "portyu9/ai-qa-automation"
EXPECTED_REPOSITORY_ID = 1341984495
EXPECTED_OWNER = "portyu9"
EXPECTED_DEFAULT_BRANCH = "main"
EXPECTED_WORKFLOW_ID = 339754724
EXPECTED_WORKFLOW_NAME = "CI — ƳƤ AI QA Automation Framework"
EXPECTED_WORKFLOW_PATH = ".github/workflows/ci.yml"
EXPECTED_REQUIRED_JOB = "Required PR Gate"
EXPECTED_REQUIRED_STEP = "Require every automatic gate to succeed"
EXPECTED_SUPPLY_CHAIN_JOB = "Supply Chain / Wheel + SBOM + Container"
EXPECTED_SUPPLY_CHAIN_ARTIFACT = "supply-chain-evidence"
EXPECTED_BUILD_MANIFEST = "build-manifest.json"
EXPECTED_CI_CONTRACT_STEP = "Verify CI authority contract"
EXPECTED_STATUS_CONTEXT = "Trusted PR Gate"
EXPECTED_SUBJECT_BINDING = (
    "CI_SUBJECT_SHA: ${{ github.event_name == 'repository_dispatch' "
    "&& github.event.client_payload.expected_merge_sha || github.sha }}"
)
MAX_WEBHOOK_BYTES = 2 * 1024 * 1024
MAX_API_BYTES = 8 * 1024 * 1024
MAX_ARTIFACT_BYTES = 4 * 1024 * 1024
MAX_ARTIFACT_ENTRIES = 32
MAX_ARTIFACT_UNCOMPRESSED_BYTES = 8 * 1024 * 1024
MAX_BUILD_MANIFEST_BYTES = 256 * 1024
MAX_POLICY_BYTES = 256 * 1024
MAX_JOBS = 100
MAX_DELIVERY_ID = 128
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
PROTECTED_PATHS = (
    ".github",
    ".claude",
    ".dockerignore",
    ".gitattributes",
    ".mcp.json",
    ".pre-commit-config.yaml",
    "CLAUDE.md",
    "Dockerfile",
    "evals",
    "examples",
    "pyproject.toml",
    "requirements",
    "scripts",
    "tests",
    "src/ai_qa_automation/__init__.py",
    "src/ai_qa_automation/io_safety.py",
    "src/ai_qa_automation/tools/__init__.py",
    "src/ai_qa_automation/tools/execution_env.py",
)
PROTECTED_PATH_SET = frozenset(PROTECTED_PATHS)


class StrictJsonError(ValueError):
    pass


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StrictJsonError("duplicate JSON object key")
        result[key] = value
    return result


def strict_json_loads(payload: bytes, *, max_bytes: int, label: str) -> Any:
    if len(payload) > max_bytes:
        raise StrictJsonError(f"{label} exceeds bounded size")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise StrictJsonError(f"{label} must be UTF-8") from exc
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(
                StrictJsonError("non-standard JSON number")
            ),
        )
    except json.JSONDecodeError as exc:
        raise StrictJsonError(f"{label} is malformed JSON") from exc


def require_dict(value: Any, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def require_list(value: Any, *, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be an array")
    return value


def require_str(value: Any, *, label: str, max_len: int = 1024) -> str:
    if not isinstance(value, str) or not value or len(value) > max_len:
        raise ValueError(f"{label} must be a bounded non-empty string")
    return value


def require_positive_int(value: Any, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{label} must be a positive integer")
    return value


def require_sha(value: Any, *, label: str) -> str:
    rendered = require_str(value, label=label, max_len=40)
    if FULL_SHA_RE.fullmatch(rendered) is None:
        raise ValueError(f"{label} must be a full lowercase SHA-1")
    return rendered


@dataclass(frozen=True, order=True)
class ProtectedTransition:
    path: str
    base_oid: str
    subject_oid: str

    @classmethod
    def from_json(cls, value: Any) -> "ProtectedTransition":
        item = require_dict(value, label="protected transition")
        if set(item) != {"path", "base_oid", "subject_oid"}:
            raise ValueError("protected transition fields are not exact")
        path = require_str(item["path"], label="protected transition path", max_len=256)
        if path not in PROTECTED_PATH_SET:
            raise ValueError("protected transition path is not recognized")
        base_oid = item["base_oid"]
        subject_oid = item["subject_oid"]
        for label, oid in (("base_oid", base_oid), ("subject_oid", subject_oid)):
            if oid != "MISSING" and (
                not isinstance(oid, str) or FULL_SHA_RE.fullmatch(oid) is None
            ):
                raise ValueError(f"protected transition {label} is invalid")
        return cls(path=path, base_oid=base_oid, subject_oid=subject_oid)

    def as_json(self) -> dict[str, str]:
        return {"path": self.path, "base_oid": self.base_oid, "subject_oid": self.subject_oid}


@dataclass(frozen=True)
class Subject:
    pr_number: int
    head_sha: str
    base_sha: str
    merge_sha: str
    merge_tree_sha: str
    head_ref: str
    protected_changes: tuple[ProtectedTransition, ...]


@dataclass(frozen=True)
class OneShotPolicy:
    schema_version: int
    policy_id: str
    repository: str
    repository_id: int
    pr_number: int
    head_sha: str
    base_sha: str
    merge_sha: str
    protected_changes: tuple[ProtectedTransition, ...]
    not_before: datetime
    expires_at: datetime

    @classmethod
    def parse(cls, payload: bytes) -> "OneShotPolicy":
        raw = require_dict(
            strict_json_loads(payload, max_bytes=MAX_POLICY_BYTES, label="maintenance policy"),
            label="maintenance policy",
        )
        expected_fields = {
            "schema_version",
            "policy_id",
            "repository",
            "repository_id",
            "pr_number",
            "head_sha",
            "base_sha",
            "merge_sha",
            "protected_changes",
            "not_before",
            "expires_at",
        }
        if set(raw) != expected_fields:
            raise ValueError("maintenance policy fields are not exact")
        if raw["schema_version"] != 1:
            raise ValueError("maintenance policy schema version is unsupported")
        policy_id = require_str(raw["policy_id"], label="policy id", max_len=128)
        repository = require_str(raw["repository"], label="policy repository", max_len=256)
        repository_id = require_positive_int(raw["repository_id"], label="policy repository id")
        pr_number = require_positive_int(raw["pr_number"], label="policy pull request number")
        head_sha = require_sha(raw["head_sha"], label="policy head SHA")
        base_sha = require_sha(raw["base_sha"], label="policy base SHA")
        merge_sha = require_sha(raw["merge_sha"], label="policy merge SHA")
        transitions = tuple(
            sorted(
                ProtectedTransition.from_json(item)
                for item in require_list(raw["protected_changes"], label="policy protected changes")
            )
        )
        if (
            not transitions
            or len(transitions) > len(PROTECTED_PATHS)
            or len({item.path for item in transitions}) != len(transitions)
        ):
            raise ValueError("policy protected changes are empty, duplicate, or excessive")
        not_before = _parse_time(raw["not_before"], label="policy not_before")
        expires_at = _parse_time(raw["expires_at"], label="policy expires_at")
        if expires_at <= not_before:
            raise ValueError("policy expiry must be after activation")
        return cls(
            schema_version=1,
            policy_id=policy_id,
            repository=repository,
            repository_id=repository_id,
            pr_number=pr_number,
            head_sha=head_sha,
            base_sha=base_sha,
            merge_sha=merge_sha,
            protected_changes=transitions,
            not_before=not_before,
            expires_at=expires_at,
        )

    def admit(
        self, *, subject: Subject, repository: str, repository_id: int, now: datetime
    ) -> None:
        if now.tzinfo is None:
            raise ValueError("policy evaluation time must be timezone-aware")
        now = now.astimezone(UTC)
        if self.repository != EXPECTED_REPOSITORY or self.repository_id != EXPECTED_REPOSITORY_ID:
            raise PermissionError("policy is not bound to the reviewed repository")
        if repository != self.repository or repository_id != self.repository_id:
            raise PermissionError("live repository identity does not match policy")
        if not (self.not_before <= now < self.expires_at):
            raise PermissionError("maintenance policy is not active")
        if (
            subject.pr_number != self.pr_number
            or subject.head_sha != self.head_sha
            or subject.base_sha != self.base_sha
            or subject.merge_sha != self.merge_sha
            or subject.protected_changes != self.protected_changes
        ):
            raise PermissionError(
                "live protected subject does not match the one-shot maintenance policy"
            )


def _parse_time(value: Any, *, label: str) -> datetime:
    text = require_str(value, label=label, max_len=64)
    if not text.endswith("Z"):
        raise ValueError(f"{label} must use UTC Z notation")
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{label} is not an ISO-8601 timestamp") from exc
    return parsed.astimezone(UTC)


def verify_webhook_signature(*, secret: bytes, body: bytes, signature_header: str | None) -> None:
    if not secret:
        raise ValueError("webhook secret is required")
    if len(body) > MAX_WEBHOOK_BYTES:
        raise ValueError("webhook body exceeds bounded size")
    if not signature_header or not signature_header.startswith("sha256="):
        raise PermissionError("webhook SHA-256 signature is missing")
    supplied = signature_header.removeprefix("sha256=")
    if DIGEST_RE.fullmatch(supplied) is None:
        raise PermissionError("webhook SHA-256 signature is malformed")
    expected = hmac.new(secret, body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, supplied):
        raise PermissionError("webhook SHA-256 signature mismatch")


@dataclass(frozen=True)
class Wakeup:
    delivery_id: str
    installation_id: int
    repository: str
    repository_id: int
    run_id: int
    event_head_sha: str


def parse_workflow_run_wakeup(
    *, event_header: str | None, delivery_header: str | None, body: bytes
) -> Wakeup:
    if event_header != "workflow_run":
        raise ValueError("webhook event is not workflow_run")
    delivery_id = require_str(delivery_header, label="webhook delivery id", max_len=MAX_DELIVERY_ID)
    raw = require_dict(
        strict_json_loads(body, max_bytes=MAX_WEBHOOK_BYTES, label="webhook body"),
        label="webhook body",
    )
    if raw.get("action") != "completed":
        raise ValueError("workflow_run action must be completed")
    repository = require_dict(raw.get("repository"), label="webhook repository")
    installation = require_dict(raw.get("installation"), label="webhook installation")
    run = require_dict(raw.get("workflow_run"), label="webhook workflow run")
    repo_name = require_str(repository.get("full_name"), label="webhook repository name", max_len=256)
    repo_id = require_positive_int(repository.get("id"), label="webhook repository id")
    installation_id = require_positive_int(installation.get("id"), label="webhook installation id")
    run_id = require_positive_int(run.get("id"), label="webhook workflow run id")
    event_head_sha = require_sha(run.get("head_sha"), label="webhook workflow head SHA")
    return Wakeup(
        delivery_id=delivery_id,
        installation_id=installation_id,
        repository=repo_name,
        repository_id=repo_id,
        run_id=run_id,
        event_head_sha=event_head_sha,
    )


def derive_protected_changes(
    base_tree: dict[str, str], subject_tree: dict[str, str]
) -> tuple[ProtectedTransition, ...]:
    rows: list[ProtectedTransition] = []
    for path in PROTECTED_PATHS:
        base_oid = base_tree.get(path, "MISSING")
        subject_oid = subject_tree.get(path, "MISSING")
        if base_oid != subject_oid:
            rows.append(ProtectedTransition(path=path, base_oid=base_oid, subject_oid=subject_oid))
    return tuple(sorted(rows))


def verify_jobs(payload: Any) -> dict[str, list[str]]:
    data = require_dict(payload, label="workflow jobs response")
    total = data.get("total_count")
    jobs = require_list(data.get("jobs"), label="workflow jobs")
    if isinstance(total, bool) or not isinstance(total, int) or total < 1 or total > MAX_JOBS:
        raise ValueError("workflow job count is outside bounds")
    if len(jobs) != total:
        raise ValueError("workflow jobs response is incomplete")
    by_name: dict[str, dict[str, Any]] = {}
    for raw in jobs:
        job = require_dict(raw, label="workflow job")
        name = require_str(job.get("name"), label="workflow job name", max_len=256)
        if name in by_name:
            raise ValueError("workflow jobs contain duplicate names")
        by_name[name] = job
    required_names = (
        EXPECTED_SUPPLY_CHAIN_JOB,
        "Security Gates",
        "Playwright Reference SUT",
        "34-Case Deterministic Control Evaluation",
        EXPECTED_REQUIRED_JOB,
    )
    for name in required_names:
        if name not in by_name or by_name[name].get("conclusion") != "success":
            raise ValueError(f"required evidence job did not succeed: {name}")
    quality = sorted(name for name in by_name if name.startswith("Quality / Python "))
    if len(quality) != 2 or any(by_name[name].get("conclusion") != "success" for name in quality):
        raise ValueError("exactly two successful Python quality jobs are required")
    if not _step_success(by_name[EXPECTED_SUPPLY_CHAIN_JOB], EXPECTED_CI_CONTRACT_STEP):
        raise ValueError("CI authority contract step did not succeed")
    if not _step_success(by_name[EXPECTED_REQUIRED_JOB], EXPECTED_REQUIRED_STEP):
        raise ValueError("Required PR Gate aggregate step did not succeed")
    return {"required_jobs": sorted(required_names), "quality_jobs": quality}


def _step_success(job: dict[str, Any], expected_name: str) -> bool:
    steps = job.get("steps")
    if not isinstance(steps, list):
        return False
    matches = [
        item for item in steps if isinstance(item, dict) and item.get("name") == expected_name
    ]
    return len(matches) == 1 and matches[0].get("conclusion") == "success"


def verify_candidate_workflow(text: str) -> None:
    if EXPECTED_SUBJECT_BINDING not in text:
        raise ValueError("candidate workflow is not subject-bound")
    if "\n  pull_request:\n" not in text:
        raise ValueError("candidate workflow lacks reviewed pull_request trigger")
    if f"\n    name: {EXPECTED_REQUIRED_JOB}\n" not in text:
        raise ValueError("candidate workflow lacks deterministic Required PR Gate")


def verify_build_manifest_archive(
    archive: bytes, *, expected_merge_sha: str, expected_tree_sha: str
) -> dict[str, str]:
    if len(archive) < 1 or len(archive) > MAX_ARTIFACT_BYTES:
        raise ValueError("artifact archive size is outside bounds")
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
            infos = bundle.infolist()
            if not infos or len(infos) > MAX_ARTIFACT_ENTRIES:
                raise ValueError("artifact entry count is outside bounds")
            seen: set[str] = set()
            total_uncompressed = 0
            manifest_info: zipfile.ZipInfo | None = None
            for info in infos:
                name = info.filename
                path = PurePosixPath(name)
                mode = info.external_attr >> 16
                if (
                    not name
                    or "\\" in name
                    or "\x00" in name
                    or path.is_absolute()
                    or ".." in path.parts
                    or name in seen
                    or info.is_dir()
                    or stat.S_IFMT(mode) not in {0, stat.S_IFREG}
                    or info.flag_bits & 0x1
                ):
                    raise ValueError("artifact contains unsafe or duplicate entry")
                seen.add(name)
                total_uncompressed += info.file_size
                if total_uncompressed > MAX_ARTIFACT_UNCOMPRESSED_BYTES:
                    raise ValueError("artifact uncompressed size exceeds bound")
                if name == EXPECTED_BUILD_MANIFEST:
                    manifest_info = info
            if manifest_info is None:
                raise ValueError("artifact is missing build-manifest.json")
            if not 1 <= manifest_info.file_size <= MAX_BUILD_MANIFEST_BYTES:
                raise ValueError("build manifest size is outside bounds")
            manifest_bytes = bundle.read(manifest_info)
    except zipfile.BadZipFile as exc:
        raise ValueError("artifact is not a valid ZIP") from exc
    manifest = require_dict(
        strict_json_loads(
            manifest_bytes, max_bytes=MAX_BUILD_MANIFEST_BYTES, label="build manifest"
        ),
        label="build manifest",
    )
    if (
        manifest.get("schema_version") != 1
        or manifest.get("kind") != "unsigned_reproducible_build_manifest"
    ):
        raise ValueError("build manifest schema/kind is not reviewed")
    source = require_dict(manifest.get("source"), label="build manifest source")
    commit = require_sha(source.get("commit_sha"), label="build manifest commit SHA")
    tree = require_sha(source.get("tree_sha"), label="build manifest tree SHA")
    if commit != expected_merge_sha or tree != expected_tree_sha:
        raise ValueError("build manifest subject identity mismatch")
    if source.get("tracked_worktree_clean") is not True:
        raise ValueError("build manifest did not record a clean tracked worktree")
    return {"commit_sha": commit, "tree_sha": tree}
