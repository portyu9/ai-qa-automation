from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from ..fs_authority import (
    descriptor_relative_authority_supported,
    pin_directory_identity,
    read_bytes_confined,
    stat_confined_entry,
)
from ..fs_observation import ConfinedFileScan, scan_regular_files_confined
from ..models import (
    AgentRunState,
    ControlPlaneFileSubject,
    ControlPlaneManifest,
    ControlPlaneRevalidationStatus,
    ControlPlaneSubject,
    TerminalStatus,
)

_MAX_PROJECT_ENTRIES = 4_096
_MAX_CONTROLLER_ENTRIES = 8_192
_MAX_FILE_BYTES = 4_000_000
_MAX_PROJECT_TOTAL_BYTES = 32_000_000
_MAX_CONTROLLER_TOTAL_BYTES = 64_000_000
_HASH_PREFIX = "sha256:"

TRUSTED_PROJECT_SKILLS = (
    "investigate-test-failure",
    "self-heal-test",
    "generate-test",
    "prioritize-regression",
    "performance-test",
)
_REQUIRED_PROJECT_CLAUDE_FILES = frozenset(
    {"settings.json", *(f"skills/{name}/SKILL.md" for name in TRUSTED_PROJECT_SKILLS)}
)


@dataclass(frozen=True)
class ControlPlaneObservation:
    project_root_identity: tuple[int, int]
    project_metadata_digest: str
    controller_root_identity: tuple[int, int]
    controller_metadata_digest: str


@dataclass(frozen=True)
class ControlPlaneCapture:
    subject: ControlPlaneSubject
    observation: ControlPlaneObservation


def controller_package_root() -> Path:
    """Return the live package root whose source/resources define controller behavior."""

    return Path(__file__).resolve().parents[1]


def capture_control_plane_subject(
    control_root: Path,
    *,
    controller_root: Path | None = None,
) -> ControlPlaneCapture:
    """Capture an exact bounded subject for project authority and controller package bytes.

    The content-addressed subject always includes the live project inputs and
    controller package manifest. Git identity is bound separately only after the
    caller proves the byte subject remained stable around Git observation.
    """

    if not descriptor_relative_authority_supported():
        raise RuntimeError(
            "control-plane provenance requires descriptor-relative filesystem authority"
        )
    root = control_root.expanduser().absolute()
    package = (controller_root or controller_package_root()).expanduser().absolute()

    project_manifest, project_root_identity, project_metadata_digest = _capture_project(root)
    controller_manifest, controller_root_identity, controller_metadata_digest = _capture_tree(
        package,
        label="controller package provenance",
        max_entries=_MAX_CONTROLLER_ENTRIES,
        max_total_bytes=_MAX_CONTROLLER_TOTAL_BYTES,
        ignored_names=frozenset({"__pycache__"}),
    )
    canonical_subject = {
        "schema": "ai-qa-control-plane-subject/v1",
        "project_manifest_digest": project_manifest.digest,
        "controller_manifest_digest": controller_manifest.digest,
    }
    subject_digest = _canonical_digest(canonical_subject)
    subject = ControlPlaneSubject(
        subject_digest=subject_digest,
        project_manifest=project_manifest,
        controller_manifest=controller_manifest,
    )
    return ControlPlaneCapture(
        subject=subject,
        observation=ControlPlaneObservation(
            project_root_identity=project_root_identity,
            project_metadata_digest=project_metadata_digest,
            controller_root_identity=controller_root_identity,
            controller_metadata_digest=controller_metadata_digest,
        ),
    )


def bind_control_git_identity(
    capture: ControlPlaneCapture,
    *,
    control_git_sha: str | None,
    control_git_clean: bool | None,
) -> ControlPlaneCapture:
    """Attach supporting Git identity without changing the content-addressed subject."""

    subject = ControlPlaneSubject(
        subject_digest=capture.subject.subject_digest,
        project_manifest=capture.subject.project_manifest,
        controller_manifest=capture.subject.controller_manifest,
        control_git_sha=control_git_sha,
        control_git_clean=control_git_clean,
    )
    return ControlPlaneCapture(subject=subject, observation=capture.observation)


def same_control_plane_capture(
    left: ControlPlaneCapture, right: ControlPlaneCapture
) -> bool:
    """Return whether two captures identify the same bytes and ownership observation."""

    return (
        left.subject.subject_digest == right.subject.subject_digest
        and left.observation == right.observation
    )


def enforce_terminal_control_plane_subject(
    state: AgentRunState,
    *,
    bound: ControlPlaneCapture,
    control_root: Path,
    controller_root: Path | None = None,
) -> tuple[ControlPlaneRevalidationStatus, str]:
    """Revalidate the bound control subject and conservatively demote candidate SUCCESS."""

    try:
        current = capture_control_plane_subject(
            control_root,
            controller_root=controller_root,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        status = ControlPlaneRevalidationStatus.UNAVAILABLE
        state.control_plane_revalidation_status = status
        state.control_plane_terminal_subject_digest = None
        reason = (
            "trusted control-plane subject could not be revalidated safely: "
            f"{type(exc).__name__}"
        )
        if state.terminal_status is None or state.terminal_status is TerminalStatus.SUCCESS:
            state.terminal_status = TerminalStatus.INFRASTRUCTURE_FAILURE
            state.terminal_reason = (
                "Terminal success was refused because trusted control-plane identity "
                "could not be revalidated safely."
            )
        return status, reason

    state.control_plane_terminal_subject_digest = current.subject.subject_digest
    content_matches = current.subject.subject_digest == bound.subject.subject_digest
    ownership_matches = current.observation == bound.observation
    if content_matches and ownership_matches:
        status = ControlPlaneRevalidationStatus.VERIFIED
        reason = "trusted control-plane subject matches the bound run-start subject"
    else:
        status = ControlPlaneRevalidationStatus.DRIFTED
        reason = (
            "trusted control-plane content changed during the run"
            if not content_matches
            else "trusted control-plane filesystem ownership/metadata changed during the run"
        )
        if state.terminal_status is None or state.terminal_status is TerminalStatus.SUCCESS:
            state.terminal_status = TerminalStatus.BLOCKED
            state.terminal_reason = (
                "Terminal success was refused because the trusted control-plane subject drifted "
                "after run-start provenance was bound."
            )
    state.control_plane_revalidation_status = status
    return status, reason


def _capture_project(root: Path) -> tuple[ControlPlaneManifest, tuple[int, int], str]:
    root_identity = pin_directory_identity(root, label="control-plane project root")

    claude_entry = stat_confined_entry(
        root,
        ".claude",
        label="control-plane .claude directory",
        expected_root_identity=root_identity,
    )
    if not stat.S_ISDIR(claude_entry.st_mode):
        raise ValueError("trusted .claude authority must be a regular directory")
    claude_identity = (claude_entry.st_dev, claude_entry.st_ino)

    claude_file, claude_metadata = _capture_single_file(
        root,
        "CLAUDE.md",
        expected_root_identity=root_identity,
        label="control-plane CLAUDE.md",
    )
    mcp_file, mcp_metadata, mcp_absent = _capture_optional_file(
        root,
        ".mcp.json",
        expected_root_identity=root_identity,
        label="control-plane .mcp.json",
    )
    claude_manifest, observed_claude_identity, claude_tree_metadata = _capture_tree(
        root / ".claude",
        label="control-plane .claude provenance",
        max_entries=_MAX_PROJECT_ENTRIES,
        max_total_bytes=_MAX_PROJECT_TOTAL_BYTES,
        expected_root_identity=claude_identity,
    )
    if observed_claude_identity != claude_identity:
        raise ValueError("trusted .claude authority changed identity during capture")
    claude_paths = frozenset(item.path for item in claude_manifest.files)
    missing_required = sorted(_REQUIRED_PROJECT_CLAUDE_FILES - claude_paths)
    if missing_required:
        raise ValueError(
            "trusted .claude authority is missing required project inputs: "
            + ", ".join(missing_required)
        )

    final_claude = stat_confined_entry(
        root,
        ".claude",
        label="control-plane .claude directory",
        expected_root_identity=root_identity,
    )
    if _stable_signature(final_claude) != _stable_signature(claude_entry):
        raise ValueError("trusted .claude authority changed during capture")
    _verify_single_file_metadata(
        root,
        "CLAUDE.md",
        expected_root_identity=root_identity,
        expected_metadata=claude_metadata,
        label="control-plane CLAUDE.md",
    )
    _verify_optional_file_metadata(
        root,
        ".mcp.json",
        expected_root_identity=root_identity,
        expected_metadata=mcp_metadata,
        expected_absent=mcp_absent,
        label="control-plane .mcp.json",
    )

    prefixed_claude_files = tuple(
        ControlPlaneFileSubject(
            path=f".claude/{item.path}",
            size=item.size,
            content_hash=item.content_hash,
        )
        for item in claude_manifest.files
    )
    prefixed_directories = tuple(
        ".claude" if item == "." else f".claude/{item}"
        for item in claude_manifest.directories
    )
    files = tuple(
        sorted(
            (claude_file,) + ((mcp_file,) if mcp_file is not None else ()) + prefixed_claude_files,
            key=lambda item: item.path,
        )
    )
    prefixed_directories = tuple(sorted(prefixed_directories))
    absent_paths = (".mcp.json",) if mcp_absent else ()
    total_bytes = sum(item.size for item in files)
    if total_bytes > _MAX_PROJECT_TOTAL_BYTES:
        raise ValueError("control-plane project provenance exceeds total byte ingestion limit")
    manifest_payload = {
        "files": [item.model_dump(mode="json") for item in files],
        "directories": list(prefixed_directories),
        "absent_paths": list(absent_paths),
    }
    manifest = ControlPlaneManifest(
        digest=_canonical_digest(manifest_payload),
        files=files,
        directories=prefixed_directories,
        absent_paths=absent_paths,
        total_bytes=total_bytes,
    )
    metadata_payload = {
        "root_identity": root_identity,
        "claude_directory": _stable_signature(claude_entry),
        "claude_file": claude_metadata,
        "mcp_file": mcp_metadata,
        "mcp_absent": mcp_absent,
        "claude_tree": claude_tree_metadata,
    }
    return manifest, root_identity, _canonical_digest(metadata_payload)


def _capture_tree(
    root: Path,
    *,
    label: str,
    max_entries: int,
    max_total_bytes: int,
    ignored_names: frozenset[str] = frozenset(),
    expected_root_identity: tuple[int, int] | None = None,
) -> tuple[ControlPlaneManifest, tuple[int, int], str]:
    before = scan_regular_files_confined(
        root,
        max_entries=max_entries,
        ignored_names=ignored_names,
        label=label,
        expected_root_identity=expected_root_identity,
    )
    _require_complete_scan(before, label=label)
    total_bytes = 0
    files: list[ControlPlaneFileSubject] = []
    for observed in before.files:
        if observed.size > _MAX_FILE_BYTES:
            raise ValueError(f"{label} file exceeds per-file byte ingestion limit")
        total_bytes += observed.size
        if total_bytes > max_total_bytes:
            raise ValueError(f"{label} exceeds total byte ingestion limit")
        raw = read_bytes_confined(
            root,
            observed.path.as_posix(),
            max_bytes=_MAX_FILE_BYTES,
            label=f"{label} file {observed.path.as_posix()}",
            expected_root_identity=before.root_identity,
            expected_entry_identity=(
                observed.metadata_signature[0],
                observed.metadata_signature[1],
            ),
        )
        if len(raw) != observed.size:
            raise ValueError(f"{label} file size changed during capture")
        files.append(
            ControlPlaneFileSubject(
                path=observed.path.as_posix(),
                size=len(raw),
                content_hash=_hash_bytes(raw),
            )
        )

    after = scan_regular_files_confined(
        root,
        max_entries=max_entries,
        ignored_names=ignored_names,
        label=label,
        expected_root_identity=before.root_identity,
    )
    _require_complete_scan(after, label=label)
    if after != before:
        raise ValueError(f"{label} namespace changed during capture")

    directories = tuple(sorted(item.path.as_posix() for item in before.directories))
    ordered_files = tuple(sorted(files, key=lambda item: item.path))
    manifest_payload = {
        "files": [item.model_dump(mode="json") for item in ordered_files],
        "directories": list(directories),
        "absent_paths": [],
    }
    manifest = ControlPlaneManifest(
        digest=_canonical_digest(manifest_payload),
        files=ordered_files,
        directories=directories,
        absent_paths=(),
        total_bytes=total_bytes,
    )
    metadata_digest = _scan_metadata_digest(before)
    return manifest, before.root_identity, metadata_digest


def _capture_single_file(
    root: Path,
    relative_path: str,
    *,
    expected_root_identity: tuple[int, int],
    label: str,
) -> tuple[ControlPlaneFileSubject, tuple[int, ...]]:
    before = stat_confined_entry(
        root,
        relative_path,
        label=label,
        expected_root_identity=expected_root_identity,
    )
    if not stat.S_ISREG(before.st_mode):
        raise ValueError(f"{label} must be a regular file")
    if before.st_size > _MAX_FILE_BYTES:
        raise ValueError(f"{label} exceeds per-file byte ingestion limit")
    raw = read_bytes_confined(
        root,
        relative_path,
        max_bytes=_MAX_FILE_BYTES,
        label=label,
        expected_root_identity=expected_root_identity,
        expected_entry_identity=(before.st_dev, before.st_ino),
    )
    after = stat_confined_entry(
        root,
        relative_path,
        label=label,
        expected_root_identity=expected_root_identity,
    )
    if _stable_signature(after) != _stable_signature(before):
        raise ValueError(f"{label} changed during capture")
    return (
        ControlPlaneFileSubject(
            path=relative_path,
            size=len(raw),
            content_hash=_hash_bytes(raw),
        ),
        _stable_signature(before),
    )


def _capture_optional_file(
    root: Path,
    relative_path: str,
    *,
    expected_root_identity: tuple[int, int],
    label: str,
) -> tuple[ControlPlaneFileSubject | None, tuple[int, ...] | None, bool]:
    try:
        captured, metadata = _capture_single_file(
            root,
            relative_path,
            expected_root_identity=expected_root_identity,
            label=label,
        )
    except FileNotFoundError:
        return None, None, True
    return captured, metadata, False


def _verify_single_file_metadata(
    root: Path,
    relative_path: str,
    *,
    expected_root_identity: tuple[int, int],
    expected_metadata: tuple[int, ...],
    label: str,
) -> None:
    current = stat_confined_entry(
        root,
        relative_path,
        label=label,
        expected_root_identity=expected_root_identity,
    )
    if _stable_signature(current) != expected_metadata:
        raise ValueError(f"{label} changed during project provenance capture")


def _verify_optional_file_metadata(
    root: Path,
    relative_path: str,
    *,
    expected_root_identity: tuple[int, int],
    expected_metadata: tuple[int, ...] | None,
    expected_absent: bool,
    label: str,
) -> None:
    try:
        current = stat_confined_entry(
            root,
            relative_path,
            label=label,
            expected_root_identity=expected_root_identity,
        )
    except FileNotFoundError:
        if expected_absent:
            return
        raise ValueError(f"{label} disappeared during project provenance capture") from None
    if expected_absent:
        raise ValueError(f"{label} appeared during project provenance capture")
    if expected_metadata is None or _stable_signature(current) != expected_metadata:
        raise ValueError(f"{label} changed during project provenance capture")


def _require_complete_scan(scan: ConfinedFileScan, *, label: str) -> None:
    if scan.resource_truncated:
        raise ValueError(f"{label} namespace exceeds bounded observation resources")
    if scan.unsafe_paths or scan.unreadable_paths or scan.truncated:
        raise ValueError(f"{label} namespace cannot be observed completely and safely")


def _scan_metadata_digest(scan: ConfinedFileScan) -> str:
    payload = {
        "root_identity": scan.root_identity,
        "files": [
            {
                "path": item.path.as_posix(),
                "metadata": item.metadata_signature,
            }
            for item in scan.files
        ],
        "directories": [
            {
                "path": item.path.as_posix(),
                "ownership": item.metadata_signature[:3],
            }
            for item in scan.directories
        ],
    }
    return _canonical_digest(payload)


def _stable_signature(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _canonical_digest(payload: object) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return _hash_bytes(canonical.encode("utf-8"))


def _hash_bytes(value: bytes) -> str:
    return f"{_HASH_PREFIX}{hashlib.sha256(value).hexdigest()}"
