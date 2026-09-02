from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from ai_qa_automation.evidence import EvidenceStore
from ai_qa_automation.fs_authority import descriptor_relative_authority_supported
from ai_qa_automation.models import AgentRunState
from ai_qa_automation.runtime.attestation import build_run_attestation
from ai_qa_automation.runtime.budget import ExecutionBudget
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.lineage import build_run_lineage
from ai_qa_automation.runtime.recovery import inspect_recovery
from ai_qa_automation.runtime.run_control import RuntimeControl
from ai_qa_automation.runtime.stale_recovery import recover_stale_mutation
from ai_qa_automation.runtime.workspace_lease import WorkspaceLease
from ai_qa_automation.state import StateStore


def _require_descriptor_authority() -> None:
    if not descriptor_relative_authority_supported():
        pytest.skip("descriptor-relative no-follow authority is unavailable on this platform")


def _replace_directory(path: Path) -> Path:
    moved = path.with_name(f"{path.name}-original")
    path.rename(moved)
    path.mkdir()
    return moved


def _identity(path: Path) -> tuple[int, int]:
    status = path.stat(follow_symlinks=False)
    return status.st_dev, status.st_ino


def _write_runtime_fixture(
    run_dir: Path,
    workspace: Path,
    journal: RunJournal,
    *,
    pending_mutation: dict[str, object] | None = None,
    fingerprint: str = "fp",
) -> None:
    workspace_status = workspace.stat(follow_symlinks=False)
    payload = {
        "lease_id": "lease-old",
        "workspace": str(workspace.resolve()),
        "workspace_root_identity": {
            "device": workspace_status.st_dev,
            "inode": workspace_status.st_ino,
        },
        "workspace_fingerprint": fingerprint,
        "budget": {
            "tool_calls": 0,
            "network_calls": 0,
            "mutations": 0,
            "elapsed_seconds": 0.0,
        },
        "journal_event_count": journal.event_count,
        "journal_head_hash": journal.head_hash,
        "circuit_failures": {},
        "open_circuits": [],
        "max_repeated_action": 3,
        "repeated_action_counts": {},
        "pending_mutation": pending_mutation,
        "updated_at": "2026-09-02T00:00:00+00:00",
    }
    (run_dir / "runtime.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def _create_inspection_run(tmp_path: Path) -> tuple[Path, Path]:
    workspace = tmp_path / "sut"
    workspace.mkdir()
    run_dir = tmp_path / "artifacts" / "run-owned"
    state_store = StateStore(run_dir / "state.json")
    state_store.save(
        AgentRunState(
            run_id="run-owned",
            objective="inspect persisted authority",
            workspace=str(workspace),
        )
    )
    journal = RunJournal(
        run_dir / "journal.jsonl",
        expected_parent_identity=state_store.parent_identity,
    )
    journal.append("run_initialized")
    _write_runtime_fixture(run_dir, workspace, journal)
    (run_dir / "evidence-manifest.json").write_text(
        json.dumps(
            {
                "run_id": "run-owned",
                "regulated_mode": False,
                "evidence": [],
                "artifacts": [],
                "sanitization_status": "SANITIZED",
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return run_dir, workspace


def _copy_coherent_replacement(original: Path, replacement: Path) -> None:
    for name in ("state.json", "journal.jsonl", "runtime.json", "evidence-manifest.json"):
        source = original / name
        if source.is_file():
            (replacement / name).write_bytes(source.read_bytes())


def test_state_store_rejects_ordinary_run_root_replacement(tmp_path: Path) -> None:
    _require_descriptor_authority()
    run_dir = tmp_path / "artifacts" / "run-state"
    store = StateStore(run_dir / "state.json")
    state = AgentRunState(run_id="run-state", objective="state authority", workspace=str(tmp_path))
    store.save(state)

    original = _replace_directory(run_dir)

    with pytest.raises(ValueError, match="state directory changed identity"):
        store.save(state)
    with pytest.raises(ValueError, match="state directory changed identity"):
        store.load()
    assert not (run_dir / "state.json").exists()
    assert (original / "state.json").is_file()


def test_evidence_store_rejects_ordinary_run_root_replacement(tmp_path: Path) -> None:
    _require_descriptor_authority()
    root = tmp_path / "artifacts"
    store = EvidenceStore(root, "run-evidence", regulated_mode=True)
    store.register_artifact(
        relative_path="before.bin",
        content=b"before",
        originating_tool="test",
    )

    original = _replace_directory(store.run_root)

    with pytest.raises(ValueError, match="evidence run root changed identity"):
        store.register_artifact(
            relative_path="after.bin",
            content=b"trusted-after",
            originating_tool="test",
        )
    assert not (store.run_root / "after.bin").exists()
    assert (original / "before.bin").read_bytes() == b"before"


def test_nested_artifact_parent_replacement_cannot_redirect_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_descriptor_authority()
    root = tmp_path / "artifacts"
    store = EvidenceStore(root, "run-nested")
    real_link = os.link
    attack_bytes = b"attacker-owned"
    swapped = False

    def racing_link(src: Any, dst: Any, *args: Any, **kwargs: Any) -> None:
        nonlocal swapped
        real_link(src, dst, *args, **kwargs)
        if not swapped and str(dst) == "context.bin":
            swapped = True
            parent = store.run_root / "browser"
            moved = parent.with_name("browser-original")
            parent.rename(moved)
            parent.mkdir()
            (parent / "context.bin").write_bytes(attack_bytes)

    monkeypatch.setattr(os, "link", racing_link)

    with pytest.raises(ValueError, match="parent changed identity"):
        store.register_artifact(
            relative_path="browser/context.bin",
            content=b"trusted-bytes",
            originating_tool="test",
        )

    assert swapped is True
    assert (store.run_root / "browser" / "context.bin").read_bytes() == attack_bytes
    assert (store.run_root / "browser-original" / "context.bin").read_bytes() == b"trusted-bytes"
    assert not (store.run_root / "evidence-manifest.json").exists()


def test_runtime_metadata_cannot_close_in_replacement_run_root(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "sut"
    workspace.mkdir()
    run_dir = tmp_path / "artifacts" / "run-runtime"
    store = StateStore(run_dir / "state.json")
    journal = RunJournal(
        run_dir / "journal.jsonl",
        expected_parent_identity=store.parent_identity,
    )
    control = RuntimeControl(
        workspace=workspace,
        budget=ExecutionBudget(
            max_tool_calls=5,
            max_network_calls=5,
            max_mutations=2,
            max_wall_seconds=60.0,
        ),
        journal=journal,
        metadata_path=run_dir / "runtime.json",
        lease_id="lease-runtime",
        max_repeated_action=3,
        persistence_root_identity=store.parent_identity,
    )
    control.persist()

    original = _replace_directory(run_dir)

    with pytest.raises(RuntimeError, match="runtime metadata directory changed identity"):
        control.persist()
    assert not (run_dir / "runtime.json").exists()
    assert (original / "runtime.json").is_file()


def test_workspace_lease_persists_exact_run_root_identity(tmp_path: Path) -> None:
    _require_descriptor_authority()
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    run_dir = artifact_root / "run-lease"
    state_store = StateStore(run_dir / "state.json")
    expected = state_store.parent_identity
    lease = WorkspaceLease(
        artifact_root,
        workspace,
        "run-lease",
        run_root_identity=expected,
    )
    lease.acquire()
    try:
        raw = lease.path.read_text(encoding="utf-8")
        metadata = json.loads(raw)
    finally:
        lease.release()

    assert metadata["run_root_identity"] == {"device": expected[0], "inode": expected[1]}


def test_stale_recovery_rejects_coherent_replacement_prior_run_before_target_write(
    tmp_path: Path,
) -> None:
    _require_descriptor_authority()
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    target = workspace / "tests" / "test_target.py"
    target.parent.mkdir(parents=True)
    target.write_text("mutated\n", encoding="utf-8")

    prior_run = artifact_root / "run-old"
    state_store = StateStore(prior_run / "state.json")
    state_store.save(
        AgentRunState(
            run_id="run-old",
            objective="stale mutation",
            workspace=str(workspace),
        )
    )
    original_identity = state_store.parent_identity
    original_bytes = b"original\n"
    backup = prior_run / "rollback" / "target.bin"
    backup.parent.mkdir()
    backup.write_bytes(original_bytes)
    journal = RunJournal(
        prior_run / "journal.jsonl",
        expected_parent_identity=original_identity,
    )
    journal.append("mutation_prepared")
    pending = {
        "relative_path": "tests/test_target.py",
        "existed": True,
        "backup_path": str(backup.absolute()),
        "original_sha256": hashlib.sha256(original_bytes).hexdigest(),
        "change_revision_before": 0,
    }
    _write_runtime_fixture(
        prior_run,
        workspace,
        journal,
        pending_mutation=pending,
        fingerprint="mutated-fingerprint",
    )

    original = _replace_directory(prior_run)
    _copy_coherent_replacement(original, prior_run)
    replacement_backup = prior_run / "rollback" / "target.bin"
    replacement_backup.parent.mkdir()
    replacement_backup.write_bytes(original_bytes)

    result = recover_stale_mutation(
        artifact_root=artifact_root,
        workspace=workspace,
        previous_lease={
            "run_id": "run-old",
            "run_root_identity": {
                "device": original_identity[0],
                "inode": original_identity[1],
            },
        },
        current_workspace_fingerprint="mutated-fingerprint",
        recovering_run_id="run-new",
    )

    assert result["status"] == "BLOCKED"
    assert "changed identity" in str(result["reason"])
    assert target.read_text(encoding="utf-8") == "mutated\n"


def test_stale_recovery_requires_prior_run_root_identity_on_supported_platform(
    tmp_path: Path,
) -> None:
    _require_descriptor_authority()
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    (artifact_root / "run-old").mkdir(parents=True)

    result = recover_stale_mutation(
        artifact_root=artifact_root,
        workspace=workspace,
        previous_lease={"run_id": "run-old"},
        current_workspace_fingerprint="fp",
        recovering_run_id="run-new",
    )

    assert result["status"] == "BLOCKED"
    assert "run-root identity authority is missing" in str(result["reason"])


@pytest.mark.parametrize(
    ("operation", "expect_exception"),
    [
        (lambda path: build_run_attestation(path), True),
        (lambda path: build_run_lineage(path), True),
        (lambda path: inspect_recovery(path), False),
    ],
    ids=("attestation", "lineage", "recovery"),
)
def test_multi_subject_inspection_rejects_run_root_substitution_mid_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: Callable[[Path], object],
    expect_exception: bool,
) -> None:
    _require_descriptor_authority()
    run_dir, _workspace = _create_inspection_run(tmp_path)
    real_load = StateStore.load
    swapped = False

    def swapping_load(self: StateStore) -> AgentRunState:
        nonlocal swapped
        loaded = real_load(self)
        if not swapped and self.path.parent == run_dir:
            swapped = True
            original = _replace_directory(run_dir)
            _copy_coherent_replacement(original, run_dir)
        return loaded

    monkeypatch.setattr(StateStore, "load", swapping_load)

    if expect_exception:
        with pytest.raises((OSError, RuntimeError, ValueError)):
            operation(run_dir)
    else:
        result = operation(run_dir)
        assert isinstance(result, dict)
        assert result["recoverable"] is False
    assert swapped is True
