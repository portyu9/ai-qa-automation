from __future__ import annotations

import json
from pathlib import Path

import pytest

import ai_qa_automation.runtime.run_control as run_control_module
from ai_qa_automation.fs_authority import descriptor_relative_authority_supported
from ai_qa_automation.runtime.budget import ExecutionBudget
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.run_control import RuntimeControl


def _control(tmp_path: Path) -> RuntimeControl:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    run_dir = tmp_path / "run"
    control = RuntimeControl(
        workspace=workspace,
        budget=ExecutionBudget(
            max_tool_calls=10,
            max_network_calls=5,
            max_mutations=2,
            max_wall_seconds=60,
        ),
        journal=RunJournal(run_dir / "journal.jsonl"),
        metadata_path=run_dir / "runtime.json",
        lease_id="runtime-metadata-publication-uncertainty-test",
    )
    control.persist()
    return control


def test_fallback_post_publication_failure_blocks_later_runtime_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(run_control_module, "descriptor_relative_authority_supported", lambda: False)
    control = _control(tmp_path)
    original_fsync_directory = run_control_module.fsync_directory

    control.repeated_action_counts["ambiguous"] = 1

    def fail_after_replacement(path: Path) -> None:
        raise OSError("runtime directory durability became ambiguous")

    monkeypatch.setattr(run_control_module, "fsync_directory", fail_after_replacement)
    with pytest.raises(OSError, match="runtime directory durability became ambiguous"):
        control.persist()

    ambiguous = json.loads(control.metadata_path.read_text(encoding="utf-8"))
    assert ambiguous["repeated_action_counts"] == {"ambiguous": 1}

    monkeypatch.setattr(run_control_module, "fsync_directory", original_fsync_directory)
    control.repeated_action_counts["later"] = 1

    with pytest.raises(OSError, match="runtime metadata write state is uncertain"):
        control.persist()

    persisted = json.loads(control.metadata_path.read_text(encoding="utf-8"))
    assert persisted["repeated_action_counts"] == {"ambiguous": 1}


def test_fallback_prepublication_failure_remains_retryable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(run_control_module, "descriptor_relative_authority_supported", lambda: False)
    control = _control(tmp_path)
    original_mkstemp = run_control_module.tempfile.mkstemp

    control.repeated_action_counts["prepublication"] = 1

    def fail_before_temp_creation(*args: object, **kwargs: object) -> tuple[int, str]:
        raise OSError("runtime temp creation failed before publication")

    monkeypatch.setattr(run_control_module.tempfile, "mkstemp", fail_before_temp_creation)
    with pytest.raises(OSError, match="before publication"):
        control.persist()

    monkeypatch.setattr(run_control_module.tempfile, "mkstemp", original_mkstemp)
    control.repeated_action_counts["retry"] = 1
    control.persist()

    persisted = json.loads(control.metadata_path.read_text(encoding="utf-8"))
    assert persisted["repeated_action_counts"] == {
        "prepublication": 1,
        "retry": 1,
    }


def test_unreconciled_descriptor_publication_blocks_later_runtime_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if not descriptor_relative_authority_supported():
        pytest.skip("descriptor-relative runtime publication authority is unavailable")

    control = _control(tmp_path)
    original_atomic_write = run_control_module.atomic_write_bytes_confined
    original_reconcile = run_control_module._reconcile_runtime_metadata_publication

    def publish_then_raise(
        root: Path,
        relative_path: str | Path,
        data: bytes,
        *,
        create_parents: bool,
        create_only: bool,
        label: str,
        expected_root_identity: tuple[int, int] | None = None,
    ) -> None:
        original_atomic_write(
            root,
            relative_path,
            data,
            create_parents=create_parents,
            create_only=create_only,
            label=label,
            expected_root_identity=expected_root_identity,
        )
        raise OSError("runtime publication outcome is unresolved")

    monkeypatch.setattr(run_control_module, "atomic_write_bytes_confined", publish_then_raise)
    monkeypatch.setattr(
        run_control_module,
        "_reconcile_runtime_metadata_publication",
        lambda *args, **kwargs: False,
    )

    control.repeated_action_counts["ambiguous"] = 1
    with pytest.raises(OSError, match="runtime publication outcome is unresolved"):
        control.persist()

    ambiguous = json.loads(control.metadata_path.read_text(encoding="utf-8"))
    assert ambiguous["repeated_action_counts"] == {"ambiguous": 1}

    monkeypatch.setattr(run_control_module, "atomic_write_bytes_confined", original_atomic_write)
    monkeypatch.setattr(
        run_control_module,
        "_reconcile_runtime_metadata_publication",
        original_reconcile,
    )
    control.repeated_action_counts["later"] = 1

    with pytest.raises(OSError, match="runtime metadata write state is uncertain"):
        control.persist()


def test_descriptor_interruption_is_reconciled_before_remaining_writable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if not descriptor_relative_authority_supported():
        pytest.skip("descriptor-relative runtime publication authority is unavailable")

    control = _control(tmp_path)
    original_atomic_write = run_control_module.atomic_write_bytes_confined
    original_reconcile = run_control_module._reconcile_runtime_metadata_publication
    reconciliation_attempts = 0

    def publish_then_interrupt(
        root: Path,
        relative_path: str | Path,
        data: bytes,
        *,
        create_parents: bool,
        create_only: bool,
        label: str,
        expected_root_identity: tuple[int, int] | None = None,
    ) -> None:
        original_atomic_write(
            root,
            relative_path,
            data,
            create_parents=create_parents,
            create_only=create_only,
            label=label,
            expected_root_identity=expected_root_identity,
        )
        raise KeyboardInterrupt("runtime publication interrupted after visibility")

    def count_reconciliation(
        path: Path,
        rendered_bytes: bytes,
        *,
        expected_parent_identity: tuple[int, int] | None,
    ) -> bool:
        nonlocal reconciliation_attempts
        reconciliation_attempts += 1
        return original_reconcile(
            path,
            rendered_bytes,
            expected_parent_identity=expected_parent_identity,
        )

    monkeypatch.setattr(run_control_module, "atomic_write_bytes_confined", publish_then_interrupt)
    monkeypatch.setattr(
        run_control_module,
        "_reconcile_runtime_metadata_publication",
        count_reconciliation,
    )

    control.repeated_action_counts["interrupted"] = 1
    with pytest.raises(KeyboardInterrupt, match="after visibility"):
        control.persist()

    assert reconciliation_attempts == 1

    monkeypatch.setattr(run_control_module, "atomic_write_bytes_confined", original_atomic_write)
    monkeypatch.setattr(
        run_control_module,
        "_reconcile_runtime_metadata_publication",
        original_reconcile,
    )
    control.repeated_action_counts["later"] = 1
    control.persist()

    persisted = json.loads(control.metadata_path.read_text(encoding="utf-8"))
    assert persisted["repeated_action_counts"] == {
        "interrupted": 1,
        "later": 1,
    }


def test_reconciliation_interruption_blocks_later_runtime_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if not descriptor_relative_authority_supported():
        pytest.skip("descriptor-relative runtime publication authority is unavailable")

    control = _control(tmp_path)
    original_atomic_write = run_control_module.atomic_write_bytes_confined
    original_reconcile = run_control_module._reconcile_runtime_metadata_publication

    def publish_then_raise(
        root: Path,
        relative_path: str | Path,
        data: bytes,
        *,
        create_parents: bool,
        create_only: bool,
        label: str,
        expected_root_identity: tuple[int, int] | None = None,
    ) -> None:
        original_atomic_write(
            root,
            relative_path,
            data,
            create_parents=create_parents,
            create_only=create_only,
            label=label,
            expected_root_identity=expected_root_identity,
        )
        raise OSError("runtime publication requires reconciliation")

    def interrupt_reconciliation(*args: object, **kwargs: object) -> bool:
        raise KeyboardInterrupt("runtime reconciliation interrupted")

    monkeypatch.setattr(run_control_module, "atomic_write_bytes_confined", publish_then_raise)
    monkeypatch.setattr(
        run_control_module,
        "_reconcile_runtime_metadata_publication",
        interrupt_reconciliation,
    )

    control.repeated_action_counts["ambiguous"] = 1
    with pytest.raises(KeyboardInterrupt, match="runtime reconciliation interrupted"):
        control.persist()

    monkeypatch.setattr(run_control_module, "atomic_write_bytes_confined", original_atomic_write)
    monkeypatch.setattr(
        run_control_module,
        "_reconcile_runtime_metadata_publication",
        original_reconcile,
    )
    control.repeated_action_counts["later"] = 1

    with pytest.raises(OSError, match="runtime metadata write state is uncertain"):
        control.persist()
