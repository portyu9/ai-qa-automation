from __future__ import annotations

import errno
import os
from pathlib import Path

import pytest

import ai_qa_automation.evidence as evidence_module
from ai_qa_automation.evidence import EvidenceStore
from ai_qa_automation.models import EvidenceItem, EvidenceKind, EvidenceNature


def _item(run_id: str, suffix: str) -> EvidenceItem:
    return EvidenceItem(
        run_id=run_id,
        kind=EvidenceKind.SOURCE_OBSERVATION,
        nature=EvidenceNature.OBSERVED_FACT,
        source="audit-interruption-test",
        source_identifier=suffix,
        summary=f"evidence {suffix}",
        structured_data={"z": suffix, "a": 1},
    )


def test_write_fd_all_handles_short_writes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "short.bin"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
    real_write = os.write

    def short_write(target_fd: int, content: bytes | memoryview) -> int:
        view = memoryview(content)
        return real_write(target_fd, view[: min(2, len(view))])

    monkeypatch.setattr(evidence_module.os, "write", short_write)
    try:
        evidence_module._write_fd_all(fd, b"abcdef")
    finally:
        os.close(fd)
    assert path.read_bytes() == b"abcdef"


def test_failed_partial_audit_append_rolls_back_and_store_remains_usable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = EvidenceStore(tmp_path, "run", regulated_mode=True)
    store.add(_item("run", "first"))
    audit_path = tmp_path / "run" / "audit-log.jsonl"
    manifest_path = tmp_path / "run" / "evidence-manifest.json"
    audit_before = audit_path.read_bytes()
    manifest_before = manifest_path.read_bytes()
    real_write_all = evidence_module._write_fd_all
    injected = False

    def fail_after_partial(fd: int, content: bytes) -> None:
        nonlocal injected
        if not injected:
            injected = True
            os.write(fd, content[: min(7, len(content))])
            raise OSError(errno.EIO, "simulated mid-record write failure")
        real_write_all(fd, content)

    monkeypatch.setattr(evidence_module, "_write_fd_all", fail_after_partial)
    with pytest.raises(OSError, match="simulated mid-record write failure"):
        store.add(_item("run", "failed"))

    assert audit_path.read_bytes() == audit_before
    assert manifest_path.read_bytes() == manifest_before
    assert store.verify_audit_chain() is True
    assert [item.source_identifier for item in store.all()] == ["first"]

    monkeypatch.setattr(evidence_module, "_write_fd_all", real_write_all)
    store.add(_item("run", "after"))
    assert store.verify_audit_chain() is True
    restored = EvidenceStore(tmp_path, "run", regulated_mode=True)
    assert [item.source_identifier for item in restored.all()] == ["first", "after"]


def test_failed_audit_truncate_latches_future_regulated_writes_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = EvidenceStore(tmp_path, "run", regulated_mode=True)
    store.add(_item("run", "first"))
    audit_path = tmp_path / "run" / "audit-log.jsonl"
    audit_before = audit_path.read_bytes()
    real_write_all = evidence_module._write_fd_all

    def fail_after_partial(fd: int, content: bytes) -> None:
        os.write(fd, content[: min(5, len(content))])
        raise OSError(errno.EIO, "simulated append failure")

    def fail_truncate(_fd: int, _length: int) -> None:
        raise OSError(errno.EIO, "simulated rollback failure")

    monkeypatch.setattr(evidence_module, "_write_fd_all", fail_after_partial)
    monkeypatch.setattr(evidence_module.os, "ftruncate", fail_truncate)
    with pytest.raises(OSError, match="rollback could not be durably proven"):
        store.add(_item("run", "failed"))

    assert audit_path.read_bytes() != audit_before
    assert [item.source_identifier for item in store.all()] == ["first"]

    monkeypatch.setattr(evidence_module, "_write_fd_all", real_write_all)
    with pytest.raises(OSError, match="write state is uncertain"):
        store.add(_item("run", "blocked"))
    assert [item.source_identifier for item in store.all()] == ["first"]
    assert store.verify_audit_chain() is False
    with pytest.raises(ValueError, match="audit log integrity check failed"):
        EvidenceStore(tmp_path, "run", regulated_mode=True)


def test_failed_audit_rollback_fsync_latches_future_regulated_writes_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = EvidenceStore(tmp_path, "run", regulated_mode=True)
    store.add(_item("run", "first"))
    real_write_all = evidence_module._write_fd_all

    def fail_after_partial(fd: int, content: bytes) -> None:
        os.write(fd, content[: min(5, len(content))])
        raise OSError(errno.EIO, "simulated append failure")

    def fail_fsync(_fd: int) -> None:
        raise OSError(errno.EIO, "simulated rollback fsync failure")

    monkeypatch.setattr(evidence_module, "_write_fd_all", fail_after_partial)
    monkeypatch.setattr(evidence_module.os, "fsync", fail_fsync)
    with pytest.raises(OSError, match="rollback could not be durably proven"):
        store.add(_item("run", "failed"))

    monkeypatch.setattr(evidence_module, "_write_fd_all", real_write_all)
    with pytest.raises(OSError, match="write state is uncertain"):
        store.add(_item("run", "blocked"))
    assert [item.source_identifier for item in store.all()] == ["first"]


def test_keyboard_interrupt_after_partial_audit_write_cleans_staged_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = EvidenceStore(tmp_path, "run", regulated_mode=True)
    store.add(_item("run", "first"))
    audit_path = tmp_path / "run" / "audit-log.jsonl"
    audit_before = audit_path.read_bytes()
    real_write_all = evidence_module._write_fd_all
    injected = False

    def interrupt_after_partial(fd: int, content: bytes) -> None:
        nonlocal injected
        if not injected:
            injected = True
            os.write(fd, content[: min(5, len(content))])
            raise KeyboardInterrupt("simulated operator interruption")
        real_write_all(fd, content)

    monkeypatch.setattr(evidence_module, "_write_fd_all", interrupt_after_partial)
    with pytest.raises(KeyboardInterrupt, match="operator interruption"):
        store.add(_item("run", "interrupted"))

    assert audit_path.read_bytes() == audit_before
    assert [item.source_identifier for item in store.all()] == ["first"]
    assert store.verify_audit_chain() is True


def test_first_audit_directory_fsync_failure_latches_store_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = EvidenceStore(tmp_path, "run", regulated_mode=True)

    def fail_directory_fsync(_path: Path) -> None:
        raise OSError(errno.EIO, "simulated directory fsync failure")

    monkeypatch.setattr(evidence_module, "fsync_directory", fail_directory_fsync)
    with pytest.raises(OSError, match="directory durability could not be proven"):
        store.add(_item("run", "first"))

    assert store.all() == []
    with pytest.raises(OSError, match="write state is uncertain"):
        store.add(_item("run", "blocked"))
    assert store.all() == []
    with pytest.raises(ValueError, match="registry does not match audit log"):
        EvidenceStore(tmp_path, "run", regulated_mode=True)


def test_keyboard_interrupt_after_partial_artifact_audit_write_cleans_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = EvidenceStore(tmp_path, "run", regulated_mode=True)
    real_write_all = evidence_module._write_fd_all
    injected = False

    def interrupt_after_partial(fd: int, content: bytes) -> None:
        nonlocal injected
        if not injected:
            injected = True
            os.write(fd, content[: min(5, len(content))])
            raise KeyboardInterrupt("simulated artifact audit interruption")
        real_write_all(fd, content)

    monkeypatch.setattr(evidence_module, "_write_fd_all", interrupt_after_partial)
    with pytest.raises(KeyboardInterrupt, match="artifact audit interruption"):
        store.register_artifact(
            relative_path="proof.txt",
            content=b"proof",
            originating_tool="audit-interruption-test",
        )

    assert not (tmp_path / "run" / "proof.txt").exists()
    assert store._artifacts == {}
    assert store.verify_audit_chain() is True
    restored = EvidenceStore(tmp_path, "run", regulated_mode=True)
    assert restored._artifacts == {}


def test_audit_descriptor_close_failure_latches_store_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = EvidenceStore(tmp_path, "run", regulated_mode=True)
    real_open = evidence_module.os.open
    real_close = evidence_module.os.close
    audit_fd: int | None = None

    def capture_audit_open(
        path: object, flags: int, mode: int = 0o777, *, dir_fd: int | None = None
    ) -> int:
        nonlocal audit_fd
        if dir_fd is None:
            fd = real_open(path, flags, mode)
        else:
            fd = real_open(path, flags, mode, dir_fd=dir_fd)
        if str(path).endswith("audit-log.jsonl"):
            audit_fd = fd
        return fd

    def fail_audit_close(fd: int) -> None:
        if fd == audit_fd:
            real_close(fd)
            raise OSError(errno.EIO, "simulated audit descriptor close failure")
        real_close(fd)

    monkeypatch.setattr(evidence_module.os, "open", capture_audit_open)
    monkeypatch.setattr(evidence_module.os, "close", fail_audit_close)
    with pytest.raises(OSError, match="descriptor close could not be proven"):
        store.add(_item("run", "first"))

    assert store.all() == []
    with pytest.raises(OSError, match="write state is uncertain"):
        store.add(_item("run", "blocked"))
    assert store.all() == []
    assert store.verify_audit_chain() is True
    with pytest.raises(ValueError, match="registry does not match audit log"):
        EvidenceStore(tmp_path, "run", regulated_mode=True)
