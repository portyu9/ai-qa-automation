from __future__ import annotations

import errno
import os
from pathlib import Path

import pytest

import ai_qa_automation.evidence as evidence_module
import ai_qa_automation.fs_authority as fs_authority_module
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


def _capture_audit_descriptor(monkeypatch: pytest.MonkeyPatch) -> dict[str, int | None]:
    real_open = fs_authority_module.os.open
    captured: dict[str, int | None] = {"fd": None}

    def capture_open(
        path: object, flags: int, mode: int = 0o777, *, dir_fd: int | None = None
    ) -> int:
        if dir_fd is None:
            fd = real_open(path, flags, mode)
        else:
            fd = real_open(path, flags, mode, dir_fd=dir_fd)
        if str(path) == "audit-log.jsonl":
            captured["fd"] = fd
        return fd

    monkeypatch.setattr(fs_authority_module.os, "open", capture_open)
    return captured


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


def test_failed_partial_audit_append_rolls_back_and_latches_store_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = EvidenceStore(tmp_path, "run", regulated_mode=True)
    store.add(_item("run", "first"))
    audit_path = tmp_path / "run" / "audit-log.jsonl"
    manifest_path = tmp_path / "run" / "evidence-manifest.json"
    audit_before = audit_path.read_bytes()
    manifest_before = manifest_path.read_bytes()
    captured = _capture_audit_descriptor(monkeypatch)
    real_write = fs_authority_module.os.write
    injected = False

    def fail_after_partial(fd: int, content: bytes | memoryview) -> int:
        nonlocal injected
        if fd == captured["fd"] and not injected:
            injected = True
            view = memoryview(content)
            real_write(fd, view[: min(7, len(view))])
            raise OSError(errno.EIO, "simulated mid-record write failure")
        return real_write(fd, content)

    monkeypatch.setattr(fs_authority_module.os, "write", fail_after_partial)
    with pytest.raises(OSError, match="simulated mid-record write failure"):
        store.add(_item("run", "failed"))

    assert audit_path.read_bytes() == audit_before
    assert manifest_path.read_bytes() == manifest_before
    assert store.verify_audit_chain() is True
    assert [item.source_identifier for item in store.all()] == ["first"]
    with pytest.raises(OSError, match="write state is uncertain"):
        store.add(_item("run", "blocked"))

    restored = EvidenceStore(tmp_path, "run", regulated_mode=True)
    assert [item.source_identifier for item in restored.all()] == ["first"]


def test_failed_audit_truncate_latches_future_regulated_writes_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = EvidenceStore(tmp_path, "run", regulated_mode=True)
    store.add(_item("run", "first"))
    audit_path = tmp_path / "run" / "audit-log.jsonl"
    audit_before = audit_path.read_bytes()
    captured = _capture_audit_descriptor(monkeypatch)
    real_write = fs_authority_module.os.write

    def fail_after_partial(fd: int, content: bytes | memoryview) -> int:
        if fd == captured["fd"]:
            view = memoryview(content)
            real_write(fd, view[: min(5, len(view))])
            raise OSError(errno.EIO, "simulated append failure")
        return real_write(fd, content)

    def fail_truncate(_fd: int, _length: int) -> None:
        raise OSError(errno.EIO, "simulated rollback failure")

    monkeypatch.setattr(fs_authority_module.os, "write", fail_after_partial)
    monkeypatch.setattr(fs_authority_module.os, "ftruncate", fail_truncate)
    with pytest.raises(OSError, match="rollback could not be durably proven"):
        store.add(_item("run", "failed"))

    assert audit_path.read_bytes() != audit_before
    assert [item.source_identifier for item in store.all()] == ["first"]

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
    captured = _capture_audit_descriptor(monkeypatch)
    real_write = fs_authority_module.os.write

    def fail_after_partial(fd: int, content: bytes | memoryview) -> int:
        if fd == captured["fd"]:
            view = memoryview(content)
            real_write(fd, view[: min(5, len(view))])
            raise OSError(errno.EIO, "simulated append failure")
        return real_write(fd, content)

    def fail_fsync(_fd: int) -> None:
        raise OSError(errno.EIO, "simulated rollback fsync failure")

    monkeypatch.setattr(fs_authority_module.os, "write", fail_after_partial)
    monkeypatch.setattr(fs_authority_module.os, "fsync", fail_fsync)
    with pytest.raises(OSError, match="rollback could not be durably proven"):
        store.add(_item("run", "failed"))

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
    captured = _capture_audit_descriptor(monkeypatch)
    real_write = fs_authority_module.os.write
    injected = False

    def interrupt_after_partial(fd: int, content: bytes | memoryview) -> int:
        nonlocal injected
        if fd == captured["fd"] and not injected:
            injected = True
            view = memoryview(content)
            real_write(fd, view[: min(5, len(view))])
            raise KeyboardInterrupt("simulated operator interruption")
        return real_write(fd, content)

    monkeypatch.setattr(fs_authority_module.os, "write", interrupt_after_partial)
    with pytest.raises(KeyboardInterrupt, match="operator interruption"):
        store.add(_item("run", "interrupted"))

    assert audit_path.read_bytes() == audit_before
    assert [item.source_identifier for item in store.all()] == ["first"]
    assert store.verify_audit_chain() is True
    store.add(_item("run", "after"))
    assert [item.source_identifier for item in store.all()] == ["first", "after"]


def test_first_audit_directory_fsync_failure_latches_store_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = EvidenceStore(tmp_path, "run", regulated_mode=True)
    captured = _capture_audit_descriptor(monkeypatch)
    real_fsync = fs_authority_module.os.fsync
    audit_file_synced = False

    def fail_directory_fsync(fd: int) -> None:
        nonlocal audit_file_synced
        if fd == captured["fd"]:
            audit_file_synced = True
            real_fsync(fd)
            return
        if audit_file_synced:
            raise OSError(errno.EIO, "simulated directory fsync failure")
        real_fsync(fd)

    monkeypatch.setattr(fs_authority_module.os, "fsync", fail_directory_fsync)
    with pytest.raises(OSError, match="simulated directory fsync failure"):
        store.add(_item("run", "first"))

    assert store.all() == []
    with pytest.raises(OSError, match="write state is uncertain"):
        store.add(_item("run", "blocked"))
    assert store.all() == []
    restored = EvidenceStore(tmp_path, "run", regulated_mode=True)
    assert restored.all() == []


def test_keyboard_interrupt_after_partial_artifact_audit_leaves_unregistered_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = EvidenceStore(tmp_path, "run", regulated_mode=True)
    captured = _capture_audit_descriptor(monkeypatch)
    real_write = fs_authority_module.os.write
    injected = False

    def interrupt_after_partial(fd: int, content: bytes | memoryview) -> int:
        nonlocal injected
        if fd == captured["fd"] and not injected:
            injected = True
            view = memoryview(content)
            real_write(fd, view[: min(5, len(view))])
            raise KeyboardInterrupt("simulated artifact audit interruption")
        return real_write(fd, content)

    monkeypatch.setattr(fs_authority_module.os, "write", interrupt_after_partial)
    with pytest.raises(KeyboardInterrupt, match="artifact audit interruption"):
        store.register_artifact(
            relative_path="proof.txt",
            content=b"proof",
            originating_tool="audit-interruption-test",
        )

    assert (tmp_path / "run" / "proof.txt").read_bytes() == b"proof"
    assert store._artifacts == {}
    assert store.verify_audit_chain() is True
    restored = EvidenceStore(tmp_path, "run", regulated_mode=True)
    assert restored._artifacts == {}


def test_audit_descriptor_close_failure_latches_store_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = EvidenceStore(tmp_path, "run", regulated_mode=True)
    captured = _capture_audit_descriptor(monkeypatch)
    real_close = fs_authority_module.os.close
    injected = False

    def fail_audit_close(fd: int) -> None:
        nonlocal injected
        if fd == captured["fd"] and not injected:
            injected = True
            captured["fd"] = None
            real_close(fd)
            raise OSError(errno.EIO, "simulated audit descriptor close failure")
        real_close(fd)

    monkeypatch.setattr(fs_authority_module.os, "close", fail_audit_close)
    with pytest.raises(OSError, match="descriptor close could not be proven"):
        store.add(_item("run", "first"))

    assert store.all() == []
    with pytest.raises(OSError, match="write state is uncertain"):
        store.add(_item("run", "blocked"))
    assert store.all() == []
    assert store.verify_audit_chain() is True
    with pytest.raises(ValueError, match="registry does not match audit log"):
        EvidenceStore(tmp_path, "run", regulated_mode=True)
