from pathlib import Path

import pytest

from ai_qa_automation.runtime.journal import RunJournal


def test_journal_rejects_preexisting_symlink_target(tmp_path: Path) -> None:
    outside = tmp_path / "outside.jsonl"
    outside.write_text("outside\n", encoding="utf-8")
    journal = tmp_path / "run" / "journal.jsonl"
    journal.parent.mkdir()
    try:
        journal.symlink_to(outside)
    except OSError as exc:  # pragma: no cover - platform/filesystem capability
        pytest.skip(f"symlink creation unavailable: {exc}")

    with pytest.raises(ValueError, match=r"journal path.*symlink"):
        RunJournal(journal)

    assert outside.read_text(encoding="utf-8") == "outside\n"


def test_journal_refuses_path_replaced_by_symlink_after_initialization(tmp_path: Path) -> None:
    journal_path = tmp_path / "run" / "journal.jsonl"
    subject = RunJournal(journal_path)
    subject.append("started")
    journal_path.unlink()
    outside = tmp_path / "outside.jsonl"
    outside.write_text("outside\n", encoding="utf-8")
    try:
        journal_path.symlink_to(outside)
    except OSError as exc:  # pragma: no cover - platform/filesystem capability
        pytest.skip(f"symlink creation unavailable: {exc}")

    with pytest.raises(RuntimeError, match="became a symlink"):
        subject.append("should-not-write")

    with pytest.raises(RuntimeError, match="became a symlink"):
        subject.verify()

    assert outside.read_text(encoding="utf-8") == "outside\n"


def _replace_journal_parent(
    journal_path: Path,
    *,
    replacement_bytes: bytes,
) -> tuple[Path, Path]:
    original_parent = journal_path.parent.with_name("original-run")
    journal_path.parent.rename(original_parent)
    journal_path.parent.mkdir()
    replacement = journal_path.parent / journal_path.name
    replacement.write_bytes(replacement_bytes)
    return original_parent, replacement


def test_journal_refuses_parent_swap_after_append_preflight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    journal_path = tmp_path / "run" / "journal.jsonl"
    subject = RunJournal(journal_path)
    subject.append("started")
    original_assert = subject._assert_owned_path
    swapped: dict[str, Path] = {}

    def replace_after_preflight(parent_fd: int | None = None) -> None:
        original_assert(parent_fd)
        if swapped:
            return
        original_parent, replacement = _replace_journal_parent(
            journal_path,
            replacement_bytes=b"attacker-controlled\n",
        )
        swapped.update(original_parent=original_parent, replacement=replacement)

    monkeypatch.setattr(subject, "_assert_owned_path", replace_after_preflight)

    with pytest.raises(RuntimeError, match="journal directory changed identity"):
        subject.append("should-not-write")

    replacement = swapped["replacement"]
    original_parent = swapped["original_parent"]
    assert replacement.read_bytes() == b"attacker-controlled\n"
    assert "should-not-write" not in (original_parent / journal_path.name).read_text(
        encoding="utf-8"
    )


def test_journal_refuses_parent_swap_after_verify_preflight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    journal_path = tmp_path / "run" / "journal.jsonl"
    subject = RunJournal(journal_path)
    subject.append("started")
    original_bytes = journal_path.read_bytes()
    original_assert = subject._assert_owned_path
    swapped: dict[str, Path] = {}

    def replace_after_preflight(parent_fd: int | None = None) -> None:
        original_assert(parent_fd)
        if swapped:
            return
        original_parent, replacement = _replace_journal_parent(
            journal_path,
            replacement_bytes=original_bytes,
        )
        swapped.update(original_parent=original_parent, replacement=replacement)

    monkeypatch.setattr(subject, "_assert_owned_path", replace_after_preflight)

    with pytest.raises(RuntimeError, match="journal directory changed identity"):
        subject.verify()

    replacement = swapped["replacement"]
    original_parent = swapped["original_parent"]
    assert replacement.read_bytes() == original_bytes
    assert (original_parent / journal_path.name).read_bytes() == original_bytes
