from __future__ import annotations

import os
from pathlib import Path

import pytest

import ai_qa_automation.fs_observation as fs_observation
from ai_qa_automation.fs_observation import scan_regular_files_confined


def write(path: Path, content: str = "x") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_confined_scan_is_sorted_and_does_not_descend_ignored_directories(tmp_path: Path) -> None:
    write(tmp_path / "z.py")
    write(tmp_path / "a" / "b.py")
    write(tmp_path / "node_modules" / "pkg" / "ignored.py")

    result = scan_regular_files_confined(
        tmp_path,
        max_entries=20,
        ignored_names={"node_modules"},
        label="test scan",
    )

    assert [item.path.as_posix() for item in result.files] == ["a/b.py", "z.py"]
    assert result.truncated is False
    assert result.unsafe_paths == ()
    assert result.unreadable_paths == ()
    assert result.observed_entries == 4


def test_entry_budget_stops_before_materializing_oversized_directory(tmp_path: Path) -> None:
    for index in range(6):
        write(tmp_path / f"file-{index}.txt")

    result = scan_regular_files_confined(
        tmp_path,
        max_entries=2,
        label="test scan",
    )

    assert result.truncated is True
    assert result.observed_entries == 2
    assert result.files == ()


def test_symlink_entries_are_never_followed(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("symlink setup differs on Windows")
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    write(outside / "secret.py", "secret")
    (tmp_path / "external").symlink_to(outside, target_is_directory=True)
    write(tmp_path / "safe.py", "safe")

    result = scan_regular_files_confined(
        tmp_path,
        max_entries=20,
        label="test scan",
    )

    assert [item.path.as_posix() for item in result.files] == ["safe.py"]
    assert [path.as_posix() for path in result.unsafe_paths] == ["external"]
    assert result.truncated is False


def test_symlink_root_is_rejected_without_resolving_alias(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("symlink setup differs on Windows")
    target = tmp_path / "target"
    target.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(target, target_is_directory=True)

    with pytest.raises(ValueError, match="root is a symlink"):
        scan_regular_files_confined(alias, max_entries=10, label="test scan")


def test_unsupported_descriptor_scan_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fs_observation, "descriptor_relative_authority_supported", lambda: False)

    with pytest.raises(RuntimeError, match="descriptor-relative"):
        scan_regular_files_confined(tmp_path, max_entries=10, label="test scan")


@pytest.mark.parametrize("value", [0, -1, True, 1.5, "10"])
def test_invalid_entry_bound_is_rejected(tmp_path: Path, value: object) -> None:
    with pytest.raises(ValueError):
        scan_regular_files_confined(tmp_path, max_entries=value, label="test scan")  # type: ignore[arg-type]


def test_invalid_ignored_name_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="direct entry names"):
        scan_regular_files_confined(
            tmp_path,
            max_entries=10,
            ignored_names={"nested/path"},
            label="test scan",
        )


def test_entry_budget_never_fetches_a_hidden_sentinel_beyond_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for index in range(5):
        write(tmp_path / f"file-{index}.txt")

    real_scandir = fs_observation.os.scandir
    next_calls = 0

    class CountingIterator:
        def __init__(self, inner: object) -> None:
            self.inner = inner

        def __enter__(self):
            self.inner.__enter__()  # type: ignore[attr-defined]
            return self

        def __exit__(self, exc_type: object, exc: object, tb: object) -> object:
            return self.inner.__exit__(exc_type, exc, tb)  # type: ignore[attr-defined]

        def __iter__(self):
            return self

        def __next__(self):
            nonlocal next_calls
            next_calls += 1
            return next(self.inner)  # type: ignore[arg-type]

    def counting_scandir(path: object):
        return CountingIterator(real_scandir(path))  # type: ignore[arg-type]

    monkeypatch.setattr(fs_observation.os, "scandir", counting_scandir)
    monkeypatch.setattr(fs_observation.os, "supports_fd", {*os.supports_fd, counting_scandir})

    result = scan_regular_files_confined(tmp_path, max_entries=2, label="test scan")

    assert result.observed_entries == 2
    assert next_calls == 2
    assert result.truncated is True
