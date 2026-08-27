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


def test_root_only_ignore_does_not_hide_nested_same_name(tmp_path: Path) -> None:
    write(tmp_path / ".git" / "root-metadata", "root")
    write(tmp_path / "nested" / ".git" / "HEAD", "nested")
    write(tmp_path / "visible.txt", "visible")

    result = scan_regular_files_confined(
        tmp_path,
        max_entries=20,
        ignored_root_names={".git"},
        label="test scan",
    )

    assert [item.path.as_posix() for item in result.files] == [
        "nested/.git/HEAD",
        "visible.txt",
    ]
    assert ".git" not in {item.path.as_posix() for item in result.directories}
    assert "nested/.git" in {item.path.as_posix() for item in result.directories}
    assert result.truncated is False


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


def test_scan_exposes_and_enforces_root_identity(tmp_path: Path) -> None:
    write(tmp_path / "safe.py", "safe")

    result = scan_regular_files_confined(tmp_path, max_entries=20, label="test scan")
    current = tmp_path.stat(follow_symlinks=False)

    assert result.root_identity == (current.st_dev, current.st_ino)

    with pytest.raises(ValueError, match="root changed identity since authorization"):
        scan_regular_files_confined(
            tmp_path,
            max_entries=20,
            label="test scan",
            expected_root_identity=(current.st_dev, current.st_ino + 1),
        )


def test_symlink_entries_are_never_followed_and_mark_scan_incomplete(tmp_path: Path) -> None:
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
    assert result.truncated is True


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


@pytest.mark.parametrize("argument", ["ignored_names", "ignored_root_names"])
def test_invalid_ignored_name_is_rejected(tmp_path: Path, argument: str) -> None:
    kwargs = {argument: {"nested/path"}}
    with pytest.raises(ValueError, match="direct entry names"):
        scan_regular_files_confined(
            tmp_path,
            max_entries=10,
            label="test scan",
            **kwargs,  # type: ignore[arg-type]
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


def test_truncated_directory_is_signature_checked_before_return(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for index in range(4):
        write(tmp_path / f"file-{index}.txt")

    real_scandir = fs_observation.os.scandir
    root_identity = (tmp_path.stat().st_dev, tmp_path.stat().st_ino)

    class MutatingIterator:
        def __init__(self, inner: object, mutate: bool) -> None:
            self.inner = inner
            self.mutate = mutate
            self.calls = 0

        def __enter__(self):
            self.inner.__enter__()  # type: ignore[attr-defined]
            return self

        def __exit__(self, exc_type: object, exc: object, tb: object) -> object:
            return self.inner.__exit__(exc_type, exc, tb)  # type: ignore[attr-defined]

        def __iter__(self):
            return self

        def __next__(self):
            entry = next(self.inner)  # type: ignore[arg-type]
            self.calls += 1
            if self.mutate and self.calls == 2:
                write(tmp_path / "late.txt")
            return entry

    def mutating_scandir(path: object):
        status = os.fstat(path) if isinstance(path, int) else Path(path).stat()  # type: ignore[arg-type]
        return MutatingIterator(real_scandir(path), (status.st_dev, status.st_ino) == root_identity)

    monkeypatch.setattr(fs_observation.os, "scandir", mutating_scandir)
    monkeypatch.setattr(fs_observation.os, "supports_fd", {*os.supports_fd, mutating_scandir})

    with pytest.raises(ValueError, match="directory changed during traversal"):
        scan_regular_files_confined(tmp_path, max_entries=2, label="test scan")


def test_nested_truncation_still_signature_checks_ancestor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    child = tmp_path / "child"
    for index in range(4):
        write(child / f"file-{index}.txt")

    real_scandir = fs_observation.os.scandir
    child_status = child.stat()
    child_identity = (child_status.st_dev, child_status.st_ino)

    class MutatingIterator:
        def __init__(self, inner: object, mutate: bool) -> None:
            self.inner = inner
            self.mutate = mutate
            self.calls = 0

        def __enter__(self):
            self.inner.__enter__()  # type: ignore[attr-defined]
            return self

        def __exit__(self, exc_type: object, exc: object, tb: object) -> object:
            return self.inner.__exit__(exc_type, exc, tb)  # type: ignore[attr-defined]

        def __iter__(self):
            return self

        def __next__(self):
            entry = next(self.inner)  # type: ignore[arg-type]
            self.calls += 1
            if self.mutate and self.calls == 2:
                write(tmp_path / "late-root.txt")
            return entry

    def mutating_scandir(path: object):
        status = os.fstat(path) if isinstance(path, int) else Path(path).stat()  # type: ignore[arg-type]
        return MutatingIterator(
            real_scandir(path), (status.st_dev, status.st_ino) == child_identity
        )

    monkeypatch.setattr(fs_observation.os, "scandir", mutating_scandir)
    monkeypatch.setattr(fs_observation.os, "supports_fd", {*os.supports_fd, mutating_scandir})

    with pytest.raises(ValueError, match="directory changed during traversal"):
        scan_regular_files_confined(tmp_path, max_entries=3, label="test scan")


def test_directory_depth_is_hard_bounded_and_reported_as_truncated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fs_observation, "_MAX_DIRECTORY_DEPTH", 2)
    write(tmp_path / "one" / "two" / "three" / "deep.py")
    write(tmp_path / "root.py")

    result = scan_regular_files_confined(tmp_path, max_entries=20, label="test scan")

    assert result.truncated is True
    assert [item.path.as_posix() for item in result.files] == ["root.py"]


def test_default_directory_depth_cap_is_resource_bounded() -> None:
    assert 1 <= fs_observation._MAX_DIRECTORY_DEPTH <= 128
