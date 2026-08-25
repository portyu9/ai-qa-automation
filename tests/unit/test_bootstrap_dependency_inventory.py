from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

import ai_qa_automation.runtime.bootstrap as bootstrap_module
from ai_qa_automation.fs_observation import scan_regular_files_confined
from ai_qa_automation.runtime.bootstrap import _dependency_inventory


def write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def test_dependency_inventory_hashes_confined_manifest_bytes(tmp_path: Path) -> None:
    content = b'[project]\nname = "example"\n'
    write(tmp_path / "pyproject.toml", content)
    write(tmp_path / "src" / "ignored.py", b"pass\n")

    rows, truncated = _dependency_inventory(tmp_path)

    assert truncated is False
    assert rows == [
        {
            "path": "pyproject.toml",
            "size": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
            "hashed": True,
            "reason": None,
        }
    ]


def test_dependency_inventory_marks_oversized_manifest_without_reading_it(tmp_path: Path) -> None:
    write(tmp_path / "package.json", b"x" * 32)

    rows, truncated = _dependency_inventory(tmp_path, max_file_bytes=8)

    assert truncated is True
    assert rows[0]["path"] == "package.json"
    assert rows[0]["hashed"] is False
    assert rows[0]["reason"] == "file-size-limit:8"


def test_dependency_inventory_never_follows_symlink_manifest(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("symlink setup differs on Windows")
    outside = tmp_path.parent / f"{tmp_path.name}-manifest-outside"
    write(outside / "real.toml", b"secret")
    (tmp_path / "pyproject.toml").symlink_to(outside / "real.toml")

    rows, truncated = _dependency_inventory(tmp_path)

    assert truncated is True
    assert rows == [
        {
            "path": "pyproject.toml",
            "size": None,
            "sha256": None,
            "hashed": False,
            "reason": "ambiguous-or-non-file",
        }
    ]


def test_dependency_inventory_parent_swap_cannot_redirect_manifest_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.name == "nt":
        pytest.skip("descriptor-relative no-follow scan is Unix-only")
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    write(workspace / "config" / "package.json", b'{"name":"inside"}')
    write(outside / "package.json", b'{"name":"outside"}')

    real_scan = scan_regular_files_confined

    def scan_then_swap(*args: object, **kwargs: object):
        result = real_scan(*args, **kwargs)
        original = workspace / "config"
        original.rename(workspace / "config-original")
        (workspace / "config").symlink_to(outside, target_is_directory=True)
        return result

    monkeypatch.setattr(bootstrap_module, "scan_regular_files_confined", scan_then_swap)

    rows, truncated = _dependency_inventory(workspace)

    assert truncated is True
    assert rows == [
        {
            "path": "config/package.json",
            "size": None,
            "sha256": None,
            "hashed": False,
            "reason": "read-failed-or-grew-during-hash",
        }
    ]


def test_dependency_inventory_scan_limit_counts_directory_entries(tmp_path: Path) -> None:
    for index in range(5):
        (tmp_path / f"empty-{index}").mkdir()
    write(tmp_path / "z" / "pyproject.toml", b"[project]\n")

    rows, truncated = _dependency_inventory(tmp_path, max_scan_files=2)

    assert rows == []
    assert truncated is True


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_files": 0},
        {"max_scan_files": True},
        {"max_file_bytes": 1.5},
    ],
)
def test_dependency_inventory_rejects_invalid_bounds(
    tmp_path: Path, kwargs: dict[str, object]
) -> None:
    with pytest.raises(ValueError):
        _dependency_inventory(tmp_path, **kwargs)  # type: ignore[arg-type]
