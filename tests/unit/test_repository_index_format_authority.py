from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from ai_qa_automation.tools._repository_common import git_index_has_split_link


def _git(repo: Path, *args: str, allow_failure: bool = False) -> subprocess.CompletedProcess[str]:
    executable = shutil.which("git")
    if executable is None:
        pytest.skip("git executable is unavailable")
    home = repo.parent / ".aiqa-index-format-git-home"
    home.mkdir(exist_ok=True)
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(home),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_PAGER": "cat",
        "LANG": os.environ.get("LANG", "C.UTF-8"),
    }
    result = subprocess.run(
        [executable, *args],
        cwd=repo,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0 and not allow_failure:
        raise AssertionError(f"git {' '.join(args)} failed: {result.stderr}")
    return result


def _init_repo(repo: Path, *, object_format: str = "sha1") -> None:
    repo.mkdir()
    init_args = ["init", "-q"]
    if object_format != "sha1":
        init_args.append(f"--object-format={object_format}")
    result = _git(repo, *init_args, allow_failure=object_format != "sha1")
    if result.returncode != 0:
        pytest.skip(f"Git object format {object_format} is unavailable: {result.stderr.strip()}")
    _git(repo, "config", "user.name", "AI QA Test")
    _git(repo, "config", "user.email", "aiqa@example.invalid")
    (repo / "alpha.txt").write_text("alpha\n", encoding="utf-8")
    (repo / "alphabet.txt").write_text("alphabet\n", encoding="utf-8")
    nested = repo / "nested"
    nested.mkdir()
    (nested / "alpha.txt").write_text("nested\n", encoding="utf-8")
    _git(repo, "add", "--", "alpha.txt", "alphabet.txt", "nested/alpha.txt")
    _git(repo, "commit", "-q", "-m", "initial")


def _index_bytes(repo: Path) -> bytes:
    return (repo / ".git" / "index").read_bytes()


def _force_index_version(repo: Path, version: int) -> None:
    if version == 3:
        # Git writes v3 only when an extended index flag is needed; merely
        # requesting --index-version=3 may legitimately remain on v2.
        _git(repo, "update-index", "--skip-worktree", "alpha.txt")
        return
    _git(repo, "update-index", f"--index-version={version}")


@pytest.mark.parametrize("version", [2, 3, 4])
def test_split_index_link_is_detected_across_supported_index_versions(
    tmp_path: Path,
    version: int,
) -> None:
    repo = tmp_path / f"repo-v{version}"
    _init_repo(repo)
    _force_index_version(repo, version)

    normal = _index_bytes(repo)
    assert int.from_bytes(normal[4:8], "big") == version
    assert git_index_has_split_link(normal) is False

    _git(repo, "update-index", "--split-index")
    if version == 3:
        # Split-index consolidation can move the extended entry into the shared
        # index and collapse the main index to v2. Reapplying the flag creates a
        # genuine v3 main split index with both an extended entry and link extension.
        _git(repo, "update-index", "--skip-worktree", "alpha.txt")
    split = _index_bytes(repo)

    assert int.from_bytes(split[4:8], "big") == version
    assert git_index_has_split_link(split) is True


def test_split_index_link_is_detected_in_sha256_repository(tmp_path: Path) -> None:
    repo = tmp_path / "repo-sha256"
    _init_repo(repo, object_format="sha256")
    _git(repo, "update-index", "--index-version=4")

    normal = _index_bytes(repo)
    assert git_index_has_split_link(normal) is False

    _git(repo, "update-index", "--split-index")
    split = _index_bytes(repo)

    assert git_index_has_split_link(split) is True


def test_index_parser_rejects_checksum_corruption(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init_repo(repo)
    raw = bytearray(_index_bytes(repo))
    assert len(raw) > 32
    raw[12] ^= 0x01

    with pytest.raises(RuntimeError, match="checksum"):
        git_index_has_split_link(bytes(raw))


def test_index_parser_rejects_extension_length_past_checksum_boundary() -> None:
    body = (
        b"DIRC"
        + (2).to_bytes(4, "big")
        + (0).to_bytes(4, "big")
        + b"TEST"
        + (4).to_bytes(4, "big")
        + b"x"
    )
    raw = body + hashlib.sha1(body, usedforsecurity=False).digest()

    with pytest.raises(RuntimeError, match="extension exceeds"):
        git_index_has_split_link(raw)
