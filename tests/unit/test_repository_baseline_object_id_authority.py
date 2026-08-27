from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from ai_qa_automation.fs_authority import descriptor_relative_authority_supported
from ai_qa_automation.tools.repository import RepositoryInspector


def _git(repo: Path, *args: str) -> str:
    executable = shutil.which("git")
    if executable is None:
        pytest.skip("git executable is unavailable")
    home = repo.parent / ".aiqa-baseline-object-id-git-home"
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
    if result.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed: {result.stderr}")
    return result.stdout.rstrip("\r\n")


def _init_two_commit_repo(repo: Path, *, object_format: str = "sha1") -> tuple[str, str]:
    if not descriptor_relative_authority_supported():
        pytest.skip("descriptor-relative filesystem authority is unavailable")
    repo.mkdir()
    try:
        _git(repo, "init", "-q", f"--object-format={object_format}")
    except AssertionError as exc:
        pytest.skip(f"installed Git does not support {object_format} repositories: {exc}")
    _git(repo, "config", "user.name", "AI QA Test")
    _git(repo, "config", "user.email", "aiqa@example.invalid")
    tracked = repo / "tracked.txt"
    tracked.write_text("baseline\n", encoding="utf-8")
    _git(repo, "add", "--", "tracked.txt")
    _git(repo, "commit", "-q", "-m", "baseline")
    baseline = _git(repo, "rev-parse", "HEAD")
    tracked.write_text("head\n", encoding="utf-8")
    _git(repo, "add", "--", "tracked.txt")
    _git(repo, "commit", "-q", "-m", "head")
    head = _git(repo, "rev-parse", "HEAD")
    assert head != baseline
    return baseline, head


def test_change_set_rejects_bare_abbreviated_object_id_but_allows_explicit_hex_ref(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    baseline, _head = _init_two_commit_repo(repo)
    abbreviated = baseline[:12]
    assert _git(repo, "rev-parse", "--verify", f"{abbreviated}^{{commit}}") == baseline

    inspector = RepositoryInspector(repo)
    with pytest.raises(ValueError, match="abbreviated object id"):
        inspector.change_set(abbreviated)

    _git(repo, "branch", "deadbeef", baseline)
    with pytest.raises(ValueError, match="abbreviated object id"):
        inspector.change_set("deadbeef")

    explicit = inspector.change_set("refs/heads/deadbeef")
    assert explicit.baseline_sha == baseline
    assert explicit.committed_files == ("tracked.txt",)


def test_change_set_requires_exact_full_object_id_in_sha256_repository(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    baseline, _head = _init_two_commit_repo(repo, object_format="sha256")
    assert len(baseline) == 64
    prefix = baseline[:40]
    assert _git(repo, "rev-parse", "--verify", f"{prefix}^{{commit}}") == baseline

    inspector = RepositoryInspector(repo)
    with pytest.raises(RuntimeError, match="baseline full object id"):
        inspector.change_set(prefix)

    exact = inspector.change_set(baseline)
    assert exact.baseline_sha == baseline
    assert exact.committed_files == ("tracked.txt",)
