from __future__ import annotations

import os
import shutil
import subprocess
import zlib
from pathlib import Path

import pytest

from ai_qa_automation.tools.repository import RepositoryInspector


def _git(repo: Path, *args: str) -> str:
    executable = shutil.which("git")
    if executable is None:
        pytest.skip("git executable is unavailable")
    home = repo.parent / ".aiqa-object-integrity-git-home"
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


def _init_repo(repo: Path) -> None:
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "AI QA Test")
    _git(repo, "config", "user.email", "aiqa@example.invalid")


def test_read_file_at_rejects_tampered_loose_blob_under_existing_oid(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init_repo(repo)
    original = b"ORIGINAL"
    tampered = b"TAMPERED"
    assert len(original) == len(tampered)

    (repo / "payload.bin").write_bytes(original)
    _git(repo, "add", "payload.bin")
    _git(repo, "commit", "-q", "-m", "baseline")
    commit_sha = _git(repo, "rev-parse", "HEAD")
    blob_oid = _git(repo, "rev-parse", f"{commit_sha}:payload.bin")
    assert len(blob_oid) == 40

    object_path = repo / ".git" / "objects" / blob_oid[:2] / blob_oid[2:]
    forged_loose_object = f"blob {len(tampered)}\0".encode("ascii") + tampered
    object_path.write_bytes(zlib.compress(forged_loose_object))

    assert _git(repo, "cat-file", "blob", blob_oid) == tampered.decode("ascii")
    with pytest.raises(RuntimeError, match="content-addressed object id"):
        RepositoryInspector(repo).read_file_at(commit_sha, "payload.bin")
