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


def _replace_loose_object(repo: Path, object_id: str, object_type: str, body: bytes) -> None:
    object_path = repo / ".git" / "objects" / object_id[:2] / object_id[2:]
    object_path.chmod(0o644)
    encoded = f"{object_type} {len(body)}\0".encode("ascii") + body
    object_path.write_bytes(zlib.compress(encoded))


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

    _replace_loose_object(repo, blob_oid, "blob", tampered)

    assert _git(repo, "cat-file", "blob", blob_oid) == tampered.decode("ascii")
    with pytest.raises(RuntimeError, match="content-addressed object id"):
        RepositoryInspector(repo).read_file_at(commit_sha, "payload.bin")


def test_read_file_at_rejects_tampered_tree_under_existing_oid(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init_repo(repo)
    (repo / "payload.bin").write_bytes(b"ORIGINAL")
    _git(repo, "add", "payload.bin")
    _git(repo, "commit", "-q", "-m", "baseline")
    commit_sha = _git(repo, "rev-parse", "HEAD")
    tree_oid = _git(repo, "rev-parse", f"{commit_sha}^{{tree}}")
    blob_oid = _git(repo, "rev-parse", f"{commit_sha}:payload.bin")
    assert len(tree_oid) == len(blob_oid) == 40

    forged_tree = b"100755 payload.bin\0" + bytes.fromhex(blob_oid)
    _replace_loose_object(repo, tree_oid, "tree", forged_tree)

    with pytest.raises(RuntimeError):
        RepositoryInspector(repo).read_file_at(commit_sha, "payload.bin")


def test_snapshot_rejects_branch_ref_that_points_to_tree_object(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init_repo(repo)
    (repo / "tracked.txt").write_text("tracked\n", encoding="utf-8")
    _git(repo, "add", "tracked.txt")
    _git(repo, "commit", "-q", "-m", "baseline")
    commit_sha = _git(repo, "rev-parse", "HEAD")
    tree_oid = _git(repo, "rev-parse", f"{commit_sha}^{{tree}}")
    branch = _git(repo, "symbolic-ref", "--short", "HEAD")
    ref_path = repo / ".git" / "refs" / "heads" / branch
    ref_path.write_text(f"{tree_oid}\n", encoding="ascii")

    assert _git(repo, "rev-parse", "HEAD") == tree_oid
    assert _git(repo, "ls-tree", "-r", tree_oid)

    snapshot = RepositoryInspector(repo).snapshot()

    assert snapshot.git_sha is None
    assert snapshot.fingerprint_complete is False
    assert snapshot.fingerprint_incomplete_reasons == ("git-inspection-incomplete",)
