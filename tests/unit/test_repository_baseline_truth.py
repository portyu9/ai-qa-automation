from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from ai_qa_automation.runtime.bootstrap import _contract_drift_reports
from ai_qa_automation.tools.repository import RepositoryChangeSet, RepositoryInspector


def _git(repo: Path, *args: str) -> str:
    executable = shutil.which("git")
    if executable is None:
        pytest.skip("git executable is unavailable")
    home = repo.parent / ".aiqa-baseline-truth-git-home"
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


def _commit(repo: Path, message: str = "checkpoint") -> str:
    _git(repo, "add", "--all")
    _git(repo, "commit", "-q", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


def test_read_file_at_reports_true_absence_from_valid_commit(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init_repo(repo)
    (repo / "tracked.txt").write_text("tracked\n", encoding="utf-8")
    commit_sha = _commit(repo)

    inspector = RepositoryInspector(repo)

    with pytest.raises(FileNotFoundError, match=r"missing\.json"):
        inspector.read_file_at(commit_sha, "missing.json")


def test_read_file_at_uses_literal_tree_path_for_metacharacters(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init_repo(repo)
    payload = b"\x00\xffliteral-path\n"
    (repo / "literal*name.json").write_bytes(payload)
    (repo / "literalXname.json").write_bytes(b"must-not-match\n")
    commit_sha = _commit(repo)

    observed = RepositoryInspector(repo).read_file_at(commit_sha, "literal*name.json")

    assert observed == payload


def test_read_file_at_ignores_git_replacement_objects(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init_repo(repo)
    original = b"ORIGINAL"
    replacement = b"REPLACED"
    assert len(original) == len(replacement)

    (repo / "payload.bin").write_bytes(original)
    original_commit = _commit(repo, "original")
    original_blob = _git(repo, "rev-parse", f"{original_commit}:payload.bin")

    (repo / "payload.bin").write_bytes(replacement)
    replacement_commit = _commit(repo, "replacement")
    replacement_blob = _git(repo, "rev-parse", f"{replacement_commit}:payload.bin")

    _git(repo, "replace", original_commit, replacement_commit)
    _git(repo, "replace", original_blob, replacement_blob)
    assert _git(repo, "show", f"{original_commit}:payload.bin") == replacement.decode()

    observed = RepositoryInspector(repo).read_file_at(original_commit, "payload.bin")

    assert observed == original


def test_change_set_rejects_legacy_git_grafts(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init_repo(repo)
    (repo / "tracked.txt").write_text("baseline\n", encoding="utf-8")
    baseline_sha = _commit(repo, "baseline")
    _git(repo, "branch", "baseline", baseline_sha)

    (repo / "tracked.txt").write_text("head\n", encoding="utf-8")
    head_sha = _commit(repo, "head")
    _git(repo, "config", "advice.graftFileDeprecated", "false")
    graft_file = repo / ".git" / "info" / "grafts"
    graft_file.parent.mkdir(parents=True, exist_ok=True)
    graft_file.write_text(f"{head_sha}\n", encoding="ascii")

    with pytest.raises(RuntimeError, match="graft metadata"):
        RepositoryInspector(repo).change_set("baseline")


def test_read_file_at_rejects_invalid_commit_as_repository_failure(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init_repo(repo)
    (repo / "tracked.txt").write_text("tracked\n", encoding="utf-8")
    _commit(repo)

    inspector = RepositoryInspector(repo)
    invalid_commit = "f" * 40

    with pytest.raises(RuntimeError):
        inspector.read_file_at(invalid_commit, "tracked.txt")


def test_read_file_at_rejects_non_blob_tree_entry(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init_repo(repo)
    contracts = repo / "contracts"
    contracts.mkdir()
    (contracts / "openapi.json").write_text('{"openapi":"3.1.0"}', encoding="utf-8")
    commit_sha = _commit(repo)

    with pytest.raises(RuntimeError, match="baseline path is not a Git blob"):
        RepositoryInspector(repo).read_file_at(commit_sha, "contracts")


def test_blob_lookup_rejects_malformed_or_ambiguous_tree_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inspector = RepositoryInspector(tmp_path)
    object_id = "1" * 40
    nul = "\0"
    malformed = [
        f"not-a-tree-record{nul}",
        f"100644 blob {object_id}\tother.json{nul}",
        f"100644 blob {object_id}\tpayload.json{nul}100644 blob {'2' * 40}\tpayload.json{nul}",
        f"100644 mystery {object_id}\tpayload.json{nul}",
        f"100644 blob not-a-sha\tpayload.json{nul}",
    ]

    for raw in malformed:
        monkeypatch.setattr(inspector, "_git", lambda *args, _raw=raw, **kwargs: _raw)
        with pytest.raises(RuntimeError, match="tree entry"):
            inspector._blob_oid_at("a" * 40, "payload.json")


def test_size_failure_after_blob_presence_remains_repository_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inspector = RepositoryInspector(tmp_path)
    monkeypatch.setattr(inspector, "_blob_oid_at", lambda *_args: "3" * 40)

    def fail_size(*args: str, **kwargs: object) -> str:
        if args == ("rev-parse", "--show-object-format"):
            return "sha1"
        raise RuntimeError("synthetic object corruption")

    monkeypatch.setattr(inspector, "_git", fail_size)

    with pytest.raises(RuntimeError, match="synthetic object corruption"):
        inspector.read_file_at("a" * 40, "payload.json")


def test_content_failure_after_blob_presence_remains_repository_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inspector = RepositoryInspector(tmp_path)
    monkeypatch.setattr(inspector, "_blob_oid_at", lambda *_args: "4" * 40)

    def git_metadata(*args: str, **kwargs: object) -> str:
        if args == ("rev-parse", "--show-object-format"):
            return "sha1"
        if len(args) == 3 and args[:2] == ("cat-file", "-s"):
            return "4"
        raise AssertionError(f"unexpected git metadata command: {args}")

    monkeypatch.setattr(inspector, "_git", git_metadata)

    def fail_content(*args: str, **kwargs: object) -> bytes:
        raise RuntimeError("synthetic blob read failure")

    monkeypatch.setattr(inspector, "_git_bytes", fail_content)

    with pytest.raises(RuntimeError, match="synthetic blob read failure"):
        inspector.read_file_at("a" * 40, "payload.json")


def test_added_openapi_contract_is_non_breaking_with_real_repository_inspector(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    _init_repo(repo)
    (repo / "README.md").write_text("baseline\n", encoding="utf-8")
    baseline_sha = _commit(repo, "baseline")
    (repo / "openapi.json").write_text(
        '{"openapi":"3.1.0","info":{"title":"demo","version":"1"},"paths":{}}',
        encoding="utf-8",
    )
    change_set = RepositoryChangeSet(
        requested_base_ref="main",
        baseline_sha=baseline_sha,
        merge_base_sha=baseline_sha,
        head_sha=baseline_sha,
        committed_files=(),
        worktree_files=("openapi.json",),
        changed_files=("openapi.json",),
    )

    reports = _contract_drift_reports(
        workspace=repo,
        inspector=RepositoryInspector(repo),
        change_set=change_set,
        changed_files=("openapi.json",),
    )

    assert len(reports) == 1
    assert reports[0]["severity"] == "NON_BREAKING"
    assert reports[0]["analyzed"] is True
    assert reports[0]["reason"] is None
    assert reports[0]["changes"][0]["rule_id"] == "OAS-CONTRACT-ADDED"  # type: ignore[index]


def test_invalid_baseline_commit_is_not_normalized_to_added_contract(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init_repo(repo)
    (repo / "README.md").write_text("baseline\n", encoding="utf-8")
    baseline_sha = _commit(repo, "baseline")
    (repo / "openapi.json").write_text(
        '{"openapi":"3.1.0","info":{"title":"demo","version":"1"},"paths":{}}',
        encoding="utf-8",
    )
    invalid_commit = "f" * 40
    assert invalid_commit != baseline_sha
    change_set = RepositoryChangeSet(
        requested_base_ref="main",
        baseline_sha=invalid_commit,
        merge_base_sha=invalid_commit,
        head_sha=baseline_sha,
        committed_files=(),
        worktree_files=("openapi.json",),
        changed_files=("openapi.json",),
    )

    reports = _contract_drift_reports(
        workspace=repo,
        inspector=RepositoryInspector(repo),
        change_set=change_set,
        changed_files=("openapi.json",),
    )

    assert reports == [
        {
            "path": "openapi.json",
            "contract_kind": "openapi",
            "severity": "NOT_ANALYZED",
            "changes": [],
            "analyzed": False,
            "reason": "baseline read failed: RuntimeError",
        }
    ]
