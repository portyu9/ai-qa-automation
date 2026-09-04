from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from contextlib import AbstractContextManager
from pathlib import Path

import pytest

import ai_qa_automation.tools.execution_subject as subject_module
from ai_qa_automation.evidence import EvidenceStore
from ai_qa_automation.fs_authority import (
    descriptor_relative_authority_supported,
    pin_directory_identity,
)
from ai_qa_automation.tools.execution_env import BoundedSubprocessResult
from ai_qa_automation.tools.execution_subject import (
    ExecutionSubjectError,
    MaterializedExecutionSubject,
    materialized_pytest_execution_subject,
)
from ai_qa_automation.tools.pytest_sandbox import (
    BubblewrapPytestSandbox,
    PytestSandboxPreflight,
)
from ai_qa_automation.tools.repository import RepositoryInspector, RepositorySnapshot
from ai_qa_automation.tools.test_execution import TestRunner


def _require_descriptor_authority() -> None:
    if not descriptor_relative_authority_supported():
        pytest.skip("descriptor-relative filesystem authority is unavailable")


def _materialized_subject(
    workspace: Path,
    snapshot: RepositorySnapshot,
    tmp_path: Path,
) -> AbstractContextManager[MaterializedExecutionSubject]:
    scratch_root = tmp_path / "pytest-scratch"
    scratch_root.mkdir(exist_ok=True)
    return materialized_pytest_execution_subject(
        workspace,
        expected_snapshot=snapshot,
        scratch_root=scratch_root,
        expected_scratch_root_identity=pin_directory_identity(
            scratch_root,
            label="test pytest scratch root",
        ),
    )


def _git(repo: Path, *args: str) -> str:
    executable = shutil.which("git")
    if executable is None:
        pytest.skip("git executable is unavailable")
    home = repo.parent / ".aiqa-execution-subject-git-home"
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
    (repo / "tracked.txt").write_text("baseline\n", encoding="utf-8")
    (repo / "test_sample.py").write_text(
        "def test_sample():\n    assert True\n",
        encoding="utf-8",
    )
    _git(repo, "add", "--", "tracked.txt", "test_sample.py")
    _git(repo, "commit", "-q", "-m", "initial")


def test_materialized_subject_excludes_ordinary_ignored_inputs_and_git_metadata(
    tmp_path: Path,
) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    (workspace / ".gitignore").write_text("runtime-data/\n", encoding="utf-8")
    _git(workspace, "add", "--", ".gitignore")
    _git(workspace, "commit", "-q", "-m", "ignore runtime data")
    ignored = workspace / "runtime-data" / "config.json"
    ignored.parent.mkdir()
    ignored.write_text('{"mode":"before"}\n', encoding="utf-8")

    snapshot = RepositoryInspector(workspace).snapshot()
    assert snapshot.fingerprint_complete is True
    assert snapshot.changed_files == ()

    with _materialized_subject(workspace, snapshot, tmp_path) as subject:
        assert (subject.root / "tracked.txt").read_text(encoding="utf-8") == "baseline\n"
        assert (subject.root / "test_sample.py").is_file()
        assert not (subject.root / "runtime-data").exists()
        assert not (subject.root / ".git").exists()
        ignored.write_text('{"mode":"after"}\n', encoding="utf-8")
        assert not (subject.root / "runtime-data" / "config.json").exists()
        assert subject.ignored_inputs_excluded is True
        assert subject.git_metadata_excluded is True
        assert subject.source_fingerprint == snapshot.fingerprint
        assert subject.digest.startswith("sha256:")


def test_materialized_subject_includes_nonignored_untracked_regular_file(
    tmp_path: Path,
) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    untracked = workspace / "candidate.py"
    untracked.write_text("VALUE = 7\n", encoding="utf-8")

    snapshot = RepositoryInspector(workspace).snapshot()
    assert snapshot.fingerprint_complete is True
    assert "candidate.py" in snapshot.changed_files

    with _materialized_subject(workspace, snapshot, tmp_path) as subject:
        assert (subject.root / "candidate.py").read_text(encoding="utf-8") == "VALUE = 7\n"


def test_materialized_subject_preserves_staged_delete_ignored_replacement(
    tmp_path: Path,
) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    (workspace / ".gitignore").write_text("tracked.txt\n", encoding="utf-8")
    _git(workspace, "add", "--", ".gitignore")
    _git(workspace, "commit", "-q", "-m", "ignore tracked replacement")
    _git(workspace, "rm", "--cached", "--", "tracked.txt")
    (workspace / "tracked.txt").write_text("physical-replacement\n", encoding="utf-8")
    assert "tracked.txt" not in _git(
        workspace,
        "ls-files",
        "--others",
        "--exclude-standard",
    )

    snapshot = RepositoryInspector(workspace).snapshot()
    assert snapshot.fingerprint_complete is True
    assert snapshot.changed_files == ("tracked.txt",)

    with _materialized_subject(workspace, snapshot, tmp_path) as subject:
        assert (subject.root / "tracked.txt").read_text(encoding="utf-8") == (
            "physical-replacement\n"
        )
        assert not (subject.root / ".git").exists()


@pytest.mark.skipif(os.name == "nt", reason="symlink authority test requires POSIX")
def test_ignored_symlink_cannot_enter_materialized_execution_namespace(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    (workspace / ".gitignore").write_text("ignored-link\n", encoding="utf-8")
    _git(workspace, "add", "--", ".gitignore")
    _git(workspace, "commit", "-q", "-m", "ignore symlink")
    outside = tmp_path / "outside-secret.txt"
    outside.write_text("secret\n", encoding="utf-8")
    (workspace / "ignored-link").symlink_to(outside)

    snapshot = RepositoryInspector(workspace).snapshot()
    assert snapshot.fingerprint_complete is True
    assert snapshot.changed_files == ()

    with _materialized_subject(workspace, snapshot, tmp_path) as subject:
        assert not (subject.root / "ignored-link").exists()
        assert not (subject.root / ".git").exists()


@pytest.mark.skipif(os.name == "nt", reason="symlink authority test requires POSIX")
def test_nonignored_symlink_fails_closed_before_materialization(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    outside = tmp_path / "outside.txt"
    outside.write_text("outside\n", encoding="utf-8")
    (workspace / "visible-link").symlink_to(outside)

    snapshot = RepositoryInspector(workspace).snapshot()
    assert snapshot.fingerprint_complete is False

    with pytest.raises(ExecutionSubjectError, match="fingerprint is incomplete"):
        with _materialized_subject(workspace, snapshot, tmp_path):
            raise AssertionError("unsafe symlink subject must not be yielded")


def test_materialized_subject_total_bytes_are_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    snapshot = RepositoryInspector(workspace).snapshot()
    assert snapshot.fingerprint_complete is True
    monkeypatch.setattr(subject_module, "_MAX_EXECUTION_SUBJECT_TOTAL_BYTES", 1)

    with pytest.raises(ExecutionSubjectError, match="total byte budget"):
        with _materialized_subject(workspace, snapshot, tmp_path):
            raise AssertionError("over-budget execution subject must not be yielded")


def test_bound_index_parser_rejects_checksum_corruption(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    raw_index = bytearray(RepositoryInspector(workspace)._read_index_bytes())
    assert len(raw_index) > 32
    raw_index[16] ^= 0x01

    with pytest.raises(ExecutionSubjectError, match="checksum is invalid or ambiguous"):
        subject_module._parse_bound_index_entries(bytes(raw_index))


def test_bound_index_parser_rejects_unknown_mandatory_extension(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    raw_index = RepositoryInspector(workspace)._read_index_bytes()
    oid_bytes = subject_module._git_index_oid_bytes(raw_index)
    body = raw_index[:-oid_bytes] + b"abcd" + (0).to_bytes(4, "big")
    if oid_bytes == 20:
        checksum = hashlib.sha1(body, usedforsecurity=False).digest()
    else:
        checksum = hashlib.sha256(body).digest()

    with pytest.raises(ExecutionSubjectError, match="mandatory Git index extension"):
        subject_module._parse_bound_index_entries(body + checksum)


def test_materialized_subject_supports_git_index_v4(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    _git(workspace, "update-index", "--index-version", "4")
    snapshot = RepositoryInspector(workspace).snapshot()
    assert snapshot.fingerprint_complete is True

    with _materialized_subject(workspace, snapshot, tmp_path) as subject:
        assert (subject.root / "tracked.txt").read_text(encoding="utf-8") == "baseline\n"
        assert (subject.root / "test_sample.py").is_file()


@pytest.mark.skipif(os.name == "nt", reason="POSIX executable bits are required")
def test_unstaged_executable_mode_change_fails_closed(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    tracked = workspace / "tracked.txt"
    tracked.chmod(tracked.stat().st_mode | 0o111)

    snapshot = RepositoryInspector(workspace).snapshot()
    assert snapshot.fingerprint_complete is True
    assert "tracked.txt" in snapshot.changed_files

    with pytest.raises(ExecutionSubjectError, match="executable mode diverges"):
        with _materialized_subject(workspace, snapshot, tmp_path):
            raise AssertionError("unstaged executable authority must not be yielded")


@pytest.mark.skipif(os.name == "nt", reason="POSIX executable bits are required")
def test_executable_untracked_path_fails_closed(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    executable = workspace / "tool.sh"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(executable.stat().st_mode | 0o111)

    snapshot = RepositoryInspector(workspace).snapshot()
    assert snapshot.fingerprint_complete is True
    assert "tool.sh" in snapshot.changed_files

    with pytest.raises(ExecutionSubjectError, match="lacks Git-index mode authority"):
        with _materialized_subject(workspace, snapshot, tmp_path):
            raise AssertionError("untracked executable authority must not be yielded")


@pytest.mark.skipif(os.name == "nt", reason="POSIX executable bits are required")
def test_staged_executable_mode_is_materialized_from_git_index(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    tracked = workspace / "tracked.txt"
    tracked.chmod(tracked.stat().st_mode | 0o111)
    _git(workspace, "add", "--", "tracked.txt")

    snapshot = RepositoryInspector(workspace).snapshot()
    assert snapshot.fingerprint_complete is True
    assert "tracked.txt" in snapshot.changed_files

    with _materialized_subject(workspace, snapshot, tmp_path) as subject:
        assert (subject.root / "tracked.txt").stat().st_mode & 0o111


class _BoundWorkspaceSandbox:
    python_executable = Path(sys.executable)

    def __init__(
        self,
        workspace: Path,
        observations: list[Path],
        *,
        forbidden_source_workspace: Path | None = None,
        source_workspace_hidden: bool = False,
    ) -> None:
        self.workspace = workspace.resolve()
        self.observations = observations
        self.forbidden_source_workspace = (
            None if forbidden_source_workspace is None else forbidden_source_workspace.resolve()
        )
        self.source_workspace_hidden = source_workspace_hidden
        self.result = BoundedSubprocessResult(
            returncode=0,
            stdout="1 passed",
            stderr="",
            stdout_truncated=False,
            stderr_truncated=False,
            timed_out=False,
        )
        self.preflight_result = PytestSandboxPreflight(
            ready=True,
            backend="fake-materialized-test-sandbox",
            reason=None,
            workspace_identity_bound=True,
            workspace_read_only=True,
            forbidden_roots_hidden=True,
            no_non_loopback_interfaces=True,
            effective_capabilities_zero=True,
        )

    def for_materialized_workspace(
        self,
        workspace: Path,
        *,
        forbidden_source_workspace: Path,
    ) -> _BoundWorkspaceSandbox:
        return _BoundWorkspaceSandbox(
            workspace,
            self.observations,
            forbidden_source_workspace=forbidden_source_workspace,
            source_workspace_hidden=True,
        )

    def preflight(self) -> PytestSandboxPreflight:
        return self.preflight_result

    def run(self, command, *, env, timeout_seconds):
        ignored = self.workspace / "runtime-data" / "config.json"
        self.observations.append(ignored)
        if ignored.exists():
            raise AssertionError("Git-ignored source input leaked into pytest execution subject")
        if (self.workspace / ".git").exists():
            raise AssertionError("Git metadata leaked into pytest execution subject")
        return self.preflight_result, self.result


class _ScratchObservingSandbox(_BoundWorkspaceSandbox):
    def __init__(
        self,
        workspace: Path,
        observations: list[Path],
        homes: list[Path],
        *,
        forbidden_source_workspace: Path | None = None,
        source_workspace_hidden: bool = False,
    ) -> None:
        super().__init__(
            workspace,
            observations,
            forbidden_source_workspace=forbidden_source_workspace,
            source_workspace_hidden=source_workspace_hidden,
        )
        self.homes = homes

    def for_materialized_workspace(
        self,
        workspace: Path,
        *,
        forbidden_source_workspace: Path,
    ) -> _ScratchObservingSandbox:
        return _ScratchObservingSandbox(
            workspace,
            self.observations,
            self.homes,
            forbidden_source_workspace=forbidden_source_workspace,
            source_workspace_hidden=True,
        )

    def run(self, command, *, env, timeout_seconds):
        self.homes.append(Path(env["HOME"]).resolve())
        return super().run(command, env=env, timeout_seconds=timeout_seconds)


class _SourceVisibleSandbox(_BoundWorkspaceSandbox):
    def for_materialized_workspace(
        self,
        workspace: Path,
        *,
        forbidden_source_workspace: Path,
    ) -> _BoundWorkspaceSandbox:
        return _BoundWorkspaceSandbox(
            workspace,
            self.observations,
            forbidden_source_workspace=forbidden_source_workspace,
            source_workspace_hidden=False,
        )


def test_test_runner_executes_against_materialized_subject_not_source_workspace(
    tmp_path: Path,
) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    (workspace / ".gitignore").write_text("runtime-data/\n", encoding="utf-8")
    _git(workspace, "add", "--", ".gitignore")
    _git(workspace, "commit", "-q", "-m", "ignore runtime data")
    ignored = workspace / "runtime-data" / "config.json"
    ignored.parent.mkdir()
    ignored.write_text('{"mode":"host-only"}\n', encoding="utf-8")

    observations: list[Path] = []
    evidence = EvidenceStore(tmp_path / "artifacts", "run-materialized-subject")
    runner = TestRunner(
        workspace,
        evidence,
        sandbox=_BoundWorkspaceSandbox(workspace, observations),
    )

    result = runner.run_pytest([])

    assert result.exit_code == 0
    assert result.execution_started is True
    assert len(observations) == 1
    assert observations[0].parent.parent != workspace
    exit_item = evidence.get(result.evidence_ids[0])
    execution_subject = exit_item.structured_data["execution_subject"]
    assert execution_subject["ignored_inputs_excluded"] is True
    assert execution_subject["git_metadata_excluded"] is True
    assert (
        execution_subject["source_fingerprint"]
        == RepositoryInspector(workspace).snapshot().fingerprint
    )


def test_custom_sandbox_without_source_hiding_is_blocked_before_execution(
    tmp_path: Path,
) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    observations: list[Path] = []
    runner = TestRunner(
        workspace,
        EvidenceStore(tmp_path / "artifacts", "run-source-visible-sandbox"),
        sandbox=_SourceVisibleSandbox(workspace, observations),
    )

    result = runner.run_pytest([])

    assert result.exit_code == 126
    assert result.execution_started is False
    assert observations == []
    assert "did not prove the source workspace is hidden" in result.stderr


def test_default_bubblewrap_blocks_source_overlap_with_runtime_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    monkeypatch.setattr(
        BubblewrapPytestSandbox,
        "_runtime_roots",
        lambda _sandbox: (workspace.parent.resolve(),),
    )
    runner = TestRunner(
        workspace,
        EvidenceStore(tmp_path / "artifacts", "run-runtime-root-overlap"),
    )

    result = runner.run_pytest([])

    assert result.exit_code == 126
    assert result.execution_started is False
    assert "source workspace overlaps a host runtime root exposed to pytest" in result.stderr


def test_test_runner_ignores_ambient_tmpdir_for_materialization_and_host_home(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    monkeypatch.setenv("TMPDIR", str(workspace))
    observations: list[Path] = []
    homes: list[Path] = []
    evidence = EvidenceStore(tmp_path / "artifacts", "run-hostile-tmpdir")
    scratch_directories: list[Path] = []
    real_temporary_directory = tempfile.TemporaryDirectory

    def require_explicit_scratch_dir(*args, **kwargs):
        directory = kwargs.get("dir")
        assert directory is not None
        scratch_directories.append(Path(directory).resolve())
        return real_temporary_directory(*args, **kwargs)

    monkeypatch.setattr(tempfile, "TemporaryDirectory", require_explicit_scratch_dir)
    runner = TestRunner(
        workspace,
        evidence,
        sandbox=_ScratchObservingSandbox(workspace, observations, homes),
    )

    result = runner.run_pytest([])

    assert result.exit_code == 0
    assert result.execution_started is True
    assert len(observations) == 1
    assert len(homes) == 1
    assert scratch_directories == [evidence.run_root, evidence.run_root]
    assert evidence.run_root in observations[0].parents
    assert evidence.run_root in homes[0].parents
    assert workspace not in observations[0].parents
    assert workspace not in homes[0].parents
