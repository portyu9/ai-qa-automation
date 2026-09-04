from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

import ai_qa_automation.tools.pytest_sandbox as sandbox_module
from ai_qa_automation.evidence import EvidenceStore
from ai_qa_automation.fs_authority import descriptor_relative_authority_supported
from ai_qa_automation.tools.execution_env import BoundedSubprocessResult
from ai_qa_automation.tools.pytest_sandbox import BubblewrapPytestSandbox, PytestSandboxPreflight
from ai_qa_automation.tools.repository import RepositoryInspector
from ai_qa_automation.tools.test_execution import TestRunner


def _require_descriptor_authority() -> None:
    if not descriptor_relative_authority_supported():
        pytest.skip("descriptor-relative filesystem authority is unavailable")


def _git(repo: Path, *args: str) -> None:
    executable = shutil.which("git")
    if executable is None:
        pytest.skip("git executable is unavailable")
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(repo.parent),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
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
        raise AssertionError(result.stderr)


def _init_repo(repo: Path) -> None:
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "AI QA Test")
    _git(repo, "config", "user.email", "aiqa@example.invalid")
    (repo / "test_sample.py").write_text("def test_sample():\n    assert True\n", encoding="utf-8")
    _git(repo, "add", "--", "test_sample.py")
    _git(repo, "commit", "-q", "-m", "initial")


def _result(*, returncode: int = 0) -> BoundedSubprocessResult:
    return BoundedSubprocessResult(
        returncode=returncode,
        stdout="",
        stderr="",
        stdout_truncated=False,
        stderr_truncated=False,
        timed_out=False,
    )


def _ready_preflight(sandbox: BubblewrapPytestSandbox, executable: Path) -> PytestSandboxPreflight:
    return PytestSandboxPreflight(
        ready=True,
        backend="bubblewrap",
        reason=None,
        executable=str(executable),
        executable_sha256=sandbox._hash_executable(executable),
        version="bubblewrap 0.12.0",
        parent_namespaces={
            "mnt": "m1",
            "pid": "p1",
            "net": "n1",
            "user": "u1",
            "ipc": "i1",
            "uts": "t1",
        },
        child_namespaces={
            "mnt": "m2",
            "pid": "p2",
            "net": "n2",
            "user": "u2",
            "ipc": "i2",
            "uts": "t2",
        },
        workspace_identity_bound=True,
        workspace_read_only=True,
        forbidden_roots_hidden=True,
        no_non_loopback_interfaces=True,
        effective_capabilities_zero=True,
    )


def test_repository_inspection_does_not_create_ambient_git_home(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    monkeypatch.setenv("TMPDIR", str(workspace))
    monkeypatch.setattr(
        tempfile,
        "TemporaryDirectory",
        lambda *args, **kwargs: pytest.fail("repository inspection must not create temp HOME"),
    )

    snapshot = RepositoryInspector(workspace).snapshot()

    assert snapshot.git_sha is not None
    assert snapshot.fingerprint_complete is True


def test_bubblewrap_preflight_roots_host_home_in_evidence_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    evidence = tmp_path / "evidence"
    workspace.mkdir()
    evidence.mkdir()
    monkeypatch.setenv("TMPDIR", str(workspace))
    observed: list[Path] = []
    real_temporary_directory = tempfile.TemporaryDirectory

    def capture_directory(*args, **kwargs):
        directory = kwargs.get("dir")
        assert directory is not None
        observed.append(Path(directory).resolve())
        return real_temporary_directory(*args, **kwargs)

    monkeypatch.setattr(sandbox_module.tempfile, "TemporaryDirectory", capture_directory)
    monkeypatch.setattr(sandbox_module.shutil, "which", lambda *args, **kwargs: None)

    result = BubblewrapPytestSandbox(workspace, evidence_root=evidence).preflight()

    assert result.ready is False
    assert observed == [evidence.resolve()]


def test_bubblewrap_run_roots_host_home_and_status_file_in_evidence_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    evidence = tmp_path / "evidence"
    workspace.mkdir()
    evidence.mkdir()
    executable = tmp_path / "bwrap"
    executable.write_bytes(b"bubblewrap")
    executable.chmod(0o755)
    sandbox = BubblewrapPytestSandbox(workspace, evidence_root=evidence)
    preflight = _ready_preflight(sandbox, executable)
    monkeypatch.setattr(sandbox, "preflight", lambda: preflight)
    monkeypatch.setenv("TMPDIR", str(workspace))
    observed_directories: list[Path] = []
    observed_files: list[Path] = []
    real_temporary_directory = tempfile.TemporaryDirectory
    real_temporary_file = tempfile.TemporaryFile

    def capture_directory(*args, **kwargs):
        directory = kwargs.get("dir")
        assert directory is not None
        observed_directories.append(Path(directory).resolve())
        return real_temporary_directory(*args, **kwargs)

    def capture_file(*args, **kwargs):
        directory = kwargs.get("dir")
        assert directory is not None
        observed_files.append(Path(directory).resolve())
        return real_temporary_file(*args, **kwargs)

    def fake_run(*args, **kwargs):
        status_fd = kwargs["pass_fds"][0]
        os.write(status_fd, b'{"child-pid":123}\n{"exit-code":0}\n')
        return _result(returncode=0)

    monkeypatch.setattr(sandbox_module.tempfile, "TemporaryDirectory", capture_directory)
    monkeypatch.setattr(sandbox_module.tempfile, "TemporaryFile", capture_file)
    monkeypatch.setattr(sandbox_module, "run_bounded_subprocess", fake_run)

    _, result = sandbox.run(
        [str(sandbox.python_executable), "-m", "pytest"],
        env={"LANG": "C.UTF-8"},
        timeout_seconds=5,
    )

    assert result.returncode == 0
    assert observed_directories == [evidence.resolve()]
    assert observed_files == [evidence.resolve()]


def test_bubblewrap_preflight_rejects_stale_evidence_root_identity_before_temp_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    evidence = tmp_path / "evidence"
    workspace.mkdir()
    evidence.mkdir()
    sandbox = BubblewrapPytestSandbox(
        workspace,
        evidence_root=evidence,
        expected_evidence_root_identity=(-1, -1),
    )
    monkeypatch.setattr(
        sandbox_module.tempfile,
        "TemporaryDirectory",
        lambda *args, **kwargs: pytest.fail("stale scratch authority must block first"),
    )

    result = sandbox.preflight()

    assert result.ready is False
    assert "changed identity since authorization" in (result.reason or "")


def test_test_runner_preflight_rejects_workspace_evidence_overlap(
    tmp_path: Path,
) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    evidence = EvidenceStore(workspace / "artifacts", "run-overlap")
    runner = TestRunner(workspace, evidence)

    result = runner.sandbox_preflight()

    assert result.ready is False
    assert "scratch-root authority is unavailable" in (result.reason or "")
