from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import ai_qa_automation.tools.pytest_sandbox as sandbox_module
from ai_qa_automation.tools.execution_env import BoundedSubprocessResult
from ai_qa_automation.tools.pytest_sandbox import (
    BubblewrapPytestSandbox,
    PytestSandboxExecutionUnverified,
    PytestSandboxPreflight,
    PytestSandboxUnavailable,
)


def process_result(
    *, returncode: int = 0, stdout: str = "", stderr: str = ""
) -> BoundedSubprocessResult:
    return BoundedSubprocessResult(
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        stdout_truncated=False,
        stderr_truncated=False,
        timed_out=False,
    )


def ready_preflight(executable: Path) -> PytestSandboxPreflight:
    return PytestSandboxPreflight(
        ready=True,
        backend="bubblewrap",
        reason=None,
        executable=str(executable),
        executable_sha256="sha256:" + "a" * 64,
        version="bubblewrap 0.12.0",
        parent_namespaces={"mnt": "1", "pid": "2", "net": "3", "user": "4"},
        child_namespaces={"mnt": "5", "pid": "6", "net": "7", "user": "8"},
        workspace_identity_bound=True,
        workspace_read_only=True,
        forbidden_roots_hidden=True,
        no_non_loopback_interfaces=True,
        effective_capabilities_zero=True,
    )


def test_bubblewrap_preflight_fails_closed_when_executable_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "sut"
    evidence = tmp_path / "evidence"
    workspace.mkdir()
    evidence.mkdir()
    observed: dict[str, object] = {}

    def missing_bwrap(command: str, *, path: str | None = None) -> None:
        observed.update({"command": command, "path": path})
        return None

    monkeypatch.setattr(sandbox_module.shutil, "which", missing_bwrap)

    result = BubblewrapPytestSandbox(workspace, evidence_root=evidence).preflight()

    assert observed == {"command": "bwrap", "path": "/usr/bin:/bin"}

    assert result.ready is False
    assert result.backend == "bubblewrap"
    assert result.executable is None
    assert "not available" in (result.reason or "")


def test_bubblewrap_preflight_rejects_symlink_executable_before_resolution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "sut"
    evidence = tmp_path / "evidence"
    workspace.mkdir()
    evidence.mkdir()
    target = tmp_path / "real-bwrap"
    target.write_bytes(b"trusted")
    target.chmod(0o755)
    link = tmp_path / "bwrap"
    link.symlink_to(target)
    monkeypatch.setattr(sandbox_module.shutil, "which", lambda *args, **kwargs: str(link))

    result = BubblewrapPytestSandbox(workspace, evidence_root=evidence).preflight()

    assert result.ready is False
    assert "cannot be bound safely" in (result.reason or "")


def test_bubblewrap_command_has_no_host_root_or_network_share_and_mounts_target_read_only(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "sut"
    evidence = tmp_path / "evidence"
    workspace.mkdir()
    evidence.mkdir()
    sandbox = BubblewrapPytestSandbox(workspace, evidence_root=evidence)

    command = sandbox._build_command(  # noqa: SLF001 - authority contract test
        Path("/usr/bin/bwrap"),
        [str(sandbox.python_executable), "-m", "pytest", "tests/test_demo.py"],
        status_fd=9,
    )

    for required in (
        "--die-with-parent",
        "--new-session",
        "--unshare-user",
        "--disable-userns",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-ipc",
        "--unshare-uts",
        "--cap-drop",
        "--clearenv",
        "--json-status-fd",
    ):
        assert required in command
    assert "--share-net" not in command
    assert any(
        command[index : index + 3] == ["--ro-bind", str(workspace.resolve()), "/workspace"]
        for index in range(max(0, len(command) - 2))
    )
    assert str(evidence.resolve()) not in command
    assert not any(
        command[index : index + 3] == ["--bind", "/", "/"]
        or command[index : index + 3] == ["--ro-bind", "/", "/"]
        for index in range(max(0, len(command) - 2))
    )


def test_bubblewrap_preflight_requires_all_observed_isolation_facts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "sut"
    evidence = tmp_path / "evidence"
    workspace.mkdir()
    evidence.mkdir()
    executable = tmp_path / "bwrap"
    executable.write_bytes(b"bubblewrap")
    executable.chmod(0o755)
    monkeypatch.setattr(sandbox_module.shutil, "which", lambda *args, **kwargs: str(executable))
    monkeypatch.setattr(
        BubblewrapPytestSandbox,
        "_namespace_identities",
        staticmethod(lambda: {"mnt": "m1", "pid": "p1", "net": "n1", "user": "u1"}),
    )
    responses = iter(
        [
            process_result(stdout="bubblewrap 0.12.0\n"),
            process_result(
                stdout=json.dumps(
                    {
                        "namespaces": {"mnt": "m2", "pid": "p2", "net": "n2", "user": "u2"},
                        "workspace_identity_bound": True,
                        "workspace_read_only": True,
                        "forbidden_roots_hidden": True,
                        "no_non_loopback_interfaces": True,
                        "effective_capabilities_zero": True,
                    }
                )
            ),
        ]
    )
    monkeypatch.setattr(
        sandbox_module,
        "run_bounded_subprocess",
        lambda *args, **kwargs: next(responses),
    )

    result = BubblewrapPytestSandbox(workspace, evidence_root=evidence).preflight()

    assert result.ready is True
    assert result.workspace_identity_bound is True
    assert result.workspace_read_only is True
    assert result.forbidden_roots_hidden is True
    assert result.no_non_loopback_interfaces is True
    assert result.effective_capabilities_zero is True
    assert result.parent_namespaces == {"mnt": "m1", "pid": "p1", "net": "n1", "user": "u1"}
    assert result.child_namespaces == {"mnt": "m2", "pid": "p2", "net": "n2", "user": "u2"}
    assert result.executable_sha256 is not None


def test_bubblewrap_run_requires_status_proof_that_child_started(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "sut"
    evidence = tmp_path / "evidence"
    workspace.mkdir()
    evidence.mkdir()
    executable = tmp_path / "bwrap"
    executable.write_bytes(b"bubblewrap")
    executable.chmod(0o755)
    sandbox = BubblewrapPytestSandbox(workspace, evidence_root=evidence)
    preflight = ready_preflight(executable)
    digest = sandbox._hash_executable(executable)  # noqa: SLF001
    preflight = PytestSandboxPreflight(**{**preflight.__dict__, "executable_sha256": digest})
    monkeypatch.setattr(sandbox, "preflight", lambda: preflight)

    def fake_run(*args, **kwargs):
        status_fd = kwargs["pass_fds"][0]
        os.write(status_fd, b'{"exit-code":1}\n')
        return process_result(returncode=1)

    monkeypatch.setattr(sandbox_module, "run_bounded_subprocess", fake_run)

    with pytest.raises(PytestSandboxUnavailable, match="did not prove"):
        sandbox.run(
            [str(sandbox.python_executable), "-m", "pytest"],
            env={"LANG": "C.UTF-8"},
            timeout_seconds=5,
        )


def test_bubblewrap_run_rejects_status_exit_mismatch_after_child_started(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "sut"
    evidence = tmp_path / "evidence"
    workspace.mkdir()
    evidence.mkdir()
    executable = tmp_path / "bwrap"
    executable.write_bytes(b"bubblewrap")
    executable.chmod(0o755)
    sandbox = BubblewrapPytestSandbox(workspace, evidence_root=evidence)
    digest = sandbox._hash_executable(executable)  # noqa: SLF001
    preflight = ready_preflight(executable)
    preflight = PytestSandboxPreflight(**{**preflight.__dict__, "executable_sha256": digest})
    monkeypatch.setattr(sandbox, "preflight", lambda: preflight)

    def fake_run(*args, **kwargs):
        status_fd = kwargs["pass_fds"][0]
        os.write(status_fd, b'{"child-pid":123}\n{"exit-code":0}\n')
        return process_result(returncode=1)

    monkeypatch.setattr(sandbox_module, "run_bounded_subprocess", fake_run)

    with pytest.raises(PytestSandboxExecutionUnverified, match="exit code"):
        sandbox.run(
            [str(sandbox.python_executable), "-m", "pytest"],
            env={"LANG": "C.UTF-8"},
            timeout_seconds=5,
        )


def test_bubblewrap_run_rejects_duplicate_exit_status_injection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "sut"
    evidence = tmp_path / "evidence"
    workspace.mkdir()
    evidence.mkdir()
    executable = tmp_path / "bwrap"
    executable.write_bytes(b"bubblewrap")
    executable.chmod(0o755)
    sandbox = BubblewrapPytestSandbox(workspace, evidence_root=evidence)
    digest = sandbox._hash_executable(executable)  # noqa: SLF001
    preflight = ready_preflight(executable)
    preflight = PytestSandboxPreflight(**{**preflight.__dict__, "executable_sha256": digest})
    monkeypatch.setattr(sandbox, "preflight", lambda: preflight)

    def fake_run(*args, **kwargs):
        status_fd = kwargs["pass_fds"][0]
        os.write(
            status_fd,
            b'{"child-pid":123}\n{"exit-code":0}\n{"exit-code":0}\n',
        )
        return process_result(returncode=0)

    monkeypatch.setattr(sandbox_module, "run_bounded_subprocess", fake_run)

    with pytest.raises(PytestSandboxExecutionUnverified, match="exit code"):
        sandbox.run(
            [str(sandbox.python_executable), "-m", "pytest"],
            env={"LANG": "C.UTF-8"},
            timeout_seconds=5,
        )


def test_probe_script_keeps_its_json_runtime_dependency_explicit() -> None:
    assert "import json" in sandbox_module._PROBE_SCRIPT  # noqa: SLF001
    compile(sandbox_module._PROBE_SCRIPT, "<pytest-sandbox-probe>", "exec")  # noqa: SLF001


def test_execution_guard_script_revalidates_before_exec() -> None:
    script = sandbox_module._EXECUTION_GUARD_SCRIPT  # noqa: SLF001
    compile(script, "<pytest-sandbox-execution-guard>", "exec")
    for required in (
        "/proc/self/ns/",
        "observed_workspace.st_dev",
        "probe.write_text",
        "forbidden_root.exists",
        "socket.if_nameindex",
        "CapEff:",
        "os.execv",
    ):
        assert required in script


def test_bubblewrap_run_wraps_pytest_with_execution_time_guard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "sut"
    evidence = tmp_path / "evidence"
    workspace.mkdir()
    evidence.mkdir()
    executable = tmp_path / "bwrap"
    executable.write_bytes(b"bubblewrap")
    executable.chmod(0o755)
    sandbox = BubblewrapPytestSandbox(workspace, evidence_root=evidence)
    digest = sandbox._hash_executable(executable)  # noqa: SLF001
    preflight = ready_preflight(executable)
    preflight = PytestSandboxPreflight(**{**preflight.__dict__, "executable_sha256": digest})
    monkeypatch.setattr(sandbox, "preflight", lambda: preflight)
    observed: dict[str, list[str]] = {}

    def fake_run(command, *args, **kwargs):
        observed["command"] = list(command)
        status_fd = kwargs["pass_fds"][0]
        os.write(status_fd, b'{"child-pid":123}\n{"exit-code":0}\n')
        return process_result(returncode=0)

    monkeypatch.setattr(sandbox_module, "run_bounded_subprocess", fake_run)

    sandbox.run(
        [str(sandbox.python_executable), "-m", "pytest"],
        env={"LANG": "C.UTF-8"},
        timeout_seconds=5,
    )

    command = observed["command"]
    assert sandbox_module._EXECUTION_GUARD_SCRIPT in command  # noqa: SLF001
    guard_index = command.index(sandbox_module._EXECUTION_GUARD_SCRIPT)  # noqa: SLF001
    assert "--" in command[guard_index:]
    assert command[-3:] == [str(sandbox.python_executable), "-m", "pytest"]
