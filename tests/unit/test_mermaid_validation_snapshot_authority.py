from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import scripts.mermaid_output as mermaid_output
import scripts.validate_mermaid as mermaid


def _write_required_repo(root: Path, readme: str) -> None:
    root.mkdir(exist_ok=True)
    (root / "README.md").write_text(readme, encoding="utf-8")
    (root / "CONTRIBUTING.md").write_text("# Contributing\n", encoding="utf-8")
    (root / "SECURITY.md").write_text("# Security\n", encoding="utf-8")
    (root / "docs").mkdir(exist_ok=True)


def test_snapshot_records_exact_document_digest(tmp_path: Path) -> None:
    content = b"```mermaid\nflowchart LR\nA --> B\n```\n"
    _write_required_repo(tmp_path, content.decode())
    snapshots = mermaid._discover_mermaid_snapshot(tmp_path)
    assert len(snapshots) == 1
    assert snapshots[0].content == content
    assert snapshots[0].sha256 == hashlib.sha256(content).hexdigest()


def test_snapshot_render_source_is_not_reopened_from_mutated_workspace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    original = "```mermaid\nflowchart LR\nA --> B\n```\n"
    replacement = "```mermaid\nflowchart LR\nX --> Y\n```\n"
    _write_required_repo(tmp_path, original)
    monkeypatch.chdir(tmp_path)
    seen: list[bytes] = []

    def fake_run(root: Path, relative_path: Path, _output: Path, _count: int) -> None:
        (tmp_path / "README.md").write_text(replacement, encoding="utf-8")
        seen.append((root / relative_path).read_bytes())

    monkeypatch.setattr(mermaid, "_run_mermaid", fake_run)
    assert mermaid.main() == 0
    result = json.loads(capsys.readouterr().out)
    assert seen == [original.encode()]
    assert result["documents"][0]["sha256"] == hashlib.sha256(original.encode()).hexdigest()


def test_repository_root_replacement_during_discovery_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "repo"
    _write_required_repo(root, "```mermaid\nflowchart LR\nA --> B\n```\n")
    real_snapshot = mermaid._snapshot_from_bytes
    swapped = False

    def swapping_snapshot(path: Path, data: bytes) -> mermaid.MermaidDocumentSnapshot | None:
        nonlocal swapped
        snapshot = real_snapshot(path, data)
        if not swapped:
            swapped = True
            old = tmp_path / "old-repo"
            root.rename(old)
            root.mkdir()
        return snapshot

    monkeypatch.setattr(mermaid, "_snapshot_from_bytes", swapping_snapshot)
    with pytest.raises((ValueError, FileNotFoundError)):
        mermaid._discover_mermaid_snapshot(root)


def test_renderer_timeout_force_removes_exact_container_id_without_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "snapshot"
    output = tmp_path / "output"
    root.mkdir()
    output.mkdir()
    calls: list[list[str]] = []

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(command)
        if command[1] == "run":
            cidfile = Path(command[command.index("--cidfile") + 1])
            cidfile.write_text("b" * 64 + "\n", encoding="ascii")
            return subprocess.CompletedProcess(command, 0)
        if command[1] == "exec":
            raise subprocess.TimeoutExpired(command, mermaid.RENDER_TIMEOUT_SECONDS)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(mermaid, "_resolve_docker_executable", lambda: "docker")
    monkeypatch.setattr(mermaid.subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="render exceeded"):
        mermaid._run_mermaid(root, Path("README.md"), output, 1)
    assert not any(command[1] == "cp" for command in calls)
    assert calls[-1] == ["docker", "rm", "--force", "b" * 64]


def test_renderer_nonzero_completion_does_not_copy_and_force_removes_exact_container_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "snapshot"
    output = tmp_path / "output"
    root.mkdir()
    output.mkdir()
    calls: list[list[str]] = []

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(command)
        if command[1] == "run":
            cidfile = Path(command[command.index("--cidfile") + 1])
            cidfile.write_text("e" * 64 + "\n", encoding="ascii")
            return subprocess.CompletedProcess(command, 0)
        if command[1] == "exec":
            raise subprocess.CalledProcessError(1, command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(mermaid, "_resolve_docker_executable", lambda: "docker")
    monkeypatch.setattr(mermaid.subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="did not complete successfully"):
        mermaid._run_mermaid(root, Path("README.md"), output, 1)
    assert not any(command[1] == "cp" for command in calls)
    assert calls[-1] == ["docker", "rm", "--force", "e" * 64]


def test_renderer_cleanup_failure_is_a_hard_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "snapshot"
    output = tmp_path / "output"
    root.mkdir()
    output.mkdir()

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        if command[1] == "run":
            cidfile = Path(command[command.index("--cidfile") + 1])
            cidfile.write_text("c" * 64 + "\n", encoding="ascii")
            return subprocess.CompletedProcess(command, 0)
        if command[1] == "exec":
            return subprocess.CompletedProcess(command, 0)
        if command[1] == "cp":
            (output / "rendered.md").write_text("# Rendered\n", encoding="utf-8")
            (output / "rendered-1.svg").write_text("<svg/>\n", encoding="utf-8")
            return subprocess.CompletedProcess(command, 0)
        assert command[-1] == "c" * 64
        return subprocess.CompletedProcess(command, 1)

    monkeypatch.setattr(mermaid, "_resolve_docker_executable", lambda: "docker")
    monkeypatch.setattr(mermaid.subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="cleanup did not confirm removal"):
        mermaid._run_mermaid(root, Path("README.md"), output, 1)


def test_renderer_copy_failure_still_force_removes_exact_container_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "snapshot"
    output = tmp_path / "output"
    root.mkdir()
    output.mkdir()
    calls: list[list[str]] = []

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(command)
        if command[1] == "run":
            cidfile = Path(command[command.index("--cidfile") + 1])
            cidfile.write_text("d" * 64 + "\n", encoding="ascii")
            return subprocess.CompletedProcess(command, 0)
        if command[1] == "exec":
            return subprocess.CompletedProcess(command, 0)
        if command[1] == "cp":
            raise subprocess.CalledProcessError(1, command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(mermaid, "_resolve_docker_executable", lambda: "docker")
    monkeypatch.setattr(mermaid.subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="output copy could not be completed"):
        mermaid._run_mermaid(root, Path("README.md"), output, 1)
    assert calls[-1] == ["docker", "rm", "--force", "d" * 64]


def test_renderer_cleanup_without_exact_container_id_fails_closed_after_best_effort(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cidfile = tmp_path / "missing.cid"
    calls: list[list[str]] = []

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(mermaid, "_resolve_docker_executable", lambda: "docker")
    monkeypatch.setattr(mermaid.subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="exact container identity was unavailable"):
        mermaid._remove_renderer_container("aiqa-mermaid-private-name", cidfile)
    assert calls == [["docker", "rm", "--force", "aiqa-mermaid-private-name"]]


def test_nested_renderer_output_parent_symlink_is_rejected_without_host_read(
    tmp_path: Path,
) -> None:
    output = tmp_path / "output"
    output.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "ARCHITECTURE.md").write_text("# fake rendered\n", encoding="utf-8")
    (outside / "ARCHITECTURE-1.svg").write_text("<svg/>\n", encoding="utf-8")
    try:
        (output / "docs").symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable on this platform")

    with pytest.raises(RuntimeError, match="flat private output namespace"):
        mermaid._validate_rendered_outputs(
            output,
            Path("docs/ARCHITECTURE.md"),
            expected_count=1,
        )


def test_renderer_rejects_preexisting_output_namespace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshot = tmp_path / "snapshot"
    output = tmp_path / "output"
    snapshot.mkdir()
    output.mkdir()
    (output / "stale.svg").write_text("stale\n", encoding="utf-8")

    def should_not_run(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Docker must not run with a non-empty output root")

    monkeypatch.setattr(mermaid.subprocess, "run", should_not_run)
    with pytest.raises(RuntimeError, match="must be empty"):
        mermaid._run_mermaid(snapshot, Path("README.md"), output, 1)


def test_renderer_rejects_unexpected_output_entry(tmp_path: Path) -> None:
    output = tmp_path / "output"
    output.mkdir()
    (output / "rendered.md").write_text("# Rendered\n", encoding="utf-8")
    (output / "rendered-1.svg").write_text("<svg/>\n", encoding="utf-8")
    (output / "unexpected.bin").write_bytes(b"unexpected")
    with pytest.raises(RuntimeError, match="unexpected output entry"):
        mermaid._validate_rendered_outputs(output, Path("rendered.md"), expected_count=1)


def test_renderer_output_rejects_unexpected_directory_entry(tmp_path: Path) -> None:
    output = tmp_path / "output"
    output.mkdir()
    (output / "rendered.md").write_text("# Rendered\n", encoding="utf-8")
    (output / "rendered-1.svg").write_text("<svg/>\n", encoding="utf-8")
    (output / "unexpected").mkdir()
    with pytest.raises(RuntimeError, match="unexpected output entry"):
        mermaid._validate_rendered_outputs(
            output,
            Path("rendered.md"),
            expected_count=1,
        )


def test_renderer_rejects_empty_svg(tmp_path: Path) -> None:
    output = tmp_path / "output"
    output.mkdir()
    (output / "rendered.md").write_text("# Rendered\n", encoding="utf-8")
    (output / "rendered-1.svg").write_bytes(b"")
    with pytest.raises(RuntimeError, match="empty SVG"):
        mermaid._validate_rendered_outputs(output, Path("rendered.md"), expected_count=1)


def test_main_uses_distinct_empty_output_roots_for_same_stem_documents(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_content = b"```mermaid\nflowchart LR\nA --> B\n```\n"
    second_content = b"```mermaid\nflowchart LR\nB --> C\n```\n"
    first = mermaid.MermaidDocumentSnapshot(
        relative_path=Path("docs/same.md"),
        diagram_count=1,
        content=first_content,
        sha256=hashlib.sha256(first_content).hexdigest(),
    )
    second = mermaid.MermaidDocumentSnapshot(
        relative_path=Path("docs/same.MD"),
        diagram_count=1,
        content=second_content,
        sha256=hashlib.sha256(second_content).hexdigest(),
    )
    observed: list[Path] = []
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(mermaid, "_discover_mermaid_snapshot", lambda _root: [first, second])
    monkeypatch.setattr(mermaid, "_write_snapshot", lambda *_args: None)

    def fake_run(_root: Path, _path: Path, output_root: Path, _count: int) -> None:
        assert output_root.is_dir()
        assert list(output_root.iterdir()) == []
        observed.append(output_root)

    monkeypatch.setattr(mermaid, "_run_mermaid", fake_run)
    assert mermaid.main() == 0
    assert len(observed) == 2
    assert observed[0] != observed[1]


def test_docker_executable_is_resolved_to_one_absolute_executable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    docker = tmp_path / "docker"
    docker.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    docker.chmod(0o755)
    monkeypatch.setattr(mermaid.shutil, "which", lambda _name: str(docker))
    assert mermaid._resolve_docker_executable() == str(docker.resolve())


def test_rendered_output_validation_enforces_aggregate_byte_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "output"
    output.mkdir()
    (output / "rendered.md").write_bytes(b"123456")
    (output / "rendered-1.svg").write_bytes(b"123456")
    monkeypatch.setattr(mermaid_output, "MAX_RENDER_TOTAL_BYTES", 10)
    with pytest.raises(RuntimeError, match="aggregate bytes"):
        mermaid._validate_rendered_outputs(output, Path("rendered.md"), expected_count=1)


def test_validate_mermaid_script_executes_with_helper_import_outside_package(
    tmp_path: Path,
) -> None:
    for name in mermaid.PUBLIC_ROOT_MARKDOWN:
        (tmp_path / name).write_text("plain documentation\n", encoding="utf-8")
    env = os.environ.copy()
    env.pop("GITHUB_ACTIONS", None)
    env.pop("CI_SUBJECT_SHA", None)
    env.pop("GITHUB_SHA", None)
    completed = subprocess.run(
        [sys.executable, str(Path(mermaid.__file__).resolve())],
        cwd=tmp_path,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=5,
        check=False,
    )
    assert completed.returncode != 0
    assert "docs" in completed.stderr.lower()


def test_main_releases_each_render_output_before_next_document(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    first = mermaid.MermaidDocumentSnapshot(
        Path("README.md"), 1, b"first", hashlib.sha256(b"first").hexdigest()
    )
    second = mermaid.MermaidDocumentSnapshot(
        Path("docs/SECOND.md"), 1, b"second", hashlib.sha256(b"second").hexdigest()
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(mermaid, "_discover_mermaid_snapshot", lambda _root: [first, second])
    observed: list[Path] = []

    def fake_run(_root: Path, _relative: Path, output: Path, _count: int) -> None:
        if observed:
            assert not observed[-1].exists()
        (output / "probe").write_text("x", encoding="utf-8")
        observed.append(output)

    monkeypatch.setattr(mermaid, "_run_mermaid", fake_run)
    assert mermaid.main() == 0
    assert len(observed) == 2
    assert all(not path.exists() for path in observed)
    capsys.readouterr()
