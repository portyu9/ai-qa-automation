from __future__ import annotations

import io
import re
import subprocess
import tarfile
from pathlib import Path

import pytest

import scripts.validate_mermaid as mermaid
from ai_qa_automation.tools.execution_env import controller_executable_search_path


def _write_required_root_docs(root: Path) -> None:
    for name in ("CONTRIBUTING.md", "SECURITY.md"):
        (root / name).write_text(f"# {name}\n", encoding="utf-8")


def _render_archive() -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, data in (("rendered.md", b"# Rendered\n"), ("rendered-1.svg", b"<svg/>\n")):
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    return buffer.getvalue()


def test_discovers_mermaid_documents_and_counts_blocks(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text(
        "# Readme\n\n```mermaid\nflowchart LR\nA --> B\n```\n",
        encoding="utf-8",
    )
    _write_required_root_docs(tmp_path)
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "ARCHITECTURE.md").write_text(
        "```mermaid\nsequenceDiagram\nA->>B: one\n```\n\n```mermaid\nflowchart TD\nB --> C\n```\n",
        encoding="utf-8",
    )
    (docs / "PLAIN.md").write_text("No diagrams here.\n", encoding="utf-8")

    assert mermaid._discover_mermaid_documents(tmp_path) == [
        (Path("README.md"), 1),
        (Path("docs/ARCHITECTURE.md"), 2),
    ]


def test_renderer_incompatible_mermaid_fences_fail_closed(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text(
        "~~~~mermaid\nflowchart LR\nA --> B\n~~~~\n",
        encoding="utf-8",
    )
    _write_required_root_docs(tmp_path)
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "ALT.md").write_text(
        "````mermaid\nflowchart TD\nB --> C\n````\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="pinned Mermaid CLI renderer"):
        mermaid._discover_mermaid_documents(tmp_path)


def test_discovery_includes_public_root_security_document(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# Readme\n", encoding="utf-8")
    (tmp_path / "CONTRIBUTING.md").write_text("# Contributing\n", encoding="utf-8")
    (tmp_path / "SECURITY.md").write_text(
        "```mermaid\nflowchart LR\nA --> B\n```\n",
        encoding="utf-8",
    )
    (tmp_path / "docs").mkdir()

    assert mermaid._discover_mermaid_documents(tmp_path) == [(Path("SECURITY.md"), 1)]


def test_discovery_fails_closed_when_no_mermaid_documents_exist(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# No diagrams\n", encoding="utf-8")
    _write_required_root_docs(tmp_path)
    (tmp_path / "docs").mkdir()

    with pytest.raises(ValueError, match="no Mermaid diagrams discovered"):
        mermaid._discover_mermaid_documents(tmp_path)


def test_candidate_files_reject_docs_symlink(tmp_path: Path) -> None:
    _write_required_root_docs(tmp_path)
    (tmp_path / "README.md").write_text("# Readme\n", encoding="utf-8")
    target = tmp_path / "real-docs"
    target.mkdir()
    docs = tmp_path / "docs"
    try:
        docs.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable on this platform")

    with pytest.raises(ValueError, match="docs must be a real directory"):
        mermaid._candidate_files(tmp_path)


def test_regular_file_reader_rejects_symlinks(tmp_path: Path) -> None:
    target = tmp_path / "target.md"
    target.write_text("```mermaid\nflowchart LR\nA --> B\n```\n", encoding="utf-8")
    link = tmp_path / "linked.md"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable on this platform")

    with pytest.raises(ValueError, match="regular non-symlink file"):
        mermaid._read_regular_file(link)


def test_renderer_uses_immutable_image_and_bounded_container_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    relative_path = Path("README.md")
    (root / relative_path).write_text(
        "```mermaid\nflowchart LR\nA --> B\n```\n",
        encoding="utf-8",
    )
    output_root = tmp_path / "output"
    output_root.mkdir()
    calls: list[tuple[list[str], dict[str, object]]] = []
    resolved_env: dict[str, str] = {}

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append((command, kwargs))
        if command[1] == "run":
            cidfile = Path(command[command.index("--cidfile") + 1])
            cidfile.write_text("a" * 64 + "\n", encoding="ascii")
            return subprocess.CompletedProcess(command, 0)
        if command[1] == "exec" and command[-1] == mermaid.RENDER_WAIT_COMMAND:
            return subprocess.CompletedProcess(command, 0, stdout=b"")
        if command[1] == "exec":
            return subprocess.CompletedProcess(command, 0, stdout=_render_archive())
        assert command[1:3] == ["rm", "--force"]
        return subprocess.CompletedProcess(command, 0)

    def fake_docker_resolver(*, env: dict[str, str]) -> str:
        resolved_env.update(env)
        return "/usr/bin/docker"

    monkeypatch.setattr(mermaid, "_resolve_docker_executable", fake_docker_resolver)
    monkeypatch.setattr(mermaid.subprocess, "run", fake_run)

    mermaid._run_mermaid(root, relative_path, output_root, 1)

    assert resolved_env["PATH"] == controller_executable_search_path()
    command, kwargs = calls[0]
    assert command[0] == "/usr/bin/docker"
    assert re.fullmatch(
        r"ghcr\.io/mermaid-js/mermaid-cli/mermaid-cli@sha256:[0-9a-f]{64}",
        mermaid.MERMAID_IMAGE,
    )
    assert "--rm" not in command
    assert "--detach" in command
    assert "--name" in command
    assert "--cidfile" in command
    assert "--network" in command and command[command.index("--network") + 1] == "none"
    assert "--read-only" in command
    assert "--cap-drop" in command and command[command.index("--cap-drop") + 1] == "ALL"
    assert "--security-opt" in command
    assert command[command.index("--security-opt") + 1] == "no-new-privileges"
    assert "--ulimit" in command
    assert command[command.index("--ulimit") + 1] == (
        f"fsize={mermaid.MAX_RENDER_FILE_BYTES}:{mermaid.MAX_RENDER_FILE_BYTES}"
    )
    assert mermaid.MERMAID_IMAGE in command
    assert f"type=bind,src={root},dst=/repo,readonly" in command
    assert not any("type=bind" in item and "dst=/out" in item for item in command)
    out_tmpfs = command[command.index("--tmpfs", command.index("--tmpfs") + 1) + 1]
    assert f"size={mermaid.MAX_RENDER_TOTAL_BYTES}" in out_tmpfs
    assert f"nr_inodes={mermaid.MAX_RENDER_OUTPUT_ENTRIES}" in out_tmpfs
    assert command[command.index("--entrypoint") + 1] == "/bin/sh"
    assert mermaid.RENDER_WRAPPER in command
    assert command[-1] == "/repo/README.md"
    assert kwargs["timeout"] == mermaid.DOCKER_START_TIMEOUT_SECONDS
    assert kwargs["check"] is True

    wait_command, wait_kwargs = calls[1]
    assert wait_command == [
        "/usr/bin/docker",
        "exec",
        "a" * 64,
        "/bin/sh",
        "-c",
        mermaid.RENDER_WAIT_COMMAND,
    ]
    assert wait_kwargs["timeout"] == mermaid.RENDER_TIMEOUT_SECONDS

    archive_command, archive_kwargs = calls[2]
    assert archive_command[:5] == ["/usr/bin/docker", "exec", "a" * 64, "/bin/sh", "-c"]
    assert "/bin/busybox tar -C /out -cf - ." in archive_command[-1]
    assert f"head -c {mermaid.MAX_RENDER_ARCHIVE_BYTES + 1}" in archive_command[-1]
    assert archive_kwargs["timeout"] == mermaid.DOCKER_COPY_TIMEOUT_SECONDS
    assert archive_kwargs["stdout"] is subprocess.PIPE
    assert calls[3][0] == ["/usr/bin/docker", "rm", "--force", "a" * 64]

    for _docker_command, docker_kwargs in calls:
        docker_env = docker_kwargs["env"]
        assert isinstance(docker_env, dict)
        assert docker_env["PATH"] == controller_executable_search_path()
        assert "DOCKER_HOST" not in docker_env
        assert "DOCKER_CONTEXT" not in docker_env
        assert "DOCKER_CONFIG" not in docker_env

    assert (output_root / "rendered.md").read_text(encoding="utf-8") == "# Rendered\n"
    assert (output_root / "rendered-1.svg").read_text(encoding="utf-8") == "<svg/>\n"
