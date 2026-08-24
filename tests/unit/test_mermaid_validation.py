from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

import scripts.validate_mermaid as mermaid


def _write_required_root_docs(root: Path) -> None:
    for name in ("CONTRIBUTING.md", "SECURITY.md"):
        (root / name).write_text(f"# {name}\n", encoding="utf-8")


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


def test_discovers_tilde_and_long_backtick_mermaid_fences(tmp_path: Path) -> None:
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

    assert mermaid._discover_mermaid_documents(tmp_path) == [
        (Path("README.md"), 1),
        (Path("docs/ALT.md"), 1),
    ]


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
    output_root = tmp_path / "output"
    output_root.mkdir()
    observed: dict[str, object] = {}

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        observed["command"] = command
        observed["kwargs"] = kwargs
        destination = output_root / relative_path
        destination.write_text("# Rendered\n", encoding="utf-8")
        (output_root / "README-1.svg").write_text("<svg/>\n", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(mermaid.subprocess, "run", fake_run)

    mermaid._run_mermaid(root, relative_path, output_root, 1)

    command = observed["command"]
    assert isinstance(command, list)
    assert re.fullmatch(
        r"ghcr\.io/mermaid-js/mermaid-cli/mermaid-cli@sha256:[0-9a-f]{64}",
        mermaid.MERMAID_IMAGE,
    )
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
    kwargs = observed["kwargs"]
    assert isinstance(kwargs, dict)
    assert kwargs["timeout"] == mermaid.RENDER_TIMEOUT_SECONDS
    assert kwargs["check"] is True
