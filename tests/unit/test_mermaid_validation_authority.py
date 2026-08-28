from __future__ import annotations

import os
from pathlib import Path

import pytest

import scripts.validate_mermaid as mermaid


def test_ci_identity_separates_validation_subject_from_github_event_sha(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject_sha = "a" * 40
    github_event_sha = "b" * 40
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("CI_SUBJECT_SHA", subject_sha)
    monkeypatch.setenv("GITHUB_SHA", github_event_sha)

    assert mermaid._ci_identity() == (subject_sha, github_event_sha)


@pytest.mark.parametrize("name", ["CI_SUBJECT_SHA", "GITHUB_SHA"])
def test_ci_identity_rejects_missing_required_ci_sha(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
) -> None:
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("CI_SUBJECT_SHA", "a" * 40)
    monkeypatch.setenv("GITHUB_SHA", "b" * 40)
    monkeypatch.delenv(name)

    with pytest.raises(ValueError, match=f"{name} must be a full lowercase GitHub commit SHA"):
        mermaid._ci_identity()


def test_candidate_discovery_enforces_directory_entry_limit_during_iteration(
    tmp_path: Path,
) -> None:
    docs = tmp_path / "docs"
    docs.mkdir()
    for index in range(mermaid.MAX_MARKDOWN_FILES + 1):
        (docs / f"entry-{index:03d}.txt").write_text("x", encoding="utf-8")

    with pytest.raises(ValueError, match="direct entries"):
        mermaid._candidate_files(tmp_path)


def test_bounded_fd_reader_rejects_bytes_beyond_budget(tmp_path: Path) -> None:
    path = tmp_path / "input.md"
    path.write_bytes(b"12345")
    fd = os.open(path, os.O_RDONLY)
    try:
        with pytest.raises(ValueError, match="exceeds 4 bytes"):
            mermaid._read_fd_bounded(fd, max_bytes=4, label="test input")
    finally:
        os.close(fd)


def test_mermaid_discovery_enforces_total_diagram_limit(tmp_path: Path) -> None:
    docs = tmp_path / "docs"
    docs.mkdir()
    for name in mermaid.PUBLIC_ROOT_MARKDOWN:
        (tmp_path / name).write_text("plain documentation\n", encoding="utf-8")
    diagram = "```mermaid\nflowchart LR\n  A --> B\n```\n"
    (docs / "many.md").write_text(
        diagram * (mermaid.MAX_MERMAID_DIAGRAMS + 1),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Mermaid diagrams"):
        mermaid._discover_mermaid_documents(tmp_path)


def test_generated_svg_validation_fails_on_first_excess_output(tmp_path: Path) -> None:
    destination = tmp_path / "README.md"
    (tmp_path / "README-1.svg").write_text("<svg/>\n", encoding="utf-8")
    (tmp_path / "README-2.svg").write_text("<svg/>\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="more than 1 SVG"):
        mermaid._validate_generated_svgs(destination, expected_count=1)
