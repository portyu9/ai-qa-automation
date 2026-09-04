from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

import scripts.validate_mermaid as mermaid
from ai_qa_automation.tools.execution_env import controller_executable_search_path


def test_ci_identity_separates_validation_subject_from_github_event_sha(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject_sha = "a" * 40
    github_event_sha = "b" * 40
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("CI_SUBJECT_SHA", subject_sha)
    monkeypatch.setenv("GITHUB_SHA", github_event_sha)

    assert mermaid._ci_identity() == (subject_sha, github_event_sha)


def test_main_emits_selected_subject_and_separate_event_sha(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    subject_sha = "a" * 40
    github_event_sha = "b" * 40
    content = b"```mermaid\nflowchart LR\nA --> B\n```\n"
    document = mermaid.MermaidDocumentSnapshot(
        relative_path=Path("README.md"),
        diagram_count=1,
        content=content,
        sha256=hashlib.sha256(content).hexdigest(),
    )
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("CI_SUBJECT_SHA", subject_sha)
    monkeypatch.setenv("GITHUB_SHA", github_event_sha)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(mermaid, "_discover_mermaid_snapshot", lambda root: [document])
    monkeypatch.setattr(mermaid, "_run_mermaid", lambda *args, **kwargs: None)

    assert mermaid.main() == 0

    result = json.loads(capsys.readouterr().out)
    assert result["schema_version"] == 2
    assert result["subject_sha"] == subject_sha
    assert result["github_event_sha"] == github_event_sha
    assert result["documents"] == [
        {
            "path": "README.md",
            "diagram_count": 1,
            "sha256": hashlib.sha256(content).hexdigest(),
        }
    ]


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


def test_docker_resolution_uses_restricted_controller_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hostile = tmp_path / "target-bin"
    hostile.mkdir()
    hostile_docker = hostile / "docker"
    hostile_docker.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
    hostile_docker.chmod(0o755)
    monkeypatch.setenv("PATH", str(hostile))
    monkeypatch.setenv("DOCKER_HOST", "tcp://attacker.invalid:2375")
    monkeypatch.setenv("DOCKER_CONTEXT", "hostile-context")
    observed: dict[str, str] = {}

    def fake_resolve(executable: str, *, env: dict[str, str]) -> str:
        assert executable == "docker"
        observed.update(env)
        return "/usr/bin/docker"

    monkeypatch.setattr(mermaid, "resolve_executable", fake_resolve)
    env = mermaid.restricted_subprocess_env(home=tmp_path / "controller-home")

    assert mermaid._resolve_docker_executable(env=env) == "/usr/bin/docker"
    assert observed["PATH"] == controller_executable_search_path()
    assert str(hostile) not in observed["PATH"].split(os.pathsep)
    assert "DOCKER_HOST" not in observed
    assert "DOCKER_CONTEXT" not in observed


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
