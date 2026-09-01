from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from scripts.verify_release_candidate import verify_release_candidate


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _repository(tmp_path: Path, *, version: str = "0.1.0") -> tuple[Path, str]:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-b", "main")
    _git(root, "config", "user.email", "release-test@example.invalid")
    _git(root, "config", "user.name", "Release Test")
    (root / "pyproject.toml").write_text(
        "\n".join(
            (
                "[project]",
                'name = "ai-qa-automation"',
                f'version = "{version}"',
                "",
            )
        ),
        encoding="utf-8",
    )
    _git(root, "add", "pyproject.toml")
    _git(root, "commit", "-m", "test release subject")
    return root, _git(root, "rev-parse", "HEAD")


def test_release_candidate_binds_tag_version_main_and_exact_subject(tmp_path: Path) -> None:
    root, head = _repository(tmp_path)

    result = verify_release_candidate(
        root=root,
        release_tag="v0.1.0",
        expected_source_sha=head,
        expected_ref="refs/heads/main",
    )

    assert result["result"] == "PASS"
    assert result["release_tag"] == "v0.1.0"
    assert result["project_version"] == "0.1.0"
    assert result["source_sha"] == head
    assert result["publishing_authority"] == "none"
    assert result["signature_claim"] == "none"


@pytest.mark.parametrize("tag", ["0.1.0", "v01.1.0", "v0.1", "v0.1.0-rc1", "latest"])
def test_release_candidate_rejects_noncanonical_tag(tmp_path: Path, tag: str) -> None:
    root, head = _repository(tmp_path)

    with pytest.raises(ValueError, match=r"stable vMAJOR\.MINOR\.PATCH"):
        verify_release_candidate(
            root=root,
            release_tag=tag,
            expected_source_sha=head,
            expected_ref="refs/heads/main",
        )


def test_release_candidate_rejects_version_mismatch(tmp_path: Path) -> None:
    root, head = _repository(tmp_path, version="0.2.0")

    with pytest.raises(ValueError, match="does not match static project version"):
        verify_release_candidate(
            root=root,
            release_tag="v0.1.0",
            expected_source_sha=head,
            expected_ref="refs/heads/main",
        )


def test_release_candidate_rejects_non_main_ref(tmp_path: Path) -> None:
    root, head = _repository(tmp_path)

    with pytest.raises(ValueError, match="only from refs/heads/main"):
        verify_release_candidate(
            root=root,
            release_tag="v0.1.0",
            expected_source_sha=head,
            expected_ref="refs/heads/release-test",
        )


def test_release_candidate_rejects_wrong_subject(tmp_path: Path) -> None:
    root, _ = _repository(tmp_path)

    with pytest.raises(ValueError, match="does not match expected source SHA"):
        verify_release_candidate(
            root=root,
            release_tag="v0.1.0",
            expected_source_sha="0" * 40,
            expected_ref="refs/heads/main",
        )


def test_release_candidate_rejects_tracked_worktree_drift(tmp_path: Path) -> None:
    root, head = _repository(tmp_path)
    (root / "pyproject.toml").write_text(
        '[project]\nname = "ai-qa-automation"\nversion = "0.1.0"\n# drift\n',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="tracked worktree changes"):
        verify_release_candidate(
            root=root,
            release_tag="v0.1.0",
            expected_source_sha=head,
            expected_ref="refs/heads/main",
        )


def test_release_candidate_rejects_symlinked_project_metadata(tmp_path: Path) -> None:
    root, head = _repository(tmp_path)
    metadata = root / "pyproject.toml"
    replacement = tmp_path / "replacement.toml"
    replacement.write_bytes(metadata.read_bytes())
    metadata.unlink()
    metadata.symlink_to(replacement)

    with pytest.raises(ValueError, match="regular non-symlink"):
        verify_release_candidate(
            root=root,
            release_tag="v0.1.0",
            expected_source_sha=head,
            expected_ref="refs/heads/main",
        )


def test_release_candidate_requires_two_identical_wheels(tmp_path: Path) -> None:
    root, head = _repository(tmp_path)
    wheel_a = tmp_path / "a" / "ai_qa_automation-0.1.0-py3-none-any.whl"
    wheel_b = tmp_path / "b" / "ai_qa_automation-0.1.0-py3-none-any.whl"
    wheel_a.parent.mkdir()
    wheel_b.parent.mkdir()
    wheel_a.write_bytes(b"same wheel bytes")
    wheel_b.write_bytes(b"same wheel bytes")

    result = verify_release_candidate(
        root=root,
        release_tag="v0.1.0",
        expected_source_sha=head,
        expected_ref="refs/heads/main",
        wheel_a=wheel_a,
        wheel_b=wheel_b,
    )

    assert result["wheel"]["reproducible_builds"] == 2
    assert result["wheel"]["size_bytes"] == len(b"same wheel bytes")

    wheel_b.write_bytes(b"different wheel bytes")
    with pytest.raises(ValueError, match="not byte-identical"):
        verify_release_candidate(
            root=root,
            release_tag="v0.1.0",
            expected_source_sha=head,
            expected_ref="refs/heads/main",
            wheel_a=wheel_a,
            wheel_b=wheel_b,
        )


def test_release_candidate_rejects_symlinked_wheel(tmp_path: Path) -> None:
    root, head = _repository(tmp_path)
    actual = tmp_path / "actual.whl"
    actual.write_bytes(b"same wheel bytes")
    wheel_a = tmp_path / "a" / "ai_qa_automation-0.1.0-py3-none-any.whl"
    wheel_b = tmp_path / "b" / "ai_qa_automation-0.1.0-py3-none-any.whl"
    wheel_a.parent.mkdir()
    wheel_b.parent.mkdir()
    wheel_a.symlink_to(actual)
    wheel_b.write_bytes(b"same wheel bytes")

    with pytest.raises(ValueError, match="regular non-symlink"):
        verify_release_candidate(
            root=root,
            release_tag="v0.1.0",
            expected_source_sha=head,
            expected_ref="refs/heads/main",
            wheel_a=wheel_a,
            wheel_b=wheel_b,
        )


def test_release_candidate_rejects_single_wheel_argument(tmp_path: Path) -> None:
    root, head = _repository(tmp_path)
    wheel = tmp_path / "ai_qa_automation-0.1.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel")

    with pytest.raises(ValueError, match="both release wheel paths"):
        verify_release_candidate(
            root=root,
            release_tag="v0.1.0",
            expected_source_sha=head,
            expected_ref="refs/heads/main",
            wheel_a=wheel,
        )
