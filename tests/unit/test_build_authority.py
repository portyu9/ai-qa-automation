from __future__ import annotations

import shutil
from pathlib import Path

import pytest

import scripts.verify_build_authority as build_authority

ROOT = Path(__file__).resolve().parents[2]


def _copy_pyproject(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    shutil.copyfile(ROOT / "pyproject.toml", root / "pyproject.toml")
    return root


def test_repository_build_authority_is_static() -> None:
    result = build_authority.verify_build_authority(ROOT)

    assert result["result"] == "PASS"
    assert result["build_backend"] == "hatchling.build"
    assert result["build_requirements"] == ["hatchling==1.32.0"]
    assert result["dynamic_metadata"] is False
    assert result["source_execution_extensions"] is False
    assert len(result["pyproject_sha256"]) == 64


def test_build_authority_rejects_backend_path(tmp_path: Path) -> None:
    root = _copy_pyproject(tmp_path)
    path = root / "pyproject.toml"
    text = path.read_text(encoding="utf-8").replace(
        'build-backend = "hatchling.build"\n',
        'build-backend = "hatchling.build"\nbackend-path = ["."]\n',
        1,
    )
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="build-system authority"):
        build_authority.verify_build_authority(root)


def test_build_authority_rejects_custom_backend(tmp_path: Path) -> None:
    root = _copy_pyproject(tmp_path)
    path = root / "pyproject.toml"
    text = path.read_text(encoding="utf-8").replace(
        'build-backend = "hatchling.build"',
        'build-backend = "project_backend"',
        1,
    )
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="build-system authority"):
        build_authority.verify_build_authority(root)


def test_build_authority_rejects_custom_build_hook(tmp_path: Path) -> None:
    root = _copy_pyproject(tmp_path)
    path = root / "pyproject.toml"
    path.write_text(
        path.read_text(encoding="utf-8")
        + '\n[tool.hatch.build.targets.wheel.hooks.custom]\npath = "hatch_build.py"\n',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Hatch authority"):
        build_authority.verify_build_authority(root)


def test_build_authority_rejects_code_version_source(tmp_path: Path) -> None:
    root = _copy_pyproject(tmp_path)
    path = root / "pyproject.toml"
    path.write_text(
        path.read_text(encoding="utf-8")
        + '\n[tool.hatch.version]\nsource = "code"\npath = "src/ai_qa_automation/__init__.py"\n',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Hatch authority"):
        build_authority.verify_build_authority(root)


def test_build_authority_rejects_dynamic_metadata(tmp_path: Path) -> None:
    root = _copy_pyproject(tmp_path)
    path = root / "pyproject.toml"
    text = path.read_text(encoding="utf-8").replace(
        'version = "0.1.0"\n',
        'dynamic = ["version"]\n',
        1,
    )
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="version must remain static"):
        build_authority.verify_build_authority(root)


def test_build_authority_rejects_symlinked_pyproject(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    external = tmp_path / "external.toml"
    shutil.copyfile(ROOT / "pyproject.toml", external)
    (root / "pyproject.toml").symlink_to(external)

    with pytest.raises(ValueError, match="symlink"):
        build_authority.verify_build_authority(root)


def test_build_authority_enforces_pyproject_ingestion_bound(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "pyproject.toml").write_bytes(b"x" * (build_authority.MAX_PYPROJECT_BYTES + 1))

    with pytest.raises(ValueError, match="ingestion limit"):
        build_authority.verify_build_authority(root)
