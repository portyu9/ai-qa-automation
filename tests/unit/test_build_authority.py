from __future__ import annotations

import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

import scripts.verify_build_authority as build_authority

ROOT = Path(__file__).resolve().parents[2]


def _copy_build_inputs(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    shutil.copyfile(ROOT / "pyproject.toml", root / "pyproject.toml")
    shutil.copyfile(ROOT / "README.md", root / "README.md")
    shutil.copyfile(ROOT / "LICENSE", root / "LICENSE")
    (root / "src").mkdir()
    shutil.copytree(ROOT / "src" / "ai_qa_automation", root / "src" / "ai_qa_automation")
    return root


def test_repository_build_authority_is_static() -> None:
    result = build_authority.verify_build_authority(ROOT)

    assert result["result"] == "PASS"
    assert result["build_backend"] == "hatchling.build"
    assert result["build_requirements"] == ["hatchling==1.32.0"]
    assert result["project_file_inputs"] == {
        "readme": "README.md",
        "license": {"file": "LICENSE"},
    }
    assert result["build_source_root"] == "src/ai_qa_automation"
    assert result["build_source_entries"] > 0
    assert result["build_source_symlinks"] is False
    assert result["dynamic_metadata"] is False
    assert result["source_execution_extensions"] is False
    assert result["installed_hatch_entry_points"] == []
    assert len(result["pyproject_sha256"]) == 64


def test_build_authority_rejects_backend_path(tmp_path: Path) -> None:
    root = _copy_build_inputs(tmp_path)
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
    root = _copy_build_inputs(tmp_path)
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
    root = _copy_build_inputs(tmp_path)
    path = root / "pyproject.toml"
    path.write_text(
        path.read_text(encoding="utf-8")
        + '\n[tool.hatch.build.targets.wheel.hooks.custom]\npath = "hatch_build.py"\n',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Hatch authority"):
        build_authority.verify_build_authority(root)


def test_build_authority_rejects_code_version_source(tmp_path: Path) -> None:
    root = _copy_build_inputs(tmp_path)
    path = root / "pyproject.toml"
    path.write_text(
        path.read_text(encoding="utf-8")
        + '\n[tool.hatch.version]\nsource = "code"\npath = "src/ai_qa_automation/__init__.py"\n',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Hatch authority"):
        build_authority.verify_build_authority(root)


def test_build_authority_rejects_dynamic_metadata(tmp_path: Path) -> None:
    root = _copy_build_inputs(tmp_path)
    path = root / "pyproject.toml"
    text = path.read_text(encoding="utf-8").replace(
        'version = "0.1.0"\n',
        'dynamic = ["version"]\n',
        1,
    )
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="version must remain static"):
        build_authority.verify_build_authority(root)


def test_build_authority_rejects_readme_authority_expansion(tmp_path: Path) -> None:
    root = _copy_build_inputs(tmp_path)
    path = root / "pyproject.toml"
    text = path.read_text(encoding="utf-8").replace(
        'readme = "README.md"',
        'readme = "docs/README.md"',
        1,
    )
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="project readme build input"):
        build_authority.verify_build_authority(root)


def test_build_authority_rejects_license_authority_expansion(tmp_path: Path) -> None:
    root = _copy_build_inputs(tmp_path)
    path = root / "pyproject.toml"
    text = path.read_text(encoding="utf-8").replace(
        'license = {file = "LICENSE"}',
        'license = {file = "COPYING"}',
        1,
    )
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="project license build input"):
        build_authority.verify_build_authority(root)


def test_build_authority_rejects_license_files_expansion(tmp_path: Path) -> None:
    root = _copy_build_inputs(tmp_path)
    path = root / "pyproject.toml"
    text = path.read_text(encoding="utf-8").replace(
        'license = {file = "LICENSE"}\n',
        'license = {file = "LICENSE"}\nlicense-files = ["NOTICE*"]\n',
        1,
    )
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="license-files"):
        build_authority.verify_build_authority(root)


def test_build_authority_rejects_installed_hatch_plugin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rogue = SimpleNamespace(name="rogue", value="rogue_plugin.hooks")
    monkeypatch.setattr(
        build_authority.importlib_metadata,
        "entry_points",
        lambda **kwargs: [rogue] if kwargs == {"group": "hatch"} else [],
    )

    with pytest.raises(ValueError, match="third-party Hatch entry points are forbidden"):
        build_authority.verify_build_authority(ROOT)


def test_build_authority_rejects_symlinked_pyproject(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    external = tmp_path / "external.toml"
    shutil.copyfile(ROOT / "pyproject.toml", external)
    (root / "pyproject.toml").symlink_to(external)

    with pytest.raises(ValueError, match="symlink"):
        build_authority.verify_build_authority(root)


def test_build_authority_rejects_symlinked_readme(tmp_path: Path) -> None:
    root = _copy_build_inputs(tmp_path)
    external = tmp_path / "external-readme.md"
    external.write_text("outside exact source tree", encoding="utf-8")
    readme = root / "README.md"
    readme.unlink()
    readme.symlink_to(external)

    with pytest.raises(ValueError, match="project readme must be a regular non-symlink build input"):
        build_authority.verify_build_authority(root)


def test_build_authority_rejects_symlinked_license(tmp_path: Path) -> None:
    root = _copy_build_inputs(tmp_path)
    external = tmp_path / "external-license.txt"
    external.write_text("outside exact source tree", encoding="utf-8")
    license_path = root / "LICENSE"
    license_path.unlink()
    license_path.symlink_to(external)

    with pytest.raises(ValueError, match="project license must be a regular non-symlink build input"):
        build_authority.verify_build_authority(root)


def test_build_authority_rejects_symlinked_package_root(tmp_path: Path) -> None:
    root = _copy_build_inputs(tmp_path)
    package_root = root / "src" / "ai_qa_automation"
    external = tmp_path / "external-package"
    package_root.rename(external)
    package_root.symlink_to(external, target_is_directory=True)

    with pytest.raises(ValueError, match="must be a real non-symlink directory"):
        build_authority.verify_build_authority(root)


def test_build_authority_rejects_symlink_inside_package_tree(tmp_path: Path) -> None:
    root = _copy_build_inputs(tmp_path)
    package_root = root / "src" / "ai_qa_automation"
    victim = package_root / "__init__.py"
    external = tmp_path / "outside.py"
    external.write_text("EXTERNAL = True\n", encoding="utf-8")
    victim.unlink()
    victim.symlink_to(external)

    with pytest.raises(ValueError, match="build source symlink is forbidden"):
        build_authority.verify_build_authority(root)


def test_build_authority_enforces_source_entry_ingestion_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_build_inputs(tmp_path)
    monkeypatch.setattr(build_authority, "MAX_BUILD_SOURCE_ENTRIES", 1)

    with pytest.raises(ValueError, match="entry ingestion limit"):
        build_authority.verify_build_authority(root)


def test_build_authority_enforces_pyproject_ingestion_bound(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "pyproject.toml").write_bytes(b"x" * (build_authority.MAX_PYPROJECT_BYTES + 1))

    with pytest.raises(ValueError, match="ingestion limit"):
        build_authority.verify_build_authority(root)
