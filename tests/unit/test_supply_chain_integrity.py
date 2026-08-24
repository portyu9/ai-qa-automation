from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pytest

import scripts.verify_supply_chain as supply_chain
from scripts.generate_build_manifest import generate_manifest
from scripts.verify_supply_chain import EDITABLE_INSTALL_RE, parse_hash_lock, verify_repository

ROOT = Path(__file__).resolve().parents[2]
SHA256_ZERO = "0" * 64


def test_repository_supply_chain_contract_is_self_consistent() -> None:
    result = verify_repository(ROOT)

    assert result["result"] == "PASS"
    assert result["schema_version"] == 1
    assert result["locks"]["build-py311.lock"]["packages"] > 0
    assert result["locks"]["runtime-py311.lock"]["packages"] > 0
    assert result["base_image"].startswith("python:3.11.16-slim@sha256:")


def test_hash_lock_rejects_missing_hash(tmp_path: Path) -> None:
    lock = tmp_path / "missing.lock"
    lock.write_text("demo==1.0\n", encoding="utf-8")

    with pytest.raises(ValueError, match="missing SHA-256"):
        parse_hash_lock(lock)


def test_hash_lock_rejects_non_exact_requirement(tmp_path: Path) -> None:
    lock = tmp_path / "range.lock"
    lock.write_text(f"demo>=1.0 \\\n    --hash=sha256:{SHA256_ZERO}\n", encoding="utf-8")

    with pytest.raises(ValueError, match="exact == pin"):
        parse_hash_lock(lock)


def test_hash_lock_rejects_direct_url(tmp_path: Path) -> None:
    lock = tmp_path / "url.lock"
    lock.write_text(
        f"demo @ https://example.invalid/demo.whl \\\n    --hash=sha256:{SHA256_ZERO}\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="direct URL/VCS"):
        parse_hash_lock(lock)


def test_hash_lock_rejects_non_sha256_hash(tmp_path: Path) -> None:
    lock = tmp_path / "md5.lock"
    lock.write_text(
        "demo==1.0 \\\n    --hash=md5:00000000000000000000000000000000\n", encoding="utf-8"
    )

    with pytest.raises(ValueError, match="only SHA-256"):
        parse_hash_lock(lock)


def test_hash_lock_accepts_exact_sha256_requirement(tmp_path: Path) -> None:
    lock = tmp_path / "valid.lock"
    lock.write_text(f"demo==1.0 \\\n    --hash=sha256:{SHA256_ZERO}\n", encoding="utf-8")

    parsed = parse_hash_lock(lock)

    assert parsed["demo"].version == "1.0"
    assert parsed["demo"].hashes == (SHA256_ZERO,)


def test_hash_lock_rejects_symlinked_file(tmp_path: Path) -> None:
    target = tmp_path / "real.lock"
    target.write_text(f"demo==1.0 \\\n    --hash=sha256:{SHA256_ZERO}\n", encoding="utf-8")
    linked = tmp_path / "linked.lock"
    linked.symlink_to(target)

    with pytest.raises(ValueError, match="symlink"):
        parse_hash_lock(linked)


def _copy_requirements(tmp_path: Path, *, name: str = "requirements") -> Path:
    directory = tmp_path / name
    shutil.copytree(ROOT / "requirements", directory)
    return directory


def test_lock_set_rejects_symlinked_lock(tmp_path: Path) -> None:
    directory = _copy_requirements(tmp_path)
    external = tmp_path / "external.lock"
    shutil.copyfile(directory / "runtime-py311.lock", external)
    victim = directory / "runtime-py311.lock"
    victim.unlink()
    victim.symlink_to(external)

    with pytest.raises(ValueError, match="regular non-symlink file"):
        supply_chain._read_lock_set(directory)


def test_lock_set_rejects_symlinked_directory(tmp_path: Path) -> None:
    real_directory = _copy_requirements(tmp_path, name="requirements-real")
    linked_directory = tmp_path / "requirements-linked"
    linked_directory.symlink_to(real_directory, target_is_directory=True)

    with pytest.raises(ValueError, match="directory is a symlink"):
        supply_chain._read_lock_set(linked_directory)


def test_lock_set_enforces_enumeration_bound_during_scan(tmp_path: Path) -> None:
    directory = _copy_requirements(tmp_path)
    for index in range(supply_chain.MAX_REQUIREMENTS_ENTRIES):
        (directory / f"junk-{index:02d}.txt").write_text("x", encoding="utf-8")

    with pytest.raises(ValueError, match="entry ingestion limit"):
        supply_chain._read_lock_set(directory)


def test_lock_set_rejects_directory_swap_after_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = _copy_requirements(tmp_path)
    external = _copy_requirements(tmp_path, name="external")
    original_scandir = supply_chain.os.scandir
    swapped = False

    def swapping_scandir(path: Any) -> Any:
        nonlocal swapped
        if not swapped and isinstance(path, int):
            swapped = True
            preserved = directory.with_name("requirements-preserved")
            directory.rename(preserved)
            directory.symlink_to(external, target_is_directory=True)
        return original_scandir(path)

    monkeypatch.setattr(supply_chain.os, "scandir", swapping_scandir)

    with pytest.raises(ValueError, match=r"changed|symlink"):
        supply_chain._read_lock_set(directory)


def test_lock_set_rejects_file_substitution_before_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = _copy_requirements(tmp_path)
    external = tmp_path / "external.lock"
    shutil.copyfile(directory / "runtime-py311.lock", external)
    original_open = supply_chain.os.open
    swapped = False

    def swapping_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        nonlocal swapped
        if (
            not swapped
            and path == "runtime-py311.lock"
            and kwargs.get("dir_fd") is not None
        ):
            swapped = True
            victim = directory / "runtime-py311.lock"
            victim.unlink()
            victim.symlink_to(external)
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(supply_chain.os, "open", swapping_open)

    with pytest.raises(ValueError, match=r"became a symlink|changed"):
        supply_chain._read_lock_set(directory)


@pytest.mark.parametrize(
    "command",
    [
        "python -m pip install --no-deps --no-build-isolation -e .",
        "python -m pip install --no-deps --editable .",
        "python -m pip install --editable=.",
    ],
)
def test_editable_ci_install_detector_fails_closed(command: str) -> None:
    assert EDITABLE_INSTALL_RE.search(command)


def test_non_editable_ci_install_is_not_misclassified() -> None:
    assert not EDITABLE_INSTALL_RE.search("python -m pip install --no-deps --no-build-isolation .")


def test_build_manifest_requires_two_byte_identical_wheels(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wheel_a_dir = tmp_path / "a"
    wheel_b_dir = tmp_path / "b"
    wheel_a_dir.mkdir()
    wheel_b_dir.mkdir()
    wheel_a = wheel_a_dir / "ai_qa_automation-0.1.0-py3-none-any.whl"
    wheel_b = wheel_b_dir / wheel_a.name
    wheel_a.write_bytes(b"same-wheel")
    wheel_b.write_bytes(b"same-wheel")
    sbom = tmp_path / "runtime-sbom.cdx.json"
    sbom.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.4",
                "components": [{"name": "anyio", "version": "4.14.2"}],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "315532800")

    manifest = generate_manifest(ROOT, wheel_a, wheel_b, sbom)

    assert manifest["build"]["two_builds_byte_identical"] is True
    assert manifest["identity"] == {"signed": False, "status": "NOT_PROVIDED"}

    wheel_b.write_bytes(b"different-wheel")
    with pytest.raises(ValueError, match="different SHA-256"):
        generate_manifest(ROOT, wheel_a, wheel_b, sbom)
