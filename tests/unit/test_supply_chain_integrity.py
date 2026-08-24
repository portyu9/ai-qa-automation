from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.generate_build_manifest import generate_manifest
from scripts.verify_supply_chain import parse_hash_lock, verify_repository

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
    lock.write_text("demo==1.0 \\\n    --hash=md5:00000000000000000000000000000000\n", encoding="utf-8")

    with pytest.raises(ValueError, match="only SHA-256"):
        parse_hash_lock(lock)


def test_hash_lock_accepts_exact_sha256_requirement(tmp_path: Path) -> None:
    lock = tmp_path / "valid.lock"
    lock.write_text(f"demo==1.0 \\\n    --hash=sha256:{SHA256_ZERO}\n", encoding="utf-8")

    parsed = parse_hash_lock(lock)

    assert parsed["demo"].version == "1.0"
    assert parsed["demo"].hashes == (SHA256_ZERO,)


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
