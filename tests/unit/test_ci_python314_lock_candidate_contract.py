from __future__ import annotations

import shutil
from pathlib import Path

import pytest

import scripts.verify_ci_contract as ci_contract

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_NAME = "python314-lock-candidate.yml"


def _copy_contract_repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    workflow_dir = root / ".github" / "workflows"
    workflow_dir.parent.mkdir(parents=True)
    shutil.copytree(ROOT / ".github" / "workflows", workflow_dir)
    return root


def _rewrite_and_rebind(
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    old: str,
    new: str,
) -> None:
    path = root / ".github" / "workflows" / WORKFLOW_NAME
    text = path.read_text(encoding="utf-8")
    assert old in text
    mutated = text.replace(old, new, 1)
    path.write_text(mutated, encoding="utf-8")
    monkeypatch.setattr(
        ci_contract,
        "EXPECTED_LOCK_CANDIDATE_WORKFLOW_BLOB_SHA",
        ci_contract._git_blob_sha1(mutated),
    )


def test_python314_lock_candidate_contract_is_read_only_and_temporary() -> None:
    result = ci_contract.verify_ci_contract(ROOT)
    candidate = result["workflows"]["python314_lock_candidate"]

    assert candidate == {
        "purpose": "temporary-read-only-lock-candidate",
        "source": "exact-pr-head-pyproject",
        "python_version": "3.14.7",
        "uv_version": "0.12.1",
        "resolution": "double-compile-byte-identity",
        "mutation": "none",
        "workflow_definition": "exact-reviewed-git-blob",
    }


def test_python314_lock_candidate_rejects_write_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_contract_repo(tmp_path)
    _rewrite_and_rebind(
        root,
        monkeypatch,
        old="  contents: read\n",
        new="  contents: write\n",
    )

    with pytest.raises(ValueError, match="must be read-only"):
        ci_contract.verify_ci_contract(root)


def test_python314_lock_candidate_rejects_checkout_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_contract_repo(tmp_path)
    marker = "    steps:\n"
    checkout = (
        "    steps:\n"
        "      - name: Forbidden checkout\n"
        "        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7\n"
    )
    _rewrite_and_rebind(root, monkeypatch, old=marker, new=checkout)

    with pytest.raises(ValueError, match="actions/checkout@"):
        ci_contract.verify_ci_contract(root)


def test_python314_lock_candidate_rejects_single_resolution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_contract_repo(tmp_path)
    path = root / ".github" / "workflows" / WORKFLOW_NAME
    text = path.read_text(encoding="utf-8")
    second = """          uv pip compile generated/pyproject.toml generated/build-backend.in \\
            --python-version '3.14.7' \\
            --extra dev \\
            --generate-hashes \\
            --no-header \\
            --output-file generated/dev-py314-b.lock
"""
    assert second in text
    mutated = text.replace(second, "", 1)
    path.write_text(mutated, encoding="utf-8")
    monkeypatch.setattr(
        ci_contract,
        "EXPECTED_LOCK_CANDIDATE_WORKFLOW_BLOB_SHA",
        ci_contract._git_blob_sha1(mutated),
    )

    with pytest.raises(ValueError, match="independently resolve the lock twice"):
        ci_contract.verify_ci_contract(root)
