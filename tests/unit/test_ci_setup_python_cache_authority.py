from __future__ import annotations

import shutil
from pathlib import Path

import pytest

import scripts.verify_ci_contract as ci_contract

ROOT = Path(__file__).resolve().parents[2]


def _copy_workflows(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    workflow_dir = root / ".github" / "workflows"
    workflow_dir.parent.mkdir(parents=True)
    shutil.copytree(ROOT / ".github" / "workflows", workflow_dir)
    return root


def test_repository_automatic_ci_has_no_setup_python_cache_authority() -> None:
    ci_text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    result = ci_contract.verify_ci_contract(ROOT)

    assert "cache: pip" not in ci_text
    assert "cache-dependency-path:" not in ci_text
    assert result["workflows"]["automatic"]["setup_python_cache"] is False


def test_ci_contract_rejects_pre_verifier_setup_python_cache(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8")
    marker = "          python-version: ${{ matrix.python-version }}\n"
    assert marker in text
    path.write_text(
        text.replace(
            marker,
            marker
            + "          cache: pip\n"
            + "          cache-dependency-path: ${{ matrix.lock-file }}\n",
            1,
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="dependency caching is forbidden"):
        ci_contract.verify_ci_contract(root)
