from __future__ import annotations

import shutil
from pathlib import Path

import pytest

import scripts.verify_ci_contract as ci_contract

ROOT = Path(__file__).resolve().parents[2]


def _copy_workflows(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "repo"
    workflow_dir = root / ".github" / "workflows"
    workflow_dir.parent.mkdir(parents=True)
    shutil.copytree(ROOT / ".github" / "workflows", workflow_dir)
    return root, workflow_dir / "ci.yml"


def test_ci_contract_rejects_missing_path_lookup_that_masks_git_failure(tmp_path: Path) -> None:
    root, path = _copy_workflows(tmp_path)
    text = path.read_text(encoding="utf-8")
    current = (
        '            oid="$("${git_clean_env[@]}" /usr/bin/git ls-tree '
        "--format='%(objectname)' \"$revision\" -- \"$path\")\"\n"
    )
    weakened = (
        '            if oid="$("${git_clean_env[@]}" /usr/bin/git rev-parse '
        '"${revision}:${path}" 2>/dev/null)"; then\n'
        "              :\n"
        "            else\n"
        "              oid=''\n"
        "            fi\n"
    )
    assert current in text
    path.write_text(text.replace(current, weakened, 1), encoding="utf-8")

    with pytest.raises(ValueError, match="protected change manifest contract"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_fixed_protected_manifest_scratch_path(tmp_path: Path) -> None:
    root, path = _copy_workflows(tmp_path)
    text = path.read_text(encoding="utf-8")
    current = '          changes_file="$(mktemp "$RUNNER_TEMP/aiqa-protected-changes.XXXXXX")"\n'
    weakened = '          changes_file="$RUNNER_TEMP/aiqa-protected-changes.tsv"\n'
    assert current in text
    path.write_text(text.replace(current, weakened, 1), encoding="utf-8")

    with pytest.raises(ValueError, match="protected change manifest contract"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_removed_precheckout_dispatch_sha_validation(tmp_path: Path) -> None:
    root, path = _copy_workflows(tmp_path)
    text = path.read_text(encoding="utf-8")
    supply_chain = ci_contract._job_block(text, "supply-chain")
    step = ci_contract._step_block(supply_chain, "Validate trusted dispatch subject syntax")
    assert step in text
    path.write_text(text.replace(step + "\n", "", 1), encoding="utf-8")

    with pytest.raises(ValueError, match="protected change manifest contract"):
        ci_contract.verify_ci_contract(root)
