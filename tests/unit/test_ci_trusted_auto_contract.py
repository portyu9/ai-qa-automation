from __future__ import annotations

import shutil
from pathlib import Path

import pytest

import scripts.verify_ci_contract as ci_contract

ROOT = Path(__file__).resolve().parents[2]


def _copy_contract_repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    workflow_dir = root / ".github" / "workflows"
    workflow_dir.parent.mkdir(parents=True)
    shutil.copytree(ROOT / ".github" / "workflows", workflow_dir)
    scripts_dir = root / "scripts"
    scripts_dir.mkdir()
    shutil.copyfile(ROOT / "scripts" / "ci_contract_base.py", scripts_dir / "ci_contract_base.py")
    return root


def test_trusted_auto_contract_is_frozen_and_read_only() -> None:
    result = ci_contract.verify_ci_contract(ROOT)
    auto = result["workflows"]["trusted_auto"]

    assert auto["trigger"] == "workflow_run:completed:reviewed-ci"
    assert auto["candidate_execution_guard"] == (
        "exact-merge-parents-plus-zero-protected-object-drift"
    )
    assert auto["validation_authority"] == "read-only-secret-free-before-reporter"
    assert auto["status_writer"] == "dedicated-github-app"
    assert auto["maintenance_fallback"] == "owner-repository-dispatch-exact-object-manifest"


def test_trusted_auto_contract_rejects_candidate_checkout_in_preflight(tmp_path: Path) -> None:
    root = _copy_contract_repo(tmp_path)
    path = root / ".github" / "workflows" / "trusted-pr-auto.yml"
    text = path.read_text(encoding="utf-8")
    marker = "          ref: ${{ github.sha }}\n"
    assert marker in text
    path.write_text(
        text.replace(marker, "          ref: ${{ needs.preflight.outputs.merge_sha }}\n", 1),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="exact reviewed automatic trust definition"):
        ci_contract.verify_ci_contract(root)


def test_trusted_auto_contract_rejects_native_write_permission(tmp_path: Path) -> None:
    root = _copy_contract_repo(tmp_path)
    path = root / ".github" / "workflows" / "trusted-pr-auto.yml"
    text = path.read_text(encoding="utf-8")
    marker = "  contents: read\n"
    assert marker in text
    path.write_text(text.replace(marker, "  contents: write\n", 1), encoding="utf-8")

    with pytest.raises(ValueError, match="exact reviewed automatic trust definition"):
        ci_contract.verify_ci_contract(root)


def test_trusted_auto_contract_rejects_removed_protected_path(tmp_path: Path) -> None:
    root = _copy_contract_repo(tmp_path)
    path = root / ".github" / "workflows" / "trusted-pr-auto.yml"
    text = path.read_text(encoding="utf-8")
    marker = "            tests\n"
    assert marker in text
    path.write_text(text.replace(marker, "", 1), encoding="utf-8")

    with pytest.raises(ValueError, match="exact reviewed automatic trust definition"):
        ci_contract.verify_ci_contract(root)


def test_trusted_auto_contract_rejects_reporter_secret_before_final_revalidation(
    tmp_path: Path,
) -> None:
    root = _copy_contract_repo(tmp_path)
    path = root / ".github" / "workflows" / "trusted-pr-auto.yml"
    text = path.read_text(encoding="utf-8")
    marker = "      - name: Revalidate automatic trusted admission\n"
    assert marker in text
    injected = (
        "      - name: Illicit early secret consumer\n"
        "        env:\n"
        "          BAD: ${{ secrets.TRUSTED_GATE_APP_PRIVATE_KEY }}\n"
        "        run: test -n \"$BAD\"\n\n"
    )
    path.write_text(text.replace(marker, injected + marker, 1), encoding="utf-8")

    with pytest.raises(ValueError, match="exact reviewed automatic trust definition"):
        ci_contract.verify_ci_contract(root)


def test_trusted_auto_contract_rejects_frozen_base_verifier_drift(tmp_path: Path) -> None:
    root = _copy_contract_repo(tmp_path)
    path = root / "scripts" / "ci_contract_base.py"
    path.write_text(path.read_text(encoding="utf-8") + "\n# drift\n", encoding="utf-8")

    with pytest.raises(ValueError, match="frozen hardened definition"):
        ci_contract.verify_ci_contract(root)
