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


def _ci_path(root: Path) -> Path:
    return root / ".github" / "workflows" / "ci.yml"


def _replace_supply_chain_step(text: str, step_name: str, replacement: str) -> str:
    job = ci_contract._job_block(text, "supply-chain")
    step = ci_contract._step_block(job, step_name)
    assert step in text
    return text.replace(step, replacement, 1)


def test_repository_ci_contract_exposes_build_and_sbom_authority() -> None:
    result = ci_contract.verify_ci_contract(ROOT)
    automatic = result["workflows"]["automatic"]

    assert automatic["prebuild_authority"] == "static-before-project-install"
    assert automatic["build_provenance_subject"] == "github.sha/no-replace-objects"
    assert automatic["sbom_lineage"] == "sha256-bracketed-across-wheel-builds"


def test_every_automatic_project_install_is_immediately_build_authority_guarded() -> None:
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    semantic = ci_contract._semantic_text(text)
    project_install = "          python -m pip install --no-deps --no-build-isolation ."
    guarded_install = (
        "          python scripts/verify_build_authority.py > /dev/null\n" + project_install
    )

    assert semantic.count(project_install) == 5
    assert semantic.count(guarded_install) == 5


def test_ci_contract_rejects_removed_prebuild_authority_step(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = _ci_path(root)
    text = path.read_text(encoding="utf-8").replace(
        f"          {ci_contract.BUILD_AUTHORITY_COMMAND}\n",
        "          true\n",
        1,
    )
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="exact reviewed pre-install step"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_removed_supply_chain_preinstall_revalidation(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = _ci_path(root)
    text = path.read_text(encoding="utf-8")
    job = ci_contract._job_block(text, "supply-chain")
    step = ci_contract._step_block(job, ci_contract.VERIFICATION_INSTALL_STEP_NAME)
    mutated = step.replace(
        "          python scripts/verify_build_authority.py > /dev/null\n", "", 1
    )
    path.write_text(
        _replace_supply_chain_step(text, ci_contract.VERIFICATION_INSTALL_STEP_NAME, mutated),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="revalidate static build authority"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_supply_chain_build_authority_after_project_install(
    tmp_path: Path,
) -> None:
    root = _copy_workflows(tmp_path)
    path = _ci_path(root)
    text = path.read_text(encoding="utf-8")
    job = ci_contract._job_block(text, "supply-chain")
    step = ci_contract._step_block(job, ci_contract.VERIFICATION_INSTALL_STEP_NAME)
    original = (
        "          python scripts/verify_build_authority.py > /dev/null\n"
        "          python -m pip install --no-deps --no-build-isolation .\n"
    )
    replacement = (
        "          python -m pip install --no-deps --no-build-isolation .\n"
        "          python scripts/verify_build_authority.py > /dev/null\n"
    )
    assert original in step
    mutated = step.replace(original, replacement, 1)
    path.write_text(
        _replace_supply_chain_step(text, ci_contract.VERIFICATION_INSTALL_STEP_NAME, mutated),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="revalidate static build authority"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_missing_sbom_digest_export(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = _ci_path(root)
    text = path.read_text(encoding="utf-8").replace(
        '          printf \'RUNTIME_SBOM_SHA256=%s\\n\' "$runtime_sbom_sha256" >> "$GITHUB_ENV"\n',
        "",
        1,
    )
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="digest-exporting evidence step"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_removed_prebuild_sbom_lineage_check(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = _ci_path(root)
    text = path.read_text(encoding="utf-8")
    marker = (
        "          read -r observed_sbom_sha256 _ < <(/usr/bin/sha256sum artifacts/ci/runtime-sbom.cdx.json)\n"
        '          test "$observed_sbom_sha256" = "$RUNTIME_SBOM_SHA256"\n'
    )
    assert text.count(marker) == 3
    text = text.replace(marker, "", 1)
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="exact reviewed event-subject-bound step"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_missing_build_authority_evidence_upload(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = _ci_path(root)
    text = path.read_text(encoding="utf-8").replace(
        f"            {ci_contract.BUILD_AUTHORITY_ARTIFACT}\n",
        "",
        1,
    )
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="exact reviewed pinned action step"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_unsafe_supply_chain_step_order(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = _ci_path(root)
    text = path.read_text(encoding="utf-8")
    build_step = ci_contract._step_block(
        ci_contract._job_block(text, "supply-chain"),
        ci_contract.BUILD_AUTHORITY_STEP_NAME,
    )
    install_step = ci_contract._step_block(
        ci_contract._job_block(text, "supply-chain"),
        ci_contract.VERIFICATION_INSTALL_STEP_NAME,
    )
    text = text.replace(build_step, "__BUILD_STEP__", 1)
    text = text.replace(install_step, build_step, 1)
    text = text.replace("__BUILD_STEP__", install_step, 1)
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="out of reviewed order"):
        ci_contract.verify_ci_contract(root)
