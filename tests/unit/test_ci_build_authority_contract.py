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

    assert automatic["prebuild_authority"] == (
        "exact-lock-and-build-authority-before-validation-installs"
    )
    assert automatic["dependency_install_count"] == 5
    assert automatic["dependency_install_authority"] == (
        "exact-reviewed-locks-preinstall-and-postinstall-revalidated"
    )
    assert automatic["project_install_count"] == 5
    assert automatic["project_install_authority"] == "immediate-static-revalidation"
    assert automatic["archive_build_authority"] == "verified-and-matched-before-wheel-builds"
    assert automatic["build_provenance_subject"] == "CI_SUBJECT_SHA/isolated-git-view"
    assert automatic["archive_attribute_authority"] == "versioned-tree-only"
    assert automatic["sbom_lineage"] == "parent-digest-bound-and-bracketed"


def test_every_automatic_dependency_install_is_authority_bracketed() -> None:
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    lines = ci_contract._semantic_text(text).splitlines()
    indices = [
        index
        for index, line in enumerate(lines)
        if line.startswith(ci_contract.AUTOMATIC_DEPENDENCY_INSTALL_PREFIX)
    ]

    assert len(indices) == 5
    for index in indices:
        assert lines[index - 1] == ci_contract.BUILD_AUTHORITY_REVALIDATION_COMMAND
        assert lines[index + 1] == ci_contract.BUILD_AUTHORITY_REVALIDATION_COMMAND


def test_every_automatic_project_install_is_immediately_build_authority_guarded() -> None:
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    semantic = ci_contract._semantic_text(text)
    project_install = ci_contract.AUTOMATIC_PROJECT_INSTALL_COMMAND
    guarded_install = ci_contract.BUILD_AUTHORITY_REVALIDATION_COMMAND + "\n" + project_install

    assert semantic.count(project_install) == 5
    assert semantic.count(guarded_install) == 5


def test_reproducible_archives_are_build_authority_verified_before_wheels() -> None:
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    step = ci_contract._step_block(
        ci_contract._job_block(text, "supply-chain"),
        ci_contract.REPRODUCIBLE_BUILD_STEP_NAME,
    )

    assert step.count("python scripts/verify_build_authority.py --root") == 2
    assert (
        "cmp -s artifacts/ci/build-authority-archive-a.json "
        "artifacts/ci/build-authority-archive-b.json"
    ) in step


def test_ci_contract_rejects_removed_dependency_preinstall_guard(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = _ci_path(root)
    text = path.read_text(encoding="utf-8")
    marker = ci_contract.BUILD_AUTHORITY_REVALIDATION_COMMAND + "\n"
    dependency_index = text.index(ci_contract.AUTOMATIC_DEPENDENCY_INSTALL_PREFIX)
    guard_index = text.rfind(marker, 0, dependency_index)
    assert guard_index >= 0
    text = text[:guard_index] + text[guard_index + len(marker) :]
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="every automatic dependency install"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_removed_dependency_postinstall_guard(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = _ci_path(root)
    text = path.read_text(encoding="utf-8")
    dependency_index = text.index(ci_contract.AUTOMATIC_DEPENDENCY_INSTALL_PREFIX)
    guard = "\n" + ci_contract.BUILD_AUTHORITY_REVALIDATION_COMMAND
    guard_index = text.index(guard, dependency_index)
    text = text[:guard_index] + text[guard_index + len(guard) :]
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="every automatic dependency install"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_unguarded_non_supply_chain_project_install(
    tmp_path: Path,
) -> None:
    root = _copy_workflows(tmp_path)
    path = _ci_path(root)
    text = path.read_text(encoding="utf-8")
    guarded_install = (
        ci_contract.BUILD_AUTHORITY_REVALIDATION_COMMAND
        + "\n"
        + ci_contract.AUTOMATIC_PROJECT_INSTALL_COMMAND
    )
    assert text.count(guarded_install) == 5
    text = text.replace(
        guarded_install,
        ci_contract.AUTOMATIC_PROJECT_INSTALL_COMMAND,
        1,
    )
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="every automatic dependency install"):
        ci_contract.verify_ci_contract(root)


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


def test_ci_contract_rejects_removed_supply_chain_prelock_revalidation(tmp_path: Path) -> None:
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

    with pytest.raises(ValueError, match="every automatic dependency install"):
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

    with pytest.raises(ValueError, match="every automatic dependency install"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_removed_archive_build_authority_guard(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = _ci_path(root)
    text = path.read_text(encoding="utf-8").replace(
        '          python scripts/verify_build_authority.py --root "$build_a" > artifacts/ci/build-authority-archive-a.json\n',
        "",
        1,
    )
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="exact reviewed validation-subject-bound step"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_unmatched_archive_build_authority_evidence(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = _ci_path(root)
    text = path.read_text(encoding="utf-8").replace(
        "          cmp -s artifacts/ci/build-authority-archive-a.json artifacts/ci/build-authority-archive-b.json\n",
        "",
        1,
    )
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="exact reviewed validation-subject-bound step"):
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

    with pytest.raises(ValueError, match="exact reviewed validation-subject-bound step"):
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


def test_ci_contract_rejects_missing_archive_build_authority_evidence_upload(
    tmp_path: Path,
) -> None:
    root = _copy_workflows(tmp_path)
    path = _ci_path(root)
    text = path.read_text(encoding="utf-8")
    artifact = ci_contract.ARCHIVE_BUILD_AUTHORITY_ARTIFACTS[0]
    text = path.read_text(encoding="utf-8").replace(f"            {artifact}\n", "", 1)
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


def test_ci_contract_rejects_appended_runtime_sbom_command(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = _ci_path(root)
    text = path.read_text(encoding="utf-8")
    step = ci_contract._step_block(
        ci_contract._job_block(text, "supply-chain"),
        ci_contract.RUNTIME_SBOM_STEP_NAME,
    )
    path.write_text(
        _replace_supply_chain_step(
            text, ci_contract.RUNTIME_SBOM_STEP_NAME, step + "\n          true"
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="exact reviewed digest-exporting evidence step"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_appended_reproducible_build_command(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = _ci_path(root)
    text = path.read_text(encoding="utf-8")
    step = ci_contract._step_block(
        ci_contract._job_block(text, "supply-chain"),
        ci_contract.REPRODUCIBLE_BUILD_STEP_NAME,
    )
    path.write_text(
        _replace_supply_chain_step(
            text,
            ci_contract.REPRODUCIBLE_BUILD_STEP_NAME,
            step + "\n          true",
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="exact reviewed validation-subject-bound step"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_appended_supply_chain_upload_authority(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = _ci_path(root)
    text = path.read_text(encoding="utf-8")
    step = ci_contract._step_block(
        ci_contract._job_block(text, "supply-chain"),
        ci_contract.SUPPLY_CHAIN_UPLOAD_STEP_NAME,
    )
    path.write_text(
        _replace_supply_chain_step(
            text,
            ci_contract.SUPPLY_CHAIN_UPLOAD_STEP_NAME,
            step + "\n        env:\n          UNREVIEWED: value",
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="exact reviewed pinned action step"):
        ci_contract.verify_ci_contract(root)
