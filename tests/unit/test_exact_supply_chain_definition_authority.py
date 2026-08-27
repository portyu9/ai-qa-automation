from __future__ import annotations

import shutil
from pathlib import Path

import pytest

import scripts.verify_ci_contract as ci_contract
import scripts.verify_supply_chain as supply_chain

ROOT = Path(__file__).resolve().parents[2]


def test_reviewed_definition_blob_constants_match_repository_bytes() -> None:
    ci_text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    docker_text = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert ci_contract._git_blob_sha1(ci_text) == ci_contract.EXPECTED_AUTOMATIC_WORKFLOW_BLOB_SHA
    assert supply_chain._git_blob_sha1(docker_text) == supply_chain.EXPECTED_DOCKERFILE_BLOB_SHA


def test_verifier_reports_exact_reviewed_definition_authority() -> None:
    ci_result = ci_contract.verify_ci_contract(ROOT)
    supply_chain_result = supply_chain.verify_repository(ROOT)

    assert ci_result["workflows"]["automatic"]["workflow_definition"] == ("exact-reviewed-git-blob")
    assert supply_chain_result["dockerfile_authority"] == "exact-reviewed-git-blob"


@pytest.mark.parametrize(
    "extra_command",
    [
        "          python -m pip install . --no-deps --no-build-isolation",
        "          pip install --no-build-isolation --no-deps .",
        "          python -m pip install --no-build-isolation . --no-deps",
    ],
)
def test_ci_contract_rejects_additional_equivalent_project_install(
    tmp_path: Path,
    extra_command: str,
) -> None:
    root = tmp_path / "repo"
    workflow_dir = root / ".github" / "workflows"
    workflow_dir.parent.mkdir(parents=True)
    shutil.copytree(ROOT / ".github" / "workflows", workflow_dir)
    path = workflow_dir / "ci.yml"
    text = path.read_text(encoding="utf-8")
    marker = ci_contract.AUTOMATIC_PROJECT_INSTALL_COMMAND
    assert marker in text
    path.write_text(text.replace(marker, f"{marker}\n{extra_command}", 1), encoding="utf-8")

    with pytest.raises(ValueError, match="exact reviewed automatic workflow definition"):
        ci_contract.verify_ci_contract(root)


@pytest.mark.parametrize(
    "extra_instruction",
    [
        "RUN apt-get update",
        "RUN python -m pip install requests",
        "ADD https://example.invalid/tool /tmp/tool",
    ],
)
def test_supply_chain_rejects_additional_docker_authority(
    tmp_path: Path,
    extra_instruction: str,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    dockerfile = root / "Dockerfile"
    dockerfile.write_text(
        (ROOT / "Dockerfile").read_text(encoding="utf-8") + f"\n{extra_instruction}\n",
        encoding="utf-8",
    )
    base_text = (ROOT / "requirements" / "base-image.lock").read_text(encoding="utf-8").strip()

    with pytest.raises(ValueError, match="exact reviewed runtime-composition definition"):
        supply_chain._verify_docker(root, base_text)
