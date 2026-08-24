from __future__ import annotations

import shutil
from pathlib import Path

import pytest

import scripts.verify_ci_contract as ci_contract
import scripts.verify_supply_chain as supply_chain

ROOT = Path(__file__).resolve().parents[2]


def _copy_workflows(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    workflow_dir = root / ".github" / "workflows"
    workflow_dir.parent.mkdir(parents=True)
    shutil.copytree(ROOT / ".github" / "workflows", workflow_dir)
    return root


def test_repository_ci_contract_is_self_consistent() -> None:
    result = ci_contract.verify_ci_contract(ROOT)

    assert result["result"] == "PASS"
    assert result["schema_version"] == 1
    assert result["workflows"]["automatic"]["required_gate"] == "Required PR Gate"
    assert result["workflows"]["automatic"]["secrets"] is False
    assert result["workflows"]["manual"]["credentialed_model"] == "manual-only"


def test_ci_action_authority_matches_supply_chain_verifier() -> None:
    assert ci_contract.EXPECTED_ACTION_SHAS == supply_chain.EXPECTED_ACTION_SHAS


def test_ci_contract_rejects_pull_request_target(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8").replace("  pull_request:\n", "  pull_request_target:\n", 1)
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="missing required automatic trigger|pull_request_target"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_write_permission(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8").replace("  contents: read", "  contents: write", 1)
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="contents: read|write permission"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_secret_in_automatic_workflow(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    path.write_text(
        path.read_text(encoding="utf-8") + "\n# ${{ secrets.ANTHROPIC_API_KEY }}\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="forbidden automatic-CI authority token"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_automatic_trigger_in_manual_workflow(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "manual-validation.yml"
    text = path.read_text(encoding="utf-8").replace(
        "on:\n  workflow_dispatch:\n",
        "on:\n  workflow_dispatch:\n  pull_request:\n",
        1,
    )
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="automatic trigger is forbidden"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_unexpected_workflow(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    rogue = root / ".github" / "workflows" / "rogue.yml"
    rogue.write_text("name: rogue\non: push\n", encoding="utf-8")

    with pytest.raises(ValueError, match="unexpected workflow set"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_unbound_checkout(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8").replace("ref: ${{ github.sha }}", "ref: main")
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="every checkout must bind to github.sha"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_fail_open_required_gate(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8").replace("      - security\n", "", 1)
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="does not depend on security"):
        ci_contract.verify_ci_contract(root)
