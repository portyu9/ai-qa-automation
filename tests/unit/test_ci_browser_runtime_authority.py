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


def test_repository_ci_uses_hosted_browser_without_automatic_installer() -> None:
    result = ci_contract.verify_ci_contract(ROOT)
    automatic = result["workflows"]["automatic"]

    assert automatic["browser_runtime_authority"] == (
        "hosted-system-chrome-observed-without-automatic-installer"
    )


def test_ci_contract_rejects_playwright_privileged_browser_bootstrap(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8")
    marker = "      - name: Verify hosted Chrome runtime\n"
    assert marker in text
    text = text.replace(
        marker,
        "      - name: Reinstall browser runtime\n"
        "        run: python -m playwright install --with-deps chromium\n\n" + marker,
        1,
    )
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="forbidden automatic-CI authority token"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_requires_exact_hosted_chrome_observation(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8")
    browser_job = ci_contract._job_block(text, "browser-reference-sut")
    step = ci_contract._step_block(browser_job, ci_contract.HOSTED_BROWSER_STEP_NAME)
    assert step in text
    path.write_text(text.replace(step, "", 1), encoding="utf-8")

    with pytest.raises(ValueError, match="exactly one step named Verify hosted Chrome runtime"):
        ci_contract.verify_ci_contract(root)
