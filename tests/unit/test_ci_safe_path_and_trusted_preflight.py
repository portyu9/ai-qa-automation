from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
MANUAL_WORKFLOW = ROOT / ".github" / "workflows" / "manual-validation.yml"
TRUSTED_AUTO_WORKFLOW = ROOT / ".github" / "workflows" / "trusted-pr-auto.yml"


def test_all_repository_python_workflows_enable_safe_path() -> None:
    ci_text = CI_WORKFLOW.read_text(encoding="utf-8")
    manual_text = MANUAL_WORKFLOW.read_text(encoding="utf-8")
    trusted_auto_text = TRUSTED_AUTO_WORKFLOW.read_text(encoding="utf-8")

    assert ci_text.count('  PYTHONSAFEPATH: "1"') == 1
    assert manual_text.count('  PYTHONSAFEPATH: "1"') == 1
    assert trusted_auto_text.count('  PYTHONSAFEPATH: "1"') == 1
    assert trusted_auto_text.count('          PYTHONSAFEPATH: ""') == 1


def test_trusted_bot_codeql_safe_path_exception_is_analyze_only() -> None:
    text = TRUSTED_AUTO_WORKFLOW.read_text(encoding="utf-8")
    bot_codeql = text[text.index("  bot-codeql:") : text.index("  required-gate:")]
    analyze_start = bot_codeql.index("      - name: Analyze exact governed bot branch")
    analyze = bot_codeql[analyze_start:]

    assert '          PYTHONSAFEPATH: ""' in analyze
    assert '          PYTHONSAFEPATH: ""' not in bot_codeql[:analyze_start]


def test_empty_safe_path_restores_sibling_import_for_tool_scripts(tmp_path: Path) -> None:
    tool_dir = tmp_path / "tool"
    tool_dir.mkdir()
    (tool_dir / "python_tracer.py").write_text("VALUE = 1\n", encoding="utf-8")
    index = tool_dir / "index.py"
    index.write_text(
        "from python_tracer import VALUE\nassert VALUE == 1\n",
        encoding="utf-8",
    )

    env = os.environ.copy()
    env["PYTHONSAFEPATH"] = "1"
    blocked = subprocess.run(
        [sys.executable, str(index)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert blocked.returncode != 0
    assert "No module named 'python_tracer'" in blocked.stderr

    env["PYTHONSAFEPATH"] = ""
    restored = subprocess.run(
        [sys.executable, str(index)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert restored.returncode == 0, restored.stderr


def test_python_safe_path_blocks_repository_local_pip_module_shadow(tmp_path: Path) -> None:
    marker = "REPOSITORY_LOCAL_PIP_SHADOW_EXECUTED"
    (tmp_path / "pip.py").write_text(f"print({marker!r})\n", encoding="utf-8")
    env = os.environ.copy()
    env["PYTHONSAFEPATH"] = "1"

    result = subprocess.run(
        [sys.executable, "-m", "pip", "--version"],
        cwd=tmp_path,
        env=env,
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert marker not in result.stdout
    assert marker not in result.stderr
    assert "pip " in result.stdout


def test_ordinary_ci_has_no_repository_dispatch_authority() -> None:
    text = CI_WORKFLOW.read_text(encoding="utf-8")

    assert "repository_dispatch:" not in text
    assert "trusted-pr-validation" not in text
    assert "github.event.client_payload" not in text
    assert "  trusted-status:" not in text
    assert "Trusted PR Gate Reporter" not in text
    assert "TRUSTED_GATE_APP_CLIENT_ID" not in text
    assert "TRUSTED_GATE_APP_PRIVATE_KEY" not in text
    assert "  CI_SUBJECT_SHA: ${{ github.sha }}" in text
    dispatch_override = (
        "      CI_SUBJECT_SHA: "
        "${{ github.event_name == 'workflow_dispatch' && inputs.subject_sha || github.sha }}"
    )
    assert text.count(dispatch_override) == 5


def test_supply_chain_binds_event_subject_before_python() -> None:
    text = CI_WORKFLOW.read_text(encoding="utf-8")
    supply_chain = text[text.index("  supply-chain:") : text.index("  security:")]
    pre_python = supply_chain[: supply_chain.index("      - name: Set up Python")]

    assert "      - name: Checkout exact validation subject" in pre_python
    assert "          ref: ${{ env.CI_SUBJECT_SHA }}" in pre_python
    assert "          persist-credentials: false" in pre_python
    assert "          fetch-depth: 2" in pre_python
    assert 'run: test "$(git rev-parse HEAD)" = "$CI_SUBJECT_SHA"' in pre_python
    assert "repository_dispatch" not in pre_python
    assert "github.event.client_payload" not in pre_python
    assert "${{ secrets." not in pre_python


def test_validation_jobs_wait_for_supply_chain_preflight() -> None:
    text = CI_WORKFLOW.read_text(encoding="utf-8")
    expected_headers = {
        "quality": "  quality:\n    name: Quality / Python ${{ matrix.python-version }}\n    needs: supply-chain\n",
        "deterministic-evals": "  deterministic-evals:\n    name: 34-Case Deterministic Control Evaluation\n    needs: supply-chain\n",
        "security": "  security:\n    name: Security Gates\n    needs: supply-chain\n",
        "browser-reference-sut": "  browser-reference-sut:\n    name: Playwright Reference SUT\n    needs: supply-chain\n",
    }
    for header in expected_headers.values():
        assert header in text

    supply_chain = text[text.index("  supply-chain:") : text.index("  security:")]
    assert "          fetch-depth: 2\n" in supply_chain


def test_trusted_app_credential_remains_isolated_to_automatic_reporter() -> None:
    ordinary = CI_WORKFLOW.read_text(encoding="utf-8")
    trusted_auto = TRUSTED_AUTO_WORKFLOW.read_text(encoding="utf-8")

    assert "TRUSTED_GATE_APP_CLIENT_ID" not in ordinary
    assert "TRUSTED_GATE_APP_PRIVATE_KEY" not in ordinary
    assert trusted_auto.count("${{ vars.TRUSTED_GATE_APP_CLIENT_ID }}") == 1
    assert trusted_auto.count("${{ secrets.TRUSTED_GATE_APP_PRIVATE_KEY }}") == 1

    reporter = trusted_auto[trusted_auto.index("  trusted-status:") :]
    assert "    environment:\n      name: trusted-pr-gate\n      deployment: false" in reporter
    assert "      - name: Revalidate automatic trusted admission" in reporter
    assert "      - name: Mint dedicated Trusted PR Gate token" in reporter
    assert "      - name: Publish automatic exact-subject trusted status" in reporter
    assert (
        reporter.index("Revalidate automatic trusted admission")
        < reporter.index("Mint dedicated Trusted PR Gate token")
        < reporter.index("Publish automatic exact-subject trusted status")
    )
