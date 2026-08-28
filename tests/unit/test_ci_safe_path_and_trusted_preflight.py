from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
MANUAL_WORKFLOW = ROOT / ".github" / "workflows" / "manual-validation.yml"


def test_all_repository_python_workflows_enable_safe_path() -> None:
    ci_text = CI_WORKFLOW.read_text(encoding="utf-8")
    manual_text = MANUAL_WORKFLOW.read_text(encoding="utf-8")

    assert ci_text.count('  PYTHONSAFEPATH: "1"') == 1
    assert manual_text.count('  PYTHONSAFEPATH: "1"') == 1


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


def test_trusted_dispatch_preflight_freezes_control_plane_before_python() -> None:
    text = CI_WORKFLOW.read_text(encoding="utf-8")
    supply_chain = text[text.index("  supply-chain:") : text.index("  security:")]
    preflight = supply_chain[
        supply_chain.index(
            "      - name: Verify trusted control-plane subject"
        ) : supply_chain.index("      - name: Set up Python")
    ]

    assert "if: github.event_name == 'repository_dispatch'" in preflight
    assert 'test "$GITHUB_REF" = "refs/heads/main"' in preflight
    assert 'test "$GITHUB_ACTOR" = "$GITHUB_REPOSITORY_OWNER"' in preflight
    assert '/usr/bin/git rev-list --parents -n 1 "$CI_SUBJECT_SHA"' in preflight
    assert 'test "$base_sha" = "$GITHUB_SHA"' in preflight
    assert 'test -z "$extra_parent"' in preflight
    for path in (
        ".github",
        ".claude",
        ".dockerignore",
        ".mcp.json",
        ".pre-commit-config.yaml",
        "CLAUDE.md",
        "Dockerfile",
        "evals",
        "examples",
        "pyproject.toml",
        "requirements",
        "scripts",
        "tests",
        "src/ai_qa_automation/__init__.py",
        "src/ai_qa_automation/io_safety.py",
        "src/ai_qa_automation/tools/__init__.py",
        "src/ai_qa_automation/tools/execution_env.py",
    ):
        assert f"            {path}\n" in preflight
    assert preflight.index("/usr/bin/git rev-list") < preflight.index("protected_paths=(")


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


def test_trusted_reporter_treats_dispatch_payload_as_data() -> None:
    text = CI_WORKFLOW.read_text(encoding="utf-8")
    trusted_status = text[text.index("  trusted-status:") :]
    publish_step = trusted_status[
        trusted_status.index("      - name: Publish exact-subject trusted status") :
    ]
    run_script = publish_step[publish_step.index("        run: |\n") :]

    for variable, expression in (
        ("PR_NUMBER", "${{ github.event.client_payload.pr_number }}"),
        ("EXPECTED_HEAD_SHA", "${{ github.event.client_payload.expected_head_sha }}"),
        ("EXPECTED_BASE_SHA", "${{ github.event.client_payload.expected_base_sha }}"),
        ("EXPECTED_MERGE_SHA", "${{ github.event.client_payload.expected_merge_sha }}"),
        ("AUTHORIZED", "${{ github.event.client_payload.authorized }}"),
        ("VALIDATION_RESULT", "${{ needs.required-gate.result }}"),
    ):
        assert f"          {variable}: {expression}\n" in publish_step

    assert "${{ github.event.client_payload." not in run_script
    assert 'printf -v job_results_json \'{"validation":"%s"}\' "$VALIDATION_RESULT"' in run_script
    assert '--pr-number "$PR_NUMBER"' in run_script
    assert '--expected-head-sha "$EXPECTED_HEAD_SHA"' in run_script
    assert '--expected-base-sha "$EXPECTED_BASE_SHA"' in run_script
    assert '--expected-merge-sha "$EXPECTED_MERGE_SHA"' in run_script
    assert '--authorized "$AUTHORIZED"' in run_script
    assert '--job-results-json "$job_results_json"' in run_script
