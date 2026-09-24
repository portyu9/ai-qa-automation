from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import scripts.verify_ci_contract as ci_contract

ROOT = Path(__file__).resolve().parents[2]


def _copy_contract_repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    workflow_dir = root / ".github" / "workflows"
    workflow_dir.parent.mkdir(parents=True)
    shutil.copytree(ROOT / ".github" / "workflows", workflow_dir)
    return root


def _accept_mutated_workflow_hash(monkeypatch: pytest.MonkeyPatch, text: str) -> None:
    monkeypatch.setattr(
        ci_contract._trusted_auto,
        "EXPECTED_TRUSTED_AUTO_WORKFLOW_BLOB_SHA",
        ci_contract._workflow_structure_sha1(text),
    )


def test_trusted_auto_contract_is_frozen_and_bounded() -> None:
    ci_contract._verify_frozen_base()
    result = ci_contract.verify_ci_contract(ROOT)
    auto = result["workflows"]["trusted_auto"]

    assert auto["trigger"] == "workflow_run:completed:reviewed-ci-or-codeql+schedule:5m"
    assert auto["candidate_execution_guard"] == (
        "owner-zero-protected-drift-or-exact-governed-bot-provenance"
    )
    assert auto["candidate_subject_binding"] == "job-level-exact-prospective-merge"
    assert auto["needs_skip_policy"] == "not-cancelled-plus-explicit-direct-needs-success"
    assert auto["validation_authority"] == (
        "secret-free;read-only-except-bot-codeql-security-events-write-before-reporter"
    )
    assert auto["status_writer"] == "dedicated-github-app"
    assert auto["maintenance_authority"] == (
        "autonomous-governed-bots;external-one-shot-only-for-unrecognized-protected-change"
    )
    assert auto["governed_bot_lanes"] == [
        "dependabot-actions",
        "dependency-promotion",
        "security-autoheal",
        "protected-security-remediation",
    ]
    assert {".github", "scripts"} <= set(auto["protected_paths"])
    assert "tests" not in auto["protected_paths"]


def test_ci_verifier_executes_under_python_safe_path() -> None:
    env = dict(os.environ)
    env["PYTHONSAFEPATH"] = "1"
    completed = subprocess.run(
        [sys.executable, "scripts/verify_ci_contract.py"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    assert payload == {
        "schema_version": 1,
        "result": "PASS",
        "verifier": "ci-contract",
    }


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

    with pytest.raises(
        ValueError, match="non-action structure differs from reviewed trust authority"
    ):
        ci_contract.verify_ci_contract(root)


def test_trusted_auto_contract_rejects_native_write_permission(tmp_path: Path) -> None:
    root = _copy_contract_repo(tmp_path)
    path = root / ".github" / "workflows" / "trusted-pr-auto.yml"
    text = path.read_text(encoding="utf-8")
    marker = "  contents: read\n"
    assert marker in text
    path.write_text(text.replace(marker, "  contents: write\n", 1), encoding="utf-8")

    with pytest.raises(
        ValueError, match="non-action structure differs from reviewed trust authority"
    ):
        ci_contract.verify_ci_contract(root)


def test_trusted_auto_contract_rejects_bot_codeql_permission_expansion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_contract_repo(tmp_path)
    path = root / ".github" / "workflows" / "trusted-pr-auto.yml"
    text = path.read_text(encoding="utf-8")
    job = ci_contract._job_block(text, "bot-codeql")
    marker = "      contents: read\n"
    assert marker in job
    mutated_job = job.replace(marker, "      contents: write\n", 1)
    mutated = text.replace(job, mutated_job, 1)
    path.write_text(mutated, encoding="utf-8")
    _accept_mutated_workflow_hash(monkeypatch, mutated)

    with pytest.raises(ValueError, match="permissions differ from the reviewed minimum"):
        ci_contract.verify_ci_contract(root)


def test_trusted_auto_contract_rejects_removed_protected_path(tmp_path: Path) -> None:
    root = _copy_contract_repo(tmp_path)
    path = root / ".github" / "workflows" / "trusted-pr-auto.yml"
    text = path.read_text(encoding="utf-8")
    marker = "            requirements\n"
    assert marker in text
    path.write_text(text.replace(marker, "", 1), encoding="utf-8")

    with pytest.raises(
        ValueError, match="non-action structure differs from reviewed trust authority"
    ):
        ci_contract.verify_ci_contract(root)


@pytest.mark.parametrize(
    "job_id",
    (
        "subject-guard",
        "supply-chain",
        "quality",
        "deterministic-evals",
        "security",
        "browser-reference-sut",
        "bot-codeql",
        "required-gate",
        "trusted-status",
    ),
)
def test_trusted_auto_contract_rejects_removed_cancel_safe_skip_override(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    job_id: str,
) -> None:
    root = _copy_contract_repo(tmp_path)
    path = root / ".github" / "workflows" / "trusted-pr-auto.yml"
    text = path.read_text(encoding="utf-8")
    job = ci_contract._job_block(text, job_id)
    marker = "!cancelled() && "
    assert marker in job
    mutated_job = job.replace(marker, "", 1)
    mutated = text.replace(job, mutated_job, 1)
    path.write_text(mutated, encoding="utf-8")
    _accept_mutated_workflow_hash(monkeypatch, mutated)

    with pytest.raises(
        ValueError,
        match=rf"trusted automatic job {job_id} must override skipped dependency propagation",
    ):
        ci_contract.verify_ci_contract(root)


@pytest.mark.parametrize(
    "job_id",
    ("supply-chain", "quality", "deterministic-evals", "security", "browser-reference-sut"),
)
def test_trusted_auto_contract_rejects_missing_candidate_subject_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    job_id: str,
) -> None:
    root = _copy_contract_repo(tmp_path)
    path = root / ".github" / "workflows" / "trusted-pr-auto.yml"
    text = path.read_text(encoding="utf-8")
    binding = "    env:\n      CI_SUBJECT_SHA: ${{ needs.preflight.outputs.merge_sha }}\n"
    job = ci_contract._job_block(text, job_id)
    assert binding in job
    mutated_job = job.replace(binding, "", 1)
    mutated = text.replace(job, mutated_job, 1)
    path.write_text(mutated, encoding="utf-8")
    _accept_mutated_workflow_hash(monkeypatch, mutated)

    with pytest.raises(ValueError, match=rf"validation job {job_id} must bind CI_SUBJECT_SHA"):
        ci_contract.verify_ci_contract(root)


@pytest.mark.parametrize(
    ("job_id", "message"),
    (
        ("preflight", "preflight must retain trusted workflow identity"),
        ("trusted-status", "reporter must retain trusted workflow identity"),
    ),
)
def test_trusted_auto_contract_rejects_candidate_identity_in_trusted_jobs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    job_id: str,
    message: str,
) -> None:
    root = _copy_contract_repo(tmp_path)
    path = root / ".github" / "workflows" / "trusted-pr-auto.yml"
    text = path.read_text(encoding="utf-8")
    job = ci_contract._job_block(text, job_id)
    marker = "    runs-on: ubuntu-24.04\n"
    assert marker in job
    injected = (
        marker + "    env:\n" + "      CI_SUBJECT_SHA: ${{ github.event.workflow_run.head_sha }}\n"
    )
    mutated_job = job.replace(marker, injected, 1)
    mutated = text.replace(job, mutated_job, 1)
    path.write_text(mutated, encoding="utf-8")
    _accept_mutated_workflow_hash(monkeypatch, mutated)

    with pytest.raises(ValueError, match=message):
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
        '        run: test -n "$BAD"\n\n'
    )
    path.write_text(text.replace(marker, injected + marker, 1), encoding="utf-8")

    with pytest.raises(
        ValueError, match="non-action structure differs from reviewed trust authority"
    ):
        ci_contract.verify_ci_contract(root)


def test_protected_remediation_workflow_is_schedule_only_and_author_token_is_narrow() -> None:
    result = ci_contract.verify_ci_contract(ROOT)
    protected = result["workflows"]["protected_remediation"]

    assert protected == {
        "trigger": "schedule:5m",
        "trusted_definition": "default-branch-scheduled-workflow",
        "native_token": "read-only",
        "author_token": "distinct-app:contents-write+pull-requests-write",
        "status_authority": "none",
        "candidate_workflow_execution": "forbidden",
        "mutation": "exact-route+one-file+branch-pr-only",
    }


def test_protected_remediation_contract_rejects_candidate_trigger(tmp_path: Path) -> None:
    root = _copy_contract_repo(tmp_path)
    path = root / ".github" / "workflows" / "protected-security-remediation.yml"
    text = path.read_text(encoding="utf-8")
    path.write_text(
        text.replace("on:\n  schedule:\n", "on:\n  pull_request:\n  schedule:\n", 1),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="structure differs from reviewed authority"):
        ci_contract.verify_ci_contract(root)


def test_protected_remediation_contract_rejects_status_write_app_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_contract_repo(tmp_path)
    path = root / ".github" / "workflows" / "protected-security-remediation.yml"
    text = path.read_text(encoding="utf-8")
    marker = "          permission-pull-requests: write\n"
    assert marker in text
    mutated = text.replace(marker, marker + "          permission-statuses: write\n", 1)
    path.write_text(mutated, encoding="utf-8")
    monkeypatch.setattr(
        ci_contract,
        "EXPECTED_PROTECTED_REMEDIATION_WORKFLOW_BLOB_SHA",
        ci_contract._workflow_structure_sha1(mutated),
    )

    with pytest.raises(ValueError, match="forbidden permission"):
        ci_contract.verify_ci_contract(root)
