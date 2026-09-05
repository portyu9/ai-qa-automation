from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, cast

import pytest

from ai_qa_automation.evidence import EvidenceStore
from ai_qa_automation.fs_authority import pin_directory_identity
from ai_qa_automation.models import (
    AgentRunState,
    EvidenceItem,
    EvidenceKind,
    ValidationResult,
    ValidationStatus,
)
from ai_qa_automation.policy import PolicyEngine
from ai_qa_automation.runtime.locator_repair import (
    LocatorRepairAuthorityError,
    prepare_locator_repair_binding,
)
from ai_qa_automation.tools.repository import RepositoryInspector

_LOCATOR = 'page.get_by_test_id("save-profile")'


def _git(workspace: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=workspace,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _subject(tmp_path: Path, source: str) -> tuple[Path, AgentRunState, EvidenceStore, PolicyEngine, tuple[int, int]]:
    workspace = tmp_path / "workspace"
    test_file = workspace / "tests" / "test_nodes.py"
    test_file.parent.mkdir(parents=True)
    test_file.write_text(source, encoding="utf-8")
    _git(workspace, "init", "-q")
    _git(workspace, "config", "user.email", "qa@example.test")
    _git(workspace, "config", "user.name", "QA Test")
    _git(workspace, "add", ".")
    _git(workspace, "commit", "-qm", "baseline")
    state = AgentRunState(
        objective="bind locator to exact failing node",
        workspace=str(workspace),
        target_git_sha=_git(workspace, "rev-parse", "HEAD"),
    )
    evidence = EvidenceStore(tmp_path / "artifacts", state.run_id)
    policy = PolicyEngine(tmp_path / "control", workspace, allow_test_writes=True)
    root_identity = pin_directory_identity(workspace, label="locator node workspace")
    return workspace, state, evidence, policy, root_identity


def _failure(
    workspace: Path,
    state: AgentRunState,
    evidence: EvidenceStore,
    root_identity: tuple[int, int],
    selector: str,
) -> ValidationResult:
    snapshot = RepositoryInspector(
        workspace,
        expected_root_identity=root_identity,
    ).snapshot()
    assert snapshot.git_sha
    assert snapshot.fingerprint_complete
    assert snapshot.fingerprint
    exit_item = evidence.add(
        EvidenceItem(
            run_id=state.run_id,
            kind=EvidenceKind.EXIT_CODE,
            source="pytest",
            source_identifier=f"python -m pytest {selector}",
            summary="pytest failed",
            structured_data={
                "exit_code": 1,
                "workspace_integrity_verified": True,
                "workspace_fingerprint_before": snapshot.fingerprint,
                "workspace_fingerprint_after": snapshot.fingerprint,
                "execution_subject": {
                    "git_sha": snapshot.git_sha,
                    "source_fingerprint": snapshot.fingerprint,
                },
            },
        )
    )
    error_item = evidence.add(
        EvidenceItem(
            run_id=state.run_id,
            kind=EvidenceKind.EXCEPTION,
            source="pytest",
            source_identifier=f"python -m pytest {selector}",
            summary="pytest tests failed",
            structured_data={"exit_code": 1},
        )
    )
    state.evidence_ids.extend([exit_item.id, error_item.id])
    validation = ValidationResult(
        name="pytest",
        gate_id=f"pytest:{selector}",
        revision=0,
        status=ValidationStatus.FAIL,
        summary="targeted failure",
        evidence_ids=[exit_item.id, error_item.id],
        details={"scope": "targeted", "args": [selector], "execution_started": True},
    )
    state.validation_results.append(validation)
    return validation


def _prepare(
    workspace: Path,
    state: AgentRunState,
    evidence: EvidenceStore,
    policy: PolicyEngine,
    root_identity: tuple[int, int],
    validation: ValidationResult,
) -> Any:
    return prepare_locator_repair_binding(
        workspace=workspace,
        expected_root_identity=root_identity,
        state=state,
        evidence=evidence,
        policy=policy,
        failure_validation_id=validation.id,
        original_locator=_LOCATOR,
    )


def test_file_level_failure_is_too_ambiguous_for_autonomous_locator_repair(
    tmp_path: Path,
) -> None:
    workspace, state, evidence, policy, root_identity = _subject(
        tmp_path,
        "def test_target(page):\n"
        f"    {_LOCATOR}.click()\n"
        "    assert True\n",
    )
    validation = _failure(
        workspace,
        state,
        evidence,
        root_identity,
        "tests/test_nodes.py",
    )

    with pytest.raises(LocatorRepairAuthorityError, match="explicit pytest test-node selector"):
        _prepare(workspace, state, evidence, policy, root_identity, validation)


def test_locator_outside_selected_failing_node_cannot_become_repair_authority(
    tmp_path: Path,
) -> None:
    workspace, state, evidence, policy, root_identity = _subject(
        tmp_path,
        "def test_target(page):\n"
        "    page.get_by_test_id(\"different\").click()\n"
        "    assert True\n\n"
        "def test_other(page):\n"
        f"    {_LOCATOR}.click()\n"
        "    assert True\n",
    )
    validation = _failure(
        workspace,
        state,
        evidence,
        root_identity,
        "tests/test_nodes.py::test_target",
    )

    with pytest.raises(LocatorRepairAuthorityError, match="selected failing pytest node"):
        _prepare(workspace, state, evidence, policy, root_identity, validation)
