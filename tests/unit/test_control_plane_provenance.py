from __future__ import annotations

import os
from pathlib import Path

import pytest

from ai_qa_automation import models as models_module
from ai_qa_automation.models import (
    AgentRunState,
    ControlPlaneRevalidationStatus,
    TerminalStatus,
)
from ai_qa_automation.reporting import build_final_report
from ai_qa_automation.runtime import control_plane_provenance as provenance
from ai_qa_automation.runtime.attestation import build_run_attestation
from ai_qa_automation.runtime.control_plane_provenance import (
    bind_control_git_identity,
    capture_control_plane_subject,
    enforce_terminal_control_plane_subject,
    same_control_plane_capture,
)
from ai_qa_automation.runtime.lineage import build_run_lineage
from ai_qa_automation.state import StateStore


def _control_root(tmp_path: Path) -> Path:
    root = tmp_path / "control"
    (root / ".claude" / "hooks").mkdir(parents=True)
    (root / "CLAUDE.md").write_text("trusted project instructions\n", encoding="utf-8")
    (root / ".claude" / "settings.json").write_text('{"hooks":{}}\n', encoding="utf-8")
    for skill in (
        "investigate-test-failure",
        "self-heal-test",
        "generate-test",
        "prioritize-regression",
        "performance-test",
    ):
        skill_file = root / ".claude" / "skills" / skill / "SKILL.md"
        skill_file.parent.mkdir(parents=True, exist_ok=True)
        skill_file.write_text(f"{skill} authority\n", encoding="utf-8")
    (root / ".claude" / "hooks" / "policy_guard.py").write_text(
        "POLICY = 1\n", encoding="utf-8"
    )
    return root


def _controller_root(tmp_path: Path) -> Path:
    root = tmp_path / "controller"
    (root / "runtime").mkdir(parents=True)
    (root / "tools").mkdir(parents=True)
    (root / "__init__.py").write_text("", encoding="utf-8")
    (root / "policy.py").write_text("POLICY = 1\n", encoding="utf-8")
    (root / "runtime" / "system_prompt.py").write_text("PROMPT = 'safe'\n", encoding="utf-8")
    (root / "runtime" / "runtime_hooks.py").write_text("HOOK = 1\n", encoding="utf-8")
    (root / "tools" / "repository.py").write_text("TOOL = 1\n", encoding="utf-8")
    return root


def _capture(tmp_path: Path):
    captured = capture_control_plane_subject(
        _control_root(tmp_path),
        controller_root=_controller_root(tmp_path),
    )
    return bind_control_git_identity(
        captured, control_git_sha="a" * 40, control_git_clean=False
    )


def _state(bound, *, terminal_status: TerminalStatus) -> AgentRunState:
    return AgentRunState(
        objective="verify exact control provenance",
        workspace="/tmp/target",
        target_git_sha="b" * 40,
        configuration_version="sha256:" + "c" * 64,
        control_plane_subject=bound.subject,
        control_plane_revalidation_status=ControlPlaneRevalidationStatus.BOUND,
        terminal_status=terminal_status,
        terminal_reason="preexisting terminal truth",
    )


def test_identical_control_plane_bytes_produce_stable_subject(tmp_path: Path) -> None:
    control = _control_root(tmp_path)
    controller = _controller_root(tmp_path)

    first = capture_control_plane_subject(control, controller_root=controller)
    second = capture_control_plane_subject(control, controller_root=controller)

    assert first.subject == second.subject
    assert first.subject.subject_digest == second.subject.subject_digest
    assert first.observation == second.observation


def test_project_settings_and_skill_bytes_are_authority_subjects(tmp_path: Path) -> None:
    control = _control_root(tmp_path)
    controller = _controller_root(tmp_path)
    original = capture_control_plane_subject(control, controller_root=controller)

    (control / ".claude" / "settings.json").write_text('{"hooks":{"changed":true}}\n')
    settings_changed = capture_control_plane_subject(control, controller_root=controller)
    assert settings_changed.subject.subject_digest != original.subject.subject_digest

    (control / ".claude" / "settings.json").write_text('{"hooks":{}}\n')
    (control / ".claude" / "skills" / "generate-test" / "SKILL.md").write_text(
        "different authority\n"
    )
    skill_changed = capture_control_plane_subject(control, controller_root=controller)
    assert skill_changed.subject.subject_digest != original.subject.subject_digest


def test_controller_policy_and_system_prompt_bytes_are_authority_subjects(tmp_path: Path) -> None:
    control = _control_root(tmp_path)
    controller = _controller_root(tmp_path)
    original = capture_control_plane_subject(control, controller_root=controller)

    (controller / "policy.py").write_text("POLICY = 2\n")
    changed = capture_control_plane_subject(control, controller_root=controller)

    assert changed.subject.controller_manifest.digest != original.subject.controller_manifest.digest
    assert changed.subject.subject_digest != original.subject.subject_digest


def test_untracked_project_authority_and_optional_mcp_presence_cannot_be_omitted(
    tmp_path: Path,
) -> None:
    control = _control_root(tmp_path)
    controller = _controller_root(tmp_path)
    original = capture_control_plane_subject(control, controller_root=controller)
    assert original.subject.project_manifest.absent_paths == (".mcp.json",)

    extra = control / ".claude" / "skills" / "new-skill" / "SKILL.md"
    extra.parent.mkdir(parents=True)
    extra.write_text("new untracked authority\n")
    with_untracked = capture_control_plane_subject(control, controller_root=controller)
    assert any(
        item.path.endswith("new-skill/SKILL.md")
        for item in with_untracked.subject.project_manifest.files
    )
    assert with_untracked.subject.subject_digest != original.subject.subject_digest

    (control / ".mcp.json").write_text('{"mcpServers":{}}\n')
    with_mcp = capture_control_plane_subject(control, controller_root=controller)
    assert with_mcp.subject.project_manifest.absent_paths == ()
    assert any(item.path == ".mcp.json" for item in with_mcp.subject.project_manifest.files)
    assert with_mcp.subject.subject_digest != with_untracked.subject.subject_digest


def test_git_identity_is_supporting_metadata_not_sufficient_authority(tmp_path: Path) -> None:
    control = _control_root(tmp_path)
    controller = _controller_root(tmp_path)
    captured = capture_control_plane_subject(control, controller_root=controller)
    clean = bind_control_git_identity(
        captured, control_git_sha="e" * 40, control_git_clean=True
    )
    dirty = bind_control_git_identity(
        captured, control_git_sha="e" * 40, control_git_clean=False
    )

    assert clean.subject.control_git_sha == dirty.subject.control_git_sha
    assert clean.subject.control_git_clean is True
    assert dirty.subject.control_git_clean is False
    assert clean.subject.subject_digest == dirty.subject.subject_digest




def test_missing_runtime_requested_skill_is_not_a_bindable_project_subject(tmp_path: Path) -> None:
    control = _control_root(tmp_path)
    controller = _controller_root(tmp_path)
    missing = control / ".claude" / "skills" / "self-heal-test" / "SKILL.md"
    missing.unlink()

    with pytest.raises(ValueError, match="missing required project inputs"):
        capture_control_plane_subject(control, controller_root=controller)


def test_manifest_metadata_serialization_is_bounded_during_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    control = _control_root(tmp_path)
    controller = _controller_root(tmp_path)
    monkeypatch.setattr(models_module, "_MAX_CONTROL_PLANE_MANIFEST_METADATA_BYTES", 64)

    with pytest.raises(ValueError, match="metadata serialization bound"):
        capture_control_plane_subject(control, controller_root=controller)


def test_git_observation_sandwich_detects_content_or_ownership_drift(tmp_path: Path) -> None:
    control = _control_root(tmp_path)
    controller = _controller_root(tmp_path)
    before = capture_control_plane_subject(control, controller_root=controller)

    skill = control / ".claude" / "skills" / "generate-test" / "SKILL.md"
    skill.write_text("changed between capture and Git observation\n", encoding="utf-8")
    after_content_change = capture_control_plane_subject(control, controller_root=controller)
    assert not same_control_plane_capture(before, after_content_change)

    rebound = after_content_change
    replacement = control / ".claude" / "settings.tmp"
    settings = control / ".claude" / "settings.json"
    replacement.write_bytes(settings.read_bytes())
    os.replace(replacement, settings)
    after_same_byte_replacement = capture_control_plane_subject(
        control, controller_root=controller
    )
    assert rebound.subject.subject_digest == after_same_byte_replacement.subject.subject_digest
    assert not same_control_plane_capture(rebound, after_same_byte_replacement)


def test_ignored_controller_bytecode_cache_churn_does_not_create_false_drift(
    tmp_path: Path,
) -> None:
    control = _control_root(tmp_path)
    controller = _controller_root(tmp_path)
    bound = capture_control_plane_subject(control, controller_root=controller)

    cache = controller / "runtime" / "__pycache__"
    cache.mkdir()
    (cache / "system_prompt.cpython-311.pyc").write_bytes(b"not authority")

    current = capture_control_plane_subject(control, controller_root=controller)
    assert current.subject.subject_digest == bound.subject.subject_digest
    assert current.observation == bound.observation


def test_same_byte_replacement_preserves_content_subject_but_fails_ownership_revalidation(
    tmp_path: Path,
) -> None:
    control = _control_root(tmp_path)
    controller = _controller_root(tmp_path)
    bound = capture_control_plane_subject(control, controller_root=controller)
    policy = controller / "policy.py"
    replacement = controller / "policy.tmp"
    replacement.write_bytes(policy.read_bytes())
    os.replace(replacement, policy)

    current = capture_control_plane_subject(control, controller_root=controller)
    assert current.subject.subject_digest == bound.subject.subject_digest
    assert current.observation != bound.observation

    state = _state(bound, terminal_status=TerminalStatus.SUCCESS)
    status, _ = enforce_terminal_control_plane_subject(
        state,
        bound=bound,
        control_root=control,
        controller_root=controller,
    )
    assert status is ControlPlaneRevalidationStatus.DRIFTED
    assert state.terminal_status is TerminalStatus.BLOCKED


def test_control_root_replacement_with_identical_bytes_fails_revalidation(tmp_path: Path) -> None:
    control = _control_root(tmp_path)
    controller = _controller_root(tmp_path)
    bound = capture_control_plane_subject(control, controller_root=controller)

    original = tmp_path / "control-original"
    control.rename(original)
    control.mkdir()
    for source in sorted(original.rglob("*")):
        relative = source.relative_to(original)
        destination = control / relative
        if source.is_dir():
            destination.mkdir(parents=True, exist_ok=True)
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read_bytes())

    current = capture_control_plane_subject(control, controller_root=controller)
    assert current.subject.subject_digest == bound.subject.subject_digest
    assert current.observation.project_root_identity != bound.observation.project_root_identity

    state = _state(bound, terminal_status=TerminalStatus.SUCCESS)
    status, _ = enforce_terminal_control_plane_subject(
        state,
        bound=bound,
        control_root=control,
        controller_root=controller,
    )
    assert status is ControlPlaneRevalidationStatus.DRIFTED
    assert state.terminal_status is TerminalStatus.BLOCKED


def test_incomplete_or_unsafe_project_namespace_fails_closed(tmp_path: Path) -> None:
    control = _control_root(tmp_path)
    controller = _controller_root(tmp_path)
    target = control / "CLAUDE.md"
    link = control / ".claude" / "unsafe-link"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation is unavailable")

    with pytest.raises(ValueError, match="cannot be observed completely"):
        capture_control_plane_subject(control, controller_root=controller)


def test_resource_bounds_are_enforced_during_actual_controller_ingestion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    control = _control_root(tmp_path)
    controller = _controller_root(tmp_path)
    monkeypatch.setattr(provenance, "_MAX_FILE_BYTES", 3)

    with pytest.raises(ValueError, match="per-file byte ingestion limit"):
        capture_control_plane_subject(control, controller_root=controller)


def test_terminal_success_is_demoted_on_content_drift_but_existing_failure_is_preserved(
    tmp_path: Path,
) -> None:
    control = _control_root(tmp_path)
    controller = _controller_root(tmp_path)
    bound = capture_control_plane_subject(control, controller_root=controller)
    (controller / "runtime" / "system_prompt.py").write_text("PROMPT = 'changed'\n")

    success = _state(bound, terminal_status=TerminalStatus.SUCCESS)
    status, _ = enforce_terminal_control_plane_subject(
        success,
        bound=bound,
        control_root=control,
        controller_root=controller,
    )
    assert status is ControlPlaneRevalidationStatus.DRIFTED
    assert success.terminal_status is TerminalStatus.BLOCKED
    assert success.control_plane_terminal_subject_digest != bound.subject.subject_digest

    failure = _state(bound, terminal_status=TerminalStatus.FAILURE)
    original_reason = failure.terminal_reason
    status, _ = enforce_terminal_control_plane_subject(
        failure,
        bound=bound,
        control_root=control,
        controller_root=controller,
    )
    assert status is ControlPlaneRevalidationStatus.DRIFTED
    assert failure.terminal_status is TerminalStatus.FAILURE
    assert failure.terminal_reason == original_reason


def test_unavailable_terminal_subject_demotes_only_candidate_success(tmp_path: Path) -> None:
    control = _control_root(tmp_path)
    controller = _controller_root(tmp_path)
    bound = capture_control_plane_subject(control, controller_root=controller)
    # Remove the entire required project-authority directory so terminal recapture
    # cannot establish a complete subject at all (distinct from ordinary content drift).
    import shutil

    shutil.rmtree(control / ".claude")

    success = _state(bound, terminal_status=TerminalStatus.SUCCESS)
    status, _ = enforce_terminal_control_plane_subject(
        success,
        bound=bound,
        control_root=control,
        controller_root=controller,
    )
    assert status is ControlPlaneRevalidationStatus.UNAVAILABLE
    assert success.terminal_status is TerminalStatus.INFRASTRUCTURE_FAILURE

    failure = _state(bound, terminal_status=TerminalStatus.FAILURE)
    status, _ = enforce_terminal_control_plane_subject(
        failure,
        bound=bound,
        control_root=control,
        controller_root=controller,
    )
    assert status is ControlPlaneRevalidationStatus.UNAVAILABLE
    assert failure.terminal_status is TerminalStatus.FAILURE



def test_persisted_control_subject_rejects_internally_inconsistent_digest(tmp_path: Path) -> None:
    import json

    bound = _capture(tmp_path)
    state = _state(bound, terminal_status=TerminalStatus.FAILURE)
    state_path = tmp_path / "persisted" / "state.json"
    store = StateStore(state_path)
    store.save(state)

    payload = json.loads(state_path.read_text(encoding="utf-8"))
    payload["control_plane_subject"]["project_manifest"]["digest"] = "sha256:" + "0" * 64
    state_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="control-plane manifest digest"):
        StateStore(state_path).load()

def test_report_state_attestation_and_lineage_preserve_control_subject_separately_from_target(
    tmp_path: Path,
) -> None:
    bound = _capture(tmp_path)
    state = _state(bound, terminal_status=TerminalStatus.FAILURE)
    state.control_plane_revalidation_status = ControlPlaneRevalidationStatus.VERIFIED
    state.control_plane_terminal_subject_digest = bound.subject.subject_digest

    report = build_final_report(state).model_dump(mode="json")
    provenance_payload = report["provenance"]
    assert (
        provenance_payload["control_plane_subject"]["subject_digest"]
        == bound.subject.subject_digest
    )
    assert provenance_payload["target_git_sha"] == "b" * 40
    assert provenance_payload["target_git_sha"] != bound.subject.control_git_sha

    run_dir = tmp_path / "artifacts" / state.run_id
    StateStore(run_dir / "state.json").save(state)
    attestation = build_run_attestation(run_dir)
    assert (
        attestation["runtime"]["control_plane_subject"]["subject_digest"]
        == bound.subject.subject_digest
    )
    assert attestation["target"]["git_sha"] == "b" * 40
    assert attestation["signature"]["signed"] is False
    assert attestation["outcome"]["terminal_status"] == TerminalStatus.FAILURE.value

    lineage = build_run_lineage(run_dir).as_dict()
    run_node = next(node for node in lineage["nodes"] if node["kind"] == "run")
    assert (
        run_node["attributes"]["control_plane_subject"]["subject_digest"]
        == bound.subject.subject_digest
    )
    assert run_node["attributes"]["target_git_sha"] == "b" * 40
