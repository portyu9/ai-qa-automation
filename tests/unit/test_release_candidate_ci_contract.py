from __future__ import annotations

from pathlib import Path

import pytest

import scripts.verify_ci_contract as ci_contract


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "release-candidate.yml"


def _verify_mutation(monkeypatch: pytest.MonkeyPatch, text: str) -> None:
    digest = ci_contract._trusted_auto._base._git_blob_sha1(text)
    monkeypatch.setattr(ci_contract, "EXPECTED_RELEASE_CANDIDATE_WORKFLOW_BLOB_SHA", digest)
    ci_contract._verify_release_candidate_workflow(text)


def test_release_candidate_workflow_exact_definition_passes() -> None:
    result = ci_contract._verify_release_candidate_workflow(WORKFLOW.read_text(encoding="utf-8"))
    assert result["trigger"] == "workflow_dispatch"
    assert result["permissions"] == "contents:read"
    assert result["publishing_authority"] == "none"
    assert result["builds"] == 2


def test_release_candidate_workflow_rejects_push_trigger(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text = WORKFLOW.read_text(encoding="utf-8").replace(
        "on:\n  workflow_dispatch:\n",
        "on:\n  push:\n    branches: [main]\n  workflow_dispatch:\n",
        1,
    )
    with pytest.raises(ValueError, match=r"workflow_dispatch only|unreviewed trigger"):
        _verify_mutation(monkeypatch, text)


def test_release_candidate_workflow_rejects_write_permission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text = WORKFLOW.read_text(encoding="utf-8").replace("contents: read", "contents: write", 1)
    with pytest.raises(ValueError, match="permissions must be exactly contents: read"):
        _verify_mutation(monkeypatch, text)


def test_release_candidate_workflow_rejects_subject_rebinding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text = WORKFLOW.read_text(encoding="utf-8").replace(
        "RELEASE_SUBJECT_SHA: ${{ github.sha }}",
        "RELEASE_SUBJECT_SHA: ${{ github.ref }}",
        1,
    )
    with pytest.raises(ValueError, match="release subject environment"):
        _verify_mutation(monkeypatch, text)


def test_release_candidate_workflow_rejects_removed_main_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text = WORKFLOW.read_text(encoding="utf-8").replace(
        '          test "$GITHUB_REF" = "refs/heads/main"\n',
        "",
        1,
    )
    with pytest.raises(ValueError, match="refs/heads/main"):
        _verify_mutation(monkeypatch, text)


def test_release_candidate_workflow_rejects_single_build(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text = WORKFLOW.read_text(encoding="utf-8").replace(
        '          python -m pip wheel --no-deps --no-build-isolation "$build_b" --wheel-dir "$RELEASE_EVIDENCE_DIR/wheel-b"\n',
        "",
        1,
    )
    with pytest.raises(ValueError, match="exactly two reviewed wheels"):
        _verify_mutation(monkeypatch, text)


def test_release_candidate_workflow_rejects_oidc_signing_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text = WORKFLOW.read_text(encoding="utf-8").replace(
        "permissions:\n  contents: read\n",
        "permissions:\n  contents: read\n  id-token: write\n",
        1,
    )
    with pytest.raises(ValueError, match="permissions must be exactly contents: read"):
        _verify_mutation(monkeypatch, text)
