from __future__ import annotations

import base64
import hashlib
import io
import json
import zipfile
from pathlib import Path
from typing import Any

import pytest

import scripts.trusted_pr_evidence as evidence
import scripts.verify_ci_contract as ci_contract
from scripts.trusted_pr_control import PullRequestSubject

ROOT = Path(__file__).resolve().parents[2]
SHA_A = "a" * 40
SHA_B = "b" * 40
SHA_C = "c" * 40
SHA_D = "d" * 40


def _manifest_item(path: str = ".github") -> dict[str, str]:
    return {"path": path, "base_oid": SHA_A, "subject_oid": SHA_B}


def test_trusted_evidence_contract_is_exact_and_candidate_nonexecuting() -> None:
    result = ci_contract.verify_ci_contract(ROOT)["workflows"]["trusted_evidence"]

    assert result["workflow_definition"] == "exact-reviewed-git-blob"
    assert result["evidence_verifier"] == "exact-reviewed-git-blob"
    assert result["candidate_execution"] == "none"

    text = (ROOT / ".github" / "workflows" / "trusted-pr-evidence.yml").read_text(encoding="utf-8")
    assert text.count("ref: ${{ github.sha }}") == 2
    assert "ref: ${{ github.event.client_payload.expected_merge_sha }}" not in text


def test_manifest_parser_rejects_unknown_duplicate_and_malformed_authority() -> None:
    with pytest.raises(ValueError, match="unknown or duplicate"):
        evidence._parse_manifest(
            '[{"path":"docs","base_oid":"' + SHA_A + '","subject_oid":"' + SHA_B + '"}]'
        )

    duplicate = [_manifest_item(), _manifest_item()]
    with pytest.raises(ValueError, match="unknown or duplicate"):
        evidence._parse_manifest(json.dumps(duplicate))

    malformed = [_manifest_item() | {"base_oid": "short"}]
    with pytest.raises(ValueError, match="full Git object ID"):
        evidence._parse_manifest(json.dumps(malformed))


def test_run_match_requires_exact_pr_head_base_and_branch() -> None:
    expected = PullRequestSubject(number=70, head_sha=SHA_A, base_sha=SHA_B, merge_sha=SHA_C)
    run: dict[str, Any] = {
        "event": "pull_request",
        "path": ".github/workflows/ci.yml",
        "head_sha": SHA_A,
        "head_branch": "feature",
        "status": "completed",
        "conclusion": "success",
        "pull_requests": [
            {
                "number": 70,
                "head": {"sha": SHA_A, "ref": "feature"},
                "base": {"sha": SHA_B, "ref": "main"},
            }
        ],
    }

    assert evidence._run_matches(run, expected=expected, head_ref="feature")
    assert not evidence._run_matches(
        run | {"head_sha": SHA_D}, expected=expected, head_ref="feature"
    )
    wrong_base = dict(run)
    wrong_base["pull_requests"] = [
        {
            "number": 70,
            "head": {"sha": SHA_A, "ref": "feature"},
            "base": {"sha": SHA_D, "ref": "main"},
        }
    ]
    assert not evidence._run_matches(wrong_base, expected=expected, head_ref="feature")


class _JobsApi:
    repository = "owner/repo"

    def __init__(self, jobs: list[dict[str, Any]]) -> None:
        self.jobs = jobs

    def get_json(self, path: str) -> dict[str, Any]:
        assert path.endswith("/jobs?per_page=100&filter=latest")
        return {"total_count": len(self.jobs), "jobs": self.jobs}


def _successful_job(name: str, *, steps: list[dict[str, str]] | None = None) -> dict[str, Any]:
    return {"name": name, "conclusion": "success", "steps": steps or []}


def _successful_jobs() -> list[dict[str, Any]]:
    return [
        _successful_job(
            "Supply Chain / Wheel + SBOM + Container",
            steps=[{"name": "Verify CI authority contract", "conclusion": "success"}],
        ),
        _successful_job("Quality / Python 3.11.16"),
        _successful_job("Quality / Python 3.14.7"),
        _successful_job("Security Gates"),
        _successful_job("Playwright Reference SUT"),
        _successful_job("34-Case Deterministic Control Evaluation"),
        _successful_job(
            "Required PR Gate",
            steps=[{"name": "Require every automatic gate to succeed", "conclusion": "success"}],
        ),
        {"name": "Trusted PR Gate Reporter", "conclusion": "skipped", "steps": []},
    ]


def test_job_admission_requires_candidate_ci_contract_and_required_gate() -> None:
    result = evidence._verify_jobs(_JobsApi(_successful_jobs()), 123)
    assert result["quality_jobs"] == ["Quality / Python 3.11.16", "Quality / Python 3.14.7"]

    jobs = _successful_jobs()
    jobs[0] = _successful_job("Supply Chain / Wheel + SBOM + Container")
    with pytest.raises(ValueError, match="CI authority contract"):
        evidence._verify_jobs(_JobsApi(jobs), 123)

    jobs = _successful_jobs()
    jobs[6] = _successful_job("Required PR Gate")
    with pytest.raises(ValueError, match="deterministically aggregate"):
        evidence._verify_jobs(_JobsApi(jobs), 123)


class _WorkflowApi:
    repository = "owner/repo"

    def __init__(self, text: str) -> None:
        self.text = text

    def get_json(self, path: str) -> dict[str, Any]:
        assert path.startswith("/repos/owner/repo/contents/.github/workflows/ci.yml?ref=")
        return {
            "encoding": "base64",
            "content": base64.b64encode(self.text.encode("utf-8")).decode("ascii"),
        }


def test_candidate_workflow_binding_rejects_wrong_subject_or_missing_aggregate() -> None:
    valid = (
        "on:\n  pull_request:\n"
        "env:\n  "
        + evidence.EXPECTED_SUBJECT_BINDING
        + "\njobs:\n  required-gate:\n    name: Required PR Gate\n"
    )
    evidence._verify_candidate_workflow_binding(_WorkflowApi(valid), SHA_C)

    with pytest.raises(ValueError, match=r"bound to github\.sha"):
        evidence._verify_candidate_workflow_binding(
            _WorkflowApi(
                valid.replace(evidence.EXPECTED_SUBJECT_BINDING, "CI_SUBJECT_SHA: deadbeef")
            ),
            SHA_C,
        )

    with pytest.raises(ValueError, match="Required PR Gate"):
        evidence._verify_candidate_workflow_binding(
            _WorkflowApi(valid.replace("    name: Required PR Gate\n", "")),
            SHA_C,
        )


def _artifact_archive(commit_sha: str, *, unsafe_name: str | None = None) -> bytes:
    manifest = {
        "schema_version": 1,
        "kind": "unsigned_reproducible_build_manifest",
        "source": {
            "commit_sha": commit_sha,
            "tree_sha": SHA_D,
            "tracked_worktree_clean": True,
        },
    }
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        if unsafe_name is not None:
            bundle.writestr(unsafe_name, b"unsafe")
        bundle.writestr("build-manifest.json", json.dumps(manifest, sort_keys=True))
    return buffer.getvalue()


class _ArtifactsApi:
    repository = "owner/repo"

    def __init__(
        self,
        archive: bytes,
        *,
        run_id: int = 123,
        head_sha: str = SHA_A,
        head_ref: str = "feature",
    ) -> None:
        self.archive = archive
        self.run_id = run_id
        self.head_sha = head_sha
        self.head_ref = head_ref

    def get_json(self, path: str) -> dict[str, Any]:
        assert path == (
            "/repos/owner/repo/actions/runs/123/artifacts?per_page=20&name=supply-chain-evidence"
        )
        return {
            "total_count": 1,
            "artifacts": [
                {
                    "id": 456,
                    "name": "supply-chain-evidence",
                    "size_in_bytes": len(self.archive),
                    "archive_download_url": (
                        "https://api.github.com/repos/owner/repo/actions/artifacts/456/zip"
                    ),
                    "expired": False,
                    "digest": f"sha256:{hashlib.sha256(self.archive).hexdigest()}",
                    "workflow_run": {
                        "id": self.run_id,
                        "head_sha": self.head_sha,
                        "head_branch": self.head_ref,
                    },
                }
            ],
        }


def _patch_archive_download(monkeypatch: pytest.MonkeyPatch, archive: bytes) -> None:
    def _download(**kwargs: Any) -> bytes:
        assert kwargs["repository"] == "owner/repo"
        assert kwargs["token"] == "token"
        assert kwargs["artifact_id"] == 456
        assert kwargs["expected_size"] == len(archive)
        assert kwargs["expected_digest"] == hashlib.sha256(archive).hexdigest()
        return archive

    monkeypatch.setattr(evidence, "_download_artifact_archive", _download)


def test_supply_chain_artifact_binds_selected_run_to_exact_merge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive = _artifact_archive(SHA_C)
    _patch_archive_download(monkeypatch, archive)
    expected = PullRequestSubject(number=70, head_sha=SHA_A, base_sha=SHA_B, merge_sha=SHA_C)

    result = evidence._verify_supply_chain_artifact(
        _ArtifactsApi(archive),
        token="token",
        run_id=123,
        expected=expected,
        head_ref="feature",
    )

    assert result["build_manifest_source_commit"] == SHA_C
    assert result["build_manifest_source_tree"] == SHA_D


def test_supply_chain_artifact_rejects_stale_merge_and_wrong_run_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = PullRequestSubject(number=70, head_sha=SHA_A, base_sha=SHA_B, merge_sha=SHA_C)
    stale = _artifact_archive(SHA_D)
    _patch_archive_download(monkeypatch, stale)
    with pytest.raises(ValueError, match="prospective merge SHA"):
        evidence._verify_supply_chain_artifact(
            _ArtifactsApi(stale),
            token="token",
            run_id=123,
            expected=expected,
            head_ref="feature",
        )

    exact = _artifact_archive(SHA_C)
    _patch_archive_download(monkeypatch, exact)
    with pytest.raises(ValueError, match="selected pull-request run"):
        evidence._verify_supply_chain_artifact(
            _ArtifactsApi(exact, head_sha=SHA_D),
            token="token",
            run_id=123,
            expected=expected,
            head_ref="feature",
        )


def test_build_manifest_archive_rejects_unsafe_zip_entries() -> None:
    archive = _artifact_archive(SHA_C, unsafe_name="../escape")
    with pytest.raises(ValueError, match="unsafe or duplicate"):
        evidence._verify_build_manifest_archive(archive, SHA_C)


def test_artifact_storage_download_never_receives_github_authorization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive = _artifact_archive(SHA_C)
    digest = hashlib.sha256(archive).hexdigest()
    monkeypatch.setattr(
        evidence,
        "_artifact_redirect_url",
        lambda **_: "https://artifact-storage.example/evidence.zip?signature=opaque",
    )

    class _Response:
        def __enter__(self) -> _Response:
            return self

        def __exit__(self, *_: Any) -> None:
            return None

        def read(self, size: int) -> bytes:
            assert size == evidence.MAX_ARTIFACT_BYTES + 1
            return archive

    class _Opener:
        def open(self, request: Any, *, timeout: int) -> _Response:
            assert timeout == 15
            assert request.full_url.startswith("https://artifact-storage.example/")
            assert request.get_header("Authorization") is None
            return _Response()

    monkeypatch.setattr(evidence.urllib.request, "build_opener", lambda *_: _Opener())

    assert (
        evidence._download_artifact_archive(
            repository="owner/repo",
            token="token",
            artifact_id=456,
            expected_size=len(archive),
            expected_digest=digest,
        )
        == archive
    )
